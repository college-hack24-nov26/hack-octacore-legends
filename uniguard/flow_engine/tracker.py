"""Flow Tracker with Canonical Biflow and Directionality Engine Integration.

Aggregates wire packets into flows, manages state tables, handles deterministic
timeout evictions, and integrates the unsupervised Flow Directionality & Asymmetry Engine
to enforce bidirectional exclusion before security threat detection.
"""

import threading
import time
from typing import Dict, List, Tuple, Optional, Any, Callable
from uniguard.flow_engine.flow import UnidirectionalFlow, CanonicalBiflow
from uniguard.directionality.flow_identity import CanonicalFlowKey
from uniguard.directionality.unsupervised_model import (
    UnsupervisedDirectionalityEngine,
    DirectionalityResult,
    DirectionalityState,
)


class FlowTracker:
    """Manages active IP flows with timeout eviction and optional directionality analysis."""

    def __init__(
        self,
        idle_timeout: float = 15.0,
        active_timeout: float = 60.0,
        max_flows: int = 100000,
        enable_directionality: bool = False,
        directionality_engine: Optional[UnsupervisedDirectionalityEngine] = None,
    ) -> None:
        self.idle_timeout: float = idle_timeout
        self.active_timeout: float = active_timeout
        self.max_flows: int = max_flows
        self.enable_directionality: bool = enable_directionality
        self.directionality_engine = directionality_engine or (
            UnsupervisedDirectionalityEngine() if enable_directionality else None
        )

        # Thread synchronization lock (RLock supports recursive acquisitions within process_packet -> evict_expired)
        self._lock = threading.RLock()

        # Legacy unidirectional 5-tuple table
        self.active_flows: Dict[Tuple[str, str, int, int, int], UnidirectionalFlow] = {}

        # Canonical biflow 2-way conversation table
        self.active_biflows: Dict[CanonicalFlowKey, CanonicalBiflow] = {}

        # Global operational counters
        self.total_packets_processed: int = 0
        self.total_flows_created: int = 0
        self.total_flows_evicted: int = 0

        # Directionality distribution tracking (Task 20)
        self.directionality_counts: Dict[str, int] = {
            "BIDIRECTIONAL": 0,
            "ASYMMETRIC": 0,
            "STRONGLY_ASYMMETRIC": 0,
            "UNIDIRECTIONAL_OBSERVED": 0,
            "UNKNOWN": 0,
        }
        self.total_excluded_flows: int = 0

    def process_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: int,
        pkt_len: int,
        timestamp: Optional[float] = None,
        tcp_flags: Optional[int] = None,
    ) -> List[UnidirectionalFlow]:
        """Processes an incoming packet and returns any completed or evicted flows.

        Returns:
            List of evicted UnidirectionalFlow objects (with directionality metadata attached).
        """
        now = timestamp if timestamp is not None else time.time()
        evicted_flows: List[UnidirectionalFlow] = []

        with self._lock:
            self.total_packets_processed += 1

            if self.enable_directionality:
                # ---------------------------------------------------------
                # Canonical Biflow Mode (Tasks 2, 4, 11)
                # ---------------------------------------------------------
                ckey = CanonicalFlowKey.from_endpoints(src_ip, dst_ip, src_port, dst_port, proto)

                if ckey in self.active_biflows:
                    biflow = self.active_biflows[ckey]
                    # Check active timeout slice
                    if (now - biflow.start_time) >= self.active_timeout:
                        biflow.is_closed = True
                        biflow.closure_reason = "ACTIVE_TIMEOUT"
                        uni_proj = self._finalize_biflow(biflow)
                        evicted_flows.append(uni_proj)

                        # Re-initialize continuing biflow
                        biflow = CanonicalBiflow(src_ip, dst_ip, src_port, dst_port, proto, start_time=now)
                        self.active_biflows[ckey] = biflow
                        self.total_flows_created += 1
                else:
                    if len(self.active_biflows) >= self.max_flows:
                        evicted_flows.extend(self.evict_expired(now, force_fraction=0.1))

                    biflow = CanonicalBiflow(src_ip, dst_ip, src_port, dst_port, proto, start_time=now)
                    self.active_biflows[ckey] = biflow
                    self.total_flows_created += 1

                biflow.add_packet(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    pkt_len=pkt_len,
                    timestamp=now,
                    tcp_flags=tcp_flags,
                )

                # If closed by TCP FIN/RST
                if biflow.is_closed:
                    uni_proj = self._finalize_biflow(biflow)
                    evicted_flows.append(uni_proj)
                    del self.active_biflows[ckey]

            else:
                # ---------------------------------------------------------
                # Legacy Strict Unidirectional Mode
                # ---------------------------------------------------------
                key = (src_ip, dst_ip, src_port, dst_port, proto)

                if key in self.active_flows:
                    flow = self.active_flows[key]
                    if (now - flow.start_time) >= self.active_timeout:
                        flow.is_closed = True
                        flow.closure_reason = "ACTIVE_TIMEOUT"
                        evicted_flows.append(flow)
                        flow = UnidirectionalFlow(src_ip, dst_ip, src_port, dst_port, proto, start_time=now)
                        self.active_flows[key] = flow
                        self.total_flows_created += 1
                else:
                    if len(self.active_flows) >= self.max_flows:
                        evicted_flows.extend(self.evict_expired(now, force_fraction=0.1))

                    flow = UnidirectionalFlow(src_ip, dst_ip, src_port, dst_port, proto, start_time=now)
                    self.active_flows[key] = flow
                    self.total_flows_created += 1

                flow.add_packet(pkt_len=pkt_len, timestamp=now, tcp_flags=tcp_flags)

                if flow.is_closed:
                    evicted_flows.append(flow)
                    del self.active_flows[key]

            return evicted_flows

    def _finalize_biflow(self, biflow: CanonicalBiflow) -> UnidirectionalFlow:
        """Evaluates directionality, updates counters, and projects unidirectional representation."""
        if self.directionality_engine is not None:
            features = biflow.get_directionality_features()
            result = self.directionality_engine.evaluate_flow(features, is_flow_closed=biflow.is_closed)
            biflow.directionality_result = result

            state_name = result.state.value
            self.directionality_counts[state_name] = self.directionality_counts.get(state_name, 0) + 1

            if result.is_excluded_from_unidirectional_security:
                self.total_excluded_flows += 1

        # Project dominant unidirectional flow (Task 11)
        uni_flow = biflow.get_unidirectional_projection(direction="forward")
        return uni_flow

    def evict_expired(self, current_time: float, force_fraction: float = 0.0) -> List[UnidirectionalFlow]:
        """Evicts flows that have exceeded idle or active timeouts."""
        evicted: List[UnidirectionalFlow] = []

        with self._lock:
            if self.enable_directionality:
                keys_to_evict: List[CanonicalFlowKey] = []
                # Snapshot active_biflows items to guarantee safe iteration under concurrency
                for ckey, biflow in list(self.active_biflows.items()):
                    idle_duration = current_time - biflow.last_seen_time
                    active_duration = current_time - biflow.start_time

                    if idle_duration >= self.idle_timeout:
                        biflow.is_closed = True
                        biflow.closure_reason = "IDLE_TIMEOUT"
                        keys_to_evict.append(ckey)
                        evicted.append(self._finalize_biflow(biflow))
                    elif active_duration >= self.active_timeout:
                        biflow.is_closed = True
                        biflow.closure_reason = "ACTIVE_TIMEOUT"
                        keys_to_evict.append(ckey)
                        evicted.append(self._finalize_biflow(biflow))

                for ckey in keys_to_evict:
                    del self.active_biflows[ckey]

            else:
                keys_to_evict_tuple: List[Tuple[str, str, int, int, int]] = []
                # Snapshot active_flows items to guarantee safe iteration under concurrency
                for key, flow in list(self.active_flows.items()):
                    idle_duration = current_time - flow.last_seen_time
                    active_duration = current_time - flow.start_time

                    if idle_duration >= self.idle_timeout:
                        flow.is_closed = True
                        flow.closure_reason = "IDLE_TIMEOUT"
                        keys_to_evict_tuple.append(key)
                        evicted.append(flow)
                    elif active_duration >= self.active_timeout:
                        flow.is_closed = True
                        flow.closure_reason = "ACTIVE_TIMEOUT"
                        keys_to_evict_tuple.append(key)
                        evicted.append(flow)

                for key in keys_to_evict_tuple:
                    del self.active_flows[key]

            self.total_flows_evicted += len(evicted)
            return evicted

    def flush_all(self, should_stop: Optional[Callable[[], bool]] = None) -> List[UnidirectionalFlow]:
        """Flushes all currently active flows upon shutdown or PCAP EOF."""
        evicted: List[UnidirectionalFlow] = []

        with self._lock:
            if self.enable_directionality:
                for biflow in list(self.active_biflows.values()):
                    if should_stop and should_stop():
                        break
                    biflow.is_closed = True
                    biflow.closure_reason = "FLUSH"
                    evicted.append(self._finalize_biflow(biflow))
                self.active_biflows.clear()
            else:
                for flow in list(self.active_flows.values()):
                    if should_stop and should_stop():
                        break
                    flow.is_closed = True
                    flow.closure_reason = "FLUSH"
                    evicted.append(flow)
                self.active_flows.clear()

            self.total_flows_evicted += len(evicted)
            return evicted

    def get_stats(self) -> dict:
        """Returns tracker health, flow capacity, and directionality distribution metrics."""
        with self._lock:
            active_count = len(self.active_biflows) if self.enable_directionality else len(self.active_flows)
            dir_counts_copy = dict(self.directionality_counts)
            total_directional = sum(dir_counts_copy.values()) or 1

            distribution_pct = {
                k: round((v / total_directional) * 100.0, 1)
                for k, v in dir_counts_copy.items()
            }

            return {
                "active_flows": active_count,
                "total_packets_processed": self.total_packets_processed,
                "total_flows_created": self.total_flows_created,
                "total_flows_evicted": self.total_flows_evicted,
                "enable_directionality": self.enable_directionality,
                "directionality_counts": dir_counts_copy,
                "directionality_distribution_pct": distribution_pct,
                "total_excluded_flows": self.total_excluded_flows,
            }


class CanonicalFlowTracker(FlowTracker):
    """Convenience subclass of FlowTracker with directionality engine enabled by default."""

    def __init__(
        self,
        idle_timeout: float = 15.0,
        active_timeout: float = 60.0,
        max_flows: int = 100000,
        directionality_engine: Optional[UnsupervisedDirectionalityEngine] = None,
    ) -> None:
        super().__init__(
            idle_timeout=idle_timeout,
            active_timeout=active_timeout,
            max_flows=max_flows,
            enable_directionality=True,
            directionality_engine=directionality_engine,
        )
