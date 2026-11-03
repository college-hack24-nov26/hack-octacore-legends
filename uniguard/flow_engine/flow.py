"""Unidirectional Flow Data Structure.

Maintains running state and packet metrics for a single 5-tuple unidirectional flow.
"""

from typing import Tuple, List, Optional, Dict, Any
import math


class UnidirectionalFlow:
    """Represents an active or completed unidirectional IP flow with O(1) streaming statistics."""

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: int,
        start_time: float,
        max_sampled_packets: int = 100,
        elephant_cutoff_packets: int = 50,
    ) -> None:
        # Immutable 5-tuple
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto

        # Timing
        self.start_time: float = start_time
        self.last_seen_time: float = start_time

        # Running counters (64-bit safe)
        self.packet_count: int = 0
        self.byte_count: int = 0

        # Memory-bounded sample window for entropy & backward-compatibility
        self.max_sampled_packets: int = max_sampled_packets
        self.packet_lengths: List[int] = []
        self.inter_arrival_times: List[float] = []

        # Elephant flow cutoff and bypass state
        self.elephant_cutoff_packets: int = elephant_cutoff_packets
        self.is_elephant: bool = False
        self.is_analyzed: bool = False
        self.is_benign: bool = True

        # O(1) Welford running statistics for packet lengths
        self.pkt_len_min: float = 0.0
        self.pkt_len_max: float = 0.0
        self.pkt_len_mean: float = 0.0
        self._pkt_len_m2: float = 0.0

        # O(1) Welford running statistics for inter-arrival times (IAT)
        self.iat_count: int = 0
        self.iat_min: float = 0.0
        self.iat_max: float = 0.0
        self.iat_mean: float = 0.0
        self._iat_m2: float = 0.0

        # TCP Flag counts
        self.tcp_syn_cnt: int = 0
        self.tcp_psh_cnt: int = 0
        self.tcp_ack_cnt: int = 0
        self.tcp_fin_cnt: int = 0
        self.tcp_rst_cnt: int = 0
        self.tcp_urg_cnt: int = 0

        # Flow closure flag
        self.is_closed: bool = False
        self.closure_reason: Optional[str] = None

    @property
    def key(self) -> Tuple[str, str, int, int, int]:
        """Returns the canonical 5-tuple identifying this unidirectional flow."""
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto)

    @property
    def duration(self) -> float:
        """Returns the current duration of the flow in seconds."""
        return max(0.0, self.last_seen_time - self.start_time)

    @property
    def pkt_len_std(self) -> float:
        """Population standard deviation of packet lengths (matches np.std ddof=0)."""
        if self.packet_count <= 1:
            return 0.0
        var = max(0.0, self._pkt_len_m2 / self.packet_count)
        return math.sqrt(var)

    @property
    def iat_std(self) -> float:
        """Population standard deviation of inter-arrival times (matches np.std ddof=0)."""
        if self.iat_count <= 1:
            return 0.0
        var = max(0.0, self._iat_m2 / self.iat_count)
        return math.sqrt(var)

    def add_packet(
        self,
        pkt_len: int,
        timestamp: float,
        tcp_flags: Optional[int] = None,
    ) -> None:
        """Incorporates a single unidirectional packet into this flow record using O(1) operations.
        
        Args:
            pkt_len: Size of the packet in bytes.
            timestamp: Packet observation timestamp (epoch seconds).
            tcp_flags: Optional bitmask of TCP flags if protocol is TCP.
        """
        self.packet_count += 1
        self.byte_count += pkt_len

        # 1. Update Packet Length Statistics via Welford's Algorithm
        f_len = float(pkt_len)
        if self.packet_count == 1:
            self.pkt_len_min = f_len
            self.pkt_len_max = f_len
            self.pkt_len_mean = f_len
            self._pkt_len_m2 = 0.0
        else:
            if f_len < self.pkt_len_min:
                self.pkt_len_min = f_len
            if f_len > self.pkt_len_max:
                self.pkt_len_max = f_len
            delta = f_len - self.pkt_len_mean
            self.pkt_len_mean += delta / self.packet_count
            delta2 = f_len - self.pkt_len_mean
            self._pkt_len_m2 += delta * delta2

        # Retain bounded sample window for exact Shannon entropy & inspection
        if len(self.packet_lengths) < self.max_sampled_packets:
            self.packet_lengths.append(pkt_len)

        # 2. Update Inter-Arrival Time (IAT) Statistics via Welford's Algorithm
        if self.packet_count > 1:
            iat = max(0.0, timestamp - self.last_seen_time)
            self.iat_count += 1
            if self.iat_count == 1:
                self.iat_min = iat
                self.iat_max = iat
                self.iat_mean = iat
                self._iat_m2 = 0.0
            else:
                if iat < self.iat_min:
                    self.iat_min = iat
                if iat > self.iat_max:
                    self.iat_max = iat
                delta_iat = iat - self.iat_mean
                self.iat_mean += delta_iat / self.iat_count
                delta_iat2 = iat - self.iat_mean
                self._iat_m2 += delta_iat * delta_iat2

            if len(self.inter_arrival_times) < self.max_sampled_packets:
                self.inter_arrival_times.append(iat)

        self.last_seen_time = timestamp

        # 3. Elephant Flow Transition Check
        if self.packet_count >= self.elephant_cutoff_packets and not self.is_elephant:
            # Check if this flow is established (e.g. has ACK exchange, not a pure SYN flood)
            if self.tcp_syn_cnt <= 3:
                self.is_elephant = True

        # 4. Process TCP Flags
        if tcp_flags is not None and self.proto == 6:
            # TCP Flag Bitmasks
            # FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08, ACK: 0x10, URG: 0x20
            if tcp_flags & 0x01:
                self.tcp_fin_cnt += 1
                self.is_closed = True
                self.closure_reason = "TCP_FIN"
            if tcp_flags & 0x02:
                self.tcp_syn_cnt += 1
            if tcp_flags & 0x04:
                self.tcp_rst_cnt += 1
                self.is_closed = True
                self.closure_reason = "TCP_RST"
            if tcp_flags & 0x08:
                self.tcp_psh_cnt += 1
            if tcp_flags & 0x10:
                self.tcp_ack_cnt += 1
            if tcp_flags & 0x20:
                self.tcp_urg_cnt += 1

    def calculate_entropy(self) -> float:
        """Calculates Shannon entropy of packet lengths observed in the bounded sample window."""
        if not self.packet_lengths:
            return 0.0
        n = len(self.packet_lengths)
        freq: dict = {}
        for length in self.packet_lengths:
            freq[length] = freq.get(length, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / n
            entropy -= p * math.log2(p)
        return float(entropy)

    def to_summary_dict(self) -> dict:
        """Returns high-level metadata of the flow."""
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "duration": round(self.duration, 4),
            "start_time": self.start_time,
            "last_seen_time": self.last_seen_time,
            "is_closed": self.is_closed,
            "is_elephant": self.is_elephant,
            "closure_reason": self.closure_reason,
            "directionality_state": getattr(self, "directionality_state", None),
            "directionality_score": getattr(self, "directionality_score", None),
        }


class CanonicalBiflow:
    """Represents a canonical 2-way conversation tracking forward and reverse activity.
    
    Acts as the bridge between wire-level bidirectional packet observations and the
    unidirectional security pipeline by calculating directionality metrics and projecting
    unidirectional flow representations.
    """

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: int,
        start_time: float,
    ) -> None:
        # First packet establishes logical Forward (Initiator -> Responder)
        self.initiator_ip = src_ip
        self.responder_ip = dst_ip
        self.initiator_port = src_port
        self.responder_port = dst_port
        self.proto = proto

        self.start_time: float = start_time
        self.last_seen_time: float = start_time

        # Directional streaming counters
        from uniguard.directionality.flow_identity import CanonicalFlowKey, DirectionalCounters
        from uniguard.directionality.asymmetry_engine import AsymmetryEngine

        self.canonical_key = CanonicalFlowKey.from_endpoints(src_ip, dst_ip, src_port, dst_port, proto)
        self.fwd_counters = DirectionalCounters(direction_name="forward")
        self.rev_counters = DirectionalCounters(direction_name="reverse")

        # Directional burst and dependency tracking
        self.burst_transitions: int = 0
        self.last_packet_direction: Optional[str] = None
        self.inter_direction_lags: List[float] = []

        # Closure and Directionality metadata
        self.is_closed: bool = False
        self.closure_reason: Optional[str] = None
        self.directionality_result: Optional[Any] = None

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen_time - self.start_time)

    @property
    def total_packets(self) -> int:
        return self.fwd_counters.packet_count + self.rev_counters.packet_count

    @property
    def total_bytes(self) -> int:
        return self.fwd_counters.byte_count + self.rev_counters.byte_count

    def add_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        pkt_len: int,
        timestamp: float,
        tcp_flags: Optional[int] = None,
    ) -> None:
        """Incorporates an observed packet into the appropriate direction of this biflow."""
        # Check if packet aligns with forward initiator or reverse responder
        if src_ip == self.initiator_ip and src_port == self.initiator_port and dst_ip == self.responder_ip and dst_port == self.responder_port:
            direction = "forward"
            self.fwd_counters.add_packet(pkt_len=pkt_len, timestamp=timestamp, tcp_flags=tcp_flags)
        else:
            direction = "reverse"
            self.rev_counters.add_packet(pkt_len=pkt_len, timestamp=timestamp, tcp_flags=tcp_flags)

        # Track alternating burst transitions and response lags (Task 6)
        if self.last_packet_direction is not None and self.last_packet_direction != direction:
            self.burst_transitions += 1
            lag = max(0.0, timestamp - self.last_seen_time)
            if len(self.inter_direction_lags) < 100:
                self.inter_direction_lags.append(lag)

        self.last_packet_direction = direction
        self.last_seen_time = timestamp

        # TCP FIN/RST termination check
        if tcp_flags is not None and self.proto == 6:
            if tcp_flags & 0x01:
                self.is_closed = True
                self.closure_reason = "TCP_FIN"
            elif tcp_flags & 0x04:
                self.is_closed = True
                self.closure_reason = "TCP_RST"

    def get_directionality_features(self) -> Dict[str, float]:
        """Computes complete directionality and dependency feature dictionary."""
        from uniguard.directionality.asymmetry_engine import AsymmetryEngine
        return AsymmetryEngine.calculate_features(
            fwd=self.fwd_counters,
            rev=self.rev_counters,
            overall_duration=self.duration,
            burst_transitions=self.burst_transitions,
            inter_direction_lags=self.inter_direction_lags,
            is_client_initiated=(self.initiator_port > 1024 and self.responder_port <= 1024),
        )

    def get_unidirectional_projection(self, direction: str = "forward") -> UnidirectionalFlow:
        """Projects a UnidirectionalFlow representation for 24-feature ML security analysis."""
        if direction == "forward" or self.rev_counters.packet_count == 0:
            src_ip, dst_ip = self.initiator_ip, self.responder_ip
            src_port, dst_port = self.initiator_port, self.responder_port
            counters = self.fwd_counters
        else:
            src_ip, dst_ip = self.responder_ip, self.initiator_ip
            src_port, dst_port = self.responder_port, self.initiator_port
            counters = self.rev_counters

        uni_flow = UnidirectionalFlow(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            proto=self.proto,
            start_time=counters.first_seen if counters.packet_count > 0 else self.start_time,
        )

        uni_flow.last_seen_time = counters.last_seen if counters.packet_count > 0 else self.last_seen_time
        uni_flow.packet_count = counters.packet_count
        uni_flow.byte_count = counters.byte_count

        uni_flow.pkt_len_min = counters.pkt_len_min
        uni_flow.pkt_len_max = counters.pkt_len_max
        uni_flow.pkt_len_mean = counters.pkt_len_mean
        uni_flow._pkt_len_m2 = counters._pkt_len_m2

        uni_flow.iat_count = counters.iat_count
        uni_flow.iat_min = counters.iat_min
        uni_flow.iat_max = counters.iat_max
        uni_flow.iat_mean = counters.iat_mean
        uni_flow._iat_m2 = counters._iat_m2

        uni_flow.tcp_syn_cnt = counters.tcp_syn_cnt
        uni_flow.tcp_psh_cnt = counters.tcp_psh_cnt
        uni_flow.tcp_ack_cnt = counters.tcp_ack_cnt
        uni_flow.tcp_fin_cnt = counters.tcp_fin_cnt
        uni_flow.tcp_rst_cnt = counters.tcp_rst_cnt
        uni_flow.tcp_urg_cnt = counters.tcp_urg_cnt

        uni_flow.is_closed = self.is_closed
        uni_flow.closure_reason = self.closure_reason

        # Attach directionality result metadata
        if self.directionality_result is not None:
            uni_flow.directionality_result = self.directionality_result
            uni_flow.directionality_state = self.directionality_result.state.value
            uni_flow.directionality_score = self.directionality_result.score
            uni_flow.directionality_confidence = self.directionality_result.confidence
            uni_flow.is_excluded_from_unidirectional_security = self.directionality_result.is_excluded_from_unidirectional_security
            uni_flow.baseline_5_20 = self.directionality_result.baseline_5_20
        else:
            uni_flow.directionality_state = "UNKNOWN"
            uni_flow.directionality_score = 0.0
            uni_flow.directionality_confidence = 0.0
            uni_flow.is_excluded_from_unidirectional_security = False

        return uni_flow
