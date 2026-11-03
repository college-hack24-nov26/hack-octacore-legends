"""Unidirectional Traffic Intelligence Engine (UTIE) Core Engine.

The central technical innovation of UniGuard AI for Smart India Hackathon 2026.
Orchestrates sensor visibility awareness, traffic behavior analysis, directionality
classification, and AI threat model integration.
"""

from __future__ import annotations

import time
from typing import Dict, Any, List, Optional, Tuple
import threading

from uniguard.flow_engine.flow import UnidirectionalFlow, CanonicalBiflow
from uniguard.detection.engine import DetectionEngine, SecurityEvent
from uniguard.utie.sensor_visibility import (
    ObservationPoint,
    SensorVisibilityContext,
    SensorVisibilityEvaluator,
    SensorVisibilityAssessment,
)
from uniguard.utie.behavior_analyzer import (
    TrafficBehaviorAnalyzer,
    TrafficBehaviorSummary,
)
from uniguard.utie.classifier import (
    DirectionalityClassifier,
    DirectionalityClass,
    DirectionalityClassificationResult,
)
from uniguard.utie.report import UTIEIntelligenceReport


class UnidirectionalTrafficIntelligenceEngine:
    """Intelligent engine analyzing unidirectional network observations in UniGuard AI."""

    def __init__(
        self,
        detection_engine: Optional[DetectionEngine] = None,
        sensor_context: Optional[SensorVisibilityContext] = None,
        min_packets_threshold: int = 3,
        min_duration_threshold: float = 0.05,
    ) -> None:
        self.detection_engine = detection_engine
        self.sensor_context = sensor_context or SensorVisibilityContext()
        self.visibility_evaluator = SensorVisibilityEvaluator(self.sensor_context)
        self.classifier = DirectionalityClassifier(
            min_packets_threshold=min_packets_threshold,
            min_duration_threshold=min_duration_threshold,
        )

        anomaly_model = getattr(self.detection_engine, "anomaly_detector", None) if self.detection_engine else None
        self.behavior_analyzer = TrafficBehaviorAnalyzer(anomaly_detector=anomaly_model)

        self._lock = threading.RLock()

        # Operational Aggregates for UTIE Dashboard KPIs
        self.total_flows_analyzed: int = 0
        self.unidirectional_count: int = 0
        self.bidirectional_count: int = 0
        self.asymmetric_count: int = 0
        self.insufficient_data_count: int = 0
        self.suspicious_count: int = 0

        # Memory-bounded cache of recent intelligence reports (max 1000)
        self.recent_reports: List[UTIEIntelligenceReport] = []
        self.max_recent_cache: int = 1000

    def set_sensor_context(self, context: SensorVisibilityContext) -> None:
        """Updates the operator monitoring point and sensor constraints."""
        with self._lock:
            self.sensor_context = context
            self.visibility_evaluator = SensorVisibilityEvaluator(context)

    def analyze_flow(
        self,
        flow: UnidirectionalFlow,
        biflow: Optional[CanonicalBiflow] = None,
        security_event: Optional[SecurityEvent] = None,
    ) -> UTIEIntelligenceReport:
        """Executes full UTIE intelligence synthesis on an observed network flow.

        Args:
            flow: The dominant UnidirectionalFlow representation.
            biflow: Optional upstream CanonicalBiflow if bilateral tracking is active.
            security_event: Optional precomputed SecurityEvent from DetectionEngine.
        """
        with self._lock:
            self.total_flows_analyzed += 1
            now = time.time()
            flow_id = f"UTIE-{int(now * 1000)}-{self.total_flows_analyzed:06d}"

            # 1. Extract directional counts
            fwd_pkts = flow.packet_count
            fwd_bytes = flow.byte_count
            duration = max(0.0001, flow.duration)
            first_seen = flow.start_time
            last_seen = flow.last_seen_time

            rev_pkts: Optional[int] = None
            rev_bytes: Optional[int] = None

            if biflow is not None:
                rev_pkts = biflow.rev_counters.packet_count
                rev_bytes = biflow.rev_counters.byte_count

            # 2. Evaluate Sensor Visibility Awareness
            has_syn = (flow.tcp_syn_cnt > 0)
            has_ack = (flow.tcp_ack_cnt > 0)
            vis_assessment = self.visibility_evaluator.evaluate(
                forward_packets=fwd_pkts,
                reverse_packets=rev_pkts,
                flow_duration=duration,
                proto=flow.proto,
                has_syn=has_syn,
                has_ack=has_ack,
            )

            # 3. Classify Directionality and compute calibrated evidence score
            dir_res = self.classifier.classify(
                fwd_packets=fwd_pkts,
                rev_packets=rev_pkts,
                fwd_bytes=fwd_bytes,
                rev_bytes=rev_bytes,
                duration=duration,
                proto=flow.proto,
                visibility_assessment=vis_assessment,
                tcp_syn_cnt=flow.tcp_syn_cnt,
                tcp_ack_cnt=flow.tcp_ack_cnt,
                tcp_fin_cnt=flow.tcp_fin_cnt,
                tcp_rst_cnt=flow.tcp_rst_cnt,
            )

            # Update aggregate KPI counters
            cls_name = dir_res.classification.value
            if cls_name == DirectionalityClass.UNIDIRECTIONAL_OBSERVED.value:
                self.unidirectional_count += 1
            elif cls_name == DirectionalityClass.BIDIRECTIONAL_OBSERVED.value:
                self.bidirectional_count += 1
            elif cls_name == DirectionalityClass.ASYMMETRIC_OBSERVED.value:
                self.asymmetric_count += 1
            elif cls_name == DirectionalityClass.INSUFFICIENT_DATA.value:
                self.insufficient_data_count += 1

            # 4. Deep Traffic Behavior Analysis
            behavior = self.behavior_analyzer.analyze(flow)

            # 5. Integrate AI Detection Models (Supervised RF, Anomaly IF, Risk Scorer)
            threat_cat: Optional[str] = None
            ml_conf: Optional[float] = None
            risk_val: Optional[int] = None
            severity_str: Optional[str] = None
            anomaly_stat = "ANOMALOUS" if behavior.is_suspicious_behavior or behavior.anomaly_score > 0.45 else "NORMAL"

            if security_event is not None:
                threat_cat = security_event.threat_type
                ml_conf = security_event.confidence_pct / 100.0 if security_event.confidence_pct is not None else 0.5
                risk_val = security_event.risk_score
                severity_str = security_event.severity
            elif self.detection_engine is not None:
                try:
                    sec_evt = self.detection_engine.analyze_flow(flow)
                    threat_cat = sec_evt.threat_type
                    ml_conf = sec_evt.confidence_pct / 100.0 if sec_evt.confidence_pct is not None else 0.5
                    risk_val = sec_evt.risk_score
                    severity_str = sec_evt.severity
                except Exception:
                    pass

            # Update suspicious flow counter
            is_suspicious_flow = (
                (risk_val is not None and risk_val >= 40)
                or (threat_cat is not None and threat_cat != "BENIGN")
                or behavior.is_suspicious_behavior
            )
            if is_suspicious_flow:
                self.suspicious_count += 1

            # 6. Generate Contextual SOC Investigation Playbook Steps
            investigation_steps = self._generate_investigation_steps(
                directionality_class=cls_name,
                visibility_assessment=vis_assessment,
                behavior=behavior,
                threat_category=threat_cat,
                risk_score=risk_val or 0,
            )

            # Calculate rates
            pkt_rate = float(fwd_pkts) / duration if duration > 0 else 0.0
            byte_rate = float(fwd_bytes) / duration if duration > 0 else 0.0

            total_pkts = fwd_pkts + (rev_pkts if rev_pkts is not None else 0)
            total_bytes = fwd_bytes + (rev_bytes if rev_bytes is not None else 0)

            # 7. Construct Final Structured Report
            report = UTIEIntelligenceReport(
                flow_id=flow_id,
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                src_port=flow.src_port,
                dst_port=flow.dst_port,
                proto=flow.proto,
                proto_name=behavior.proto_name,
                directionality=cls_name,
                directionality_confidence=dir_res.confidence_score,
                directionality_evidence=dir_res.evidence_bullets,
                sensor_visibility=vis_assessment.to_dict(),
                packet_count=fwd_pkts,
                reverse_packet_count=rev_pkts,
                byte_count=fwd_bytes,
                reverse_byte_count=rev_bytes,
                total_packet_count=total_pkts,
                total_byte_count=total_bytes,
                duration=duration,
                pkt_rate=pkt_rate,
                byte_rate=byte_rate,
                first_seen=first_seen,
                last_seen=last_seen,
                traffic_behavior_summary=behavior.to_dict(),
                anomaly_status=anomaly_stat,
                anomaly_score=behavior.anomaly_score,
                ml_threat_category=threat_cat,
                ml_confidence=ml_conf,
                risk_score=risk_val,
                severity=severity_str,
                suggested_investigation_steps=investigation_steps,
                analysis_timestamp=now,
            )

            # Add to memory cache
            self.recent_reports.append(report)
            if len(self.recent_reports) > self.max_recent_cache:
                self.recent_reports.pop(0)

            return report

    def _generate_investigation_steps(
        self,
        directionality_class: str,
        visibility_assessment: SensorVisibilityAssessment,
        behavior: TrafficBehaviorSummary,
        threat_category: Optional[str],
        risk_score: int,
    ) -> List[str]:
        """Provides actionable, context-aware cybersecurity investigation steps."""
        steps: List[str] = []

        if directionality_class == DirectionalityClass.INSUFFICIENT_DATA.value:
            steps.append("1. Extend observation window: flow contains too few packets for definitive directionality classification.")
            steps.append("2. Correlate with adjacent 5-tuples from the same source IP to identify distributed probe activity.")
            return steps

        # Sensor topology awareness
        if visibility_assessment.is_reverse_direction_missing:
            if visibility_assessment.visibility_type.value == "MONITORED_ONE_WAY_HARDWARE":
                steps.append("1. Sensor Visibility: Hardware Data Diode confirmed. Do not attempt reverse-path packet recovery.")
                steps.append("2. Verify payload authorization against data diode egress policy.")
            elif visibility_assessment.visibility_type.value == "POTENTIAL_ASYMMETRIC_ROUTING":
                steps.append("1. Topology Alert: Sensor is located on an asymmetric path. Correlate with border router flow logs (NetFlow/IPFIX) to verify return path.")

        # Threat and behavior specific triage
        threat = (threat_category or "BENIGN").upper()
        if "SYN" in threat or behavior.flag_pattern == "SYN_ONLY":
            steps.append("2. Analyze SYN probe scope: check if source IP is sweeping multiple destination ports or subnets.")
            steps.append("3. Verify destination firewall SYN-flood defense (SYN cookies, rate limiting).")
        elif "UDP" in threat or behavior.flag_pattern == "UDP_STREAM":
            steps.append("2. Inspect UDP payload entropy and destination port service (DNS, NTP, SNMP, QUIC).")
            steps.append("3. Evaluate potential amplification vector or reflection abuse.")
        elif "EXFILTRATION" in threat or behavior.byte_rate > 50000.0:
            steps.append("2. Outbound data volume anomaly: inspect high byte rate without corresponding inbound session controls.")
            steps.append("3. Check destination IP reputation, ASN, and geo-location against enterprise threat intel.")
        elif behavior.is_periodic_beacon:
            steps.append("2. Periodic beaconing pattern detected: correlate timestamp intervals with host process activity for scheduled C2 heartbeat.")
        elif threat == "BENIGN":
            steps.append("1. Normal behavioral pattern observed: no immediate defensive action required.")
            steps.append("2. Telemetry logged to database for historical baseline modeling.")
        else:
            steps.append(f"1. Triage detected {threat} alert: review top contributing features and anomaly score.")
            steps.append("2. Check endpoint authentication logs and network segment isolation.")

        return steps

    def get_summary(self) -> Dict[str, Any]:
        """Returns aggregate overview KPI metrics for dashboard presentation."""
        with self._lock:
            total = max(1, self.total_flows_analyzed)
            return {
                "total_flows_analyzed": self.total_flows_analyzed,
                "unidirectional_observations": self.unidirectional_count,
                "unidirectional_pct": round((self.unidirectional_count / total) * 100.0, 1),
                "bidirectional_observations": self.bidirectional_count,
                "bidirectional_pct": round((self.bidirectional_count / total) * 100.0, 1),
                "asymmetric_observations": self.asymmetric_count,
                "asymmetric_pct": round((self.asymmetric_count / total) * 100.0, 1),
                "insufficient_data_flows": self.insufficient_data_count,
                "insufficient_data_pct": round((self.insufficient_data_count / total) * 100.0, 1),
                "suspicious_flows": self.suspicious_count,
                "suspicious_pct": round((self.suspicious_count / total) * 100.0, 1),
                "sensor_observation_point": self.sensor_context.observation_point.value,
                "sensor_is_diode": self.sensor_context.is_diode_enforced,
            }

    def reset_metrics(self) -> None:
        """Resets all aggregate session counters."""
        with self._lock:
            self.total_flows_analyzed = 0
            self.unidirectional_count = 0
            self.bidirectional_count = 0
            self.asymmetric_count = 0
            self.insufficient_data_count = 0
            self.suspicious_count = 0
            self.recent_reports.clear()
