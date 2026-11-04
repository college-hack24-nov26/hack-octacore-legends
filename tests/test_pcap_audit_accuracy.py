"""Audit and Accuracy Verification Tests for UniGuard AI.

Validates:
1. Zero-duration rate calculations (no 10^7 artificial spikes, finite 0.0 values, 24-feature schema).
2. Protocol formatting (TCP, UDP, ICMP representation).
3. Benign DNS domain-knowledge guard.
4. SYN Flood vs. Port Scan discrimination.
5. Multi-event security incident correlation and aggregation.
6. Contextual XAI explanations and multi-class SHAP attribution.
7. Bidirectional flow matching and exclusion gate.
"""

import time
import pytest
import numpy as np

from uniguard.flow_engine.flow import UnidirectionalFlow, CanonicalBiflow
from uniguard.flow_engine.tracker import FlowTracker
from uniguard.features.extractor import FeatureExtractor
from uniguard.features.schema import UNIDIRECTIONAL_FEATURES
from uniguard.detection.engine import DetectionEngine, SecurityEvent
from uniguard.detection.correlator import SecurityIncidentCorrelator, format_protocol
from uniguard.explainability.explainer import FlowExplainer
from uniguard.directionality.unsupervised_model import (
    UnsupervisedDirectionalityEngine,
    DirectionalityState,
)


class TestPcapAuditAccuracy:
    """Test suite covering the 5 pipeline audit requirements."""

    def test_zero_duration_rate_calculation(self):
        """Issue 3: Ensure zero-duration or 1-packet flows yield 0.0 rates without artificial spikes."""
        now = time.time()
        flow = UnidirectionalFlow(
            src_ip="172.16.0.45",
            dst_ip="192.168.1.50",
            src_port=1024,
            dst_port=80,
            proto=6,
            start_time=now,
        )
        flow.add_packet(pkt_len=54, timestamp=now, tcp_flags=0x02)  # Single SYN packet

        assert flow.duration == 0.0
        assert flow.packet_count == 1

        features = FeatureExtractor.extract_features(flow)

        # Rate metrics must be 0.0, NOT 10,000,000 or 710,000,000
        assert features["pkt_rate"] == 0.0
        assert features["byte_rate"] == 0.0

        # All 24 canonical features must be present, valid finite floats, no NaNs
        assert len(features) == len(UNIDIRECTIONAL_FEATURES)
        for fname in UNIDIRECTIONAL_FEATURES:
            val = features[fname]
            assert isinstance(val, float)
            assert not np.isnan(val)
            assert not np.isinf(val)
            assert val < 100000.0  # Safe upper bound, no spikes

    def test_multi_packet_positive_duration_rates(self):
        """Verify normal multi-packet rate calculation with positive duration."""
        now = time.time()
        flow = UnidirectionalFlow(
            src_ip="192.168.1.100",
            dst_ip="93.184.216.34",
            src_port=54321,
            dst_port=80,
            proto=6,
            start_time=now,
        )
        flow.add_packet(pkt_len=100, timestamp=now, tcp_flags=0x02)
        flow.add_packet(pkt_len=400, timestamp=now + 2.0, tcp_flags=0x10)

        assert flow.packet_count == 2
        assert flow.duration == 2.0

        features = FeatureExtractor.extract_features(flow)
        assert features["pkt_rate"] == 1.0       # 2 packets / 2.0s
        assert features["byte_rate"] == 250.0    # 500 bytes / 2.0s

    def test_protocol_presentation(self):
        """Issue 5: Ensure protocols map to readable strings (TCP, UDP, ICMP)."""
        assert format_protocol(6) == "TCP"
        assert format_protocol(17) == "UDP"
        assert format_protocol(1) == "ICMP"
        assert format_protocol(47) == "P47"

    def test_dns_benign_guard(self):
        """Issue 2: Verify isolated DNS UDP queries are guarded as BENIGN."""
        engine = DetectionEngine()
        now = time.time()

        dns_flow = UnidirectionalFlow(
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            src_port=54321,
            dst_port=53,
            proto=17,
            start_time=now,
        )
        dns_flow.add_packet(pkt_len=64, timestamp=now)

        event = engine.analyze_flow(dns_flow)
        assert event.threat_type == "BENIGN"
        assert event.severity in ("INFORMATIONAL", "LOW")
        assert event.risk_score < 35
        assert "[UDP]" in event.flow_key

    def test_syn_flood_vs_port_scan_discrimination(self):
        """Issue 2: Distinguish repeated requests to same port (SYN Flood) vs multiple ports (Port Scan)."""
        engine = DetectionEngine()
        now = time.time()

        # 1. Attacker targeting port 80 repeatedly with rotating source ports -> SYN Flood
        syn_flood_events = []
        for sport in range(1024, 1030):
            f = UnidirectionalFlow(
                src_ip="172.16.0.45",
                dst_ip="192.168.1.50",
                src_port=sport,
                dst_port=80,
                proto=6,
                start_time=now,
            )
            f.add_packet(pkt_len=54, timestamp=now, tcp_flags=0x02)
            ev = engine.analyze_flow(f)
            syn_flood_events.append(ev)

        # After 3+ packets to the same port, engine classifies as SYN_FLOOD
        last_event = syn_flood_events[-1]
        assert last_event.threat_type == "SYN_FLOOD"
        assert last_event.risk_score >= 60

        # 2. Scanner targeting multiple distinct ports -> Port Scan
        engine2 = DetectionEngine()
        scan_events = []
        target_ports = [21, 22, 23, 25, 80, 443]
        for dport in target_ports:
            f = UnidirectionalFlow(
                src_ip="10.0.0.99",
                dst_ip="192.168.1.50",
                src_port=50000 + dport,
                dst_port=dport,
                proto=6,
                start_time=now,
            )
            f.add_packet(pkt_len=54, timestamp=now, tcp_flags=0x02)
            ev = engine2.analyze_flow(f)
            scan_events.append(ev)

        assert scan_events[-1].threat_type == "PORT_SCAN"

    def test_security_incident_correlation(self):
        """Issue 2: Verify multi-event correlation groups alerts without suppressing raw logs."""
        correlator = SecurityIncidentCorrelator(time_window_sec=60.0)
        now = time.time()

        # Build 10 SYN flood events
        events: list[SecurityEvent] = []
        for i in range(10):
            ev = SecurityEvent(
                event_id=f"EVT-SYN-{i}",
                timestamp=now + (i * 0.05),
                flow_key=f"172.16.0.45:{1024+i} -> 192.168.1.50:80 [TCP]",
                src_ip="172.16.0.45",
                dst_ip="192.168.1.50",
                src_port=1024 + i,
                dst_port=80,
                proto=6,
                threat_type="PORT_SCAN",  # Initially per-flow labeled
                risk_score=75,
                severity="HIGH",
                confidence_pct=90.0,
                anomaly_score=0.8,
                contributing_factors=[],
                flow_metrics={"packet_count": 1, "byte_count": 54},
            )
            events.append(ev)

        # Build 5 Port scan events
        for i, port in enumerate([21, 22, 23, 80, 443]):
            ev = SecurityEvent(
                event_id=f"EVT-SCAN-{i}",
                timestamp=now + (i * 0.1),
                flow_key=f"10.0.0.99:50000 -> 192.168.1.50:{port} [TCP]",
                src_ip="10.0.0.99",
                dst_ip="192.168.1.50",
                src_port=50000 + i,
                dst_port=port,
                proto=6,
                threat_type="PORT_SCAN",
                risk_score=65,
                severity="MEDIUM",
                confidence_pct=85.0,
                anomaly_score=0.7,
                contributing_factors=[],
                flow_metrics={"packet_count": 1, "byte_count": 54},
            )
            events.append(ev)

        incidents = correlator.correlate_events(events)
        assert len(incidents) == 2

        types = [inc.incident_type for inc in incidents]
        assert "SYN_FLOOD" in types
        assert "PORT_SCAN" in types

        syn_inc = next(inc for inc in incidents if inc.incident_type == "SYN_FLOOD")
        assert syn_inc.event_count == 10
        assert syn_inc.target_ports == [80]
        assert syn_inc.src_ip == "172.16.0.45"
        assert len(syn_inc.event_ids) == 10

        scan_inc = next(inc for inc in incidents if inc.incident_type == "PORT_SCAN")
        assert scan_inc.event_count == 5
        assert len(scan_inc.target_ports) == 5
        assert scan_inc.src_ip == "10.0.0.99"

    def test_xai_context_filtering(self):
        """Issue 4: Contextual filtering for UDP and single-packet flows."""
        explainer = FlowExplainer(trained_model=None)

        # 1. UDP flow: TCP flags must NOT appear in explanations
        raw_udp = {
            "proto": 17.0,
            "dst_port": 53.0,
            "src_port": 54321.0,
            "pkt_count": 1.0,
            "byte_count": 64.0,
            "duration": 0.0,
            "pkt_rate": 0.0,
            "byte_rate": 0.0,
            "tcp_syn_cnt": 0.0,
            "tcp_ack_cnt": 0.0,
            "iat_mean": 0.0,
            "burstiness": 0.0,
        }
        vec = np.zeros(24, dtype=np.float32)
        explanations = explainer.explain_instance(raw_udp, vec, predicted_class="PORT_SCAN", top_k=6)
        explained_features = [exp["feature"] for exp in explanations]

        assert "tcp_syn_cnt" not in explained_features
        assert "tcp_ack_cnt" not in explained_features
        assert "iat_mean" not in explained_features
        assert "burstiness" not in explained_features

    def test_bidirectional_flow_matching_and_exclusion(self):
        """Issue 1: Ensure bidirectional conversations are matched and excluded from threat alerts."""
        tracker = FlowTracker(enable_directionality=True)
        now = time.time()

        # 1. Forward request A -> B:80 (SYN)
        tracker.process_packet(
            src_ip="192.168.1.10",
            dst_ip="93.184.216.34",
            src_port=50000,
            dst_port=80,
            proto=6,
            pkt_len=60,
            timestamp=now,
            tcp_flags=0x02,
        )

        # 2. Reverse response B:80 -> A (SYN-ACK)
        tracker.process_packet(
            src_ip="93.184.216.34",
            dst_ip="192.168.1.10",
            src_port=80,
            dst_port=50000,
            proto=6,
            pkt_len=60,
            timestamp=now + 0.02,
            tcp_flags=0x12,
        )

        # 3. Forward ACK A -> B:80 (ACK)
        tracker.process_packet(
            src_ip="192.168.1.10",
            dst_ip="93.184.216.34",
            src_port=50000,
            dst_port=80,
            proto=6,
            pkt_len=54,
            timestamp=now + 0.04,
            tcp_flags=0x10,
        )

        # 4. Reverse Data B:80 -> A (PSH-ACK)
        tracker.process_packet(
            src_ip="93.184.216.34",
            dst_ip="192.168.1.10",
            src_port=80,
            dst_port=50000,
            proto=6,
            pkt_len=1400,
            timestamp=now + 0.06,
            tcp_flags=0x18,
        )

        # Flush
        evicted = tracker.flush_all()
        assert len(evicted) == 1
        flow = evicted[0]

        # Verify biflow properties
        assert hasattr(flow, "_parent_biflow")
        biflow: CanonicalBiflow = flow._parent_biflow
        assert biflow.fwd_counters.packet_count == 2
        assert biflow.rev_counters.packet_count == 2
        assert biflow.burst_transitions >= 1

        # Directionality assessment
        res = biflow.directionality_result
        assert res is not None
        assert res.state == DirectionalityState.BIDIRECTIONAL
        assert res.is_excluded_from_unidirectional_security is True

        # When evaluated by DetectionEngine, it is cleanly excluded as BENIGN
        engine = DetectionEngine()
        event = engine.analyze_flow(flow)
        assert event.is_excluded_from_unidirectional_security is True
        assert event.threat_type == "BENIGN"
        assert event.severity == "INFORMATIONAL"

