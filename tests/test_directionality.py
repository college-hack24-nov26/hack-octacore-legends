"""Comprehensive Test Suite for Unsupervised Flow Directionality & Asymmetry Engine.

Smart India Hackathon (SIH) 2026 - Tasks 2 to 20, 23.
"""

import unittest
import time
import numpy as np

from uniguard.directionality.endpoint_registry import LocalEndpointRegistry, EndpointRole
from uniguard.directionality.flow_identity import CanonicalFlowKey, DirectionalCounters
from uniguard.directionality.asymmetry_engine import AsymmetryEngine, DIRECTIONALITY_FEATURE_NAMES
from uniguard.directionality.heuristics import HeuristicBaselineComparator
from uniguard.directionality.unsupervised_model import (
    UnsupervisedDirectionalityEngine,
    DirectionalityState,
    FlowObservationState,
)
from uniguard.directionality.explainer import DirectionalityExplainer
from uniguard.flow_engine.flow import CanonicalBiflow, UnidirectionalFlow
from uniguard.flow_engine.tracker import FlowTracker, CanonicalFlowTracker
from uniguard.flow_engine.flow_affinity import FlowAffinityDispatcher
from uniguard.detection.engine import DetectionEngine
from uniguard.risk.scorer import RiskScorer


class TestDirectionalityEngine(unittest.TestCase):

    def test_local_endpoint_registry(self):
        """Task 3: Validates local IP discovery, loopback exclusion, and perspective resolution."""
        reg = LocalEndpointRegistry(auto_discover=False)
        reg.register_manual_ip("192.168.1.50")
        reg.register_manual_ip("2001:db8::1")
        reg.register_manual_subnet("10.0.0.0/24")

        # Local IP matching
        self.assertTrue(reg.is_local_ip("192.168.1.50"))
        self.assertTrue(reg.is_local_ip("2001:db8::1"))
        self.assertTrue(reg.is_local_ip("10.0.0.99"))

        # Remote IP non-matching
        self.assertFalse(reg.is_local_ip("8.8.8.8"))
        self.assertFalse(reg.is_local_ip("142.250.190.46"))

        # Loopback strictly excluded
        self.assertFalse(reg.is_local_ip("127.0.0.1"))
        self.assertFalse(reg.is_local_ip("::1"))

        # Perspective resolution
        self.assertEqual(reg.get_flow_perspective("192.168.1.50", "8.8.8.8"), EndpointRole.LOCAL_OUTBOUND)
        self.assertEqual(reg.get_flow_perspective("8.8.8.8", "192.168.1.50"), EndpointRole.LOCAL_INBOUND)
        self.assertEqual(reg.get_flow_perspective("192.168.1.50", "10.0.0.5"), EndpointRole.INTERNAL_LAN)
        self.assertEqual(reg.get_flow_perspective("1.1.1.1", "8.8.8.8"), EndpointRole.EXTERNAL_TRANSIT)

    def test_canonical_flow_identity(self):
        """Task 2 & 4: Validates canonical 5-tuple matching and directional counters."""
        # A -> B and B -> A must produce identical canonical key
        k1 = CanonicalFlowKey.from_endpoints("192.168.1.10", "104.244.42.1", 54321, 443, 6)
        k2 = CanonicalFlowKey.from_endpoints("104.244.42.1", "192.168.1.10", 443, 54321, 6)
        self.assertEqual(k1, k2)

        # Directional counters
        fwd = DirectionalCounters("forward")
        rev = DirectionalCounters("reverse")

        fwd.add_packet(1460, 100.0, tcp_flags=0x02) # SYN
        fwd.add_packet(1460, 100.1, tcp_flags=0x10) # ACK
        rev.add_packet(54, 100.05, tcp_flags=0x12)  # SYN-ACK

        self.assertEqual(fwd.packet_count, 2)
        self.assertEqual(fwd.byte_count, 2920)
        self.assertEqual(rev.packet_count, 1)
        self.assertEqual(rev.byte_count, 54)
        self.assertEqual(fwd.tcp_syn_cnt, 1)
        self.assertEqual(rev.tcp_syn_cnt, 1)

    def test_asymmetry_and_dependency_features(self):
        """Tasks 5, 6, 7: Validates Ap, Ab, direction ratio, and dependency indicators."""
        fwd = DirectionalCounters("forward")
        rev = DirectionalCounters("reverse")

        # Perfectly balanced traffic: 10 packets fwd, 10 packets rev
        for i in range(10):
            fwd.add_packet(100, 10.0 + i * 0.1)
            rev.add_packet(100, 10.05 + i * 0.1)

        feats = AsymmetryEngine.calculate_features(fwd, rev, overall_duration=1.0, burst_transitions=10)
        self.assertAlmostEqual(feats["packet_asymmetry"], 0.0, places=3)
        self.assertAlmostEqual(feats["byte_asymmetry"], 0.0, places=3)
        self.assertAlmostEqual(feats["directional_ratio"], 0.0, places=3)
        self.assertEqual(feats["reverse_presence"], 1.0)
        self.assertGreater(feats["burst_transition_rate"], 0.4)

        # Extreme one-way traffic (SYN flood / port scan): 100 packets fwd, 0 rev
        fwd_flood = DirectionalCounters("forward")
        rev_flood = DirectionalCounters("reverse")
        for i in range(100):
            fwd_flood.add_packet(64, 20.0 + i * 0.001)

        flood_feats = AsymmetryEngine.calculate_features(fwd_flood, rev_flood, overall_duration=0.1)
        self.assertAlmostEqual(flood_feats["packet_asymmetry"], 1.0, places=3)
        self.assertAlmostEqual(flood_feats["byte_asymmetry"], 1.0, places=3)
        self.assertEqual(flood_feats["reverse_presence"], 0.0)
        self.assertEqual(flood_feats["burst_transition_rate"], 0.0)

        # Verify feature vector conversion
        vec = AsymmetryEngine.to_vector(flood_feats)
        self.assertEqual(len(vec), len(DIRECTIONALITY_FEATURE_NAMES))
        self.assertIsInstance(vec, np.ndarray)

    def test_heuristic_5_20_baseline(self):
        """Task 13: Validates 5/20 baseline evaluator and comparative contrast."""
        res_triggered = HeuristicBaselineComparator.evaluate_5_20(forward_packets=25, reverse_packets=3)
        self.assertTrue(res_triggered.is_asymmetric_5_20)
        self.assertEqual(res_triggered.baseline_label, "ASYMMETRIC_5_20")

        res_not_triggered = HeuristicBaselineComparator.evaluate_5_20(forward_packets=15, reverse_packets=10)
        self.assertFalse(res_not_triggered.is_asymmetric_5_20)
        self.assertEqual(res_not_triggered.baseline_label, "BALANCED_5_20")

        comparison = HeuristicBaselineComparator.compare_with_unsupervised(
            forward_packets=25,
            reverse_packets=3,
            unsupervised_state="BIDIRECTIONAL",
            unsupervised_score=0.15,
        )
        self.assertIn("False Asymmetry in 5/20", comparison["scientific_insight"])

    def test_minimum_observation_requirements(self):
        """Task 8: Asserts premature 1-2 packet flows remain UNKNOWN and do not alert prematurely."""
        engine = UnsupervisedDirectionalityEngine(min_packets=3, min_duration_sec=0.05)
        # Flow with only 1 packet and negligible duration
        feats = {
            "forward_packet_count": 1.0,
            "reverse_packet_count": 0.0,
            "duration": 0.001,
            "packet_asymmetry": 1.0,
            "byte_asymmetry": 1.0,
        }
        res = engine.evaluate_flow(feats, is_flow_closed=False)
        self.assertEqual(res.state, DirectionalityState.UNKNOWN)
        self.assertEqual(res.observation_state, FlowObservationState.UNKNOWN)
        self.assertTrue(res.is_excluded_from_unidirectional_security)

    def test_normal_download_exclusion(self):
        """Tasks 11 & 12: Asserts normal bulk download is identified as BIDIRECTIONAL and EXCLUDED from threat pipeline."""
        biflow = CanonicalBiflow(
            src_ip="142.250.190.46", # Web/CDN server
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            proto=6,
            start_time=100.0,
        )

        t = 100.0
        # Server sends 1,000 MTU packets (1460 bytes); client returns 300 ACKs (54 bytes)
        for i in range(1000):
            t += 0.001
            biflow.add_packet("142.250.190.46", "192.168.1.100", 443, 54321, 1460, t, tcp_flags=0x10)
            if i % 3 == 0:
                t += 0.0002
                biflow.add_packet("192.168.1.100", "142.250.190.46", 54321, 443, 54, t, tcp_flags=0x10)

        feats = biflow.get_directionality_features()
        engine = UnsupervisedDirectionalityEngine()
        result = engine.evaluate_flow(feats, is_flow_closed=True)

        # Core Test Assertions for Task 12:
        # 1. High byte asymmetry must NOT cause this download to be classified as pure unidirectional attack!
        self.assertEqual(result.state, DirectionalityState.BIDIRECTIONAL)
        self.assertTrue(result.is_excluded_from_unidirectional_security)
        self.assertLess(result.score, 0.45)

        # 2. Project unidirectional flow and run through DetectionEngine
        biflow.directionality_result = result
        uni_proj = biflow.get_unidirectional_projection("forward")

        detection_engine = DetectionEngine()
        event = detection_engine.analyze_flow(uni_proj)

        # Legitimate download must be BENIGN, LOW/INFORMATIONAL risk, and marked excluded
        self.assertEqual(event.threat_type, "BENIGN")
        self.assertLessEqual(event.risk_score, 15)
        self.assertEqual(event.directionality_state, "BIDIRECTIONAL")
        self.assertTrue(event.is_excluded_from_unidirectional_security)

    def test_syn_flood_unidirectional_detection(self):
        """Tasks 10 & 16: Asserts SYN flood is correctly detected as UNIDIRECTIONAL_OBSERVED and enters security pipeline."""
        biflow = CanonicalBiflow(
            src_ip="198.51.100.88",
            dst_ip="192.168.1.10",
            src_port=45678,
            dst_port=80,
            proto=6,
            start_time=200.0,
        )

        t = 200.0
        # 300 rapid SYN packets with ZERO reverse packets
        for _ in range(300):
            t += 0.0001
            biflow.add_packet("198.51.100.88", "192.168.1.10", 45678, 80, 54, t, tcp_flags=0x02)

        feats = biflow.get_directionality_features()
        engine = UnsupervisedDirectionalityEngine()
        result = engine.evaluate_flow(feats, is_flow_closed=True)

        self.assertEqual(result.state, DirectionalityState.UNIDIRECTIONAL_OBSERVED)
        self.assertFalse(result.is_excluded_from_unidirectional_security)
        self.assertGreaterEqual(result.score, 0.85)

        biflow.directionality_result = result
        uni_proj = biflow.get_unidirectional_projection("forward")

        detection_engine = DetectionEngine()
        event = detection_engine.analyze_flow(uni_proj)

        self.assertIn(event.threat_type, ["SYN_FLOOD", "SUSPICIOUS"])
        self.assertGreaterEqual(event.risk_score, 60)

    def test_canonical_flow_tracker_and_exclusion(self):
        """Tasks 11 & 17: Validates CanonicalFlowTracker and bidirectional exclusion gate."""
        tracker = CanonicalFlowTracker(idle_timeout=10.0)

        # Conversational flow (A <-> B)
        tracker.process_packet("192.168.1.10", "10.0.0.1", 50000, 80, 6, 100, timestamp=1.0, tcp_flags=0x10)
        tracker.process_packet("10.0.0.1", "192.168.1.10", 80, 50000, 6, 200, timestamp=1.1, tcp_flags=0x10)

        # In canonical mode, both packets map to the SAME biflow
        self.assertEqual(len(tracker.active_biflows), 1)

        # Evict flow
        evicted = tracker.flush_all()
        self.assertEqual(len(evicted), 1)
        flow = evicted[0]

        self.assertTrue(hasattr(flow, "directionality_state"))
        self.assertTrue(hasattr(flow, "directionality_score"))
        self.assertTrue(hasattr(flow, "is_excluded_from_unidirectional_security"))

        stats = tracker.get_stats()
        self.assertIn("directionality_distribution_pct", stats)
        self.assertEqual(stats["total_flows_created"], 1)

    def test_flow_affinity_dispatcher(self):
        """Task 18: Asserts consistent hashing routes forward and reverse packets to the exact same worker."""
        dispatcher = FlowAffinityDispatcher(num_workers=4)

        # Forward A -> B
        w_fwd = dispatcher.get_worker_index("192.168.1.10", "8.8.8.8", 54321, 53, 17)
        # Reverse B -> A
        w_rev = dispatcher.get_worker_index("8.8.8.8", "192.168.1.10", 53, 54321, 17)

        self.assertEqual(w_fwd, w_rev, "Forward and Reverse packets must route to identical affinity worker!")

    def test_directionality_explainer(self):
        """Task 19: Validates plain-text explainability formatting."""
        engine = UnsupervisedDirectionalityEngine()
        feats = {
            "forward_packet_count": 500.0,
            "reverse_packet_count": 2.0,
            "forward_byte_count": 700000.0,
            "reverse_byte_count": 108.0,
            "packet_asymmetry": 0.992,
            "byte_asymmetry": 0.999,
            "reverse_presence": 1.0,
            "reverse_ack_ratio": 0.004,
            "burst_transition_rate": 0.004,
            "duration": 5.0,
        }
        res = engine.evaluate_flow(feats, is_flow_closed=True)
        text = DirectionalityExplainer.format_text(res)

        self.assertIn("FLOW DIRECTIONALITY & ASYMMETRY ANALYSIS", text)
        self.assertIn("Directionality State:", text)
        self.assertIn("5/20 RESEARCH BASELINE CONTRAST:", text)


if __name__ == "__main__":
    unittest.main()
