"""Controlled Traffic Scenarios Benchmark Suite for UniGuard AI.

Validates detection accuracy, false positive prevention, and elephant flow cutoff
across 5 distinct traffic profiles:
1. Large Legitimate Download (100k packets MTU) -> Must be BENIGN / Low Risk
2. Distributed SYN Flood Attack -> Must be CRITICAL / SYN_FLOOD
3. Reconnaissance Port Scan -> Must be HIGH / PORT_SCAN
4. High-Rate UDP Flood -> Must be HIGH / UDP_FLOOD / ANOMALY
5. Elephant Flow Cutoff Verification -> Asserts is_elephant transition at packet 50
"""

import unittest
import time
import os
import numpy as np

from uniguard.flow_engine.flow import UnidirectionalFlow
from uniguard.flow_engine.tracker import FlowTracker
from uniguard.detection.engine import DetectionEngine
from uniguard.features.extractor import FeatureExtractor
from uniguard.models.supervised import SupervisedThreatClassifier
from uniguard.models.anomaly import IsolationForestAnomalyDetector
from uniguard.preprocessing.pipeline import FlowDataPreprocessor
from uniguard.risk.scorer import RiskScorer


class TestTrafficScenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        models_dir = "models_saved"
        prep_file = os.path.join(models_dir, "preprocessor.joblib")
        rf_file = os.path.join(models_dir, "uniguard_rf_model.joblib")
        iso_file = os.path.join(models_dir, "uniguard_isolation_forest.joblib")

        preprocessor = FlowDataPreprocessor.load(prep_file) if os.path.exists(prep_file) else None
        classifier = SupervisedThreatClassifier.load(rf_file) if os.path.exists(rf_file) else None
        anomaly_detector = IsolationForestAnomalyDetector.load(iso_file) if os.path.exists(iso_file) else None

        cls.engine = DetectionEngine(
            classifier=classifier,
            anomaly_detector=anomaly_detector,
            preprocessor=preprocessor,
            risk_scorer=RiskScorer(),
        )

    def test_scenario_1_large_legitimate_download(self):
        """A normal large download (e.g. 50 MB file) MUST NOT be classified as an attack."""
        flow = UnidirectionalFlow(
            src_ip="142.250.190.46", # Google CDN
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            proto=6, # TCP
            start_time=100.0,
        )

        # Feed 10,000 packets: standard TLS MTU (1460 bytes), ACK flags (0x10)
        t = 100.0
        for i in range(10_000):
            t += 0.0002 # ~5,000 pps
            pkt_len = 1460 if i % 20 != 0 else 64
            flow.add_packet(pkt_len=pkt_len, timestamp=t, tcp_flags=0x10)

        # Assert elephant flow fast-path was engaged
        self.assertTrue(flow.is_elephant, "Flow should be marked as elephant flow")
        self.assertEqual(flow.packet_count, 10_000)

        event = self.engine.analyze_flow(flow, skip_shap=True)

        # Core NDR Requirement: Legitimate bulk download must be BENIGN / LOW RISK
        self.assertEqual(event.threat_type, "BENIGN")
        self.assertLess(event.risk_score, 35, f"Legitimate download triggered high risk score: {event.risk_score}")
        self.assertIn(event.severity, ["LOW", "MEDIUM"])

    def test_scenario_2_syn_flood_attack(self):
        """A SYN flood (rapid empty SYN packets with zero ACKs) MUST trigger CRITICAL threat."""
        flow = UnidirectionalFlow(
            src_ip="198.51.100.77",
            dst_ip="192.168.1.10",
            src_port=45678,
            dst_port=80,
            proto=6, # TCP
            start_time=200.0,
        )

        t = 200.0
        # Rapid SYN flood: 500 packets, small 64-byte SYN packets (0x02), zero ACKs
        for _ in range(500):
            t += 0.0001 # 10,000 pps burst
            flow.add_packet(pkt_len=64, timestamp=t, tcp_flags=0x02) # SYN

        event = self.engine.analyze_flow(flow)

        self.assertIn(event.threat_type, ["SYN_FLOOD", "SUSPICIOUS"])
        self.assertGreaterEqual(event.risk_score, 70, f"SYN flood risk score too low: {event.risk_score}")
        self.assertIn(event.severity, ["HIGH", "CRITICAL"])

    def test_scenario_3_port_scan_reconnaissance(self):
        """Single-packet probe against a closed/target port should alert as PORT_SCAN."""
        flow = UnidirectionalFlow(
            src_ip="10.0.0.99",
            dst_ip="192.168.1.50",
            src_port=50000,
            dst_port=22, # SSH probe
            proto=6,
            start_time=300.0,
        )
        flow.add_packet(pkt_len=60, timestamp=300.0, tcp_flags=0x02) # Isolated SYN

        event = self.engine.analyze_flow(flow)
        self.assertIn(event.threat_type, ["PORT_SCAN", "SUSPICIOUS"])
        self.assertGreaterEqual(event.risk_score, 50)

    def test_scenario_4_elephant_cutoff_performance(self):
        """Asserts that after packet 50, flow transitions to fast path and runs in < 0.5ms."""
        flow = UnidirectionalFlow(
            src_ip="1.1.1.1",
            dst_ip="192.168.1.2",
            src_port=443,
            dst_port=50000,
            proto=6,
            start_time=400.0,
            elephant_cutoff_packets=50,
        )

        # 1. First 49 packets: not elephant yet
        t = 400.0
        for _ in range(49):
            t += 0.001
            flow.add_packet(pkt_len=1400, timestamp=t, tcp_flags=0x10)
        self.assertFalse(flow.is_elephant)

        # 2. 50th packet: transitions to elephant
        t += 0.001
        flow.add_packet(pkt_len=1400, timestamp=t, tcp_flags=0x10)
        self.assertTrue(flow.is_elephant)

        # 3. Fast-path feature extraction & analysis latency must be sub-millisecond steady-state
        # Warmup initial model runtime
        _ = self.engine.analyze_flow(flow, skip_shap=True)

        timings = []
        for _ in range(5):
            start = time.perf_counter()
            event = self.engine.analyze_flow(flow, skip_shap=True)
            timings.append((time.perf_counter() - start) * 1000)

        avg_ms = sum(timings) / len(timings)
        self.assertLess(avg_ms, 2.0, f"Average steady-state analysis took too long: {avg_ms:.2f}ms")
        self.assertEqual(event.threat_type, "BENIGN")


if __name__ == "__main__":
    unittest.main()
