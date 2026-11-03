"""Unit Tests for Detection Engine and Persistence."""

import unittest
import os
import shutil
import tempfile
import numpy as np

from uniguard.flow_engine.flow import UnidirectionalFlow
from uniguard.preprocessing.pipeline import FlowDataPreprocessor
from uniguard.models.supervised import SupervisedThreatClassifier
from uniguard.models.anomaly import IsolationForestAnomalyDetector
from uniguard.risk.scorer import RiskScorer
from uniguard.detection.engine import DetectionEngine
from uniguard.database.storage import SecurityDatabase
from scripts.run_unidirectional_experiment import generate_benchmark_dataset


class TestDetectionPipeline(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_events.db")
        self.database = SecurityDatabase(db_path=self.db_path)

        # Train miniature models for fast test execution
        df = generate_benchmark_dataset(n_samples=200, random_seed=42)
        self.preprocessor = FlowDataPreprocessor()
        X_scaled, y_enc = self.preprocessor.fit_transform(df[self.preprocessor.feature_names], df["label"])

        self.classifier = SupervisedThreatClassifier(model_type="random_forest", n_estimators=10)
        self.classifier.train(X_scaled, y_enc, feature_names=self.preprocessor.feature_names)

        self.anomaly_detector = IsolationForestAnomalyDetector(n_estimators=10)
        self.anomaly_detector.fit(X_scaled)

        self.engine = DetectionEngine(
            classifier=self.classifier,
            anomaly_detector=self.anomaly_detector,
            preprocessor=self.preprocessor,
            risk_scorer=RiskScorer(),
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_flow_analysis_and_event_generation(self):
        flow = UnidirectionalFlow("10.0.0.5", "192.168.1.1", 54321, 80, 6, start_time=100.0)
        flow.add_packet(64, timestamp=100.0, tcp_flags=0x02) # SYN
        flow.add_packet(128, timestamp=100.1, tcp_flags=0x10) # ACK

        event = self.engine.analyze_flow(flow)

        self.assertIsNotNone(event.event_id)
        self.assertIn("10.0.0.5", event.flow_key)
        self.assertIsInstance(event.risk_score, int)
        self.assertTrue(0 <= event.risk_score <= 100)
        self.assertIn(event.severity, ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.assertEqual(len(event.contributing_factors), 4)

    def test_database_persistence_and_retrieval(self):
        flow = UnidirectionalFlow("172.16.0.4", "10.0.0.1", 1234, 443, 6, start_time=200.0)
        flow.add_packet(500, timestamp=200.0)
        event = self.engine.analyze_flow(flow)

        self.database.insert_event(event)
        recent = self.database.get_recent_events(limit=10)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["event_id"], event.event_id)
        self.assertEqual(recent[0]["threat_type"], event.threat_type)


if __name__ == "__main__":
    unittest.main()
