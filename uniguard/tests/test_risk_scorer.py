"""Unit Tests for Risk Scoring Engine."""

import unittest
from uniguard.risk.scorer import RiskScorer


class TestRiskScorer(unittest.TestCase):
    def setUp(self):
        self.scorer = RiskScorer()

    def test_benign_traffic_suppression(self):
        """Confident benign traffic should produce low/informational risk."""
        result = self.scorer.calculate_risk(
            threat_type="BENIGN",
            classifier_confidence=0.98,
            anomaly_score=0.05,
            pkt_rate=10.0,
            byte_rate=5000.0,
        )
        self.assertLessEqual(result["risk_score"], 15)
        self.assertIn(result["severity"], ["INFORMATIONAL", "LOW"])

    def test_high_criticality_syn_flood(self):
        """High-confidence SYN flood with severe anomaly should produce HIGH or CRITICAL risk."""
        result = self.scorer.calculate_risk(
            threat_type="SYN_FLOOD",
            classifier_confidence=0.95,
            anomaly_score=0.88,
            pkt_rate=2500.0, # High flood rate
            byte_rate=150000.0,
        )
        self.assertGreaterEqual(result["risk_score"], 80)
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertEqual(result["confidence_pct"], 95.0)

    def test_weights_sum_validation(self):
        """Scorer should raise error if weights don't sum to 1.0."""
        with self.assertRaises(ValueError):
            RiskScorer(w_classifier=0.5, w_anomaly=0.5, w_category=0.5, w_impact=0.1)


if __name__ == "__main__":
    unittest.main()
