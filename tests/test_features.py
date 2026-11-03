"""Unit Tests for Unidirectional Feature Extraction."""

import unittest
import numpy as np
from uniguard.flow_engine.flow import UnidirectionalFlow
from uniguard.features.extractor import FeatureExtractor
from uniguard.features.schema import UNIDIRECTIONAL_FEATURES


class TestFeatureExtractor(unittest.TestCase):
    def test_feature_vector_dimensions_and_keys(self):
        flow = UnidirectionalFlow("10.0.0.5", "192.168.1.1", 44321, 443, 6, start_time=10.0)
        flow.add_packet(64, timestamp=10.0, tcp_flags=0x02) # SYN
        flow.add_packet(128, timestamp=10.1, tcp_flags=0x10) # ACK
        flow.add_packet(1024, timestamp=10.3, tcp_flags=0x18) # PSH+ACK

        features = FeatureExtractor.extract_features(flow)
        
        # Check that all 24 canonical features are present
        self.assertEqual(len(features), 24)
        for feat in UNIDIRECTIONAL_FEATURES:
            self.assertIn(feat, features, f"Missing expected feature: {feat}")
            self.assertFalse(np.isnan(features[feat]), f"Feature {feat} contains NaN")
            self.assertFalse(np.isinf(features[feat]), f"Feature {feat} contains Inf")

        # Verify specific feature calculations
        self.assertEqual(features["proto"], 6.0)
        self.assertEqual(features["dst_port"], 443.0)
        self.assertEqual(features["pkt_count"], 3.0)
        self.assertEqual(features["byte_count"], 1216.0)
        self.assertAlmostEqual(features["duration"], 0.3, places=3)
        self.assertAlmostEqual(features["pkt_len_min"], 64.0)
        self.assertAlmostEqual(features["pkt_len_max"], 1024.0)
        self.assertEqual(features["tcp_syn_cnt"], 1.0)
        self.assertEqual(features["tcp_psh_cnt"], 1.0)
        self.assertEqual(features["tcp_ack_cnt"], 2.0)

    def test_single_packet_flow_edge_case(self):
        """Single packet flow (duration = 0) must not crash with division by zero."""
        flow = UnidirectionalFlow("10.0.0.5", "192.168.1.1", 44321, 53, 17, start_time=50.0)
        flow.add_packet(75, timestamp=50.0)

        features = FeatureExtractor.extract_features(flow)
        self.assertEqual(features["pkt_count"], 1.0)
        self.assertEqual(features["duration"], 0.0)
        self.assertFalse(np.isnan(features["pkt_rate"]))
        self.assertFalse(np.isnan(features["byte_rate"]))
        self.assertEqual(features["iat_mean"], 0.0)
        self.assertEqual(features["burstiness"], 0.0)

    def test_vector_extraction(self):
        flow = UnidirectionalFlow("1.2.3.4", "5.6.7.8", 1234, 80, 6, start_time=1.0)
        flow.add_packet(100, timestamp=1.0)
        vec = FeatureExtractor.extract_vector(flow)
        self.assertIsInstance(vec, np.ndarray)
        self.assertEqual(vec.shape, (24,))
        self.assertEqual(vec.dtype, np.float32)


if __name__ == "__main__":
    unittest.main()
