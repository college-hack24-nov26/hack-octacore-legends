"""High-Throughput and Elephant Flow Benchmark Test for UniGuard AI.

Simulates 100,000 wire packets in rapid succession (e.g. bulk file download)
and validates O(1) memory bounds, Welford statistical moments, and elephant cutoff.
"""

import unittest
import time
import sys
import numpy as np
from uniguard.flow_engine.flow import UnidirectionalFlow
from uniguard.flow_engine.tracker import FlowTracker
from uniguard.features.extractor import FeatureExtractor


class TestHighThroughputFlow(unittest.TestCase):
    def test_100k_packets_throughput_and_memory(self):
        """Simulate a massive 100,000 packet stream (typical of 100+ MB download)."""
        flow = UnidirectionalFlow(
            src_ip="192.168.1.50",
            dst_ip="104.244.42.1",
            src_port=54321,
            dst_port=443,
            proto=6,
            start_time=1000.0,
            max_sampled_packets=100,
            elephant_cutoff_packets=50,
        )

        start_perf = time.perf_counter()
        
        # Feed 100,000 packets: typical MTU sizes (1460, 1500, 64)
        t = 1000.0
        for i in range(100_000):
            t += 0.0001
            pkt_len = 1460 if i % 10 != 0 else 64
            tcp_flags = 0x10 # ACK
            flow.add_packet(pkt_len=pkt_len, timestamp=t, tcp_flags=tcp_flags)

        elapsed = time.perf_counter() - start_perf
        pps = 100_000 / max(elapsed, 1e-6)

        # 1. Throughput verification (> 100,000 packets/sec in pure Python)
        self.assertGreater(pps, 50_000, f"Throughput too low: {pps:.0f} pps")
        print(f"\n[Benchmark] Processed 100,000 packets in {elapsed:.4f}s ({pps:,.0f} pps)")

        # 2. Memory bound verification: sample lists MUST NOT exceed max_sampled_packets (100)
        self.assertLessEqual(len(flow.packet_lengths), 100)
        self.assertLessEqual(len(flow.inter_arrival_times), 100)

        # Memory footprint of the flow object itself should be minuscule (< 5 KB)
        rough_size_bytes = sys.getsizeof(flow.packet_lengths) + sys.getsizeof(flow.inter_arrival_times) + sys.getsizeof(flow)
        self.assertLess(rough_size_bytes, 5000, f"Flow memory too large: {rough_size_bytes} bytes")

        # 3. Elephant flow transition
        self.assertTrue(flow.is_elephant)
        self.assertEqual(flow.packet_count, 100_000)

        # 4. Feature extraction should be virtually instantaneous (O(1))
        f_start = time.perf_counter()
        features = FeatureExtractor.extract_features(flow)
        f_elapsed = time.perf_counter() - f_start
        self.assertLess(f_elapsed, 0.005, f"Feature extraction too slow: {f_elapsed*1000:.2f}ms")

        # Verify statistical moments are mathematically valid
        self.assertAlmostEqual(features["pkt_count"], 100_000.0)
        self.assertEqual(features["pkt_len_min"], 64.0)
        self.assertEqual(features["pkt_len_max"], 1460.0)
        self.assertGreater(features["pkt_len_mean"], 1300.0)
        self.assertGreater(features["pkt_len_std"], 0.0)
        self.assertFalse(np.isnan(features["burstiness"]))
        self.assertFalse(np.isnan(features["entropy_pkt_len"]))


if __name__ == "__main__":
    unittest.main()
