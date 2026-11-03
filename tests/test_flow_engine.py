"""Unit Tests for Unidirectional Flow Engine."""

import unittest
from uniguard.flow_engine.flow import UnidirectionalFlow
from uniguard.flow_engine.tracker import FlowTracker


class TestUnidirectionalFlow(unittest.TestCase):
    def test_flow_creation_and_key(self):
        flow = UnidirectionalFlow("192.168.1.10", "10.0.0.1", 45678, 80, 6, start_time=100.0)
        self.assertEqual(flow.key, ("192.168.1.10", "10.0.0.1", 45678, 80, 6))
        self.assertEqual(flow.packet_count, 0)
        self.assertEqual(flow.byte_count, 0)

    def test_packet_accumulation_and_iat(self):
        flow = UnidirectionalFlow("192.168.1.10", "10.0.0.1", 45678, 80, 6, start_time=100.0)
        flow.add_packet(pkt_len=60, timestamp=100.0, tcp_flags=0x02)  # SYN
        flow.add_packet(pkt_len=120, timestamp=100.5, tcp_flags=0x10) # ACK
        flow.add_packet(pkt_len=500, timestamp=101.2, tcp_flags=0x18) # PSH+ACK

        self.assertEqual(flow.packet_count, 3)
        self.assertEqual(flow.byte_count, 680)
        self.assertAlmostEqual(flow.duration, 1.2, places=4)
        self.assertEqual(len(flow.inter_arrival_times), 2)
        self.assertAlmostEqual(flow.inter_arrival_times[0], 0.5, places=4)
        self.assertAlmostEqual(flow.inter_arrival_times[1], 0.7, places=4)
        self.assertEqual(flow.tcp_syn_cnt, 1)
        self.assertEqual(flow.tcp_ack_cnt, 2)
        self.assertEqual(flow.tcp_psh_cnt, 1)


class TestFlowTracker(unittest.TestCase):
    def test_strict_unidirectional_separation(self):
        tracker = FlowTracker(idle_timeout=15.0)
        
        # Forward packet: A -> B
        tracker.process_packet("192.168.1.10", "10.0.0.1", 50000, 80, 6, pkt_len=60, timestamp=10.0)
        # Reverse packet: B -> A (if observed)
        tracker.process_packet("10.0.0.1", "192.168.1.10", 80, 50000, 6, pkt_len=60, timestamp=10.1)

        # In a strict unidirectional model, these MUST remain TWO distinct flows, never merged!
        self.assertEqual(len(tracker.active_flows), 2)
        fwd_key = ("192.168.1.10", "10.0.0.1", 50000, 80, 6)
        rev_key = ("10.0.0.1", "192.168.1.10", 80, 50000, 6)
        self.assertIn(fwd_key, tracker.active_flows)
        self.assertIn(rev_key, tracker.active_flows)
        self.assertEqual(tracker.active_flows[fwd_key].packet_count, 1)
        self.assertEqual(tracker.active_flows[rev_key].packet_count, 1)

    def test_idle_timeout_eviction(self):
        tracker = FlowTracker(idle_timeout=5.0)
        tracker.process_packet("192.168.1.10", "10.0.0.1", 50000, 80, 6, pkt_len=64, timestamp=0.0)
        
        # At t = 3.0, flow is still active
        evicted = tracker.evict_expired(current_time=3.0)
        self.assertEqual(len(evicted), 0)
        self.assertEqual(len(tracker.active_flows), 1)

        # At t = 6.0, flow has idled for 6s (> 5s timeout)
        evicted = tracker.evict_expired(current_time=6.0)
        self.assertEqual(len(evicted), 1)
        self.assertEqual(evicted[0].closure_reason, "IDLE_TIMEOUT")
        self.assertEqual(len(tracker.active_flows), 0)


if __name__ == "__main__":
    unittest.main()
