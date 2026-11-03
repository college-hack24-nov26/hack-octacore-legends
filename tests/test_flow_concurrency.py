"""Concurrency and Multi-Threading Stress Test for FlowTracker.

Validates that concurrent packet ingestion (Scapy sniffer thread simulation)
and concurrent periodic evictions / telemetry sweeps (UI worker thread simulation)
do not produce 'dictionary changed size during iteration' or deadlock under load.
"""

import unittest
import threading
import time
import random
from uniguard.flow_engine.tracker import FlowTracker, CanonicalFlowTracker


class TestFlowTrackerConcurrency(unittest.TestCase):
    """Verifies thread-safety of FlowTracker under concurrent ingestion and eviction."""

    def test_concurrent_directionality_packet_ingestion_and_eviction(self):
        """Spawns concurrent packet producers alongside eviction sweeps."""
        tracker = FlowTracker(
            idle_timeout=0.05,
            active_timeout=0.15,
            enable_directionality=True,
        )

        num_producers = 4
        packets_per_producer = 500
        total_expected_packets = num_producers * packets_per_producer

        exceptions = []
        stop_sweeper = threading.Event()

        # Sweeper thread: mimics the UI WorkerThread calling evict_expired and get_stats
        def sweeper_loop():
            while not stop_sweeper.is_set():
                try:
                    now = time.time()
                    tracker.evict_expired(now)
                    tracker.get_stats()
                    time.sleep(0.005)
                except Exception as e:
                    exceptions.append(e)

        # Producer thread: mimics Scapy capture thread invoking process_packet
        def producer_loop(producer_id: int):
            for i in range(packets_per_producer):
                try:
                    sport = 10000 + (i % 10)
                    dport = 80 if i % 2 == 0 else 443
                    tcp_flags = 0x01 if i % 25 == 0 else (0x02 if i % 10 == 0 else 0x10) # FIN, SYN, ACK
                    pkt_len = 64 + (i % 1400)
                    ts = time.time()

                    tracker.process_packet(
                        src_ip=f"10.0.{producer_id}.{i % 5}",
                        dst_ip=f"172.16.0.{(i % 5) + 1}",
                        src_port=sport,
                        dst_port=dport,
                        proto=6,
                        pkt_len=pkt_len,
                        timestamp=ts,
                        tcp_flags=tcp_flags,
                    )
                except Exception as e:
                    exceptions.append(e)
                    break

        # Start sweeper thread
        sweeper = threading.Thread(target=sweeper_loop)
        sweeper.start()

        # Start producer threads
        producers = [threading.Thread(target=producer_loop, args=(pid,)) for pid in range(num_producers)]
        for p in producers:
            p.start()

        # Wait for producers to finish
        for p in producers:
            p.join()

        # Stop sweeper thread
        stop_sweeper.set()
        sweeper.join()

        # Flush remaining flows
        flushed = tracker.flush_all()

        # Verify no exceptions occurred
        self.assertEqual(len(exceptions), 0, f"Exceptions occurred during concurrent processing: {exceptions}")
        self.assertEqual(tracker.total_packets_processed, total_expected_packets)
        self.assertGreater(tracker.total_flows_created, 0)
        self.assertEqual(len(tracker.active_biflows), 0)

    def test_concurrent_legacy_unidirectional_ingestion_and_eviction(self):
        """Spawns concurrent packet producers in legacy unidirectional mode."""
        tracker = FlowTracker(
            idle_timeout=0.05,
            active_timeout=0.15,
            enable_directionality=False,
        )

        num_producers = 4
        packets_per_producer = 500
        total_expected_packets = num_producers * packets_per_producer

        exceptions = []
        stop_sweeper = threading.Event()

        def sweeper_loop():
            while not stop_sweeper.is_set():
                try:
                    now = time.time()
                    tracker.evict_expired(now)
                    tracker.get_stats()
                    time.sleep(0.005)
                except Exception as e:
                    exceptions.append(e)

        def producer_loop(producer_id: int):
            for i in range(packets_per_producer):
                try:
                    sport = 20000 + (i % 10)
                    dport = 53 if i % 2 == 0 else 80
                    flags = 0x01 if i % 25 == 0 else 0x10
                    ts = time.time()

                    tracker.process_packet(
                        src_ip=f"192.168.{producer_id}.{i % 5}",
                        dst_ip=f"8.8.8.{(i % 4) + 1}",
                        src_port=sport,
                        dst_port=dport,
                        proto=17 if dport == 53 else 6,
                        pkt_len=128,
                        timestamp=ts,
                        tcp_flags=flags,
                    )
                except Exception as e:
                    exceptions.append(e)
                    break

        sweeper = threading.Thread(target=sweeper_loop)
        sweeper.start()

        producers = [threading.Thread(target=producer_loop, args=(pid,)) for pid in range(num_producers)]
        for p in producers:
            p.start()

        for p in producers:
            p.join()

        stop_sweeper.set()
        sweeper.join()

        flushed = tracker.flush_all()

        self.assertEqual(len(exceptions), 0, f"Exceptions occurred: {exceptions}")
        self.assertEqual(tracker.total_packets_processed, total_expected_packets)
        self.assertEqual(len(tracker.active_flows), 0)


if __name__ == "__main__":
    unittest.main()
