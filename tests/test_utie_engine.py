"""Comprehensive Automated Test Suite for Unidirectional Traffic Intelligence Engine (UTIE).

Smart India Hackathon (SIH) 2026.
Official problem statement: "AI-Based Detection of Cyber Threats in Unidirectional IP Traffic."

Validates all 14 core functional and behavioral requirements:
1. Unidirectional observed traffic
2. Bidirectional observed traffic
3. Asymmetric traffic observations
4. Incomplete flows
5. Single-packet flows (Guard against treating as unidirectional proof)
6. Unknown protocols
7. Missing timestamps
8. Empty or invalid input
9. High-volume packet processing
10. PCAP replay integration
11. Sensor visibility awareness
12. Database persistence & retrieval
13. Dashboard data integration (PySide6 & Web SOC endpoints)
14. Normal traffic patterns (Ensuring downloads/streams are not falsely flagged)
"""

import os
import sys
import time
import tempfile
import pytest

from uniguard.flow_engine.flow import UnidirectionalFlow, CanonicalBiflow
from uniguard.detection.engine import DetectionEngine, SecurityEvent
from uniguard.database.storage import SecurityDatabase
from uniguard.desktop_ui.server import SocStateBridge
from uniguard.capture.pcap_reader import PcapIngestor
from uniguard.utie import (
    ObservationPoint,
    VisibilityType,
    SensorVisibilityContext,
    SensorVisibilityAssessment,
    SensorVisibilityEvaluator,
    TrafficBehaviorSummary,
    TrafficBehaviorAnalyzer,
    DirectionalityClass,
    DirectionalityClassificationResult,
    DirectionalityClassifier,
    UTIEIntelligenceReport,
    UnidirectionalTrafficIntelligenceEngine,
)


@pytest.fixture
def utie_engine():
    """Initializes a standalone UTIE engine instance."""
    detection_engine = DetectionEngine()
    return UnidirectionalTrafficIntelligenceEngine(detection_engine=detection_engine)


@pytest.fixture
def temp_db():
    """Provides a fresh temporary SQLite database."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = SecurityDatabase(db_path=path)
    yield db
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass


def _create_synthetic_flow(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.1",
    src_port: int = 44556,
    dst_port: int = 80,
    proto: int = 6,
    packet_count: int = 10,
    pkt_len: int = 64,
    start_time: float = 1000.0,
    duration: float = 1.0,
    syn_count: int = 0,
    ack_count: int = 0,
    fin_count: int = 0,
    rst_count: int = 0,
    is_closed: bool = True,
) -> UnidirectionalFlow:
    """Helper to synthesize a UnidirectionalFlow object with deterministic parameters."""
    flow = UnidirectionalFlow(src_ip, dst_ip, src_port, dst_port, proto, start_time=start_time)
    step = duration / max(1, packet_count - 1) if packet_count > 1 else 0.0

    for i in range(packet_count):
        ts = start_time + (i * step)
        flags = 0
        if i == 0 and syn_count > 0:
            flags |= 0x02  # SYN
        elif ack_count > 0:
            flags |= 0x10  # ACK
        if fin_count > 0 and i == packet_count - 1:
            flags |= 0x01  # FIN
        if rst_count > 0 and i == packet_count - 1:
            flags |= 0x04  # RST

        flow.add_packet(pkt_len=pkt_len, timestamp=ts, tcp_flags=flags)

    # Manually adjust flag counts if explicitly parameterized
    if syn_count > 0:
        flow.tcp_syn_cnt = syn_count
    if ack_count > 0:
        flow.tcp_ack_cnt = ack_count
    if fin_count > 0:
        flow.tcp_fin_cnt = fin_count
    if rst_count > 0:
        flow.tcp_rst_cnt = rst_count

    flow.is_closed = is_closed
    return flow


# =============================================================================
# 1. Unidirectional Observed Traffic
# =============================================================================
def test_1_unidirectional_observed_traffic(utie_engine):
    """Test pure forward observed traffic without return packets."""
    flow = _create_synthetic_flow(
        packet_count=15,
        duration=2.0,
        syn_count=15,
        ack_count=0,
    )
    report = utie_engine.analyze_flow(flow)

    assert report.directionality == "UNIDIRECTIONAL_OBSERVED"
    assert report.packet_count == 15
    assert report.reverse_packet_count in (0, None)
    assert report.directionality_confidence >= 0.60
    assert len(report.directionality_evidence) > 0
    assert "0 return packets" in report.directionality_evidence[0] or "forward" in report.directionality_evidence[0].lower()


# =============================================================================
# 2. Bidirectional Observed Traffic
# =============================================================================
def test_2_bidirectional_observed_traffic(utie_engine):
    """Test balanced 2-way conversation tracking."""
    flow = _create_synthetic_flow(packet_count=20, duration=1.5, syn_count=1, ack_count=19)
    biflow = CanonicalBiflow("192.168.1.100", "10.0.0.1", 44556, 80, 6, start_time=1000.0)

    # Add 20 forward packets and 18 reverse packets
    for i in range(20):
        biflow.add_packet("192.168.1.100", "10.0.0.1", 44556, 80, pkt_len=120, timestamp=1000.0 + i * 0.05)
    for i in range(18):
        biflow.add_packet("10.0.0.1", "192.168.1.100", 80, 44556, pkt_len=1400, timestamp=1000.0 + i * 0.05 + 0.01)

    report = utie_engine.analyze_flow(flow, biflow=biflow)
    assert report.directionality == "BIDIRECTIONAL_OBSERVED"
    assert report.reverse_packet_count == 18
    assert report.directionality_confidence >= 0.80
    assert "Active 2-way conversation confirmed" in report.directionality_evidence[0]


# =============================================================================
# 3. Asymmetric Traffic Observations
# =============================================================================
def test_3_asymmetric_traffic_observations(utie_engine):
    """Test pronounced directional disparity (forward dominant with minimal reverse)."""
    flow = _create_synthetic_flow(packet_count=50, duration=3.0, ack_count=50)
    biflow = CanonicalBiflow("192.168.1.100", "10.0.0.1", 44556, 80, 6, start_time=1000.0)

    for i in range(50):
        biflow.add_packet("192.168.1.100", "10.0.0.1", 44556, 80, pkt_len=200, timestamp=1000.0 + i * 0.05)
    # Only 2 reverse ACKs
    for i in range(2):
        biflow.add_packet("10.0.0.1", "192.168.1.100", 80, 44556, pkt_len=60, timestamp=1000.0 + i * 1.0)

    report = utie_engine.analyze_flow(flow, biflow=biflow)
    assert report.directionality == "ASYMMETRIC_OBSERVED"
    assert report.reverse_packet_count == 2
    assert report.total_packet_count == 52
    assert "asymmetry" in report.directionality_evidence[0].lower()


# =============================================================================
# 4. Incomplete Flows & Ephemeral Bursts
# =============================================================================
def test_4_incomplete_flows(utie_engine):
    """Test short flow below statistical observation window."""
    flow = _create_synthetic_flow(packet_count=2, duration=0.01)
    report = utie_engine.analyze_flow(flow)

    assert report.directionality == "INSUFFICIENT_DATA"
    assert report.directionality_confidence < 0.50
    assert "below the statistical observation threshold" in report.directionality_evidence[0]


# =============================================================================
# 5. Single-Packet Flows (Crucial SIH 2026 Guard Rule)
# =============================================================================
def test_5_single_packet_flows_guard_rule(utie_engine):
    """Rule: A single packet must NEVER automatically be treated as proof of unidirectional communication."""
    flow = _create_synthetic_flow(packet_count=1, duration=0.0)
    report = utie_engine.analyze_flow(flow)

    assert report.directionality == "INSUFFICIENT_DATA"
    assert report.directionality != "UNIDIRECTIONAL_OBSERVED"
    assert "Single packets or ephemeral transient bursts cannot substantiate physical unidirectionality" in report.directionality_evidence[1]


# =============================================================================
# 6. Unknown Protocols Handling
# =============================================================================
def test_6_unknown_protocols(utie_engine):
    """Test arbitrary or custom IP protocol numbers."""
    flow = _create_synthetic_flow(proto=99, packet_count=8, duration=0.5)
    report = utie_engine.analyze_flow(flow)

    assert report.proto == 99
    assert "99" in report.proto_name
    assert report.directionality == "UNIDIRECTIONAL_OBSERVED"


# =============================================================================
# 7. Missing Timestamps & Zero Durations
# =============================================================================
def test_7_missing_timestamps(utie_engine):
    """Test edge cases with static or zero timestamps."""
    flow = _create_synthetic_flow(packet_count=6, start_time=0.0, duration=0.0)
    report = utie_engine.analyze_flow(flow)

    assert report.duration >= 0.0
    assert report.pkt_rate >= 0.0
    assert report.byte_rate >= 0.0


# =============================================================================
# 8. Empty or Invalid Input Handling
# =============================================================================
def test_8_empty_or_invalid_input(utie_engine):
    """Test flows with 0 packets or uninitialized counters."""
    flow = UnidirectionalFlow("1.1.1.1", "2.2.2.2", 1000, 2000, 6, start_time=time.time())
    report = utie_engine.analyze_flow(flow)

    assert report.directionality == "INSUFFICIENT_DATA"
    assert report.packet_count == 0


# =============================================================================
# 9. High-Volume Packet Processing Benchmark
# =============================================================================
def test_9_high_volume_packet_processing(utie_engine):
    """Benchmark high throughput processing of thousands of packets in O(1) time."""
    start_time = time.time()
    for f_idx in range(500):
        flow = _create_synthetic_flow(
            src_ip=f"10.0.{f_idx % 250}.1",
            dst_ip="192.168.1.1",
            src_port=1024 + f_idx,
            dst_port=80,
            packet_count=20,
            duration=0.5,
        )
        report = utie_engine.analyze_flow(flow)
        assert report is not None

    elapsed = time.time() - start_time
    # 500 flows * 20 pkts = 10,000 packets processed
    pps = 10000.0 / elapsed
    print(f"\n[BENCHMARK] UTIE processed 10,000 packets across 500 flows in {elapsed:.3f}s ({pps:.0f} pps)")
    assert elapsed < 5.0, f"Processing too slow ({elapsed:.3f}s)"


# =============================================================================
# 10. PCAP Replay Integration
# =============================================================================
def test_10_pcap_replay_integration(utie_engine):
    """Test integration with Scapy/PcapIngestor offline PCAP streaming."""
    pcap_path = os.path.join(os.path.dirname(__file__), "..", "data", "samples", "sample_unidirectional.pcap")
    assert os.path.exists(pcap_path), "Sample PCAP missing"

    ingestor = PcapIngestor(pcap_path)
    tracker = utie_engine.detection_engine
    packets_read = 0

    flows_analyzed = 0
    flow = UnidirectionalFlow("192.168.1.50", "192.168.1.1", 45000, 80, 6, start_time=100.0)

    for pkt in ingestor.stream_packets():
        packets_read += 1
        src, dst, sp, dp, proto, plen, ts, flags = pkt
        flow.add_packet(plen, ts, flags)
        if packets_read >= 25:
            break

    report = utie_engine.analyze_flow(flow)
    assert report.packet_count >= 20
    assert report.total_byte_count > 0
    assert report.directionality in ("UNIDIRECTIONAL_OBSERVED", "ASYMMETRIC_OBSERVED", "BIDIRECTIONAL_OBSERVED")


# =============================================================================
# 11. Sensor Visibility Awareness & Topology Penalties
# =============================================================================
def test_11_sensor_visibility_awareness(utie_engine):
    """Test operator configured observation point topologies."""
    # A. Physical Hardware Data Diode
    diode_ctx = SensorVisibilityContext(
        observation_point=ObservationPoint.DATA_DIODE_EGRESS,
        is_diode_enforced=True,
    )
    utie_engine.set_sensor_context(diode_ctx)
    flow = _create_synthetic_flow(packet_count=10, duration=1.0)
    rep_diode = utie_engine.analyze_flow(flow)

    assert rep_diode.sensor_visibility["visibility_type"] == "MONITORED_ONE_WAY_HARDWARE"
    assert rep_diode.sensor_visibility["is_reverse_missing"] is True
    assert rep_diode.directionality_confidence == 0.99
    assert rep_diode.sensor_visibility["confidence_penalty"] == 0.0

    # B. Asymmetric Routing Transit SPAN
    asym_ctx = SensorVisibilityContext(
        observation_point=ObservationPoint.ASYMMETRIC_SPAN,
    )
    utie_engine.set_sensor_context(asym_ctx)
    rep_asym = utie_engine.analyze_flow(flow)

    assert rep_asym.sensor_visibility["visibility_type"] == "POTENTIAL_ASYMMETRIC_ROUTING"
    assert rep_asym.sensor_visibility["confidence_penalty"] > 0.0


# =============================================================================
# 12. Database Persistence and Querying
# =============================================================================
def test_12_database_persistence_and_querying(temp_db, utie_engine):
    """Test full CRUD operations on SQLite utie_flow_intelligence table."""
    reports = []
    for i in range(10):
        flow = _create_synthetic_flow(
            src_ip=f"10.10.10.{i+1}",
            dst_ip="172.16.0.1",
            packet_count=15,
            duration=1.0,
        )
        rep = utie_engine.analyze_flow(flow)
        reports.append(rep)

    temp_db.insert_utie_reports_batch(reports)

    # 1. Recent query
    fetched = temp_db.get_recent_utie_reports(limit=5)
    assert len(fetched) == 5

    # 2. Search query by IP
    search_res = temp_db.search_utie_reports(query="10.10.10.3")
    assert len(search_res) == 1
    assert search_res[0]["src_ip"] == "10.10.10.3"
    assert "directionality_evidence" in search_res[0]
    assert isinstance(search_res[0]["directionality_evidence"], list)

    # 3. Summary statistics
    stats = temp_db.get_utie_summary_statistics()
    assert stats["total_flows_stored"] == 10
    assert "UNIDIRECTIONAL_OBSERVED" in stats["directionality_distribution"]


# =============================================================================
# 13. Dashboard Data Integration (Bridge & REST API parity)
# =============================================================================
def test_13_dashboard_data_integration(utie_engine):
    """Test SocStateBridge integration and summary generation."""
    bridge = SocStateBridge.get()
    flow = _create_synthetic_flow(packet_count=12, duration=0.8)
    rep = utie_engine.analyze_flow(flow)

    bridge.add_utie_report(rep)
    assert len(bridge.recent_utie_reports) > 0

    summary = utie_engine.get_summary()
    assert "total_flows_analyzed" in summary
    assert "unidirectional_observations" in summary
    assert "unidirectional_pct" in summary
    assert "sensor_observation_point" in summary


# =============================================================================
# 14. Normal Traffic Patterns (Ordinary Downloads / Streams NOT Flagged)
# =============================================================================
def test_14_normal_traffic_not_falsely_flagged_as_threats(utie_engine):
    """Test standard conversational web download: ensures ordinary downloads are NOT flagged as threats."""
    flow = _create_synthetic_flow(
        src_ip="192.168.1.50",
        dst_ip="93.184.216.34",  # example.com
        src_port=52344,
        dst_port=443,
        proto=6,
        packet_count=40,
        pkt_len=540,
        duration=4.5,
        syn_count=1,
        ack_count=39,
    )
    biflow = CanonicalBiflow("192.168.1.50", "93.184.216.34", 52344, 443, 6, start_time=1000.0)
    for i in range(40):
        biflow.add_packet("192.168.1.50", "93.184.216.34", 52344, 443, pkt_len=80, timestamp=1000.0 + i * 0.1)
    for i in range(35):
        biflow.add_packet("93.184.216.34", "192.168.1.50", 443, 52344, pkt_len=1420, timestamp=1000.0 + i * 0.1 + 0.02)

    report = utie_engine.analyze_flow(flow, biflow=biflow)

    assert report.directionality == "BIDIRECTIONAL_OBSERVED"
    assert report.ml_threat_category == "BENIGN"
    assert (report.risk_score or 0) < 30
    color, badge_text, _ = report.get_visual_indicator()
    assert "NORMAL" in badge_text
    assert color == "#3fb950"  # Green

