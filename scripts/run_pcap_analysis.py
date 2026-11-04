"""Offline PCAP Analysis Pipeline Runner for UniGuard AI.

Loads trained AI models (Random Forest, Isolation Forest, Preprocessor) and executes
the complete cybersecurity detection pipeline on PCAP network traffic.
"""

import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from uniguard.capture.pcap_reader import PcapIngestor
from uniguard.flow_engine.tracker import FlowTracker
from uniguard.features.extractor import FeatureExtractor
from uniguard.preprocessing.pipeline import FlowDataPreprocessor
from uniguard.models.supervised import SupervisedThreatClassifier
from uniguard.models.anomaly import IsolationForestAnomalyDetector
from uniguard.risk.scorer import RiskScorer
from uniguard.detection.engine import DetectionEngine
from uniguard.detection.correlator import SecurityIncidentCorrelator, format_protocol
from uniguard.database.storage import SecurityDatabase


def run_analysis(
    pcap_path: str = "data/samples/sample_unidirectional.pcap",
    models_dir: str = "models_saved",
    db_path: str = "uniguard_events.db",
) -> None:
    print("=" * 85)
    print(" UNIGUARD AI: AI-POWERED UNIDIRECTIONAL THREAT DETECTION PIPELINE")
    print(" Smart India Hackathon (SIH) 2026")
    print("=" * 85)

    # 1. Load trained AI models if available
    preprocessor = None
    classifier = None
    anomaly_detector = None

    prep_file = os.path.join(models_dir, "preprocessor.joblib")
    rf_file = os.path.join(models_dir, "uniguard_rf_model.joblib")
    iso_file = os.path.join(models_dir, "uniguard_isolation_forest.joblib")

    if os.path.exists(prep_file) and os.path.exists(rf_file):
        print("[*] Loading trained AI models from 'models_saved/'...")
        preprocessor = FlowDataPreprocessor.load(prep_file)
        classifier = SupervisedThreatClassifier.load(rf_file)
        if os.path.exists(iso_file):
            anomaly_detector = IsolationForestAnomalyDetector.load(iso_file)
        print("[OK] Dual-engine AI models and preprocessor loaded.")
    else:
        print("[!] Trained models not found. Running with baseline behavioral heuristics.")

    detection_engine = DetectionEngine(
        classifier=classifier,
        anomaly_detector=anomaly_detector,
        preprocessor=preprocessor,
        risk_scorer=RiskScorer(),
    )
    database = SecurityDatabase(db_path=db_path)

    print(f"[*] Ingesting target PCAP: {pcap_path}")
    ingestor = PcapIngestor(pcap_path)
    tracker = FlowTracker(idle_timeout=1.0, active_timeout=30.0, enable_directionality=True)

    completed_flows = []

    # Stream packets through flow engine
    for pkt in ingestor.stream_packets():
        src_ip, dst_ip, sport, dport, proto, pkt_len, ts, flags = pkt
        evicted = tracker.process_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=sport,
            dst_port=dport,
            proto=proto,
            pkt_len=pkt_len,
            timestamp=ts,
            tcp_flags=flags,
        )
        completed_flows.extend(evicted)

    # Flush remaining active flows
    completed_flows.extend(tracker.flush_all())

    stats = tracker.get_stats()
    print(f"[*] Flow Engine Aggregation & Directionality Analysis Complete:")
    print(f"    - Raw Packets Ingested: {tracker.total_packets_processed}")
    print(f"    - Active Biflows Evaluated: {len(completed_flows)}")
    print(f"    - Bidirectional Flows Excluded: {stats.get('total_excluded_flows', 0)}")
    print(f"    - Directionality Distribution: {stats.get('directionality_distribution_pct', {})}")
    print("-" * 105)
    header = f"{'FLOW (Src -> Dst:Port [Proto])':<36} | {'DIRECTIONALITY':<22} | {'THREAT TYPE':<15} | {'SEV':<8} | {'RISK':<4}"
    print(header)
    print("-" * 105)

    all_events = []
    detected_alerts = []

    for flow in completed_flows:
        # Run through detection engine
        event = detection_engine.analyze_flow(flow)
        database.insert_event(event)
        all_events.append(event)

        proto_str = format_protocol(flow.proto)
        flow_display = f"{flow.src_ip} -> {flow.dst_ip}:{flow.dst_port} [{proto_str}]"
        dir_display = f"{event.directionality_state} ({event.directionality_score:.2f})"
        print(f"{flow_display:<36} | {dir_display:<22} | {event.threat_type:<15} | {event.severity:<8} | {event.risk_score:>3}/100")

        if event.risk_score >= 35:
            detected_alerts.append(event)

    # -------------------------------------------------------------
    # Multi-Event Incident Correlation & Threat Aggregation
    # -------------------------------------------------------------
    correlator = SecurityIncidentCorrelator(time_window_sec=60.0)
    incidents = correlator.correlate_events(all_events)

    print("\n" + "=" * 95)
    print(f" SECURITY INCIDENT CORRELATION & CAMPAIGN SUMMARY ({len(incidents)} INCIDENTS IDENTIFIED)")
    print("=" * 95)
    inc_header = f"{'INCIDENT ID':<22} | {'TYPE':<14} | {'ATTACKER -> VICTIM':<30} | {'FLOWS':<6} | {'SEV':<8} | {'RISK':<4}"
    print(inc_header)
    print("-" * 95)
    for inc in incidents:
        victim_str = f"{inc.dst_ip}:{inc.target_ports[0]}" if len(inc.target_ports) == 1 else f"{inc.dst_ip} ({len(inc.target_ports)} ports)"
        target_summary = f"{inc.src_ip} -> {victim_str}"
        print(f"{inc.incident_id:<22} | {inc.incident_type:<14} | {target_summary:<30} | {inc.event_count:<6} | {inc.severity:<8} | {inc.risk_score:>3}/100")

    print("=" * 95)
    for idx, inc in enumerate(incidents, 1):
        print(f"\n[INCIDENT #{idx}] {inc.incident_type} (Severity: {inc.severity}, Risk: {inc.risk_score}/100)")
        print(f"  Incident ID   : {inc.incident_id}")
        print(f"  Attacker Host : {inc.src_ip}")
        print(f"  Target Host   : {inc.dst_ip} [Protocol: {inc.protocol}]")
        print(f"  Target Ports  : {inc.target_ports[:10]}{' ...' if len(inc.target_ports) > 10 else ''}")
        print(f"  Impact Scope  : {inc.event_count} flows, {inc.packet_count} packets, {inc.byte_count:,} bytes across {inc.duration:.3f}s")
        print(f"  Summary       : {inc.summary}")
        print("  MITRE Tactics :")
        for t in inc.tactics:
            print(f"    * {t}")
        print("  SOC Playbook  :")
        for r in inc.recommendations:
            print(f"    -> {r}")

    # -------------------------------------------------------------
    # Explainable AI (XAI) Behavioral Evidence Details
    # -------------------------------------------------------------
    print("\n" + "=" * 95)
    print(" EXPLAINABLE AI (XAI) BEHAVIORAL ATTRIBUTION SAMPLES")
    print("=" * 95)

    # Show representative alert for each distinct threat type
    shown_types = set()
    sample_alerts = []
    for alert in detected_alerts:
        if alert.threat_type not in shown_types:
            shown_types.add(alert.threat_type)
            sample_alerts.append(alert)

    # Supplement with first 2 alerts if less than 2 distinct types
    for alert in detected_alerts:
        if len(sample_alerts) >= 3:
            break
        if alert not in sample_alerts:
            sample_alerts.append(alert)

    for alert in sample_alerts:
        print(f"\n[!] ALERT: {alert.threat_type} (Severity: {alert.severity}, Risk: {alert.risk_score}/100, Confidence: {alert.confidence_pct}%)")
        print(f"    Target Flow : {alert.flow_key}")
        print(f"    Direction   : {alert.directionality_state} (Score: {alert.directionality_score:.2f}, Conf: {alert.directionality_confidence:.2f})")
        print(f"    Flow Metrics: {alert.flow_metrics}")
        print("    Explainable AI (XAI) Contributing Behavioral Factors:")
        for factor in alert.contributing_factors:
            direction_symbol = "(+)" if factor.get("direction") == "RISK_INCREASING" else "(-)"
            print(f"      - {direction_symbol} {factor['feature']}: {factor.get('explanation', factor.get('value'))}")

    print(f"\n[*] Total security events logged to database: {len(all_events)} ({len(detected_alerts)} elevated alerts) -> '{db_path}'")
    print("=" * 95)


if __name__ == "__main__":
    run_analysis()
