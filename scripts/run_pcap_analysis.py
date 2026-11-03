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
    header = f"{'FLOW (Src -> Dst:Port [Proto])':<35} | {'DIRECTIONALITY':<22} | {'THREAT TYPE':<15} | {'SEV':<8} | {'RISK':<4}"
    print(header)
    print("-" * 105)

    detected_alerts = []

    for flow in completed_flows:
        # Run through detection engine
        event = detection_engine.analyze_flow(flow)
        database.insert_event(event)

        flow_display = f"{flow.src_ip} -> {flow.dst_ip}:{flow.dst_port} [P{flow.proto}]"
        dir_display = f"{event.directionality_state} ({event.directionality_score:.2f})"
        print(f"{flow_display:<35} | {dir_display:<22} | {event.threat_type:<15} | {event.severity:<8} | {event.risk_score:>3}/100")

        if event.risk_score >= 35:
            detected_alerts.append(event)

    print("=" * 85)
    print(f" SUMMARY OF DETECTED SECURITY THREATS: {len(detected_alerts)} ALERTS GENERATED")
    print("=" * 85)

    for alert in detected_alerts[:4]:
        print(f"\n[!] ALERT: {alert.threat_type} (Severity: {alert.severity}, Risk: {alert.risk_score}/100, Confidence: {alert.confidence_pct}%)")
        print(f"    Target: {alert.flow_key}")
        print(f"    Metrics: {alert.flow_metrics}")
        print("    Explainable AI (XAI) Contributing Behavioral Factors:")
        for factor in alert.contributing_factors:
            direction_symbol = "(+)" if factor.get("direction") == "RISK_INCREASING" else "(-)"
            print(f"      - {direction_symbol} {factor['feature']}: {factor.get('explanation', factor.get('value'))}")

    if len(detected_alerts) > 4:
        print(f"\n    ... and {len(detected_alerts) - 4} additional security events logged to database: '{db_path}'")
    print("=" * 85)


if __name__ == "__main__":
    run_analysis()
