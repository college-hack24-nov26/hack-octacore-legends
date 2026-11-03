"""Comprehensive Automated Test Suite for AI Threat Explanation Engine.

Covers all 15 required test scenarios:
1. PORT_SCAN explanation.
2. SYN_FLOOD explanation.
3. DATA_EXFILTRATION explanation.
4. SLOWLORIS explanation.
5. BENIGN traffic explanation.
6. Missing feature values.
7. Missing model confidence.
8. SHAP unavailable.
9. Incorrect or incomplete flow data.
10. Unidirectional observed traffic.
11. Bidirectional observed traffic.
12. Explanation storage in SQLite.
13. Dashboard explanation display.
14. Large numbers of alerts.
15. Explanation failure without interrupting threat detection.
"""

import os
import sys
import time
import pytest
import numpy as np

# Ensure root directory is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from uniguard.explainability.schema import (
    AIThreatExplanation,
    FeatureContribution,
    DirectionalityExplanation,
)
from uniguard.explainability.behavior_rules import BehavioralEvidenceGenerator
from uniguard.explainability.investigation_playbooks import DefensiveInvestigationPlaybooks
from uniguard.explainability.engine import AIThreatExplanationEngine
from uniguard.explainability.explainer import FlowExplainer
from uniguard.flow_engine.flow import UnidirectionalFlow
from uniguard.detection.engine import DetectionEngine, SecurityEvent
from uniguard.database.storage import SecurityDatabase


@pytest.fixture
def explainer_engine():
    return AIThreatExplanationEngine()


def test_01_port_scan_explanation(explainer_engine):
    """Scenario 1: PORT_SCAN explanation with probe metrics and defensive suggestions."""
    flow_metrics = {"packet_count": 1, "byte_count": 60, "duration": 0.001, "dst_port": 80}
    raw_features = {
        "pkt_rate": 1000.0,
        "byte_rate": 60000.0,
        "tcp_syn_cnt": 1,
        "tcp_ack_cnt": 0,
        "tcp_rst_cnt": 0,
        "entropy_pkt_len": 0.0,
        "pkt_len_mean": 60.0,
        "dst_port": 80,
    }
    contributing = [
        {"feature": "tcp_syn_cnt", "value": 1, "impact_score": 0.65, "direction": "RISK_INCREASING"},
        {"feature": "pkt_rate", "value": 1000.0, "impact_score": 0.55, "direction": "RISK_INCREASING"},
    ]

    report = explainer_engine.explain_detection(
        alert_id="EVT-SCAN-01",
        flow_id="192.168.1.50:44321 -> 10.0.0.1:80 [P6]",
        threat_category="PORT_SCAN",
        model_name="Random Forest Classifier",
        model_confidence=0.92,
        risk_score=75,
        severity="HIGH",
        flow_metrics=flow_metrics,
        raw_features=raw_features,
        contributing_factors=contributing,
        directionality_state="UNIDIRECTIONAL_OBSERVED",
        directionality_score=0.95,
        directionality_confidence=0.90,
    )

    assert isinstance(report, AIThreatExplanation)
    assert report.threat_category == "PORT_SCAN"
    assert "reconnaissance" in report.summary.lower() or "probe" in report.summary.lower()
    assert report.model_name == "Random Forest Classifier"
    assert report.model_confidence == 0.92
    assert report.risk_score == 75
    assert len(report.observed_behavior) > 0
    assert any("SYN" in b for b in report.observed_behavior)
    assert len(report.feature_contributions) == 2
    assert report.feature_contributions[0]["feature"] == "tcp_syn_cnt"
    assert len(report.investigation_suggestions) >= 3
    assert any("port" in s.lower() for s in report.investigation_suggestions)


def test_02_syn_flood_explanation(explainer_engine):
    """Scenario 2: SYN_FLOOD explanation with high packet rate and repeated SYN evidence."""
    flow_metrics = {"packet_count": 500, "byte_count": 30000, "duration": 0.25, "dst_port": 443}
    raw_features = {
        "pkt_rate": 2000.0,
        "byte_rate": 120000.0,
        "tcp_syn_cnt": 500,
        "tcp_ack_cnt": 0,
        "tcp_rst_cnt": 0,
        "entropy_pkt_len": 1.2,
        "pkt_len_mean": 60.0,
        "dst_port": 443,
    }

    report = explainer_engine.explain_detection(
        alert_id="EVT-SYN-02",
        flow_id="10.0.0.5:54321 -> 10.0.0.1:443 [P6]",
        threat_category="SYN_FLOOD",
        model_name="Random Forest Classifier",
        model_confidence=0.98,
        risk_score=90,
        severity="CRITICAL",
        flow_metrics=flow_metrics,
        raw_features=raw_features,
        directionality_state="UNIDIRECTIONAL_OBSERVED",
        directionality_score=0.99,
        directionality_confidence=0.95,
    )

    assert report.threat_category == "SYN_FLOOD"
    assert "syn" in report.summary.lower()
    assert any("rate" in b.lower() for b in report.observed_behavior)
    assert any("syn" in b.lower() for b in report.observed_behavior)
    assert any("cookie" in s.lower() for s in report.investigation_suggestions)


def test_03_data_exfiltration_explanation(explainer_engine):
    """Scenario 3: DATA_EXFILTRATION explanation with high byte volume and outbound checks."""
    flow_metrics = {"packet_count": 800, "byte_count": 1200000, "duration": 3.0, "dst_port": 443}
    raw_features = {
        "pkt_rate": 266.0,
        "byte_rate": 400000.0,
        "tcp_syn_cnt": 1,
        "tcp_ack_cnt": 799,
        "entropy_pkt_len": 4.5,
        "pkt_len_mean": 1450.0,
        "dst_port": 443,
    }

    report = explainer_engine.explain_detection(
        alert_id="EVT-EXFIL-03",
        flow_id="192.168.1.10:49210 -> 203.0.113.5:443 [P6]",
        threat_category="DATA_EXFILTRATION",
        model_name="XGBoost Classifier",
        model_confidence=0.88,
        risk_score=85,
        severity="HIGH",
        flow_metrics=flow_metrics,
        raw_features=raw_features,
        directionality_state="ASYMMETRIC_OBSERVED",
    )

    assert report.threat_category == "DATA_EXFILTRATION"
    assert report.model_name == "XGBoost Classifier"
    assert any("transfer" in b.lower() or "throughput" in b.lower() or "bandwidth" in b.lower() for b in report.observed_behavior)
    assert any("destination" in s.lower() or "asn" in s.lower() for s in report.investigation_suggestions)


def test_04_slowloris_explanation(explainer_engine):
    """Scenario 4: SLOWLORIS explanation with prolonged duration and low bandwidth."""
    flow_metrics = {"packet_count": 25, "byte_count": 1200, "duration": 45.0, "dst_port": 80}
    raw_features = {
        "pkt_rate": 0.55,
        "byte_rate": 26.6,
        "tcp_syn_cnt": 1,
        "tcp_ack_cnt": 24,
        "duration": 45.0,
        "dst_port": 80,
    }

    report = explainer_engine.explain_detection(
        alert_id="EVT-SLOW-04",
        flow_id="192.168.1.80:55123 -> 10.0.0.1:80 [P6]",
        threat_category="SLOWLORIS",
        model_name="Random Forest Classifier",
        model_confidence=0.85,
        risk_score=65,
        severity="HIGH",
        flow_metrics=flow_metrics,
        raw_features=raw_features,
    )

    assert report.threat_category == "SLOWLORIS"
    assert any("prolonged" in b.lower() or "seconds" in b.lower() for b in report.observed_behavior)
    assert any("timeout" in s.lower() or "pool" in s.lower() or "proxy" in s.lower() for s in report.investigation_suggestions)


def test_05_benign_traffic_explanation(explainer_engine):
    """Scenario 5: BENIGN traffic explanation without false alarm claims."""
    flow_metrics = {"packet_count": 15, "byte_count": 4500, "duration": 1.2, "dst_port": 443}
    raw_features = {
        "pkt_rate": 12.5,
        "byte_rate": 3750.0,
        "tcp_syn_cnt": 1,
        "tcp_ack_cnt": 14,
        "entropy_pkt_len": 3.2,
        "pkt_len_mean": 300.0,
        "dst_port": 443,
    }

    report = explainer_engine.explain_detection(
        alert_id="EVT-BENIGN-05",
        flow_id="192.168.1.15:52100 -> 10.0.0.1:443 [P6]",
        threat_category="BENIGN",
        model_name="Random Forest Classifier",
        model_confidence=0.96,
        risk_score=10,
        severity="LOW",
        flow_metrics=flow_metrics,
        raw_features=raw_features,
        directionality_state="BIDIRECTIONAL_OBSERVED",
    )

    assert report.threat_category == "BENIGN"
    assert report.risk_score <= 25
    assert "baseline" in report.summary.lower() or "expected" in report.summary.lower()
    # Does not claim absolute safety
    assert any("monitoring" in s.lower() or "baseline" in s.lower() for s in report.investigation_suggestions)


def test_06_missing_feature_values(explainer_engine):
    """Scenario 6: Missing feature values handled without KeyError or crash."""
    report = explainer_engine.explain_detection(
        alert_id="EVT-MISSING-06",
        flow_id="FLOW-MISSING",
        threat_category="PORT_SCAN",
        model_name="Random Forest",
        model_confidence=0.80,
        risk_score=50,
        severity="MEDIUM",
        flow_metrics={},
        raw_features={},
        contributing_factors=None,
    )

    assert isinstance(report, AIThreatExplanation)
    assert report.alert_id == "EVT-MISSING-06"
    assert report.summary is not None
    assert isinstance(report.observed_behavior, list)
    assert isinstance(report.feature_contributions, list)


def test_07_missing_model_confidence(explainer_engine):
    """Scenario 7: Missing model confidence handled safely."""
    report = explainer_engine.explain_detection(
        alert_id="EVT-NOCONF-07",
        flow_id="FLOW-NOCONF",
        threat_category="SYN_FLOOD",
        model_name="Baseline Heuristics Engine",
        model_confidence=None,
        risk_score=70,
        severity="HIGH",
    )

    assert report.model_confidence is None
    assert report.model_name == "Baseline Heuristics Engine"
    assert "None" not in report.summary
    assert report.risk_score == 70


def test_08_shap_unavailable():
    """Scenario 8: Explainer operates when SHAP is unavailable."""
    engine_no_shap = AIThreatExplanationEngine(explainer=None)
    raw_feats = {"pkt_rate": 150.0, "tcp_syn_cnt": 10, "byte_rate": 5000.0, "duration": 1.0}
    report = engine_no_shap.explain_detection(
        alert_id="EVT-NOSHAP-08",
        flow_id="FLOW-NOSHAP",
        threat_category="SYN_FLOOD",
        model_name="Random Forest",
        model_confidence=0.85,
        risk_score=75,
        severity="HIGH",
        raw_features=raw_feats,
        contributing_factors=None,
    )

    assert len(report.feature_contributions) > 0
    assert any(c["feature"] == "pkt_rate" for c in report.feature_contributions)


def test_09_incorrect_or_incomplete_flow_data(explainer_engine):
    """Scenario 9: Corrupted or negative metrics handled safely."""
    flow_metrics = {"packet_count": -5, "byte_count": -100, "duration": -2.0}
    raw_features = {"pkt_rate": -10.0, "tcp_syn_cnt": -1}

    report = explainer_engine.explain_detection(
        alert_id="EVT-CORRUPT-09",
        flow_id="FLOW-CORRUPT",
        threat_category="ANOMALOUS",
        model_name="Isolation Forest",
        model_confidence=0.50,
        risk_score=35,
        severity="MEDIUM",
        flow_metrics=flow_metrics,
        raw_features=raw_features,
    )

    assert isinstance(report, AIThreatExplanation)
    assert report.alert_id == "EVT-CORRUPT-09"
    assert len(report.observed_behavior) > 0


def test_10_unidirectional_observed_traffic(explainer_engine):
    """Scenario 10: Unidirectional observation explains sensor visibility context."""
    report = explainer_engine.explain_detection(
        alert_id="EVT-UNIDIR-10",
        flow_id="FLOW-UNIDIR",
        threat_category="PORT_SCAN",
        model_name="Random Forest",
        model_confidence=0.90,
        risk_score=60,
        severity="HIGH",
        directionality_state="UNIDIRECTIONAL_OBSERVED",
        directionality_score=0.98,
        directionality_confidence=0.95,
    )

    dir_dict = report.directionality
    assert dir_dict["state"] == "UNIDIRECTIONAL_OBSERVED"
    assert "sensor" in dir_dict["sensor_visibility_note"].lower()
    assert "not automatically" in dir_dict["sensor_visibility_note"].lower() or "unidirectional" in dir_dict["sensor_visibility_note"].lower()


def test_11_bidirectional_observed_traffic(explainer_engine):
    """Scenario 11: Bidirectional observed traffic explains bilateral dialogue."""
    report = explainer_engine.explain_detection(
        alert_id="EVT-BIDIR-11",
        flow_id="FLOW-BIDIR",
        threat_category="BENIGN",
        model_name="Random Forest",
        model_confidence=0.95,
        risk_score=15,
        severity="LOW",
        directionality_state="BIDIRECTIONAL_OBSERVED",
        directionality_score=0.10,
        directionality_confidence=0.90,
    )

    dir_dict = report.directionality
    assert dir_dict["state"] == "BIDIRECTIONAL_OBSERVED"
    assert "bilateral" in dir_dict["explanation"].lower() or "forward and reverse" in dir_dict["explanation"].lower()


def test_12_explanation_storage_in_sqlite(explainer_engine, tmp_path):
    """Scenario 12: Structured explanation persists in SQLite and can be retrieved."""
    db_file = str(tmp_path / "test_expl.db")
    db = SecurityDatabase(db_path=db_file)
    now = time.time()

    explanation = explainer_engine.explain_detection(
        alert_id="EVT-DB-12",
        flow_id="192.168.1.1:1234 -> 10.0.0.1:80 [P6]",
        threat_category="PORT_SCAN",
        model_name="Random Forest Classifier",
        model_confidence=0.91,
        risk_score=80,
        severity="CRITICAL",
        raw_features={"pkt_rate": 500.0, "tcp_syn_cnt": 1},
    )

    event = SecurityEvent(
        event_id="EVT-DB-12",
        timestamp=now,
        flow_key="192.168.1.1:1234 -> 10.0.0.1:80 [P6]",
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=1234,
        dst_port=80,
        proto=6,
        threat_type="PORT_SCAN",
        risk_score=80,
        severity="CRITICAL",
        confidence_pct=91.0,
        anomaly_score=0.85,
        contributing_factors=[{"feature": "tcp_syn_cnt", "explanation": "Isolated SYN"}],
        flow_metrics={"packet_count": 1, "byte_count": 60},
        directionality_state="UNIDIRECTIONAL_OBSERVED",
        explanation=explanation.to_dict(),
    )

    db.insert_event(event)

    # Test retrieval via get_recent_events
    recent = db.get_recent_events(limit=10)
    assert len(recent) == 1
    retrieved = recent[0]
    assert retrieved["event_id"] == "EVT-DB-12"
    assert "explanation" in retrieved
    assert retrieved["explanation"]["threat_category"] == "PORT_SCAN"
    assert retrieved["explanation"]["risk_score"] == 80
    assert len(retrieved["explanation"]["investigation_suggestions"]) > 0

    # Test retrieval via get_event_explanation
    direct_expl = db.get_event_explanation("EVT-DB-12")
    assert direct_expl is not None
    assert direct_expl["alert_id"] == "EVT-DB-12"


def test_13_dashboard_explanation_display(explainer_engine):
    """Scenario 13: PySide6 Desktop Dashboard UI renders structured explanation."""
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication(sys.argv)
    import uniguard.desktop_ui.app as app_mod
    app_mod.WEBENGINE_AVAILABLE = False

    win = app_mod.UniGuardDesktopApp()

    now = time.time()
    explanation = explainer_engine.explain_detection(
        alert_id="EVT-UI-13",
        flow_id="192.168.1.20:44321 -> 10.0.0.5:443 [P6]",
        threat_category="SYN_FLOOD",
        model_name="Random Forest Classifier",
        model_confidence=0.96,
        risk_score=88,
        severity="CRITICAL",
        flow_metrics={"packet_count": 100, "byte_count": 6000, "duration": 0.1},
        raw_features={"pkt_rate": 1000.0, "tcp_syn_cnt": 100, "tcp_ack_cnt": 0},
    )

    event = SecurityEvent(
        event_id="EVT-UI-13",
        timestamp=now,
        flow_key="192.168.1.20:44321 -> 10.0.0.5:443 [P6]",
        src_ip="192.168.1.20",
        dst_ip="10.0.0.5",
        src_port=44321,
        dst_port=443,
        proto=6,
        threat_type="SYN_FLOOD",
        risk_score=88,
        severity="CRITICAL",
        confidence_pct=96.0,
        anomaly_score=0.92,
        contributing_factors=[{"feature": "tcp_syn_cnt", "explanation": "SYN Flood"}],
        flow_metrics={"packet_count": 100, "byte_count": 6000},
        explanation=explanation.to_dict(),
    )

    win.display_event_details(event)

    # Check UI widgets
    assert "EVT-UI-13" in win.lbl_inspect_flow.text()
    assert win.progress_risk.value() == 88
    xai_display = win.xai_text.toPlainText()
    assert "WHY WAS THIS DETECTED?" in xai_display
    assert "SYN_FLOOD" in xai_display
    assert "EXECUTIVE THREAT SUMMARY" in xai_display
    assert "FEATURE CONTRIBUTION ATTRIBUTION" in xai_display

    playbook_display = win.txt_playbook.toPlainText()
    assert "DEFENSIVE SOC ANALYST INVESTIGATION PLAYBOOK" in playbook_display
    assert "SYN_FLOOD" in playbook_display


def test_14_large_numbers_of_alerts_performance(explainer_engine):
    """Scenario 14: Engine handles large batches of alerts efficiently."""
    t0 = time.time()
    num_alerts = 200

    for i in range(num_alerts):
        threat = "SYN_FLOOD" if i % 2 == 0 else "PORT_SCAN"
        expl = explainer_engine.explain_detection(
            alert_id=f"EVT-BATCH-{i:04d}",
            flow_id=f"192.168.1.{i % 250}:5000 -> 10.0.0.1:80 [P6]",
            threat_category=threat,
            model_name="Random Forest Classifier",
            model_confidence=0.90,
            risk_score=75,
            severity="HIGH",
            raw_features={"pkt_rate": 100.0 + i, "tcp_syn_cnt": i + 1},
        )
        assert expl.alert_id == f"EVT-BATCH-{i:04d}"

    elapsed = time.time() - t0
    # Must process 200 alerts in under 1 second (< 5 ms per explanation)
    assert elapsed < 1.0, f"Performance bottleneck: 200 alerts took {elapsed:.2f}s"


def test_15_explanation_failure_without_interrupting_detection():
    """Scenario 15: Detection engine continues safely if explanation generation fails."""
    detection_engine = DetectionEngine()

    # Monkey-patch explain_detection to raise an exception
    def broken_explain(*args, **kwargs):
        raise RuntimeError("Simulated unexpected explanation engine failure")

    detection_engine.threat_explainer.explain_detection = broken_explain

    flow = UnidirectionalFlow(
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=44332,
        dst_port=80,
        proto=6,
        start_time=time.time(),
    )
    flow.packet_count = 10
    flow.byte_count = 1200
    flow.last_seen_time = flow.start_time + 1.0

    # Detection must not crash
    event = detection_engine.analyze_flow(flow)
    assert isinstance(event, SecurityEvent)
    assert event.event_id is not None
    assert event.threat_type is not None
    assert event.explanation is not None
    assert "Explanation unavailable" in event.explanation.get("summary", "")
