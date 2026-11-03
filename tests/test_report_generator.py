"""Unit and Integration Tests for Module 10: Security Report Generator.

Covers all 15 operational scenarios:
1. Valid database records report generation.
2. Empty database graceful handling.
3. Missing optional fields in event records.
4. Custom date range filtering.
5. PDF export formatting and page structure.
6. CSV export data integrity and encoding.
7. JSON export schema compliance across all 10 sections.
8. Large event datasets stress test.
9. Invalid date range handling.
10. Missing model metadata fallback.
11. Report history persistence in SQLite.
12. Report deletion and file removal.
13. ReportWorkerThread progress and finish signal emissions.
14. Worker thread cancellation and safe cleanup.
15. Directionality statistics calculation accuracy.
"""

import os
import time
import json
import tempfile
import pytest
from datetime import datetime

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QEventLoop, QTimer

from uniguard.database.storage import SecurityDatabase
from uniguard.detection.engine import SecurityEvent
from uniguard.reports.report_data_collector import ReportDataCollector
from uniguard.reports.report_charts import ReportChartGenerator
from uniguard.reports.pdf_generator import PdfReportGenerator
from uniguard.reports.csv_exporter import CsvReportExporter
from uniguard.reports.json_exporter import JsonReportExporter
from uniguard.reports.report_builder import SecurityReportBuilder
from uniguard.reports.report_history import ReportHistoryManager
from uniguard.reports.report_worker import ReportWorkerThread


# Ensure QApplication instance for any PySide6 test components
@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def test_db(tmp_path):
    """Provides an isolated SQLite database populated with realistic synthetic events."""
    db_file = str(tmp_path / "test_reports.db")
    db = SecurityDatabase(db_file)

    now = time.time()
    events = [
        SecurityEvent(
            event_id="EVT-TEST-001",
            timestamp=now - 300,
            flow_key="192.168.1.50:44444->10.0.0.1:80/6",
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
            src_port=44444,
            dst_port=80,
            proto=6,
            threat_type="PORT_SCAN",
            risk_score=85,
            severity="HIGH",
            confidence_pct=92.5,
            anomaly_score=0.45,
            contributing_factors=[{"feature": "syn_ratio_extreme"}],
            flow_metrics={"packet_count": 45, "byte_count": 2700, "duration": 1.2},
            directionality_state="UNIDIRECTIONAL",
            directionality_score=0.95,
            directionality_confidence=0.9,
            explanation={"rules_triggered": ["R01_SCAN"], "top_factors": [{"factor": "syn_ratio"}]},
        ),
        SecurityEvent(
            event_id="EVT-TEST-002",
            timestamp=now - 200,
            flow_key="192.168.1.100:55555->172.16.0.5:443/6",
            src_ip="192.168.1.100",
            dst_ip="172.16.0.5",
            src_port=55555,
            dst_port=443,
            proto=6,
            threat_type="DATA_EXFILTRATION",
            risk_score=95,
            severity="CRITICAL",
            confidence_pct=98.0,
            anomaly_score=0.82,
            contributing_factors=[{"feature": "high_bytes_out"}],
            flow_metrics={"packet_count": 1200, "byte_count": 1500000, "duration": 15.4},
            directionality_state="UNIDIRECTIONAL",
            directionality_score=1.0,
            directionality_confidence=0.95,
            explanation={"rules_triggered": ["R03_EXFIL"], "top_factors": [{"factor": "byte_volume"}]},
        ),
        SecurityEvent(
            event_id="EVT-TEST-003",
            timestamp=now - 100,
            flow_key="10.0.0.2:12345->10.0.0.1:53/17",
            src_ip="10.0.0.2",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=53,
            proto=17,
            threat_type="BENIGN",
            risk_score=10,
            severity="LOW",
            confidence_pct=99.0,
            anomaly_score=-0.15,
            contributing_factors=[],
            flow_metrics={"packet_count": 4, "byte_count": 320, "duration": 0.05},
            directionality_state="BIDIRECTIONAL",
            directionality_score=0.1,
            directionality_confidence=0.85,
        ),
    ]

    for ev in events:
        db.insert_event(ev)

    return db


# =============================================================================
# SCENARIO 1: Valid database records report generation
# =============================================================================
def test_1_valid_database_report_generation(test_db, tmp_path):
    builder = SecurityReportBuilder(db=test_db, output_dir=str(tmp_path))
    result = builder.build_report(
        report_name="SIH Security Audit",
        report_type="EXECUTIVE",
        date_range_code="LAST_24_HOURS",
        export_format="ALL",
    )

    assert result["report_id"].startswith("RPT-")
    assert result["report_name"] == "SIH Security Audit"
    assert "PDF" in result["files"]
    assert "CSV" in result["files"]
    assert "JSON" in result["files"]

    report_data = result["report_data"]
    assert report_data["section_1_executive_summary"]["total_events"] == 3
    assert report_data["section_1_executive_summary"]["high_risk_total"] == 2
    assert report_data["section_1_executive_summary"]["status"] == "ELEVATED RISK"


# =============================================================================
# SCENARIO 2: Empty database graceful handling
# =============================================================================
def test_2_empty_database_graceful_handling(tmp_path):
    empty_db = SecurityDatabase(str(tmp_path / "empty.db"))
    builder = SecurityReportBuilder(db=empty_db, output_dir=str(tmp_path))

    result = builder.build_report(
        report_name="Empty Database Audit",
        report_type="EXECUTIVE",
        date_range_code="ALL",
        export_format="ALL",
    )

    assert os.path.exists(result["files"]["PDF"])
    assert os.path.exists(result["files"]["CSV"])
    assert os.path.exists(result["files"]["JSON"])

    data = result["report_data"]
    assert data["section_1_executive_summary"]["total_events"] == 0
    assert data["section_1_executive_summary"]["high_risk_total"] == 0
    assert data["section_1_executive_summary"]["status"] == "SECURE"
    assert "no network events were logged" in data["section_1_executive_summary"]["overview_text"].lower()


# =============================================================================
# SCENARIO 3: Missing optional fields handling
# =============================================================================
def test_3_missing_optional_fields_handling(tmp_path):
    db = SecurityDatabase(str(tmp_path / "missing_fields.db"))
    # Insert bare event with minimal/null fields
    with db._get_connection() as conn:
        conn.execute("""
            INSERT INTO security_events (
                event_id, timestamp, flow_key, src_ip, dst_ip, src_port, dst_port,
                proto, threat_type, risk_score, severity, confidence_pct, anomaly_score,
                contributing_factors, flow_metrics, directionality_state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "EVT-BARE-1", time.time(), "key", "1.1.1.1", "2.2.2.2", 80, 8080,
            6, "UNKNOWN", 50, "MEDIUM", 80.0, 0.0,
            "", "", "UNKNOWN"
        ))
        conn.commit()

    builder = SecurityReportBuilder(db=db, output_dir=str(tmp_path))
    result = builder.build_report(report_name="Bare Event Report", export_format="ALL")

    assert os.path.exists(result["files"]["PDF"])
    assert result["report_data"]["section_1_executive_summary"]["total_events"] == 1


# =============================================================================
# SCENARIO 4: Custom date range filtering
# =============================================================================
def test_4_custom_date_range_filtering(test_db, tmp_path):
    collector = ReportDataCollector(test_db)
    now = time.time()

    # Time window that covers only the latest event (-100s)
    data = collector.collect(
        report_name="Filtered Audit",
        report_type="EXECUTIVE",
        date_range_label="Custom Window",
        start_time=now - 150,
        end_time=now,
    )

    assert data["metadata"]["total_events_collected"] == 1
    assert data["section_1_executive_summary"]["total_events"] == 1
    # Only benign event was in that window
    assert data["section_1_executive_summary"]["high_risk_total"] == 0


# =============================================================================
# SCENARIO 5: PDF export formatting and page structure
# =============================================================================
def test_5_pdf_export_structure(test_db, tmp_path):
    builder = SecurityReportBuilder(db=test_db, output_dir=str(tmp_path))
    result = builder.build_report(report_name="PDF Structure Test", export_format="PDF")

    pdf_path = result["files"]["PDF"]
    assert os.path.exists(pdf_path)
    assert os.path.getsize(pdf_path) > 5000  # Multi-page or structured PDF

    with open(pdf_path, "rb") as f:
        header = f.read(5)
        assert header == b"%PDF-"


# =============================================================================
# SCENARIO 6: CSV export data integrity and encoding
# =============================================================================
def test_6_csv_export_data_integrity(test_db, tmp_path):
    builder = SecurityReportBuilder(db=test_db, output_dir=str(tmp_path))
    result = builder.build_report(report_name="CSV Audit Test", export_format="CSV")

    csv_path = result["files"]["CSV"]
    assert os.path.exists(csv_path)

    with open(csv_path, "r", encoding="utf-8-sig") as f:
        content = f.read()
        assert "# UNIGUARD AI SECURITY AUDIT REPORT" in content
        assert "# SECTION 1: EXECUTIVE SUMMARY" in content
        assert "PORT_SCAN" in content
        assert "DATA_EXFILTRATION" in content
        assert "192.168.1.100" in content


# =============================================================================
# SCENARIO 7: JSON export schema compliance across all 10 sections
# =============================================================================
def test_7_json_schema_compliance(test_db, tmp_path):
    builder = SecurityReportBuilder(db=test_db, output_dir=str(tmp_path))
    result = builder.build_report(report_name="JSON Schema Test", export_format="JSON")

    json_path = result["files"]["JSON"]
    assert os.path.exists(json_path)

    with open(json_path, "r", encoding="utf-8") as f:
        loaded = json.load(f)

    # Verify all 10 standard report sections exist
    required_sections = [
        "metadata",
        "section_1_executive_summary",
        "section_2_traffic_analysis",
        "section_3_utie_intelligence",
        "section_4_threat_summary",
        "section_5_high_risk_events",
        "section_6_ai_model_analysis",
        "section_7_explainability",
        "section_8_risk_analysis",
        "section_9_timeline",
        "section_10_recommendations",
    ]
    for sec in required_sections:
        assert sec in loaded, f"Missing section: {sec}"


# =============================================================================
# SCENARIO 8: Large event datasets performance
# =============================================================================
def test_8_large_dataset_performance(tmp_path):
    db = SecurityDatabase(str(tmp_path / "large_dataset.db"))
    now = time.time()
    events = []

    for i in range(500):
        events.append(
            SecurityEvent(
                event_id=f"EVT-PERF-{i}",
                timestamp=now - (i * 10),
                flow_key=f"10.0.{i%255}.1:1234->192.168.1.1:80/6",
                src_ip=f"10.0.{i%255}.1",
                dst_ip="192.168.1.1",
                src_port=1234,
                dst_port=80,
                proto=6,
                threat_type="PORT_SCAN" if i % 5 == 0 else "BENIGN",
                risk_score=85 if i % 5 == 0 else 15,
                severity="HIGH" if i % 5 == 0 else "LOW",
                confidence_pct=90.0,
                anomaly_score=0.2,
                contributing_factors=[],
                flow_metrics={"packet_count": 10, "byte_count": 1000, "duration": 0.5},
                directionality_state="UNIDIRECTIONAL" if i % 3 == 0 else "BIDIRECTIONAL",
            )
        )
    db.insert_events_batch(events)

    builder = SecurityReportBuilder(db=db, output_dir=str(tmp_path))
    t0 = time.time()
    result = builder.build_report(report_name="Scale Audit", export_format="ALL")
    elapsed = time.time() - t0

    assert elapsed < 15.0  # Must complete in under 15 seconds
    assert result["report_data"]["section_1_executive_summary"]["total_events"] == 500


# =============================================================================
# SCENARIO 9: Invalid date range handling
# =============================================================================
def test_9_invalid_date_range_handling(test_db, tmp_path):
    collector = ReportDataCollector(test_db)
    # start_time is greater than end_time
    data = collector.collect(
        report_name="Inverted Range",
        report_type="EXECUTIVE",
        date_range_label="Inverted",
        start_time=time.time(),
        end_time=time.time() - 3600,
    )

    # Empty result returned safely without crashing
    assert data["section_1_executive_summary"]["total_events"] == 0
    assert data["section_1_executive_summary"]["status"] == "SECURE"


# =============================================================================
# SCENARIO 10: Missing model metadata fallback
# =============================================================================
def test_10_model_analysis_fallback(test_db, tmp_path):
    collector = ReportDataCollector(test_db)
    data = collector.collect("Fallback Audit", "EXECUTIVE", "ALL")

    sec6 = data["section_6_ai_model_analysis"]
    assert "active_models" in sec6
    assert len(sec6["active_models"]) >= 3
    for model in sec6["active_models"]:
        assert model["status"] == "OPERATIONAL"


# =============================================================================
# SCENARIO 11: Report history persistence in SQLite
# =============================================================================
def test_11_report_history_persistence(test_db, tmp_path):
    builder = SecurityReportBuilder(db=test_db, output_dir=str(tmp_path))
    result = builder.build_report(report_name="Persistence Test", export_format="PDF")

    history_mgr = ReportHistoryManager(test_db)
    history = history_mgr.get_history()

    assert len(history) >= 1
    found = [r for r in history if r["report_id"] == result["report_id"]]
    assert len(found) == 1
    assert found[0]["report_name"] == "Persistence Test"
    assert found[0]["export_format"] == "PDF"


# =============================================================================
# SCENARIO 12: Report deletion and file removal
# =============================================================================
def test_12_report_deletion_and_cleanup(test_db, tmp_path):
    builder = SecurityReportBuilder(db=test_db, output_dir=str(tmp_path))
    result = builder.build_report(report_name="Delete Target", export_format="PDF")

    rep_id = result["report_id"]
    pdf_path = result["files"]["PDF"]
    assert os.path.exists(pdf_path)

    history_mgr = ReportHistoryManager(test_db)
    deleted = history_mgr.delete_report(rep_id, delete_file=True)

    assert deleted is True
    assert history_mgr.db.get_report_by_id(rep_id) is None
    assert not os.path.exists(pdf_path)


# =============================================================================
# SCENARIO 13: ReportWorkerThread progress and finish signal emissions
# =============================================================================
def test_13_worker_thread_signals(qapp, test_db, tmp_path):
    builder = SecurityReportBuilder(db=test_db, output_dir=str(tmp_path))
    worker = ReportWorkerThread(
        report_name="Worker Signal Test",
        report_type="EXECUTIVE",
        date_range_code="LAST_24_HOURS",
        export_format="JSON",
        builder=builder,
    )

    progress_events = []
    finished_results = []
    failed_errors = []

    loop = QEventLoop()

    def on_finished(res):
        finished_results.append(res)
        loop.quit()

    def on_failed(err):
        failed_errors.append(err)
        loop.quit()

    worker.progress_updated.connect(lambda pct, msg: progress_events.append((pct, msg)))
    worker.report_finished.connect(on_finished)
    worker.report_failed.connect(on_failed)

    worker.start()
    QTimer.singleShot(5000, loop.quit)
    loop.exec()
    worker.wait(1000)

    assert len(failed_errors) == 0
    assert len(finished_results) == 1
    assert len(progress_events) >= 3
    assert finished_results[0]["report_name"] == "Worker Signal Test"


# =============================================================================
# SCENARIO 14: Worker thread cancellation and safe cleanup
# =============================================================================
def test_14_worker_cancellation(qapp, test_db, tmp_path):
    builder = SecurityReportBuilder(db=test_db, output_dir=str(tmp_path))
    worker = ReportWorkerThread(
        report_name="Cancellation Test",
        report_type="EXECUTIVE",
        date_range_code="ALL",
        export_format="PDF",
        builder=builder,
    )

    worker.cancel()
    assert worker._is_cancelled is True


# =============================================================================
# SCENARIO 15: Directionality statistics calculation accuracy
# =============================================================================
def test_15_directionality_statistics_accuracy(test_db):
    collector = ReportDataCollector(test_db)
    data = collector.collect("Directionality Audit", "EXECUTIVE", "ALL")

    sec3 = data["section_3_utie_intelligence"]
    # 2 out of 3 events are UNIDIRECTIONAL
    assert sec3["unidirectional_flows"] == 2
    assert sec3["bidirectional_flows"] == 1
    assert sec3["unidirectional_percentage"] == 66.7

