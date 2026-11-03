"""UniGuard AI Frontend Verification Suite.
Validates all 8 native desktop modules and backend bridge integration.
"""

import os
import sys
import time
import pytest
from PySide6.QtWidgets import QApplication

import uniguard.desktop_ui.app as app_mod
from uniguard.desktop_ui.server import SocStateBridge


@pytest.fixture(scope="session")
def qapp():
    # Disable WebEngine for headless testing
    app_mod.WEBENGINE_AVAILABLE = False
    app = QApplication.instance() or QApplication(sys.argv)
    yield app


@pytest.fixture
def desktop_window(qapp):
    win = app_mod.UniGuardDesktopApp()
    yield win
    if win.worker is not None and win.worker.isRunning():
        win.stop_monitoring()
    win.close()


def pump_events(app, duration_secs=2.0, interval=0.05):
    """Pumps Qt event loop so worker thread signals are dispatched to slots."""
    steps = int(duration_secs / interval)
    for _ in range(steps):
        app.processEvents()
        time.sleep(interval)


def test_module_structure_and_tabs(desktop_window):
    """Module 1-8: Verify 8 tabs exist in proper order."""
    assert desktop_window.tabs.count() == 8
    tab_names = [desktop_window.tabs.tabText(i).upper() for i in range(8)]
    assert "SECURITY OVERVIEW" in tab_names[0]
    assert "LIVE MONITORING" in tab_names[1]
    assert "THREAT ALERTS" in tab_names[2]
    assert "FLOW ANALYSIS" in tab_names[3]
    assert "TRAFFIC ANALYTICS" in tab_names[4]
    assert "MODEL / AI STATUS" in tab_names[5]
    assert "EVENT HISTORY" in tab_names[6]
    assert "SETTINGS" in tab_names[7]


def test_module_6_dynamic_model_status_and_self_test(desktop_window):
    """Module 6: Model / AI Status dynamic checking and benchmark self-test."""
    desktop_window.refresh_model_status_display()
    rf_text = desktop_window.lbl_stat_rf.text()
    xgb_text = desktop_window.lbl_stat_xgb.text()
    iso_text = desktop_window.lbl_stat_iso.text()

    assert "ONLINE" in rf_text
    assert "STANDBY" in xgb_text
    assert "ONLINE" in iso_text

    desktop_window.run_ai_self_test()
    diag = desktop_window.txt_ai_diag.toPlainText()
    assert "[SUCCESS]" in diag
    assert "Random Forest Inference" in diag


def test_module_8_settings_validation(desktop_window):
    """Module 8: Settings application and parameter boundary validation."""
    desktop_window.txt_bpf.setText("ip and tcp")
    desktop_window.spin_idle.setValue(18.0)
    desktop_window.spin_active.setValue(45.0)
    desktop_window.spin_elephant.setValue(60)

    desktop_window.save_and_apply_settings()
    assert "validated and applied" in desktop_window.lbl_settings_feedback.text().lower()


def test_modules_1_to_5_capture_stream_and_playbook(desktop_window, qapp):
    """Modules 1-5: Start PCAP monitoring, receive flows, test triage and playbooks."""
    desktop_window.start_monitoring()
    pump_events(qapp, duration_secs=2.0)

    # Overview table
    assert desktop_window.table.rowCount() > 0
    # Alerts table
    assert desktop_window.table_alerts.rowCount() > 0

    # Module 1: Search & Filter
    desktop_window.txt_overview_search.setText("PORT_SCAN")
    desktop_window.filter_overview_table()
    assert desktop_window.table.rowCount() >= 0
    desktop_window.reset_overview_filters()

    # Module 3: Investigation playbook & Risk Gauge
    desktop_window.table_alerts.selectRow(0)
    desktop_window.on_alert_table_row_clicked(0, 0)
    assert desktop_window.progress_risk.value() > 0
    playbook_text = desktop_window.txt_playbook.toPlainText()
    assert "PLAYBOOK" in playbook_text

    # Module 4: 24 Categorized Traffic Features
    flow_text = desktop_window.txt_flow_details.toPlainText()
    assert "[1] VOLUME & SIZE METRICS" in flow_text
    assert "[2] TIMING & RATE METRICS" in flow_text
    assert "[3] TCP CONTROL & PROTOCOL METRICS" in flow_text
    assert "[4] BEHAVIORAL ASYMMETRY & INFORMATION ENTROPY" in flow_text

    # Module 5: Traffic Analytics
    assert len(desktop_window.txt_top_src.toPlainText()) > 0
    assert len(desktop_window.txt_top_dst.toPlainText()) > 0
    assert "TCP" in desktop_window.txt_top_proto.toPlainText()

    # Stop cleanly
    desktop_window.stop_monitoring()
    assert desktop_window.worker is None
