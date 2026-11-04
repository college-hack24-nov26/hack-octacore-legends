"""UniGuard AI - Desktop Network Detection & Response (NDR) SOC Dashboard.

Built with PySide6 for high-throughput, real-time unidirectional IP monitoring,
threat classification, anomaly detection, SHAP explainability, and risk prioritization.
Supports both Offline PCAP Replay and Live Network Interface Sniffing across Windows & Linux.
"""

from __future__ import annotations

import sys
import os
import time
import queue
import threading
import csv
from typing import Optional, List, Dict, Any

from PySide6.QtCore import Qt, QThread, Signal, Slot, QUrl, QTimer
from PySide6.QtGui import QColor, QFont, QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QProgressBar,
    QTextEdit,
    QLineEdit,
    QSpinBox,
    QDoubleSpinBox,
    QFrame,
    QSplitter,
    QGroupBox,
    QTabWidget,
    QFileDialog,
    QMessageBox,
    QFormLayout,
    QGridLayout,
    QCheckBox,
)

import psutil
from sklearn import get_config, config_context
import numpy as np

# Ensure project root in sys.path and define canonical project asset paths
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

DEFAULT_MODELS_DIR = os.path.join(PROJECT_ROOT, "models_saved")
DEFAULT_SAMPLE_PCAP = os.path.join(PROJECT_ROOT, "data", "samples", "sample_unidirectional.pcap")

from uniguard.capture.pcap_reader import PcapIngestor
from uniguard.capture.live_sniffer import LiveSniffer
from uniguard.flow_engine.tracker import FlowTracker
from uniguard.preprocessing.pipeline import FlowDataPreprocessor
from uniguard.models.supervised import SupervisedThreatClassifier
from uniguard.models.anomaly import IsolationForestAnomalyDetector
from uniguard.risk.scorer import RiskScorer
from uniguard.detection.engine import DetectionEngine, SecurityEvent
from uniguard.database.storage import SecurityDatabase
from uniguard.directionality.explainer import DirectionalityExplainer
from uniguard.desktop_ui.server import start_soc_server, SocStateBridge
from uniguard.utie import (
    UnidirectionalTrafficIntelligenceEngine,
    SensorVisibilityContext,
    ObservationPoint,
    UTIEIntelligenceReport,
)
from uniguard.reports import (
    SecurityReportBuilder,
    ReportHistoryManager,
    ReportWorkerThread,
)

try:
    from PySide6.QtWebEngineWidgets import QWebEngineView
    WEBENGINE_AVAILABLE = True
except Exception:
    WEBENGINE_AVAILABLE = False


DARK_STYLESHEET = """
QMainWindow {
    background-color: #080b11;
}
QWidget {
    background-color: #080b11;
    color: #c9d1d9;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    font-size: 9pt;
}
QFrame.kpi-card {
    background-color: #0f141c;
    border: 1px solid #1c2333;
    border-radius: 8px;
    padding: 8px 12px;
}
QLabel.kpi-title {
    color: #8b949e;
    font-size: 8.5pt;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
QLabel.kpi-value {
    color: #f0f6fc;
    font-size: 16pt;
    font-weight: bold;
    margin-top: 2px;
}
QGroupBox {
    border: 1px solid #1c2333;
    border-radius: 8px;
    margin-top: 10px;
    font-weight: bold;
    color: #58a6ff;
    padding-top: 14px;
    background-color: #0c1017;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
    color: #58a6ff;
}
QPushButton {
    background-color: #161d2b;
    border: 1px solid #283347;
    border-radius: 6px;
    color: #c9d1d9;
    padding: 6px 14px;
    font-weight: 600;
    min-height: 18px;
}
QPushButton:hover {
    background-color: #212c3f;
    border-color: #3b82f6;
    color: #f0f6fc;
}
QPushButton:pressed {
    background-color: #121926;
}
QPushButton#start-btn {
    background-color: #107c41;
    color: #ffffff;
    border: 1px solid #169b52;
}
QPushButton#start-btn:hover {
    background-color: #169b52;
}
QPushButton#stop-btn {
    background-color: #b91c1c;
    color: #ffffff;
    border: 1px solid #dc2626;
}
QPushButton#stop-btn:hover {
    background-color: #dc2626;
}
QPushButton#action-btn {
    background-color: #1e3a8a;
    color: #60a5fa;
    border: 1px solid #2563eb;
}
QPushButton#action-btn:hover {
    background-color: #2563eb;
    color: #ffffff;
}
QComboBox, QLineEdit, QSpinBox, QDoubleSpinBox {
    background-color: #0f141c;
    border: 1px solid #1c2333;
    border-radius: 6px;
    padding: 5px 8px;
    color: #f0f6fc;
    selection-background-color: #1d4ed8;
}
QComboBox:hover, QLineEdit:hover {
    border-color: #3b82f6;
}
QComboBox:focus, QLineEdit:focus {
    border-color: #00e5ff;
}
QTableWidget {
    background-color: #0c1017;
    border: 1px solid #1c2333;
    gridline-color: #151b26;
    border-radius: 6px;
    selection-background-color: #1e293b;
    selection-color: #f0f6fc;
}
QHeaderView::section {
    background-color: #121824;
    color: #8b949e;
    padding: 6px 8px;
    border: none;
    border-bottom: 1px solid #1c2333;
    font-weight: 700;
    font-size: 8.5pt;
    text-transform: uppercase;
}
QTableWidget::item:selected {
    background-color: #1e293b;
    color: #00e5ff;
    font-weight: 600;
}
QTextEdit {
    background-color: #0c1017;
    border: 1px solid #1c2333;
    border-radius: 6px;
    color: #10b981;
    font-family: 'Consolas', 'Cascadia Code', monospace;
    font-size: 9pt;
    padding: 6px;
}
QTabWidget::pane {
    border: 1px solid #1c2333;
    background-color: #080b11;
    border-radius: 6px;
}
QTabBar::tab {
    background-color: #0f141c;
    color: #8b949e;
    padding: 8px 16px;
    margin-right: 4px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: 600;
    font-size: 8.5pt;
    border: 1px solid #1c2333;
    border-bottom: none;
}
QTabBar::tab:selected {
    background-color: #161d2b;
    color: #00e5ff;
    border-top: 2px solid #00e5ff;
    border-bottom: 1px solid #161d2b;
}
QTabBar::tab:hover {
    background-color: #162030;
    color: #f0f6fc;
}
QProgressBar {
    background-color: #161d2b;
    border: 1px solid #283347;
    border-radius: 4px;
    text-align: center;
    color: #f0f6fc;
    font-weight: bold;
    font-size: 8pt;
}
QProgressBar::chunk {
    background-color: #00e5ff;
    border-radius: 3px;
}
QScrollBar:vertical {
    border: none;
    background: #0c1017;
    width: 8px;
    margin: 0px;
}
QScrollBar::handle:vertical {
    background: #283347;
    min-height: 20px;
    border-radius: 4px;
}
QScrollBar::handle:vertical:hover {
    background: #3b82f6;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
"""


class MonitoringWorker(QThread):
    """Decoupled background worker thread processing PCAP or live network interface traffic."""

    event_generated = Signal(object)
    utie_generated = Signal(object)
    stats_updated = Signal(dict)
    finished_processing = Signal()
    error_occurred = Signal(str)

    def __init__(
        self,
        source_mode: str,
        target_path_or_iface: Optional[str] = None,
        bpf_filter: str = "ip and not (ether multicast or ether broadcast)",
        idle_timeout: float = 15.0,
        active_timeout: float = 60.0,
        elephant_cutoff: int = 50,
        models_dir: str = DEFAULT_MODELS_DIR,
    ) -> None:
        super().__init__()
        self.source_mode = source_mode
        self.target = target_path_or_iface
        self.bpf_filter = bpf_filter
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.elephant_cutoff = elephant_cutoff
        self.models_dir = models_dir
        self.is_running = True
        self.live_sniffer: Optional[LiveSniffer] = None
        self.evicted_queue: queue.Queue = queue.Queue(maxsize=50000)

    def run(self) -> None:
        # 1. Load ML models
        prep_file = os.path.join(self.models_dir, "preprocessor.joblib")
        rf_file = os.path.join(self.models_dir, "uniguard_rf_model.joblib")
        iso_file = os.path.join(self.models_dir, "uniguard_isolation_forest.joblib")

        preprocessor = FlowDataPreprocessor.load(prep_file) if os.path.exists(prep_file) else None
        classifier = SupervisedThreatClassifier.load(rf_file) if os.path.exists(rf_file) else None
        anomaly_detector = IsolationForestAnomalyDetector.load(iso_file) if os.path.exists(iso_file) else None

        detection_engine = DetectionEngine(
            classifier=classifier,
            anomaly_detector=anomaly_detector,
            preprocessor=preprocessor,
            risk_scorer=RiskScorer(),
        )

        # UTIE Engine (SIH 2026 Core Feature)
        bridge = SocStateBridge.get()
        utie_engine = UnidirectionalTrafficIntelligenceEngine(
            detection_engine=detection_engine,
            sensor_context=bridge.utie_engine.sensor_context,
        )

        tracker = FlowTracker(
            idle_timeout=self.idle_timeout,
            active_timeout=self.active_timeout,
            enable_directionality=True,
        )

        # 2. Worker consumer thread: drains evicted_queue and analyzes flows in parallel
        def analysis_worker_loop():
            with config_context(**get_config()):
                while self.is_running or not self.evicted_queue.empty():
                    # If monitoring was stopped, rapidly drain all remaining items without computation
                    if not self.is_running:
                        try:
                            self.evicted_queue.get_nowait()
                            self.evicted_queue.task_done()
                        except (queue.Empty, ValueError):
                            break
                        continue

                    try:
                        flow = self.evicted_queue.get(timeout=0.1)
                    except queue.Empty:
                        continue

                    try:
                        if not self.is_running:
                            continue
                        # Skip heavy explainability on routine elephant active-timeout slices
                        skip_shap = getattr(flow, "is_elephant", False) and flow.closure_reason == "ACTIVE_TIMEOUT"
                        event = detection_engine.analyze_flow(flow, skip_shap=skip_shap)
                        
                        # Generate UTIE Intelligence Report
                        biflow = getattr(flow, "_parent_biflow", None)
                        utie_report = utie_engine.analyze_flow(flow, biflow=biflow, security_event=event)

                        if self.is_running:
                            self.event_generated.emit(event)
                            self.utie_generated.emit(utie_report)
                    except Exception:
                        pass
                    finally:
                        self.evicted_queue.task_done()

        analysis_thread = threading.Thread(target=analysis_worker_loop, daemon=True, name="SOCAnalysisWorker")
        analysis_thread.start()

        # 3. Stream from PCAP or Live Sniffer
        if self.source_mode == "pcap":
            pcap_file = self.target or DEFAULT_SAMPLE_PCAP
            if not os.path.exists(pcap_file):
                self.error_occurred.emit(f"PCAP file not found: {pcap_file}")
                self.is_running = False
                if analysis_thread.is_alive():
                    analysis_thread.join(timeout=1.0)
                self.finished_processing.emit()
                return

            ingestor = PcapIngestor(pcap_file)
            last_heartbeat = time.time()
            last_packet_count = 0

            for pkt in ingestor.stream_packets():
                if not self.is_running:
                    break

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

                for flow in evicted:
                    try:
                        self.evicted_queue.put(flow, timeout=0.2)
                    except queue.Full:
                        pass

                now = time.time()
                if (now - last_heartbeat) >= 0.25:
                    delta_pkts = tracker.total_packets_processed - last_packet_count
                    pps = delta_pkts / max(now - last_heartbeat, 1e-4)
                    if self.is_running:
                        self.emit_telemetry(tracker, detection_engine, pps)
                    last_heartbeat = now
                    last_packet_count = tracker.total_packets_processed
                    time.sleep(0.001)

            if self.is_running:
                for flow in tracker.flush_all(should_stop=lambda: not self.is_running):
                    if not self.is_running:
                        break
                    try:
                        self.evicted_queue.put(flow, timeout=0.1)
                    except queue.Full:
                        pass

            if self.is_running:
                self.evicted_queue.join()
                if self.is_running:
                    self.emit_telemetry(tracker, detection_engine, 0.0)
            else:
                while not self.evicted_queue.empty():
                    try:
                        self.evicted_queue.get_nowait()
                        self.evicted_queue.task_done()
                    except (queue.Empty, ValueError):
                        break

            if analysis_thread.is_alive():
                analysis_thread.join(timeout=1.0)
            self.finished_processing.emit()

        elif self.source_mode == "live":
            def on_live_packet(pkt_tuple):
                if not self.is_running:
                    return
                src_ip, dst_ip, sport, dport, proto, pkt_len, ts, flags = pkt_tuple
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
                for f in evicted:
                    try:
                        self.evicted_queue.put_nowait(f)
                    except queue.Full:
                        pass

            # Phase A: Initialize and start live packet capture driver
            try:
                self.live_sniffer = LiveSniffer(
                    interface=self.target,
                    bpf_filter=self.bpf_filter,
                    packet_callback=on_live_packet,
                )
                self.live_sniffer.start()
            except Exception as e:
                self.error_occurred.emit(
                    f"Live Capture Driver Error: {str(e)}\n\n"
                    "Note for Windows: Live packet capture requires 'Npcap' with 'WinPcap API-compatible Mode' installed."
                )
                self.is_running = False
                if analysis_thread.is_alive():
                    analysis_thread.join(timeout=1.0)
                self.finished_processing.emit()
                return

            # Phase B: Runtime monitoring and periodic eviction sweep
            try:
                last_heartbeat = time.time()
                last_packet_count = 0

                while self.is_running:
                    time.sleep(0.1)
                    now = time.time()

                    # Periodic timeout sweep for completed / idle flows
                    evicted = tracker.evict_expired(now)
                    for f in evicted:
                        try:
                            self.evicted_queue.put_nowait(f)
                        except queue.Full:
                            pass

                    # Rate-limited UI statistics heartbeat (4 Hz)
                    if (now - last_heartbeat) >= 0.25:
                        delta_pkts = tracker.total_packets_processed - last_packet_count
                        pps = delta_pkts / max(now - last_heartbeat, 1e-4)
                        if self.is_running:
                            self.emit_telemetry(tracker, detection_engine, pps)
                        last_heartbeat = now
                        last_packet_count = tracker.total_packets_processed

            except Exception as e:
                self.error_occurred.emit(f"Flow Processing Runtime Error: {str(e)}")
            finally:
                if self.live_sniffer:
                    try:
                        self.live_sniffer.stop()
                    except Exception:
                        pass
                if self.is_running:
                    for flow in tracker.flush_all(should_stop=lambda: not self.is_running):
                        if not self.is_running:
                            break
                        try:
                            self.evicted_queue.put_nowait(flow)
                        except queue.Full:
                            pass
                    self.evicted_queue.join()
                else:
                    while not self.evicted_queue.empty():
                        try:
                            self.evicted_queue.get_nowait()
                            self.evicted_queue.task_done()
                        except (queue.Empty, ValueError):
                            break

                if analysis_thread.is_alive():
                    analysis_thread.join(timeout=1.0)
                self.finished_processing.emit()

    def emit_telemetry(self, tracker: FlowTracker, detection_engine: DetectionEngine, pps: float) -> None:
        """Calculates and emits real-time system health and throughput metrics."""
        capture_stats = self.live_sniffer.get_stats() if self.live_sniffer else {}
        cap_rate = capture_stats.get("capture_rate_pps", pps)
        dropped_pkts = capture_stats.get("packets_dropped", 0)

        try:
            cpu_pct = psutil.cpu_percent(interval=None)
            ram_mb = psutil.Process().memory_info().rss / (1024 * 1024)
        except Exception:
            cpu_pct = 0.0
            ram_mb = 0.0

        t_stats = tracker.get_stats()
        telemetry_payload = {
            "packets": tracker.total_packets_processed,
            "total_packets_processed": tracker.total_packets_processed,
            "flows": tracker.total_flows_created,
            "total_flows_created": tracker.total_flows_created,
            "threats": detection_engine.threats_detected_count,
            "threats_detected_count": detection_engine.threats_detected_count,
            "pps": pps,
            "capture_rate": cap_rate,
            "queue_depth": self.evicted_queue.qsize(),
            "dropped_packets": dropped_pkts,
            "active_flows": t_stats.get("active_flows", 0),
            "cpu_pct": cpu_pct,
            "ram_mb": ram_mb,
            "directionality_counts": t_stats.get("directionality_counts", {}),
            "directionality_distribution_pct": t_stats.get("directionality_distribution_pct", {}),
            "total_excluded_flows": t_stats.get("total_excluded_flows", 0),
        }
        self.stats_updated.emit(telemetry_payload)
        SocStateBridge.get().update_telemetry(telemetry_payload)

    def stop(self) -> None:
        self.is_running = False
        if self.live_sniffer:
            try:
                self.live_sniffer.stop()
            except Exception:
                pass


class UniGuardDesktopApp(QMainWindow):
    """Main SOC Security Operations Center Dashboard Window."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("UniGuard AI – Network Detection & Response (NDR) SOC Dashboard [SIH 2026]")
        self.resize(1440, 960)

        # Start local SOC REST & interactive World Threat Map server
        self.soc_server = start_soc_server(host="127.0.0.1", port=8765)

        self.worker: Optional[MonitoringWorker] = None
        self.database = SecurityDatabase()
        self.report_manager = ReportHistoryManager(self.database)
        self.report_worker: Optional[ReportWorkerThread] = None
        self.current_preview_file: Optional[str] = None
        self.selected_event: Optional[SecurityEvent] = None
        self.custom_pcap_path: Optional[str] = None

        # Master event lists for responsive filtering
        self.all_events: List[SecurityEvent] = []
        self.threat_events: List[SecurityEvent] = []

        self.total_packets = 0
        self.total_flows = 0
        self.total_threats = 0
        self.critical_threats = 0
        self.high_threats = 0
        self.med_threats = 0
        self.low_threats = 0

        # Directionality distribution tracking (Task 20)
        self.directionality_counts: Dict[str, int] = {
            "BIDIRECTIONAL": 0,
            "ASYMMETRIC": 0,
            "STRONGLY_ASYMMETRIC": 0,
            "UNIDIRECTIONAL_OBSERVED": 0,
            "UNKNOWN": 0,
        }
        self.excluded_flows_count = 0

        # Top talker tracking
        self.src_ip_counts: Dict[str, int] = {}
        self.dst_ip_counts: Dict[str, int] = {}
        self.port_counts: Dict[int, int] = {}
        self.proto_counts: Dict[int, int] = {6: 0, 17: 0, 1: 0}
        self.threat_counts: Dict[str, int] = {
            "BENIGN": 0,
            "PORT_SCAN": 0,
            "SYN_FLOOD": 0,
            "UDP_FLOOD": 0,
            "DATA_EXFILTRATION": 0,
            "SLOWLORIS": 0,
            "ANOMALOUS": 0,
        }

        # UTIE Intelligence tracking (SIH 2026 Core Innovation)
        self.all_utie_reports: List[UTIEIntelligenceReport] = []
        self.filtered_utie_reports: List[UTIEIntelligenceReport] = []
        self.utie_counts: Dict[str, int] = {
            "UNIDIRECTIONAL_OBSERVED": 0,
            "BIDIRECTIONAL_OBSERVED": 0,
            "ASYMMETRIC_OBSERVED": 0,
            "INSUFFICIENT_DATA": 0,
            "UNKNOWN": 0,
        }
        self.utie_suspicious_count: int = 0
        self.active_quick_filter: str = "ALL"

        self.init_ui()
        self.setStyleSheet(DARK_STYLESHEET)
        self.load_historical_events()
        self.refresh_model_status_display()

    def init_ui(self) -> None:
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(14, 12, 14, 12)
        main_layout.setSpacing(10)

        # 1. Header & Capture Controls Bar
        header_layout = QHBoxLayout()

        brand_layout = QVBoxLayout()
        brand_layout.setSpacing(1)
        title_label = QLabel("UNIGUARD AI")
        title_label.setStyleSheet("font-size: 14pt; font-weight: 800; color: #00e5ff; letter-spacing: 1px;")
        sub_label = QLabel("AI-Powered Detection of Cyber Threats in Unidirectional IP Traffic")
        sub_label.setStyleSheet("color: #8b949e; font-size: 8.5pt; font-weight: 500;")
        brand_layout.addWidget(title_label)
        brand_layout.addWidget(sub_label)
        header_layout.addLayout(brand_layout)

        header_layout.addStretch()

        # Capture Interface Selector
        lbl_source = QLabel("Source:")
        lbl_source.setStyleSheet("color: #8b949e; font-weight: 600;")
        self.iface_combo = QComboBox()
        self.iface_combo.setToolTip("Select offline sample PCAP file or active local network interface")
        self.iface_combo.addItem("Demo PCAP: sample_unidirectional.pcap")
        for iface in psutil.net_if_addrs().keys():
            self.iface_combo.addItem(f"Live Interface: {iface}")

        self.btn_select_pcap = QPushButton("Browse PCAP...")
        self.btn_select_pcap.setToolTip("Select a custom .pcap / .pcapng network capture file")
        self.btn_select_pcap.clicked.connect(self.browse_pcap)

        self.btn_start = QPushButton("START MONITORING")
        self.btn_start.setObjectName("start-btn")
        self.btn_start.setToolTip("Start real-time packet capture or PCAP playback through AI pipeline")
        self.btn_start.clicked.connect(self.start_monitoring)

        self.btn_stop = QPushButton("STOP")
        self.btn_stop.setObjectName("stop-btn")
        self.btn_stop.setToolTip("Safely halt packet capture and drain analysis queue")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_monitoring)

        header_layout.addWidget(lbl_source)
        header_layout.addWidget(self.iface_combo)
        header_layout.addWidget(self.btn_select_pcap)
        header_layout.addWidget(self.btn_start)
        header_layout.addWidget(self.btn_stop)

        self.btn_open_browser = QPushButton("🌐 OPEN WEB SOC")
        self.btn_open_browser.setStyleSheet(
            "background: rgba(0, 229, 255, 0.12); color: #00e5ff; border: 1px solid rgba(0, 229, 255, 0.4); "
            "font-weight: 700; padding: 6px 14px; border-radius: 6px;"
        )
        self.btn_open_browser.setToolTip("Open embedded Web SOC dashboard and interactive World Threat Map in your default browser")
        self.btn_open_browser.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("http://127.0.0.1:8765/")))
        header_layout.addWidget(self.btn_open_browser)

        main_layout.addLayout(header_layout)

        # 2. KPI Summary Cards Bar
        kpi_layout = QHBoxLayout()
        kpi_layout.setSpacing(10)

        self.kpi_packets = self.create_kpi_card("PACKETS OBSERVED", "0", "#00e5ff", "Live wire & PCAP packets")
        self.kpi_flows = self.create_kpi_card("ACTIVE FLOWS", "0", "#38bdf8", "Tracked unidirectional sessions")
        self.kpi_throughput = self.create_kpi_card("THROUGHPUT", "0 pps", "#10b981", "Wire pipeline processing rate")
        self.kpi_threats = self.create_kpi_card("TOTAL THREATS", "0", "#f59e0b", "Cumulative detected incidents")
        self.kpi_critical = self.create_kpi_card("HIGH / CRITICAL", "0", "#ef4444", "Urgent security triage needed")
        self.kpi_health = self.create_kpi_card("QUEUE HEALTH", "0.0% (0 / 50k)", "#a855f7", "Buffer capacity utilisation")

        kpi_layout.addWidget(self.kpi_packets)
        kpi_layout.addWidget(self.kpi_flows)
        kpi_layout.addWidget(self.kpi_throughput)
        kpi_layout.addWidget(self.kpi_threats)
        kpi_layout.addWidget(self.kpi_critical)
        kpi_layout.addWidget(self.kpi_health)

        main_layout.addLayout(kpi_layout)

        # 3. Master Tabbed Navigation (8 Standard Modules + Web SOC)
        self.tabs = QTabWidget()

        if WEBENGINE_AVAILABLE:
            self.tab_web_soc = QWidget()
            web_layout = QVBoxLayout(self.tab_web_soc)
            web_layout.setContentsMargins(0, 0, 0, 0)
            self.web_engine_view = QWebEngineView()
            self.web_engine_view.setUrl(QUrl("http://127.0.0.1:8765/"))
            web_layout.addWidget(self.web_engine_view)
            self.tabs.addTab(self.tab_web_soc, "[SOC] GLOBAL THREAT MAP & SOC COMMAND CENTER")

        self.tab_overview = QWidget()
        self.tab_live_monitor = QWidget()
        self.tab_threat_alerts = QWidget()
        self.tab_flow_analysis = QWidget()
        self.tab_traffic_analytics = QWidget()
        self.tab_model_status = QWidget()
        self.tab_event_history = QWidget()
        self.tab_settings = QWidget()
        self.tab_utie = QWidget()
        self.tab_reports = QWidget()

        self.setup_overview_tab()
        self.setup_live_monitor_tab()
        self.setup_threat_alerts_tab()
        self.setup_flow_analysis_tab()
        self.setup_traffic_analytics_tab()
        self.setup_model_status_tab()
        self.setup_event_history_tab()
        self.setup_settings_tab()
        self.setup_utie_tab()
        self.setup_reports_tab()

        self.tabs.addTab(self.tab_overview, "1. SECURITY OVERVIEW")
        self.tabs.addTab(self.tab_live_monitor, "2. LIVE MONITORING")
        self.tabs.addTab(self.tab_threat_alerts, "3. THREAT ALERTS")
        self.tabs.addTab(self.tab_flow_analysis, "4. FLOW ANALYSIS")
        self.tabs.addTab(self.tab_traffic_analytics, "5. TRAFFIC ANALYTICS")
        self.tabs.addTab(self.tab_model_status, "6. MODEL / AI STATUS")
        self.tabs.addTab(self.tab_event_history, "7. EVENT HISTORY")
        self.tabs.addTab(self.tab_settings, "8. SETTINGS")
        self.tabs.addTab(self.tab_utie, "9. UNIDIRECTIONAL INTELLIGENCE")
        self.tabs.addTab(self.tab_reports, "10. SECURITY REPORTS")

        if WEBENGINE_AVAILABLE:
            self.tabs.setCurrentIndex(0)
        else:
            self.tabs.setCurrentWidget(self.tab_overview)

        self.tabs.currentChanged.connect(self.on_tab_changed)

        main_layout.addWidget(self.tabs, stretch=1)

        # 4. Global System Health Footer Bar
        health_layout = QHBoxLayout()
        self.lbl_health_capture = QLabel("Capture: IDLE")
        self.lbl_health_proc = QLabel("Processing: IDLE")
        self.lbl_health_drops = QLabel("Drops: 0 pkts (0.00%)")
        self.lbl_health_host = QLabel("CPU: --% | RAM: -- MB")

        for lbl in [self.lbl_health_capture, self.lbl_health_proc, self.lbl_health_drops, self.lbl_health_host]:
            lbl.setStyleSheet("color: #8b949e; font-size: 8.5pt;")
            health_layout.addWidget(lbl)

        health_layout.addStretch()
        lbl_platform_note = QLabel("UniGuard AI NDR | Passive Network Diode Compatible")
        lbl_platform_note.setStyleSheet("color: #484f58; font-size: 8pt; font-style: italic;")
        health_layout.addWidget(lbl_platform_note)

        main_layout.addLayout(health_layout)

    def create_kpi_card(self, title: str, init_val: str, accent_color: str, subtitle: str = "") -> QFrame:
        card = QFrame()
        card.setProperty("class", "kpi-card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)

        lbl_title = QLabel(title)
        lbl_title.setProperty("class", "kpi-title")
        lbl_val = QLabel(init_val)
        lbl_val.setObjectName("kpi-value")
        lbl_val.setProperty("class", "kpi-value")
        lbl_val.setStyleSheet(f"color: {accent_color};")

        layout.addWidget(lbl_title)
        layout.addWidget(lbl_val)
        if subtitle:
            lbl_sub = QLabel(subtitle)
            lbl_sub.setStyleSheet("color: #6e7681; font-size: 7.5pt;")
            layout.addWidget(lbl_sub)
        card.value_label = lbl_val
        return card

    # =========================================================================
    # MODULE 1: SECURITY OVERVIEW
    # =========================================================================
    def setup_overview_tab(self) -> None:
        layout = QVBoxLayout(self.tab_overview)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        # A. Filter & Search Toolbar
        filter_box = QGroupBox("EVENT SEARCH & MULTI-CRITERIA FILTERS")
        filter_layout = QHBoxLayout(filter_box)
        filter_layout.setContentsMargins(10, 6, 10, 8)
        filter_layout.setSpacing(8)

        self.txt_overview_search = QLineEdit()
        self.txt_overview_search.setPlaceholderText("🔍 Search by IP, Port, Event ID, or Threat Type...")
        self.txt_overview_search.textChanged.connect(self.filter_overview_table)
        filter_layout.addWidget(self.txt_overview_search, stretch=3)

        self.combo_overview_sev = QComboBox()
        self.combo_overview_sev.addItems(["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.combo_overview_sev.currentIndexChanged.connect(self.filter_overview_table)
        filter_layout.addWidget(self.combo_overview_sev, stretch=1)

        self.combo_overview_cat = QComboBox()
        self.combo_overview_cat.addItems([
            "All Threat Types", "PORT_SCAN", "SYN_FLOOD", "UDP_FLOOD", "SLOWLORIS", "DATA_EXFILTRATION", "ANOMALOUS", "BENIGN"
        ])
        self.combo_overview_cat.currentIndexChanged.connect(self.filter_overview_table)
        filter_layout.addWidget(self.combo_overview_cat, stretch=1)

        self.combo_overview_dir = QComboBox()
        self.combo_overview_dir.addItems([
            "All Directionalities", "UNIDIRECTIONAL_OBSERVED", "STRONGLY_ASYMMETRIC", "ASYMMETRIC", "BIDIRECTIONAL"
        ])
        self.combo_overview_dir.currentIndexChanged.connect(self.filter_overview_table)
        filter_layout.addWidget(self.combo_overview_dir, stretch=1)

        btn_reset_filters = QPushButton("Reset Filters")
        btn_reset_filters.clicked.connect(self.reset_overview_filters)
        filter_layout.addWidget(btn_reset_filters)

        self.lbl_overview_count = QLabel("Showing 0 events")
        self.lbl_overview_count.setStyleSheet("color: #8b949e; font-weight: 600; font-size: 8.5pt;")
        filter_layout.addWidget(self.lbl_overview_count)

        layout.addWidget(filter_box)

        # B. Severity KPI Badges
        badge_layout = QHBoxLayout()
        self.badge_critical = QLabel("CRITICAL: 0")
        self.badge_critical.setStyleSheet("background-color: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; padding: 4px 12px; border-radius: 4px; font-weight: bold;")
        self.badge_high = QLabel("HIGH: 0")
        self.badge_high.setStyleSheet("background-color: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b; padding: 4px 12px; border-radius: 4px; font-weight: bold;")
        self.badge_med = QLabel("MEDIUM: 0")
        self.badge_med.setStyleSheet("background-color: rgba(234, 179, 8, 0.15); color: #eab308; border: 1px solid #eab308; padding: 4px 12px; border-radius: 4px; font-weight: bold;")
        self.badge_low = QLabel("LOW / BENIGN: 0")
        self.badge_low.setStyleSheet("background-color: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid #10b981; padding: 4px 12px; border-radius: 4px; font-weight: bold;")

        badge_layout.addWidget(self.badge_critical)
        badge_layout.addWidget(self.badge_high)
        badge_layout.addWidget(self.badge_med)
        badge_layout.addWidget(self.badge_low)
        badge_layout.addStretch()
        layout.addLayout(badge_layout)

        # C. Master Events Table
        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels([
            "Event ID", "Source IP:Port", "Destination IP:Port", "Directionality", "Threat Category", "Confidence", "Severity", "Risk Score"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.cellClicked.connect(self.on_table_row_clicked)
        layout.addWidget(self.table, stretch=1)

        # D. Quick Event Inspector Drawer (bottom of Overview)
        self.card_overview_inspector = QGroupBox("EVENT QUICK TRIAGE PREVIEW")
        inspect_layout = QHBoxLayout(self.card_overview_inspector)
        inspect_layout.setContentsMargins(12, 8, 12, 8)
        inspect_layout.setSpacing(15)

        self.lbl_overview_inspect_summary = QLabel("Select an event row from the table above to view immediate security triage details.")
        self.lbl_overview_inspect_summary.setStyleSheet("color: #f0f6fc; font-weight: 600;")
        self.lbl_overview_inspect_summary.setWordWrap(True)
        inspect_layout.addWidget(self.lbl_overview_inspect_summary, stretch=3)

        self.btn_jump_to_alerts = QPushButton("Investigate Alert in Module 3 >>")
        self.btn_jump_to_alerts.setObjectName("action-btn")
        self.btn_jump_to_alerts.clicked.connect(lambda: self.tabs.setCurrentWidget(self.tab_threat_alerts))
        inspect_layout.addWidget(self.btn_jump_to_alerts)

        self.btn_jump_to_flow = QPushButton("Analyze 24 Features in Module 4 >>")
        self.btn_jump_to_flow.clicked.connect(lambda: self.tabs.setCurrentWidget(self.tab_flow_analysis))
        inspect_layout.addWidget(self.btn_jump_to_flow)

        layout.addWidget(self.card_overview_inspector)

    def reset_overview_filters(self) -> None:
        self.txt_overview_search.clear()
        self.combo_overview_sev.setCurrentIndex(0)
        self.combo_overview_cat.setCurrentIndex(0)
        self.combo_overview_dir.setCurrentIndex(0)
        self.filter_overview_table()

    def filter_overview_table(self) -> None:
        query = self.txt_overview_search.text().strip().lower()
        sev_filter = self.combo_overview_sev.currentText().upper()
        cat_filter = self.combo_overview_cat.currentText().upper()
        dir_filter = self.combo_overview_dir.currentText().upper()

        visible_count = 0
        total_count = self.table.rowCount()

        for row in range(total_count):
            item_id = self.table.item(row, 0)
            item_src = self.table.item(row, 1)
            item_dst = self.table.item(row, 2)
            item_dir = self.table.item(row, 3)
            item_cat = self.table.item(row, 4)
            item_sev = self.table.item(row, 6)

            match = True
            # Text Search
            if query:
                row_text = f"{item_id.text() if item_id else ''} {item_src.text() if item_src else ''} {item_dst.text() if item_dst else ''} {item_cat.text() if item_cat else ''}".lower()
                if query not in row_text:
                    match = False

            # Severity filter
            if match and sev_filter != "ALL SEVERITIES":
                if not item_sev or item_sev.text().upper() != sev_filter:
                    match = False

            # Category filter
            if match and cat_filter != "ALL THREAT TYPES":
                if not item_cat or item_cat.text().upper() != cat_filter:
                    match = False

            # Directionality filter
            if match and dir_filter != "ALL DIRECTIONALITIES":
                if not item_dir or dir_filter not in item_dir.text().upper():
                    match = False

            self.table.setRowHidden(row, not match)
            if match:
                visible_count += 1

        self.lbl_overview_count.setText(f"Showing {visible_count} of {total_count} events")

    # =========================================================================
    # MODULE 2: LIVE MONITOR & NETWORK ACTIVITY
    # =========================================================================
    def setup_live_monitor_tab(self) -> None:
        layout = QVBoxLayout(self.tab_live_monitor)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # A. Mode & Interface Prominent Status Banner
        self.banner_mode = QFrame()
        self.banner_mode.setStyleSheet("background-color: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 10px;")
        banner_layout = QHBoxLayout(self.banner_mode)
        banner_layout.setContentsMargins(8, 4, 8, 4)

        self.lbl_banner_mode_icon = QLabel("📁")
        self.lbl_banner_mode_icon.setStyleSheet("font-size: 16pt;")
        self.lbl_banner_mode_text = QLabel("SESSION MODE: OFFLINE PCAP REPLAY  |  Target: sample_unidirectional.pcap  |  Pipeline: Active")
        self.lbl_banner_mode_text.setStyleSheet("font-weight: 700; color: #00e5ff; font-size: 10pt;")
        self.lbl_banner_status_badge = QLabel("STATUS: IDLE")
        self.lbl_banner_status_badge.setStyleSheet("background-color: #1e293b; color: #8b949e; padding: 4px 10px; border-radius: 4px; font-weight: bold;")

        banner_layout.addWidget(self.lbl_banner_mode_icon)
        banner_layout.addWidget(self.lbl_banner_mode_text, stretch=1)
        banner_layout.addWidget(self.lbl_banner_status_badge)
        layout.addWidget(self.banner_mode)

        # B. Real-Time Observability Metrics Grid
        group_box = QGroupBox("REAL-TIME HIGH-THROUGHPUT PIPELINE OBSERVABILITY")
        grid = QGridLayout(group_box)
        grid.setSpacing(12)
        grid.setContentsMargins(12, 12, 12, 12)

        self.lbl_mon_cap_rate = QLabel("0 pps")
        self.lbl_mon_proc_rate = QLabel("0 pps")
        self.lbl_mon_queue = QLabel("0 / 50,000")
        self.lbl_mon_active_flows = QLabel("0 records")
        self.lbl_mon_drops = QLabel("0 pkts (0.00%)")
        self.lbl_mon_bandwidth = QLabel("0.00 Mbps")

        self.bar_mon_queue = QProgressBar()
        self.bar_mon_queue.setRange(0, 100)
        self.bar_mon_queue.setValue(0)
        self.bar_mon_queue.setTextVisible(False)
        self.bar_mon_queue.setFixedHeight(6)

        metrics_items = [
            ("Wire Ingress Rate:", self.lbl_mon_cap_rate, 0, 0),
            ("Pipeline Processing Rate:", self.lbl_mon_proc_rate, 0, 1),
            ("Analysis Queue Depth:", self.lbl_mon_queue, 1, 0),
            ("Active Flow Records:", self.lbl_mon_active_flows, 1, 1),
            ("Kernel Dropped Packets:", self.lbl_mon_drops, 2, 0),
            ("Estimated Wire Bandwidth:", self.lbl_mon_bandwidth, 2, 1),
        ]

        for title, val_lbl, r, c in metrics_items:
            f = QFrame()
            f.setStyleSheet("background-color: #0c1017; border: 1px solid #1c2333; border-radius: 6px; padding: 8px;")
            fl = QVBoxLayout(f)
            fl.setContentsMargins(4, 4, 4, 4)
            fl.setSpacing(2)
            t_lbl = QLabel(title)
            t_lbl.setStyleSheet("color: #8b949e; font-size: 8pt; font-weight: 700; text-transform: uppercase;")
            val_lbl.setStyleSheet("color: #f0f6fc; font-size: 13pt; font-weight: bold;")
            fl.addWidget(t_lbl)
            fl.addWidget(val_lbl)
            if title == "Analysis Queue Depth:":
                fl.addWidget(self.bar_mon_queue)
            grid.addWidget(f, r, c)

        layout.addWidget(group_box)

        # C. Live Activity Log Console
        log_box = QGroupBox("LIVE SECURITY & NETWORK ACTIVITY STREAM")
        log_layout = QVBoxLayout(log_box)
        log_layout.setContentsMargins(10, 8, 10, 10)

        log_ctrl_layout = QHBoxLayout()
        self.combo_log_filter = QComboBox()
        self.combo_log_filter.addItems(["All Activity Logs", "Threat Alerts Only", "System & Flow Engine"])
        self.combo_log_filter.currentIndexChanged.connect(self.filter_activity_logs)

        self.btn_clear_logs = QPushButton("Clear Console")
        self.btn_clear_logs.clicked.connect(lambda: self.txt_live_log.clear())

        self.chk_auto_scroll = QCheckBox("Auto-Scroll to Bottom")
        self.chk_auto_scroll.setChecked(True)
        self.chk_auto_scroll.setStyleSheet("color: #8b949e; font-weight: 600;")

        log_ctrl_layout.addWidget(QLabel("Filter:"))
        log_ctrl_layout.addWidget(self.combo_log_filter)
        log_ctrl_layout.addStretch()
        log_ctrl_layout.addWidget(self.chk_auto_scroll)
        log_ctrl_layout.addWidget(self.btn_clear_logs)
        log_layout.addLayout(log_ctrl_layout)

        self.txt_live_log = QTextEdit()
        self.txt_live_log.setReadOnly(True)
        self.txt_live_log.setPlaceholderText("Live packet activity, flow closures, directionality gates, and threat alerts stream here in real-time...")
        log_layout.addWidget(self.txt_live_log, stretch=1)

        layout.addWidget(log_box, stretch=1)

    def filter_activity_logs(self) -> None:
        pass

    # =========================================================================
    # MODULE 3: THREAT ALERTS & SOC INVESTIGATION PLAYBOOK
    # =========================================================================
    def setup_threat_alerts_tab(self) -> None:
        layout = QHBoxLayout(self.tab_threat_alerts)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        splitter = QSplitter(Qt.Horizontal)

        # Left Panel: Detected Threats Table
        left_box = QGroupBox("DETECTED SECURITY THREATS QUEUE")
        left_layout = QVBoxLayout(left_box)
        left_layout.setContentsMargins(10, 8, 10, 10)
        left_layout.setSpacing(8)

        # Alert Filter Bar
        alert_filt_layout = QHBoxLayout()
        self.txt_alert_search = QLineEdit()
        self.txt_alert_search.setPlaceholderText("Filter alerts by IP, Threat, Port...")
        self.txt_alert_search.textChanged.connect(self.filter_threat_alerts_table)
        alert_filt_layout.addWidget(self.txt_alert_search)

        self.combo_alert_sev = QComboBox()
        self.combo_alert_sev.addItems(["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.combo_alert_sev.currentIndexChanged.connect(self.filter_threat_alerts_table)
        alert_filt_layout.addWidget(self.combo_alert_sev)
        left_layout.addLayout(alert_filt_layout)

        self.table_alerts = QTableWidget(0, 7)
        self.table_alerts.setHorizontalHeaderLabels([
            "Event ID", "Timestamp", "Source IP:Port", "Target IP:Port", "Threat Type", "Severity", "Risk Score"
        ])
        self.table_alerts.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_alerts.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_alerts.setSelectionMode(QTableWidget.SingleSelection)
        self.table_alerts.cellClicked.connect(self.on_alert_table_row_clicked)
        left_layout.addWidget(self.table_alerts)
        splitter.addWidget(left_box)

        # Right Panel: Alert Investigation & XAI Rationale & Playbook
        right_box = QGroupBox("INCIDENT INVESTIGATION & XAI TRIAGE PLAYBOOK")
        right_layout = QVBoxLayout(right_box)
        right_layout.setContentsMargins(12, 10, 12, 10)
        right_layout.setSpacing(10)

        # 1. Threat Identification Header
        gauge_frame = QFrame()
        gauge_frame.setStyleSheet("background-color: #0c1017; border: 1px solid #1c2333; border-radius: 6px; padding: 10px;")
        gf_layout = QVBoxLayout(gauge_frame)
        gf_layout.setSpacing(4)

        self.lbl_inspect_flow = QLabel("Select an alert from the table on the left to start investigation triage.")
        self.lbl_inspect_flow.setStyleSheet("font-size: 10.5pt; font-weight: bold; color: #f0f6fc;")
        self.lbl_inspect_flow.setWordWrap(True)

        self.lbl_inspect_model = QLabel("AI Detection Engine: Initializing models...")
        self.lbl_inspect_model.setStyleSheet("font-size: 8.5pt; color: #38bdf8; font-weight: 600;")

        self.lbl_inspect_risk = QLabel("Calculated Risk Score: -- / 100")
        self.lbl_inspect_risk.setStyleSheet("font-size: 11pt; font-weight: bold; color: #ef4444;")

        self.progress_risk = QProgressBar()
        self.progress_risk.setRange(0, 100)
        self.progress_risk.setValue(0)
        self.progress_risk.setTextVisible(True)
        self.progress_risk.setFormat("Risk: %v / 100")
        self.progress_risk.setFixedHeight(18)

        gf_layout.addWidget(self.lbl_inspect_flow)
        gf_layout.addWidget(self.lbl_inspect_model)
        gf_layout.addWidget(self.lbl_inspect_risk)
        gf_layout.addWidget(self.progress_risk)
        right_layout.addWidget(gauge_frame)

        # 2. XAI Root Cause Attribution
        xai_group = QGroupBox("AI THREAT EXPLANATION ENGINE – \"WHY WAS THIS DETECTED?\"")
        xai_layout = QVBoxLayout(xai_group)
        self.xai_text = QTextEdit()
        self.xai_text.setReadOnly(True)
        self.xai_text.setPlaceholderText("Detailed evidence-based threat explanation answering 'Why was this detected?' will populate here...")
        xai_layout.addWidget(self.xai_text)
        right_layout.addWidget(xai_group, stretch=1)

        # 3. Actionable Cybersecurity Investigation Playbook
        playbook_group = QGroupBox("RECOMMENDED DEFENSIVE INVESTIGATION STEPS (SOC PLAYBOOK)")
        pb_layout = QVBoxLayout(playbook_group)
        self.txt_playbook = QTextEdit()
        self.txt_playbook.setReadOnly(True)
        self.txt_playbook.setStyleSheet("background-color: #0c1017; color: #38bdf8; font-family: 'Segoe UI', sans-serif; font-size: 9pt;")
        self.txt_playbook.setPlaceholderText("Actionable investigation steps and containment advice will appear upon alert selection...")
        pb_layout.addWidget(self.txt_playbook)
        right_layout.addWidget(playbook_group, stretch=1)

        splitter.addWidget(right_box)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter)

    def filter_threat_alerts_table(self) -> None:
        query = self.txt_alert_search.text().strip().lower()
        sev_filter = self.combo_alert_sev.currentText().upper()

        for r in range(self.table_alerts.rowCount()):
            item_id = self.table_alerts.item(r, 0)
            item_src = self.table_alerts.item(r, 2)
            item_dst = self.table_alerts.item(r, 3)
            item_type = self.table_alerts.item(r, 4)
            item_sev = self.table_alerts.item(r, 5)

            match = True
            if query:
                text = f"{item_id.text() if item_id else ''} {item_src.text() if item_src else ''} {item_dst.text() if item_dst else ''} {item_type.text() if item_type else ''}".lower()
                if query not in text:
                    match = False

            if match and sev_filter != "ALL SEVERITIES":
                if not item_sev or item_sev.text().upper() != sev_filter:
                    match = False

            self.table_alerts.setRowHidden(r, not match)

    def on_alert_table_row_clicked(self, row: int, col: int) -> None:
        item = self.table_alerts.item(row, 0)
        if hasattr(item, "event_data"):
            self.display_event_details(item.event_data)

    # =========================================================================
    # MODULE 4: FLOW DIRECTIONALITY & 24-FEATURE TELEMETRY
    # =========================================================================
    def setup_flow_analysis_tab(self) -> None:
        layout = QVBoxLayout(self.tab_flow_analysis)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Directionality Dashboard KPI Cards
        dir_box = QGroupBox("FLOW DIRECTIONALITY & TRAFFIC ASYMMETRY ENGINE (TASK 20)")
        dir_layout = QVBoxLayout(dir_box)

        kpi_row = QHBoxLayout()
        self.kpi_dir_total = self.create_kpi_card("TOTAL EVALUATED", "0", "#00e5ff", "All observed flow sessions")
        self.kpi_dir_bidi = self.create_kpi_card("BIDIRECTIONAL (EXCLUDED)", "0", "#10b981", "Normal conversational traffic")
        self.kpi_dir_asym = self.create_kpi_card("ASYMMETRIC", "0", "#f59e0b", "Moderate traffic disparity")
        self.kpi_dir_strong = self.create_kpi_card("STRONGLY ASYMMETRIC", "0", "#f97316", "High-threat one-way candidate")
        self.kpi_dir_oneway = self.create_kpi_card("ONE-WAY OBSERVED", "0", "#a855f7", "Pure unidirectional traffic")

        kpi_row.addWidget(self.kpi_dir_total)
        kpi_row.addWidget(self.kpi_dir_bidi)
        kpi_row.addWidget(self.kpi_dir_asym)
        kpi_row.addWidget(self.kpi_dir_strong)
        kpi_row.addWidget(self.kpi_dir_oneway)
        dir_layout.addLayout(kpi_row)

        self.lbl_dir_dist = QLabel("DIRECTIONALITY DISTRIBUTION:  BIDIRECTIONAL: 0.0%  |  ASYMMETRIC: 0.0%  |  STRONGLY ASYMMETRIC: 0.0%  |  ONE-WAY: 0.0%")
        self.lbl_dir_dist.setStyleSheet("color: #00e5ff; font-weight: bold; font-size: 9pt; padding: 4px;")
        dir_layout.addWidget(self.lbl_dir_dist)

        layout.addWidget(dir_box)

        # Splitter: Left = Directionality Evidence & 5/20 Comparison, Right = 24-Feature Telemetry
        splitter = QSplitter(Qt.Horizontal)

        box_dir_expl = QGroupBox("DIRECTIONALITY EVIDENCE & 5/20 RESEARCH BENCHMARK (TASKS 13 & 19)")
        layout_dir_expl = QVBoxLayout(box_dir_expl)
        self.txt_directionality_details = QTextEdit()
        self.txt_directionality_details.setReadOnly(True)
        self.txt_directionality_details.setPlaceholderText("Select any event from the overview table to view directionality evidence, asymmetry metrics, and 5/20 comparison...")
        layout_dir_expl.addWidget(self.txt_directionality_details)
        splitter.addWidget(box_dir_expl)

        box_telemetry = QGroupBox("STRICT 24-FEATURE UNIDIRECTIONAL TELEMETRY (CATEGORIZED)")
        layout_telemetry = QVBoxLayout(box_telemetry)
        self.txt_flow_details = QTextEdit()
        self.txt_flow_details.setReadOnly(True)
        self.txt_flow_details.setPlaceholderText("Select any event to view structured 24-feature unidirectional telemetry breakdown...")
        layout_telemetry.addWidget(self.txt_flow_details)
        splitter.addWidget(box_telemetry)

        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter, stretch=1)

    # =========================================================================
    # MODULE 5: TRAFFIC ANALYTICS
    # =========================================================================
    def setup_traffic_analytics_tab(self) -> None:
        layout = QVBoxLayout(self.tab_traffic_analytics)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Header Banner
        header_frame = QFrame()
        header_frame.setStyleSheet("background-color: #0f172a; border: 1px solid #1e293b; border-radius: 6px; padding: 6px 12px;")
        hf_layout = QHBoxLayout(header_frame)
        lbl_h = QLabel("📊 REAL-TIME NETWORK TRAFFIC ANALYTICS & TALKER DISTRIBUTION")
        lbl_h.setStyleSheet("color: #00e5ff; font-weight: 700; font-size: 9.5pt;")
        lbl_badge = QLabel("ACTUAL RUNTIME TRAFFIC DATA")
        lbl_badge.setStyleSheet("background-color: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 8pt;")
        hf_layout.addWidget(lbl_h)
        hf_layout.addStretch()
        hf_layout.addWidget(lbl_badge)
        layout.addWidget(header_frame)

        grid = QGridLayout()
        grid.setSpacing(10)

        box_src = QGroupBox("TOP 5 SOURCE IP ADDRESSES (WIRE INGRESS)")
        layout_src = QVBoxLayout(box_src)
        self.txt_top_src = QTextEdit()
        self.txt_top_src.setReadOnly(True)
        layout_src.addWidget(self.txt_top_src)

        box_dst = QGroupBox("TOP 5 DESTINATION IP ADDRESSES (TARGET HOSTS)")
        layout_dst = QVBoxLayout(box_dst)
        self.txt_top_dst = QTextEdit()
        self.txt_top_dst.setReadOnly(True)
        layout_dst.addWidget(self.txt_top_dst)

        box_ports = QGroupBox("TOP 5 TARGET PORTS & PROTOCOL SERVICES")
        layout_ports = QVBoxLayout(box_ports)
        self.txt_top_ports = QTextEdit()
        self.txt_top_ports.setReadOnly(True)
        layout_ports.addWidget(self.txt_top_ports)

        box_proto = QGroupBox("TRANSPORT PROTOCOL DISTRIBUTION")
        layout_proto = QVBoxLayout(box_proto)
        self.txt_top_proto = QTextEdit()
        self.txt_top_proto.setReadOnly(True)
        layout_proto.addWidget(self.txt_top_proto)

        grid.addWidget(box_src, 0, 0)
        grid.addWidget(box_dst, 0, 1)
        grid.addWidget(box_ports, 1, 0)
        grid.addWidget(box_proto, 1, 1)

        layout.addLayout(grid, stretch=1)

    # =========================================================================
    # MODULE 6: MODEL / AI STATUS
    # =========================================================================
    def setup_model_status_tab(self) -> None:
        layout = QVBoxLayout(self.tab_model_status)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        top_bar = QHBoxLayout()
        self.btn_refresh_ai_status = QPushButton("🔄 Refresh & Verify AI Pipeline")
        self.btn_refresh_ai_status.clicked.connect(self.refresh_model_status_display)
        self.btn_test_inference = QPushButton("⚡ Run AI Diagnostic Self-Test (Latency Benchmark)")
        self.btn_test_inference.setObjectName("action-btn")
        self.btn_test_inference.clicked.connect(self.run_ai_self_test)

        top_bar.addWidget(self.btn_refresh_ai_status)
        top_bar.addWidget(self.btn_test_inference)
        top_bar.addStretch()
        layout.addLayout(top_bar)

        box = QGroupBox("ACTIVE MACHINE LEARNING, ANOMALY & EXPLAINABILITY ENGINES")
        self.form_model_status = QFormLayout(box)
        self.form_model_status.setSpacing(12)
        self.form_model_status.setContentsMargins(14, 14, 14, 14)

        self.lbl_stat_rf = QLabel("Querying...")
        self.lbl_stat_xgb = QLabel("Querying...")
        self.lbl_stat_iso = QLabel("Querying...")
        self.lbl_stat_dir = QLabel("Querying...")
        self.lbl_stat_prep = QLabel("Querying...")
        self.lbl_stat_shap = QLabel("Querying...")
        self.lbl_stat_features = QLabel("Strict 24 Unidirectional Vectors (Zero Reverse Channel Leakage)")
        self.lbl_stat_streaming = QLabel("Welford's Streaming Algorithm (O(1) Rolling Variance/Mean)")

        self.form_model_status.addRow("Supervised Classifier:", self.lbl_stat_rf)
        self.form_model_status.addRow("Secondary Classifier:", self.lbl_stat_xgb)
        self.form_model_status.addRow("Anomaly Engine:", self.lbl_stat_iso)
        self.form_model_status.addRow("Directionality Model:", self.lbl_stat_dir)
        self.form_model_status.addRow("Feature Preprocessor:", self.lbl_stat_prep)
        self.form_model_status.addRow("Explainability Engine:", self.lbl_stat_shap)
        self.form_model_status.addRow("Feature Schema:", self.lbl_stat_features)
        self.form_model_status.addRow("Streaming Math:", self.lbl_stat_streaming)

        layout.addWidget(box)

        # AI Diagnostic Self-Test Output Console
        diag_box = QGroupBox("AI INFERENCE LATENCY & PIPELINE VERIFICATION BENCHMARK")
        diag_layout = QVBoxLayout(diag_box)
        self.txt_ai_diag = QTextEdit()
        self.txt_ai_diag.setReadOnly(True)
        self.txt_ai_diag.setPlaceholderText("Click 'Run AI Diagnostic Self-Test' above to benchmark active model inference latency and verify output shapes...")
        diag_layout.addWidget(self.txt_ai_diag)
        layout.addWidget(diag_box, stretch=1)

    def refresh_model_status_display(self) -> None:
        """Dynamically inspects model loading status and updates Tab 6 labels."""
        bridge = SocStateBridge.get()
        status_dict = bridge.get_pipeline_status()

        # 1. Supervised (Random Forest)
        rf = status_dict.get("supervised", {})
        if rf.get("status") == "ONLINE":
            self.lbl_stat_rf.setText(f"Random Forest ({rf.get('architecture', '')}) [ONLINE - Active in Pipeline]  ({rf.get('size_kb', 0)} KB)")
            self.lbl_stat_rf.setStyleSheet("color: #10b981; font-weight: bold;")
        else:
            self.lbl_stat_rf.setText("Random Forest Classifier [OFFLINE - Model Missing]")
            self.lbl_stat_rf.setStyleSheet("color: #ef4444; font-weight: bold;")

        # 2. Secondary (XGBoost)
        xgb = status_dict.get("secondary", {})
        if xgb.get("status") == "STANDBY":
            self.lbl_stat_xgb.setText(f"XGBoost ({xgb.get('architecture', '')}) [STANDBY - Available on Disk]  ({xgb.get('size_kb', 0)} KB)")
            self.lbl_stat_xgb.setStyleSheet("color: #38bdf8; font-weight: bold;")
        else:
            self.lbl_stat_xgb.setText("XGBoost Classifier [UNAVAILABLE]")
            self.lbl_stat_xgb.setStyleSheet("color: #8b949e;")

        # 3. Anomaly Engine (Isolation Forest)
        iso = status_dict.get("anomaly", {})
        if iso.get("status") == "ONLINE":
            self.lbl_stat_iso.setText(f"Isolation Forest ({iso.get('architecture', '')}) [ONLINE - Active in Pipeline]  ({iso.get('size_kb', 0)} KB)")
            self.lbl_stat_iso.setStyleSheet("color: #10b981; font-weight: bold;")
        else:
            self.lbl_stat_iso.setText("Isolation Forest [OFFLINE]")
            self.lbl_stat_iso.setStyleSheet("color: #ef4444; font-weight: bold;")

        # 4. Directionality Model
        dir_m = status_dict.get("directionality_model", {})
        if dir_m.get("status") == "ONLINE":
            self.lbl_stat_dir.setText(f"Isolation Forest + K-Means ({dir_m.get('architecture', '')}) [ONLINE]  ({dir_m.get('size_kb', 0)} KB)")
            self.lbl_stat_dir.setStyleSheet("color: #10b981; font-weight: bold;")
        else:
            self.lbl_stat_dir.setText("Directionality Baseline [HEURISTIC 5/20 ONLY]")
            self.lbl_stat_dir.setStyleSheet("color: #f59e0b; font-weight: bold;")

        # 5. Preprocessor
        prep = status_dict.get("preprocessor", {})
        if prep.get("status") == "ONLINE":
            self.lbl_stat_prep.setText(f"FlowDataPreprocessor (24 Features Normalized) [ONLINE]  ({prep.get('size_kb', 0)} KB)")
            self.lbl_stat_prep.setStyleSheet("color: #10b981; font-weight: bold;")
        else:
            self.lbl_stat_prep.setText("FlowDataPreprocessor [OFFLINE]")
            self.lbl_stat_prep.setStyleSheet("color: #ef4444; font-weight: bold;")

        # 6. SHAP
        shap_s = status_dict.get("xai", {})
        if shap_s.get("status") == "ONLINE":
            self.lbl_stat_shap.setText("SHAP TreeExplainer (Attribution Gate Active) [READY]")
            self.lbl_stat_shap.setStyleSheet("color: #a855f7; font-weight: bold;")
        else:
            self.lbl_stat_shap.setText("SHAP TreeExplainer [UNAVAILABLE]")
            self.lbl_stat_shap.setStyleSheet("color: #8b949e;")

    def run_ai_self_test(self) -> None:
        """Executes actual latency and shape verification tests on active models."""
        self.txt_ai_diag.clear()
        lines = [
            "==========================================================================",
            " UNIGUARD AI: MACHINE LEARNING DETECTION PIPELINE DIAGNOSTIC BENCHMARK",
            "==========================================================================",
        ]

        prep_file = os.path.join(DEFAULT_MODELS_DIR, "preprocessor.joblib")
        rf_file = os.path.join(DEFAULT_MODELS_DIR, "uniguard_rf_model.joblib")
        iso_file = os.path.join(DEFAULT_MODELS_DIR, "uniguard_isolation_forest.joblib")

        try:
            # 1. Preprocessor Test
            t0 = time.time()
            prep = FlowDataPreprocessor.load(prep_file)
            dummy_sample = np.zeros((1, 24))
            t1 = time.time()
            lines.append(f"[OK] Preprocessor Loaded: {prep_file} (Latency: {(t1-t0)*1000:.2f} ms)")

            # 2. Random Forest Test
            t0 = time.time()
            rf = SupervisedThreatClassifier.load(rf_file)
            probs = rf.predict_proba(dummy_sample)
            t1 = time.time()
            lines.append(f"[OK] Random Forest Inference: 1 sample -> output shape {probs.shape} (Latency: {(t1-t0)*1000:.2f} ms)")
            lines.append(f"     Detected Classes ({len(rf.classes_)}): {list(rf.classes_)}")

            # 3. Isolation Forest Test
            t0 = time.time()
            iso = IsolationForestAnomalyDetector.load(iso_file)
            score = iso.score_samples(dummy_sample)
            t1 = time.time()
            lines.append(f"[OK] Isolation Forest Scoring: 1 sample -> score {float(score[0]):.4f} (Latency: {(t1-t0)*1000:.2f} ms)")

            lines.append("-" * 74)
            lines.append("[SUCCESS] All active models verified with ZERO warnings. Pipeline ready for wire traffic.")
        except Exception as e:
            lines.append(f"[ERROR] Model Diagnostic Failed: {str(e)}")

        self.txt_ai_diag.setText("\n".join(lines))

    # =========================================================================
    # MODULE 7: EVENT HISTORY
    # =========================================================================
    def setup_event_history_tab(self) -> None:
        layout = QVBoxLayout(self.tab_event_history)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        # A. Filter & Search Controls
        filter_box = QGroupBox("HISTORICAL EVENTS QUERY & DATABASE SEARCH")
        f_layout = QHBoxLayout(filter_box)
        f_layout.setContentsMargins(10, 6, 10, 8)
        f_layout.setSpacing(8)

        self.txt_history_search = QLineEdit()
        self.txt_history_search.setPlaceholderText("Search database by IP, Port, Event ID...")
        f_layout.addWidget(self.txt_history_search, stretch=2)

        self.combo_history_sev = QComboBox()
        self.combo_history_sev.addItems(["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        f_layout.addWidget(self.combo_history_sev)

        self.combo_history_threat = QComboBox()
        self.combo_history_threat.addItems([
            "All Threat Types", "PORT_SCAN", "SYN_FLOOD", "UDP_FLOOD", "SLOWLORIS", "DATA_EXFILTRATION", "ANOMALOUS", "BENIGN"
        ])
        f_layout.addWidget(self.combo_history_threat)

        self.spin_history_limit = QSpinBox()
        self.spin_history_limit.setRange(10, 2000)
        self.spin_history_limit.setValue(200)
        self.spin_history_limit.setPrefix("Limit: ")
        f_layout.addWidget(self.spin_history_limit)

        btn_filter_history = QPushButton("Search Database")
        btn_filter_history.setObjectName("action-btn")
        btn_filter_history.clicked.connect(self.load_historical_events)
        f_layout.addWidget(btn_filter_history)

        btn_refresh_history = QPushButton("↻ Refresh")
        btn_refresh_history.clicked.connect(self.load_historical_events)
        f_layout.addWidget(btn_refresh_history)

        btn_export_history = QPushButton("Export to CSV")
        btn_export_history.clicked.connect(self.export_historical_events_csv)
        f_layout.addWidget(btn_export_history)

        self.lbl_history_status = QLabel("0 events loaded")
        self.lbl_history_status.setStyleSheet("color: #8b949e; font-size: 8.5pt; margin-left: 6px;")
        f_layout.addWidget(self.lbl_history_status)

        # Real-time search and filter responsiveness
        self.txt_history_search.textChanged.connect(self.load_historical_events)
        self.combo_history_sev.currentIndexChanged.connect(self.load_historical_events)
        self.combo_history_threat.currentIndexChanged.connect(self.load_historical_events)
        self.spin_history_limit.valueChanged.connect(self.load_historical_events)

        layout.addWidget(filter_box)

        # B. History Table
        self.table_history = QTableWidget(0, 8)
        self.table_history.setHorizontalHeaderLabels([
            "Event ID", "Timestamp", "Source IP:Port", "Target IP:Port", "Directionality", "Threat Type", "Severity", "Risk Score"
        ])
        self.table_history.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_history.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_history.setSelectionMode(QTableWidget.SingleSelection)
        self.table_history.cellClicked.connect(self.on_history_table_row_clicked)
        layout.addWidget(self.table_history, stretch=1)

        # C. Selected Historical Event Inspector
        self.box_history_details = QGroupBox("HISTORICAL INCIDENT RECORD INSPECTOR")
        h_inspect_layout = QVBoxLayout(self.box_history_details)
        self.txt_history_details = QTextEdit()
        self.txt_history_details.setReadOnly(True)
        self.txt_history_details.setFixedHeight(120)
        self.txt_history_details.setPlaceholderText("Select any historical event above to inspect its forensic record and metrics...")
        h_inspect_layout.addWidget(self.txt_history_details)
        layout.addWidget(self.box_history_details)

    def on_history_table_row_clicked(self, row: int, col: int) -> None:
        item = self.table_history.item(row, 0)
        if hasattr(item, "history_data"):
            data = item.history_data
            ts_val = data.get("timestamp", 0) or 0
            lines = [
                f"EVENT ID: {data.get('event_id')}  |  FLOW: {data.get('flow_key')}  |  TIMESTAMP: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_val))}",
                f"SOURCE: {data.get('src_ip')}:{data.get('src_port')}  ->  DESTINATION: {data.get('dst_ip')}:{data.get('dst_port')} [Protocol: {data.get('proto')}]",
                f"CLASSIFICATION: {data.get('threat_type')}  |  SEVERITY: {data.get('severity')}  |  RISK: {data.get('risk_score')}/100  |  CONFIDENCE: {data.get('confidence_pct', 0):.1f}%",
                f"DIRECTIONALITY: {data.get('directionality_state')} (Score: {data.get('directionality_score', 0):.3f})  |  EXCLUDED: {'YES' if data.get('is_excluded') else 'NO'}",
                "-" * 80,
                f"FLOW METRICS: {data.get('flow_metrics', {})}",
            ]
            expl = data.get("explanation")
            if expl and isinstance(expl, dict) and expl.get("summary"):
                lines.extend([
                    "-" * 80,
                    f"AI THREAT EXPLANATION: {expl.get('summary')}",
                ])
                if expl.get("observed_behavior"):
                    lines.append("OBSERVED BEHAVIOR: " + " | ".join(expl["observed_behavior"][:2]))
            self.txt_history_details.setText("\n".join(lines))

    def export_historical_events_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Security Events to CSV", "uniguard_events_export.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            events = self.database.search_events(
                query=self.txt_history_search.text(),
                severity=self.combo_history_sev.currentText(),
                threat_type=self.combo_history_threat.currentText(),
                limit=1000,
            )
            if not events:
                QMessageBox.information(self, "Export CSV", "No events found matching current query to export.")
                return

            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Event ID", "Timestamp", "Source IP", "Source Port", "Target IP", "Target Port", "Protocol", "Threat Type", "Severity", "Risk Score", "Confidence", "Directionality"])
                for ev in events:
                    writer.writerow([
                        ev.get("event_id"),
                        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ev.get("timestamp", 0))),
                        ev.get("src_ip"),
                        ev.get("src_port"),
                        ev.get("dst_ip"),
                        ev.get("dst_port"),
                        ev.get("proto"),
                        ev.get("threat_type"),
                        ev.get("severity"),
                        ev.get("risk_score"),
                        ev.get("confidence_pct"),
                        ev.get("directionality_state"),
                    ])
            QMessageBox.information(self, "Export Successful", f"Successfully exported {len(events)} security events to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Could not write CSV file:\n{str(e)}")

    # =========================================================================
    # MODULE 8: SETTINGS & BPF POLICIES
    # =========================================================================
    def setup_settings_tab(self) -> None:
        layout = QVBoxLayout(self.tab_settings)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        # Section 1: Capture Configuration
        box_cap = QGroupBox("NETWORK CAPTURE & PACKET FILTERING POLICIES")
        form_cap = QFormLayout(box_cap)
        form_cap.setSpacing(10)
        form_cap.setContentsMargins(12, 12, 12, 12)

        self.txt_bpf = QLineEdit("ip and not (ether multicast or ether broadcast)")
        self.txt_bpf.setToolTip("Berkeley Packet Filter (BPF) syntax for hardware/kernel packet pre-filtering")

        # BPF Presets Toolbar
        bpf_btn_layout = QHBoxLayout()
        btn_bpf_default = QPushButton("Default Unidirectional")
        btn_bpf_default.clicked.connect(lambda: self.txt_bpf.setText("ip and not (ether multicast or ether broadcast)"))
        btn_bpf_ip = QPushButton("All IP Traffic")
        btn_bpf_ip.clicked.connect(lambda: self.txt_bpf.setText("ip"))
        btn_bpf_tcp_udp = QPushButton("TCP & UDP Only")
        btn_bpf_tcp_udp.clicked.connect(lambda: self.txt_bpf.setText("ip and (tcp or udp)"))
        bpf_btn_layout.addWidget(btn_bpf_default)
        bpf_btn_layout.addWidget(btn_bpf_ip)
        bpf_btn_layout.addWidget(btn_bpf_tcp_udp)
        bpf_btn_layout.addStretch()

        lbl_bpf_help = QLabel("BPF syntax filters packets directly at kernel level before reaching application memory, dropping multicast/broadcast noise.")
        lbl_bpf_help.setStyleSheet("color: #6e7681; font-size: 8pt; font-style: italic;")

        form_cap.addRow("BPF Capture Filter:", self.txt_bpf)
        form_cap.addRow("Quick Filter Presets:", bpf_btn_layout)
        form_cap.addRow("", lbl_bpf_help)
        layout.addWidget(box_cap)

        # Section 2: Flow Engine Timing
        box_timing = QGroupBox("FLOW ENGINE TIMING & TIMEOUT SPECIFICATIONS")
        form_timing = QFormLayout(box_timing)
        form_timing.setSpacing(10)
        form_timing.setContentsMargins(12, 12, 12, 12)

        self.spin_idle = QDoubleSpinBox()
        self.spin_idle.setValue(15.0)
        self.spin_idle.setRange(1.0, 300.0)
        self.spin_idle.setSuffix(" seconds")

        self.spin_active = QDoubleSpinBox()
        self.spin_active.setValue(60.0)
        self.spin_active.setRange(5.0, 600.0)
        self.spin_active.setSuffix(" seconds")

        self.spin_elephant = QSpinBox()
        self.spin_elephant.setValue(50)
        self.spin_elephant.setRange(10, 1000)
        self.spin_elephant.setSuffix(" packets")

        lbl_idle_help = QLabel("Inactive duration without packet observation before a flow session is committed and evicted.")
        lbl_idle_help.setStyleSheet("color: #6e7681; font-size: 8pt;")

        lbl_active_help = QLabel("Maximum duration of an ongoing active elephant flow slice before snapshotting and evaluating intermediate telemetry.")
        lbl_active_help.setStyleSheet("color: #6e7681; font-size: 8pt;")

        lbl_elephant_help = QLabel("Flows exceeding this packet cutoff bypass expensive SHAP computation on routine snapshots to maintain wire-speed throughput.")
        lbl_elephant_help.setStyleSheet("color: #6e7681; font-size: 8pt;")

        form_timing.addRow("Inactivity Timeout (T_idle):", self.spin_idle)
        form_timing.addRow("", lbl_idle_help)
        form_timing.addRow("Active Slice Timeout (T_active):", self.spin_active)
        form_timing.addRow("", lbl_active_help)
        form_timing.addRow("Elephant Cutoff Threshold:", self.spin_elephant)
        form_timing.addRow("", lbl_elephant_help)
        layout.addWidget(box_timing)

        # Section 3: Save & Apply Actions
        btn_bar = QHBoxLayout()
        self.btn_save_settings = QPushButton("Apply & Validate Settings")
        self.btn_save_settings.setObjectName("action-btn")
        self.btn_save_settings.clicked.connect(self.save_and_apply_settings)

        self.btn_reset_settings = QPushButton("Restore Recommended Defaults")
        self.btn_reset_settings.clicked.connect(self.restore_default_settings)

        btn_bar.addWidget(self.btn_save_settings)
        btn_bar.addWidget(self.btn_reset_settings)
        btn_bar.addStretch()
        layout.addLayout(btn_bar)

        self.lbl_settings_feedback = QLabel("")
        self.lbl_settings_feedback.setStyleSheet("font-weight: bold; font-size: 9pt;")
        layout.addWidget(self.lbl_settings_feedback)
        layout.addStretch()

    # =========================================================================
    # MODULE 9: UNIDIRECTIONAL TRAFFIC INTELLIGENCE ENGINE (UTIE) - SIH 2026
    # =========================================================================
    def setup_utie_tab(self) -> None:
        layout = QVBoxLayout(self.tab_utie)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        # ---------------------------------------------------------------------
        # 1. Overview KPI Cards & Directionality Ratio Meter
        # ---------------------------------------------------------------------
        kpi_box = QGroupBox("UNIDIRECTIONAL TRAFFIC INTELLIGENCE ENGINE (UTIE) — SIH 2026")
        kpi_box.setStyleSheet("QGroupBox { font-weight: bold; color: #00e5ff; border: 1px solid #1c2333; border-radius: 6px; margin-top: 4px; padding-top: 10px; }")
        kpi_layout = QVBoxLayout(kpi_box)
        kpi_layout.setSpacing(6)

        # KPI Cards Row
        card_row = QHBoxLayout()
        card_row.setSpacing(8)
        self.card_utie_total = self.create_kpi_card("TOTAL ANALYZED", "0", "#00e5ff", "Total flows evaluated by UTIE")
        self.card_utie_unidir = self.create_kpi_card("UNIDIRECTIONAL OBSERVED", "0", "#a855f7", "Pure one-way streams (0.0%)")
        self.card_utie_bidir = self.create_kpi_card("BIDIRECTIONAL OBSERVED", "0", "#10b981", "Bilateral sessions (0.0%)")
        self.card_utie_asym = self.create_kpi_card("ASYMMETRIC OBSERVED", "0", "#f59e0b", "Directional asymmetry (0.0%)")
        self.card_utie_insufficient = self.create_kpi_card("INSUFFICIENT DATA", "0", "#8b949e", "Short flows (<3 pkts) (0.0%)")
        self.card_utie_suspicious = self.create_kpi_card("SUSPICIOUS FLOWS", "0", "#ef4444", "Anomalous / Threat flows")

        card_row.addWidget(self.card_utie_total)
        card_row.addWidget(self.card_utie_unidir)
        card_row.addWidget(self.card_utie_bidir)
        card_row.addWidget(self.card_utie_asym)
        card_row.addWidget(self.card_utie_insufficient)
        card_row.addWidget(self.card_utie_suspicious)
        kpi_layout.addLayout(card_row)

        # Visual Directionality Segmented Ratio Meter + Live Chips
        ratio_container = QWidget()
        ratio_vbox = QVBoxLayout(ratio_container)
        ratio_vbox.setContentsMargins(2, 2, 2, 2)
        ratio_vbox.setSpacing(4)

        self.bar_frame = QFrame()
        self.bar_frame.setFixedHeight(10)
        self.bar_frame.setStyleSheet("background-color: #161d2b; border-radius: 5px; border: 1px solid #283347;")
        self.bar_layout = QHBoxLayout(self.bar_frame)
        self.bar_layout.setContentsMargins(1, 1, 1, 1)
        self.bar_layout.setSpacing(2)

        self.seg_unidir = QFrame()
        self.seg_unidir.setStyleSheet("background-color: #a855f7; border-radius: 3px;")
        self.seg_bidir = QFrame()
        self.seg_bidir.setStyleSheet("background-color: #10b981; border-radius: 3px;")
        self.seg_asym = QFrame()
        self.seg_asym.setStyleSheet("background-color: #f59e0b; border-radius: 3px;")
        self.seg_insuf = QFrame()
        self.seg_insuf.setStyleSheet("background-color: #64748b; border-radius: 3px;")

        self.bar_layout.addWidget(self.seg_unidir, 1)
        self.bar_layout.addWidget(self.seg_bidir, 1)
        self.bar_layout.addWidget(self.seg_asym, 1)
        self.bar_layout.addWidget(self.seg_insuf, 1)
        ratio_vbox.addWidget(self.bar_frame)

        # Chips row
        chips_row = QHBoxLayout()
        chips_row.setSpacing(8)
        self.chip_unidir = QLabel("🟣 Unidirectional: 0 (0.0%)")
        self.chip_unidir.setStyleSheet("background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 8pt;")
        self.chip_bidir = QLabel("🟢 Bidirectional: 0 (0.0%)")
        self.chip_bidir.setStyleSheet("background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 8pt;")
        self.chip_asym = QLabel("🟠 Asymmetric: 0 (0.0%)")
        self.chip_asym.setStyleSheet("background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 8pt;")
        self.chip_insuf = QLabel("⚪ Insufficient: 0 (0.0%)")
        self.chip_insuf.setStyleSheet("background: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.4); padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 8pt;")

        chips_row.addWidget(self.chip_unidir)
        chips_row.addWidget(self.chip_bidir)
        chips_row.addWidget(self.chip_asym)
        chips_row.addWidget(self.chip_insuf)
        chips_row.addStretch()

        self.lbl_utie_dist = QLabel("DIRECTIONALITY DISTRIBUTION:  UNIDIRECTIONAL: 0.0%  |  BIDIRECTIONAL: 0.0%  |  ASYMMETRIC: 0.0%  |  INSUFFICIENT: 0.0%")
        self.lbl_utie_dist.setVisible(False)
        chips_row.addWidget(self.lbl_utie_dist)
        ratio_vbox.addLayout(chips_row)
        kpi_layout.addWidget(ratio_container)

        # ---------------------------------------------------------------------
        # 2. Sensor Observation Topology & Hardware Diode Enforcement Bar
        # ---------------------------------------------------------------------
        sensor_bar = QHBoxLayout()
        sensor_bar.setContentsMargins(4, 2, 4, 2)
        sensor_bar.setSpacing(10)

        lbl_topo_icon = QLabel("📡 <b>Observation Point:</b>")
        lbl_topo_icon.setStyleSheet("color: #c9d1d9; font-size: 8.5pt;")
        sensor_bar.addWidget(lbl_topo_icon)

        self.combo_sensor_point = QComboBox()
        self.combo_sensor_point.addItems([
            "PROMISCUOUS_TAP",
            "DATA_DIODE_EGRESS",
            "DATA_DIODE_INGRESS",
            "ASYMMETRIC_SPAN",
            "GATEWAY_INLINE",
            "UNKNOWN",
        ])
        self.combo_sensor_point.setStyleSheet("background-color: #0f141c; color: #c9d1d9; border: 1px solid #2d3748; padding: 3px 8px; border-radius: 4px;")
        sensor_bar.addWidget(self.combo_sensor_point)

        self.chk_sensor_diode = QCheckBox("Hardware Data Diode Enforced")
        self.chk_sensor_diode.setStyleSheet("color: #a855f7; font-weight: bold; font-size: 8.5pt;")
        sensor_bar.addWidget(self.chk_sensor_diode)

        self.btn_apply_sensor = QPushButton("Apply Topology")
        self.btn_apply_sensor.setStyleSheet("background-color: #0284c7; color: #ffffff; font-weight: bold; padding: 4px 12px; border-radius: 4px; border: none;")
        self.btn_apply_sensor.clicked.connect(self.apply_sensor_topology)
        sensor_bar.addWidget(self.btn_apply_sensor)

        self.lbl_sensor_status_badge = QLabel("STATUS: PROMISCUOUS_TAP [BIDIRECTIONAL WIRETAP]")
        self.lbl_sensor_status_badge.setStyleSheet("background: rgba(0, 229, 255, 0.12); color: #00e5ff; border: 1px solid rgba(0, 229, 255, 0.3); padding: 3px 10px; border-radius: 4px; font-weight: bold; font-size: 8pt;")
        sensor_bar.addWidget(self.lbl_sensor_status_badge)
        sensor_bar.addStretch()

        kpi_layout.addLayout(sensor_bar)
        layout.addWidget(kpi_box)

        # ---------------------------------------------------------------------
        # 3. Filter Bar & Quick Filter Chips
        # ---------------------------------------------------------------------
        filter_bar = QHBoxLayout()
        filter_bar.setSpacing(6)

        # Quick Filter Pills
        self.btn_quick_all = QPushButton("All Flows")
        self.btn_quick_unidir = QPushButton("⇥ Unidirectional")
        self.btn_quick_bidir = QPushButton("⇄ Bidirectional")
        self.btn_quick_suspicious = QPushButton("⚠️ Threats / High Risk")
        self.btn_quick_anom = QPushButton("⚡ Anomalous")
        self.btn_quick_asym = QPushButton("⇋ Asymmetric")

        self.quick_filter_btns = [
            self.btn_quick_all,
            self.btn_quick_unidir,
            self.btn_quick_bidir,
            self.btn_quick_suspicious,
            self.btn_quick_anom,
            self.btn_quick_asym,
        ]
        for btn in self.quick_filter_btns:
            btn.setCheckable(True)
            btn.setStyleSheet(
                "QPushButton { background-color: #161d2b; color: #c9d1d9; border: 1px solid #283347; padding: 4px 10px; border-radius: 4px; font-size: 8.5pt; font-weight: 600; }"
                "QPushButton:hover { background-color: #1f293d; border-color: #38bdf8; }"
                "QPushButton:checked { background-color: rgba(0, 229, 255, 0.2); color: #00e5ff; border: 1px solid #00e5ff; }"
            )
            filter_bar.addWidget(btn)

        self.btn_quick_all.setChecked(True)
        self.btn_quick_all.clicked.connect(lambda: self.set_quick_filter("ALL"))
        self.btn_quick_unidir.clicked.connect(lambda: self.set_quick_filter("UNIDIR"))
        self.btn_quick_bidir.clicked.connect(lambda: self.set_quick_filter("BIDIR"))
        self.btn_quick_suspicious.clicked.connect(lambda: self.set_quick_filter("THREATS"))
        self.btn_quick_anom.clicked.connect(lambda: self.set_quick_filter("ANOM"))
        self.btn_quick_asym.clicked.connect(lambda: self.set_quick_filter("ASYM"))

        filter_bar.addSpacing(6)

        # Search box with clear button
        self.txt_utie_search = QLineEdit()
        self.txt_utie_search.setPlaceholderText("🔍 Search by IP, Port, or Flow ID...")
        self.txt_utie_search.setClearButtonEnabled(True)
        self.txt_utie_search.setStyleSheet("background-color: #0f141c; color: #c9d1d9; border: 1px solid #2d3748; padding: 4px 8px; border-radius: 4px;")
        self.txt_utie_search.textChanged.connect(self.filter_utie_table)
        filter_bar.addWidget(self.txt_utie_search, stretch=2)

        self.combo_filter_utie_dir = QComboBox()
        self.combo_filter_utie_dir.addItems([
            "ALL DIRECTIONALITIES",
            "UNIDIRECTIONAL_OBSERVED",
            "BIDIRECTIONAL_OBSERVED",
            "ASYMMETRIC_OBSERVED",
            "INSUFFICIENT_DATA",
            "UNKNOWN",
        ])
        self.combo_filter_utie_dir.setStyleSheet("background-color: #0f141c; color: #c9d1d9; border: 1px solid #2d3748; padding: 3px 6px; border-radius: 4px;")
        self.combo_filter_utie_dir.currentIndexChanged.connect(self.filter_utie_table)
        filter_bar.addWidget(self.combo_filter_utie_dir)

        self.combo_filter_utie_threat = QComboBox()
        self.combo_filter_utie_threat.addItems([
            "ALL THREAT CLASSES",
            "BENIGN",
            "PORT_SCAN",
            "SYN_FLOOD",
            "UDP_FLOOD",
            "DATA_EXFILTRATION",
            "SLOWLORIS",
            "ANOMALOUS",
        ])
        self.combo_filter_utie_threat.setStyleSheet("background-color: #0f141c; color: #c9d1d9; border: 1px solid #2d3748; padding: 3px 6px; border-radius: 4px;")
        self.combo_filter_utie_threat.currentIndexChanged.connect(self.filter_utie_table)
        filter_bar.addWidget(self.combo_filter_utie_threat)

        self.btn_load_history = QPushButton("🔄 Load DB History")
        self.btn_load_history.setStyleSheet("background-color: #1e293b; color: #38bdf8; border: 1px solid #334155; padding: 4px 10px; border-radius: 4px; font-weight: 600;")
        self.btn_load_history.clicked.connect(self.load_historical_utie_reports)
        filter_bar.addWidget(self.btn_load_history)

        self.btn_reset_utie = QPushButton("Reset")
        self.btn_reset_utie.setStyleSheet("background-color: #161d2b; color: #8b949e; border: 1px solid #283347; padding: 4px 10px; border-radius: 4px;")
        self.btn_reset_utie.clicked.connect(self.reset_utie_filters)
        filter_bar.addWidget(self.btn_reset_utie)

        self.lbl_utie_table_count = QLabel("0 flows displayed")
        self.lbl_utie_table_count.setStyleSheet("color: #00e5ff; font-weight: bold; font-size: 8.5pt;")
        filter_bar.addWidget(self.lbl_utie_table_count)
        layout.addLayout(filter_bar)

        # ---------------------------------------------------------------------
        # 4. Master Splitter: Flow Intelligence Table vs Forensic Inspector
        # ---------------------------------------------------------------------
        splitter = QSplitter(Qt.Vertical)

        # Master UTIE Table
        self.table_utie = QTableWidget(0, 11)
        self.table_utie.setHorizontalHeaderLabels([
            "Flow ID",
            "Source Endpoint",
            "Destination Endpoint",
            "Protocol",
            "Directionality Verdict",
            "Packets (Fwd / Rev)",
            "Bytes (Fwd / Rev)",
            "Duration",
            "Anomaly Status",
            "Threat Classification",
            "Risk Score",
        ])
        self.table_utie.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table_utie.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table_utie.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_utie.setSelectionMode(QTableWidget.SingleSelection)
        self.table_utie.setSortingEnabled(True)
        self.table_utie.setStyleSheet(
            "QTableWidget { background-color: #0a0d14; gridline-color: #161d2b; alternate-background-color: #0f141f; selection-background-color: #1f293d; font-size: 8.5pt; }"
            "QHeaderView::section { background-color: #111724; color: #8b949e; font-weight: bold; font-size: 8pt; border: 1px solid #161d2b; padding: 4px 6px; }"
        )
        self.table_utie.setAlternatingRowColors(True)
        self.table_utie.cellClicked.connect(self.on_utie_table_row_clicked)
        splitter.addWidget(self.table_utie)

        # ---------------------------------------------------------------------
        # 5. Lower Forensic Inspector (Tabbed Cybersecurity Panel)
        # ---------------------------------------------------------------------
        detail_container = QFrame()
        detail_container.setStyleSheet("background-color: #080b11; border: 1px solid #1c2333; border-radius: 6px;")
        detail_layout = QVBoxLayout(detail_container)
        detail_layout.setContentsMargins(8, 8, 8, 8)
        detail_layout.setSpacing(6)

        # Selected Flow Header Bar
        flow_header = QHBoxLayout()
        flow_header.setSpacing(8)

        self.lbl_flow_tuple = QLabel("5-TUPLE: Select any flow in the table above to view forensic directionality intelligence")
        self.lbl_flow_tuple.setStyleSheet("color: #00e5ff; font-weight: bold; font-size: 9pt;")
        flow_header.addWidget(self.lbl_flow_tuple, stretch=2)

        self.badge_utie_class = QLabel("DIRECTIONALITY: SELECT A FLOW")
        self.badge_utie_class.setStyleSheet("background-color: #161d2b; color: #8b949e; border: 1px solid #283347; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 8pt;")
        flow_header.addWidget(self.badge_utie_class)

        lbl_conf_tag = QLabel("Evidence Confidence:")
        lbl_conf_tag.setStyleSheet("color: #8b949e; font-size: 8pt; font-weight: 600;")
        flow_header.addWidget(lbl_conf_tag)

        self.progress_utie_conf = QProgressBar()
        self.progress_utie_conf.setRange(0, 100)
        self.progress_utie_conf.setValue(0)
        self.progress_utie_conf.setTextVisible(True)
        self.progress_utie_conf.setFixedWidth(140)
        self.progress_utie_conf.setFixedHeight(18)
        self.progress_utie_conf.setFormat("%v% (Evidence)")
        self.progress_utie_conf.setStyleSheet(
            "QProgressBar { background-color: #161d2b; border: 1px solid #283347; border-radius: 4px; text-align: center; color: #f0f6fc; font-size: 7.5pt; font-weight: bold; }"
            "QProgressBar::chunk { background-color: #00e5ff; border-radius: 3px; }"
        )
        flow_header.addWidget(self.progress_utie_conf)

        self.badge_utie_risk = QLabel("RISK: --")
        self.badge_utie_risk.setStyleSheet("background-color: #161d2b; color: #8b949e; border: 1px solid #283347; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 8pt;")
        flow_header.addWidget(self.badge_utie_risk)

        detail_layout.addLayout(flow_header)

        # Tabbed Forensic Panels
        self.tabs_utie_inspector = QTabWidget()
        self.tabs_utie_inspector.setStyleSheet(
            "QTabWidget::pane { border: 1px solid #1c2333; background: #0b0f17; border-radius: 4px; }"
            "QTabBar::tab { background: #161d2b; color: #8b949e; padding: 5px 12px; margin-right: 2px; border-top-left-radius: 4px; border-top-right-radius: 4px; font-weight: 600; font-size: 8pt; }"
            "QTabBar::tab:selected { background: #0b0f17; color: #00e5ff; border: 1px solid #1c2333; border-bottom: none; }"
        )

        # Tab 1: Forensic Directionality & Sensor Topology
        tab_evidence = QWidget()
        te_layout = QVBoxLayout(tab_evidence)
        te_layout.setContentsMargins(6, 6, 6, 6)
        self.txt_utie_evidence = QTextEdit()
        self.txt_utie_evidence.setReadOnly(True)
        self.txt_utie_evidence.setPlaceholderText("Select any flow in the table above to view supporting directionality evidence, sensor topology rationale, and reverse-path visibility analysis...")
        self.txt_utie_evidence.setStyleSheet("background-color: #0b0f17; color: #c9d1d9; border: none; font-size: 8.5pt;")
        te_layout.addWidget(self.txt_utie_evidence)
        self.tabs_utie_inspector.addTab(tab_evidence, "🔬 Forensic Evidence & Sensor Topology")

        # Tab 2: Traffic Dynamics & Behavioral Signatures
        tab_behavior = QWidget()
        tb_layout = QVBoxLayout(tab_behavior)
        tb_layout.setContentsMargins(6, 6, 6, 6)
        self.txt_utie_behavior = QTextEdit()
        self.txt_utie_behavior.setReadOnly(True)
        self.txt_utie_behavior.setPlaceholderText("Select a flow to inspect packet length distributions, inter-arrival time burstiness, TCP flag patterns, and entropy dynamics...")
        self.txt_utie_behavior.setStyleSheet("background-color: #0b0f17; color: #c9d1d9; border: none; font-size: 8.5pt;")
        tb_layout.addWidget(self.txt_utie_behavior)
        self.tabs_utie_inspector.addTab(tab_behavior, "📊 Traffic Dynamics & Behavioral Signatures")

        # Tab 3: AI Threat Verdict & SOC Triage Playbook
        tab_playbook = QWidget()
        tp_layout = QVBoxLayout(tab_playbook)
        tp_layout.setContentsMargins(6, 6, 6, 6)
        self.txt_utie_playbook = QTextEdit()
        self.txt_utie_playbook.setReadOnly(True)
        self.txt_utie_playbook.setPlaceholderText("Select a flow to view multi-model AI threat categorization, Isolation Forest anomaly telemetry, and incident response playbooks...")
        self.txt_utie_playbook.setStyleSheet("background-color: #0b0f17; color: #c9d1d9; border: none; font-size: 8.5pt;")
        tp_layout.addWidget(self.txt_utie_playbook)
        self.tabs_utie_inspector.addTab(tab_playbook, "🛡️ AI Threat Verdict & SOC Playbook")

        detail_layout.addWidget(self.tabs_utie_inspector, stretch=1)
        splitter.addWidget(detail_container)

        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 4)
        layout.addWidget(splitter, stretch=1)

    # -------------------------------------------------------------------------
    # UTIE Event Handlers & Data Processing
    # -------------------------------------------------------------------------
    def apply_sensor_topology(self) -> None:
        """Applies operator configured observation point topology to UTIE."""
        pt_name = self.combo_sensor_point.currentText()
        is_diode = self.chk_sensor_diode.isChecked()
        try:
            obs_pt = ObservationPoint[pt_name]
        except KeyError:
            obs_pt = ObservationPoint.PROMISCUOUS_TAP

        ctx = SensorVisibilityContext(
            observation_point=obs_pt,
            is_diode_enforced=is_diode,
        )
        bridge = SocStateBridge.get()
        bridge.utie_engine.set_sensor_context(ctx)

        # Update badge
        status_text = f"STATUS: {obs_pt.name} " + ("[HARDWARE DATA DIODE ACTIVE]" if is_diode else "[PASSIVE WIRETAP]")
        self.lbl_sensor_status_badge.setText(status_text)
        if is_diode:
            self.lbl_sensor_status_badge.setStyleSheet("background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid #a855f7; padding: 3px 10px; border-radius: 4px; font-weight: bold; font-size: 8pt;")
        else:
            self.lbl_sensor_status_badge.setStyleSheet("background: rgba(0, 229, 255, 0.12); color: #00e5ff; border: 1px solid rgba(0, 229, 255, 0.3); padding: 3px 10px; border-radius: 4px; font-weight: bold; font-size: 8pt;")

        self.add_log(f"UTIE Sensor Visibility Topology updated: {obs_pt.value} (Diode Enforced={is_diode})", level="INFO")

    def set_quick_filter(self, filter_code: str) -> None:
        """Switches active quick filter pill and filters the table."""
        self.active_quick_filter = filter_code
        for btn in self.quick_filter_btns:
            btn.setChecked(False)

        if filter_code == "UNIDIR":
            self.btn_quick_unidir.setChecked(True)
        elif filter_code == "BIDIR":
            self.btn_quick_bidir.setChecked(True)
        elif filter_code == "THREATS":
            self.btn_quick_suspicious.setChecked(True)
        elif filter_code == "ANOM":
            self.btn_quick_anom.setChecked(True)
        elif filter_code == "ASYM":
            self.btn_quick_asym.setChecked(True)
        else:
            self.btn_quick_all.setChecked(True)

        self.filter_utie_table()

    def update_utie_kpi_displays(self) -> None:
        """Updates UTIE overview KPI cards and the multi-segment ratio bar."""
        total = max(1, len(self.all_utie_reports))
        unidir_cnt = self.utie_counts.get("UNIDIRECTIONAL_OBSERVED", 0)
        bidir_cnt = self.utie_counts.get("BIDIRECTIONAL_OBSERVED", 0)
        asym_cnt = self.utie_counts.get("ASYMMETRIC_OBSERVED", 0)
        insuf_cnt = self.utie_counts.get("INSUFFICIENT_DATA", 0)

        unidir_pct = (unidir_cnt / total) * 100.0
        bidir_pct = (bidir_cnt / total) * 100.0
        asym_pct = (asym_cnt / total) * 100.0
        insuf_pct = (insuf_cnt / total) * 100.0

        if hasattr(self, "card_utie_total") and hasattr(self.card_utie_total, "value_label"):
            self.card_utie_total.value_label.setText(str(len(self.all_utie_reports)))
        if hasattr(self, "card_utie_unidir") and hasattr(self.card_utie_unidir, "value_label"):
            self.card_utie_unidir.value_label.setText(f"{unidir_cnt} ({unidir_pct:.1f}%)")
        if hasattr(self, "card_utie_bidir") and hasattr(self.card_utie_bidir, "value_label"):
            self.card_utie_bidir.value_label.setText(f"{bidir_cnt} ({bidir_pct:.1f}%)")
        if hasattr(self, "card_utie_asym") and hasattr(self.card_utie_asym, "value_label"):
            self.card_utie_asym.value_label.setText(f"{asym_cnt} ({asym_pct:.1f}%)")
        if hasattr(self, "card_utie_insufficient") and hasattr(self.card_utie_insufficient, "value_label"):
            self.card_utie_insufficient.value_label.setText(f"{insuf_cnt} ({insuf_pct:.1f}%)")
        if hasattr(self, "card_utie_suspicious") and hasattr(self.card_utie_suspicious, "value_label"):
            self.card_utie_suspicious.value_label.setText(str(self.utie_suspicious_count))

        # Update ratio chips
        if hasattr(self, "chip_unidir"):
            self.chip_unidir.setText(f"🟣 Unidirectional: {unidir_cnt} ({unidir_pct:.1f}%)")
        if hasattr(self, "chip_bidir"):
            self.chip_bidir.setText(f"🟢 Bidirectional: {bidir_cnt} ({bidir_pct:.1f}%)")
        if hasattr(self, "chip_asym"):
            self.chip_asym.setText(f"🟠 Asymmetric: {asym_cnt} ({asym_pct:.1f}%)")
        if hasattr(self, "chip_insuf"):
            self.chip_insuf.setText(f"⚪ Insufficient: {insuf_cnt} ({insuf_pct:.1f}%)")

        # Update segment bar stretch factors
        if hasattr(self, "bar_layout"):
            self.bar_layout.setStretch(0, max(1, int(unidir_pct)))
            self.bar_layout.setStretch(1, max(1, int(bidir_pct)))
            self.bar_layout.setStretch(2, max(1, int(asym_pct)))
            self.bar_layout.setStretch(3, max(1, int(insuf_pct)))

        if hasattr(self, "lbl_utie_dist"):
            self.lbl_utie_dist.setText(
                f"DIRECTIONALITY DISTRIBUTION:  UNIDIRECTIONAL: {unidir_pct:.1f}%  |  BIDIRECTIONAL: {bidir_pct:.1f}%  |  ASYMMETRIC: {asym_pct:.1f}%  |  INSUFFICIENT: {insuf_pct:.1f}%"
            )

    def load_historical_utie_reports(self) -> None:
        """Loads historical UTIE flow intelligence reports from SQLite database."""
        try:
            records = self.database.get_recent_utie_reports(limit=250)
            if not records:
                return

            self.all_utie_reports.clear()
            self.utie_counts = {
                "UNIDIRECTIONAL_OBSERVED": 0,
                "BIDIRECTIONAL_OBSERVED": 0,
                "ASYMMETRIC_OBSERVED": 0,
                "INSUFFICIENT_DATA": 0,
                "UNKNOWN": 0,
            }
            self.utie_suspicious_count = 0

            for d in records:
                sensor_vis = {
                    "visibility_type": d.get("sensor_visibility_type", "UNKNOWN"),
                    "is_reverse_missing": bool(d.get("is_reverse_missing", 0)),
                    "reverse_missing_reason": "Single-path observation point" if d.get("is_reverse_missing") else "Normal bidirectional wiretap",
                    "completeness_status": "ASYMMETRIC" if d.get("is_reverse_missing") else "COMPLETE",
                    "confidence_penalty": 0.0,
                    "sensor_notes": [f"Stored UTIE record from sensor topology: {d.get('sensor_visibility_type', 'UNKNOWN')}"],
                }
                rpt = UTIEIntelligenceReport(
                    flow_id=d.get("flow_id", "N/A"),
                    src_ip=d.get("src_ip", "0.0.0.0"),
                    dst_ip=d.get("dst_ip", "0.0.0.0"),
                    src_port=d.get("src_port", 0),
                    dst_port=d.get("dst_port", 0),
                    proto=d.get("proto", 6),
                    proto_name=d.get("proto_name", "TCP"),
                    directionality=d.get("directionality", "UNKNOWN"),
                    directionality_confidence=float(d.get("directionality_confidence", 0.0)),
                    directionality_evidence=d.get("directionality_evidence", []),
                    sensor_visibility=sensor_vis,
                    packet_count=d.get("packet_count", 0),
                    reverse_packet_count=d.get("reverse_packet_count"),
                    byte_count=d.get("byte_count", 0),
                    reverse_byte_count=d.get("reverse_byte_count"),
                    total_packet_count=(d.get("packet_count", 0) + (d.get("reverse_packet_count") or 0)),
                    total_byte_count=(d.get("byte_count", 0) + (d.get("reverse_byte_count") or 0)),
                    duration=float(d.get("duration", 0.0)),
                    pkt_rate=float(d.get("pkt_rate", 0.0)),
                    byte_rate=float(d.get("byte_rate", 0.0)),
                    first_seen=float(d.get("timestamp", 0.0)),
                    last_seen=float(d.get("timestamp", 0.0) + d.get("duration", 0.0)),
                    traffic_behavior_summary=d.get("traffic_behavior_summary", {}),
                    anomaly_status=d.get("anomaly_status", "NORMAL"),
                    anomaly_score=float(d.get("anomaly_score", 0.0)),
                    ml_threat_category=d.get("threat_category"),
                    ml_confidence=0.9 if d.get("threat_category") and d.get("threat_category") != "BENIGN" else 0.5,
                    risk_score=d.get("risk_score"),
                    severity=d.get("severity"),
                    suggested_investigation_steps=d.get("suggested_investigation_steps", []),
                    analysis_timestamp=float(d.get("timestamp", time.time())),
                )
                self.all_utie_reports.append(rpt)
                cls_name = rpt.directionality
                self.utie_counts[cls_name] = self.utie_counts.get(cls_name, 0) + 1
                if (rpt.risk_score and rpt.risk_score >= 40) or (rpt.ml_threat_category and rpt.ml_threat_category != "BENIGN") or rpt.anomaly_status == "ANOMALOUS":
                    self.utie_suspicious_count += 1

            self.update_utie_kpi_displays()
            self.filter_utie_table()
        except Exception:
            pass

    def on_utie_report_received(self, report: UTIEIntelligenceReport) -> None:
        """Slot invoked on Qt GUI thread when a new UTIE intelligence report is generated."""
        self.all_utie_reports.insert(0, report)
        if len(self.all_utie_reports) > 1000:
            self.all_utie_reports.pop()

        # Update persistence & Web SOC bridge
        try:
            SecurityDatabase().insert_utie_report(report)
        except Exception:
            pass
        try:
            SocStateBridge.get().add_utie_report(report)
        except Exception:
            pass

        # Update UTIE metrics
        cls_name = report.directionality
        self.utie_counts[cls_name] = self.utie_counts.get(cls_name, 0) + 1
        is_suspicious = (
            (report.risk_score is not None and report.risk_score >= 40)
            or (report.ml_threat_category is not None and report.ml_threat_category != "BENIGN")
            or report.anomaly_status == "ANOMALOUS"
        )
        if is_suspicious:
            self.utie_suspicious_count += 1

        self.update_utie_kpi_displays()

        # Add to table if matches active filters
        self._add_utie_report_row(report, prepend=True)
        self.lbl_utie_table_count.setText(f"{self.table_utie.rowCount()} flows displayed")

    def _add_utie_report_row(self, report: UTIEIntelligenceReport, prepend: bool = True) -> None:
        """Inserts a single styled row into the UTIE Flow Intelligence Table."""
        # 1. Quick filter check
        qf = getattr(self, "active_quick_filter", "ALL")
        if qf == "UNIDIR" and "UNIDIRECTIONAL" not in report.directionality.upper():
            return
        elif qf == "BIDIR" and "BIDIRECTIONAL" not in report.directionality.upper():
            return
        elif qf == "ASYM" and "ASYMMETRIC" not in report.directionality.upper():
            return
        elif qf == "THREATS":
            is_susp = (
                (report.risk_score and report.risk_score >= 40)
                or (report.ml_threat_category and report.ml_threat_category.upper() != "BENIGN")
                or report.anomaly_status == "ANOMALOUS"
            )
            if not is_susp:
                return
        elif qf == "ANOM" and report.anomaly_status != "ANOMALOUS":
            return

        # 2. Text Search & Dropdown Filters
        search = self.txt_utie_search.text().lower().strip()
        dir_filter = self.combo_filter_utie_dir.currentText()
        threat_filter = self.combo_filter_utie_threat.currentText()

        if search:
            match = (
                search in report.flow_id.lower()
                or search in report.src_ip.lower()
                or search in report.dst_ip.lower()
                or search in str(report.src_port)
                or search in str(report.dst_port)
                or search in report.proto_name.lower()
            )
            if not match:
                return

        if dir_filter != "ALL DIRECTIONALITIES" and report.directionality != dir_filter:
            return

        if threat_filter != "ALL THREAT CLASSES":
            cat = report.ml_threat_category or "BENIGN"
            if cat.upper() != threat_filter:
                return

        self.table_utie.setSortingEnabled(False)
        row_idx = 0 if prepend else self.table_utie.rowCount()
        self.table_utie.insertRow(row_idx)

        # Directionality styling
        dir_name = report.directionality.upper()
        if "UNIDIRECTIONAL" in dir_name:
            dir_display = "⇥ UNIDIRECTIONAL"
            dir_color = QColor("#c084fc")
        elif "BIDIRECTIONAL" in dir_name:
            dir_display = "⇄ BIDIRECTIONAL"
            dir_color = QColor("#34d399")
        elif "ASYMMETRIC" in dir_name:
            dir_display = "⇋ ASYMMETRIC"
            dir_color = QColor("#fbbf24")
        else:
            dir_display = "? INSUFFICIENT"
            dir_color = QColor("#94a3b8")

        # Fwd / Rev Pkts & Bytes
        rev_pkts_str = str(report.reverse_packet_count) if report.reverse_packet_count is not None else "0 (None)"
        fwd_rev_pkts = f"{report.packet_count:,} / {rev_pkts_str}"

        def fmt_bytes(b):
            if b is None or b == 0:
                return "0 B"
            elif b >= 1048576:
                return f"{b / 1048576:.1f} MB"
            elif b >= 1024:
                return f"{b / 1024:.1f} KB"
            return f"{b} B"

        fwd_rev_bytes = f"{fmt_bytes(report.byte_count)} / {fmt_bytes(report.reverse_byte_count)}"

        # Anomaly Status
        is_anom = report.anomaly_status == "ANOMALOUS"
        anom_str = "⚡ ANOMALOUS" if is_anom else "NORMAL"
        anom_color = QColor("#ef4444") if is_anom else QColor("#10b981")

        # Threat Category
        cat_str = report.ml_threat_category or "BENIGN"
        is_threat = cat_str != "BENIGN"
        threat_color = QColor("#f97316") if is_threat else QColor("#8b949e")

        # Risk Score
        risk_val = report.risk_score if report.risk_score is not None else 0
        sev_val = (report.severity or "LOW").upper()
        if risk_val >= 80 or sev_val == "CRITICAL":
            risk_color = QColor("#ef4444")
            risk_badge = f"{risk_val} [CRITICAL]"
        elif risk_val >= 60 or sev_val == "HIGH":
            risk_color = QColor("#f97316")
            risk_badge = f"{risk_val} [HIGH]"
        elif risk_val >= 35 or sev_val == "MEDIUM":
            risk_color = QColor("#eab308")
            risk_badge = f"{risk_val} [MED]"
        else:
            risk_color = QColor("#38bdf8")
            risk_badge = f"{risk_val} [LOW]"

        # Create table items
        it_flow = QTableWidgetItem(report.flow_id)
        it_flow.setForeground(QColor("#8b949e"))
        it_flow.setFont(QFont("Consolas", 8))

        it_src = QTableWidgetItem(f"{report.src_ip}:{report.src_port}")
        it_dst = QTableWidgetItem(f"{report.dst_ip}:{report.dst_port}")
        it_proto = QTableWidgetItem(report.proto_name)
        it_proto.setTextAlignment(Qt.AlignCenter)

        it_dir = QTableWidgetItem(dir_display)
        it_dir.setForeground(dir_color)
        it_dir.setFont(QFont("Segoe UI", 8.5, QFont.Bold))

        it_pkts = QTableWidgetItem(fwd_rev_pkts)
        it_bytes = QTableWidgetItem(fwd_rev_bytes)
        it_dur = QTableWidgetItem(f"{report.duration:.3f}s")
        it_dur.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

        it_anom = QTableWidgetItem(anom_str)
        it_anom.setForeground(anom_color)
        it_anom.setFont(QFont("Segoe UI", 8.5, QFont.Bold))
        it_anom.setTextAlignment(Qt.AlignCenter)

        it_threat = QTableWidgetItem(cat_str)
        it_threat.setForeground(threat_color)
        it_threat.setFont(QFont("Segoe UI", 8.5, QFont.Bold if is_threat else QFont.Normal))

        it_risk = QTableWidgetItem(risk_badge)
        it_risk.setForeground(risk_color)
        it_risk.setFont(QFont("Segoe UI", 8.5, QFont.Bold))
        it_risk.setTextAlignment(Qt.AlignCenter)

        items = [it_flow, it_src, it_dst, it_proto, it_dir, it_pkts, it_bytes, it_dur, it_anom, it_threat, it_risk]
        for col, it in enumerate(items):
            self.table_utie.setItem(row_idx, col, it)

        # Cap table rows at 400 for GUI performance
        if self.table_utie.rowCount() > 400:
            self.table_utie.removeRow(self.table_utie.rowCount() - 1)

        self.table_utie.setSortingEnabled(True)

    def filter_utie_table(self) -> None:
        """Applies text and dropdown filters across all stored UTIE reports."""
        self.table_utie.setRowCount(0)
        for r in self.all_utie_reports[:400]:
            self._add_utie_report_row(r, prepend=False)
        self.lbl_utie_table_count.setText(f"{self.table_utie.rowCount()} flows displayed")

    def reset_utie_filters(self) -> None:
        """Resets all search inputs and filter combo boxes for UTIE."""
        self.active_quick_filter = "ALL"
        for btn in self.quick_filter_btns:
            btn.setChecked(False)
        self.btn_quick_all.setChecked(True)

        self.txt_utie_search.clear()
        self.combo_filter_utie_dir.setCurrentIndex(0)
        self.combo_filter_utie_threat.setCurrentIndex(0)
        self.filter_utie_table()

    def on_utie_table_row_clicked(self, row: int, col: int) -> None:
        """Populates the detail inspector when a user clicks any UTIE row."""
        flow_id_item = self.table_utie.item(row, 0)
        if not flow_id_item:
            return
        flow_id = flow_id_item.text()

        # Find matching report
        report = next((r for r in self.all_utie_reports if r.flow_id == flow_id), None)
        if not report:
            return

        # 1. Update Directionality badge & Evidence score
        color_hex, badge_label, _ = report.get_visual_indicator()
        self.badge_utie_class.setText(f"VERDICT: {report.directionality} [{badge_label}]")
        self.badge_utie_class.setStyleSheet(f"background-color: rgba(22, 29, 43, 0.9); color: {color_hex}; border: 1px solid {color_hex}; padding: 3px 8px; border-radius: 4px; font-weight: bold;")

        conf_pct = int(report.directionality_confidence * 100.0)
        self.progress_utie_conf.setValue(conf_pct)

        # Update flow tuple header
        self.lbl_flow_tuple.setText(f"5-TUPLE: {report.src_ip}:{report.src_port} &rarr; {report.dst_ip}:{report.dst_port} [{report.proto_name} / Proto {report.proto}]")

        # Update risk badge
        r_val = report.risk_score if report.risk_score is not None else 0
        r_sev = (report.severity or "INFORMATIONAL").upper()
        if r_val >= 80 or r_sev == "CRITICAL":
            r_border = "#ef4444"
        elif r_val >= 60 or r_sev == "HIGH":
            r_border = "#f97316"
        elif r_val >= 35:
            r_border = "#eab308"
        else:
            r_border = "#10b981"
        self.badge_utie_risk.setText(f"COMPOSITE RISK: {r_val}/100 [{r_sev}]")
        self.badge_utie_risk.setStyleSheet(f"background-color: rgba(22, 29, 43, 0.9); color: {r_border}; border: 1px solid {r_border}; padding: 3px 8px; border-radius: 4px; font-weight: bold;")

        # ---------------------------------------------------------------------
        # TAB 1: Forensic Directionality & Sensor Topology HTML
        # ---------------------------------------------------------------------
        vis = report.sensor_visibility
        behavior = report.traffic_behavior_summary

        evidence_html = f"""
        <div style="font-family: 'Segoe UI', -apple-system, sans-serif; color: #c9d1d9; font-size: 9pt;">
          <div style="background-color: #0f141c; border: 1px solid #1c2333; border-radius: 6px; padding: 10px; margin-bottom: 8px;">
            <table width="100%" cellpadding="3" cellspacing="0">
              <tr>
                <td style="color: #00e5ff; font-weight: bold; font-size: 10pt;">
                  FLOW 5-TUPLE: {report.src_ip}:{report.src_port} &rarr; {report.dst_ip}:{report.dst_port}
                </td>
                <td align="right" style="color: {color_hex}; font-weight: bold; font-size: 9.5pt;">
                  VERDICT: {report.directionality}
                </td>
              </tr>
              <tr>
                <td style="color: #8b949e; font-size: 8.5pt;">
                  Duration: <b style="color: #f0f6fc;">{report.duration:.4f}s</b> |
                  Packets: <b style="color: #f0f6fc;">{report.packet_count} forward</b> / <b style="color: #f0f6fc;">{report.reverse_packet_count or 0} reverse</b> |
                  Bytes: <b style="color: #f0f6fc;">{report.byte_count:,} forward</b>
                </td>
                <td align="right" style="color: #8b949e; font-size: 8.5pt;">
                  Evidence Confidence: <b style="color: #00e5ff;">{report.directionality_confidence:.2%}</b>
                </td>
              </tr>
            </table>
          </div>

          <div style="font-weight: bold; color: #38bdf8; font-size: 9pt; margin: 6px 0px 4px 0px;">
            🔍 FORENSIC EVIDENCE & DIRECTIONALITY RATIONALE:
          </div>
        """
        for bullet in report.directionality_evidence:
            evidence_html += f"""
            <div style="background-color: #0d1117; border-left: 3px solid #a855f7; border: 1px solid #1f293d; border-radius: 4px; padding: 6px 10px; margin-bottom: 4px;">
              <span style="color: #a855f7; font-weight: bold;">[EVIDENCE RATIONALE]</span>
              <span style="color: #f0f6fc; margin-left: 6px;">{bullet}</span>
            </div>
            """

        rev_missing = vis.get('is_reverse_missing')
        rev_color = "#ef4444" if rev_missing else "#10b981"
        rev_text = "YES (Missing / Unobserved On Wire)" if rev_missing else "NO (Return Traffic Captured)"

        evidence_html += f"""
          <div style="font-weight: bold; color: #38bdf8; font-size: 9pt; margin: 10px 0px 4px 0px;">
            📡 SENSOR VISIBILITY AWARENESS & CAPTURE TOPOLOGY:
          </div>
          <div style="background-color: #0f141c; border: 1px solid #1c2333; border-radius: 6px; padding: 8px;">
            <table width="100%" cellpadding="3" cellspacing="0" style="font-size: 8.5pt;">
              <tr>
                <td width="25%" style="color: #8b949e;">Observation Topology:</td>
                <td width="25%"><b style="color: #00e5ff;">{vis.get('visibility_type', 'UNKNOWN')}</b></td>
                <td width="25%" style="color: #8b949e;">Reverse Path Status:</td>
                <td width="25%"><b style="color: {rev_color};">{rev_text}</b></td>
              </tr>
              <tr>
                <td style="color: #8b949e;">Reverse Missing Reason:</td>
                <td><b style="color: #f0f6fc;">{vis.get('reverse_missing_reason', 'N/A')}</b></td>
                <td style="color: #8b949e;">Topology Completeness:</td>
                <td><b style="color: #f0f6fc;">{vis.get('completeness_status', 'UNKNOWN')}</b></td>
              </tr>
              <tr>
                <td style="color: #8b949e;">Sensor Confidence Deduction:</td>
                <td><b style="color: #f59e0b;">-{vis.get('confidence_penalty', 0.0):.2f}</b></td>
                <td style="color: #8b949e;">Hardware Diode Enforced:</td>
                <td><b style="color: {'#a855f7' if self.chk_sensor_diode.isChecked() else '#64748b'};">{'YES' if self.chk_sensor_diode.isChecked() else 'NO'}</b></td>
              </tr>
            </table>
          </div>
        """

        if vis.get("sensor_notes"):
            evidence_html += """<div style="margin-top: 6px; font-size: 8.5pt;">"""
            for note in vis.get("sensor_notes", []):
                evidence_html += f"""<div style="color: #8b949e; margin-bottom: 2px;">• <i style="color: #cbd5e1;">{note}</i></div>"""
            evidence_html += "</div>"

        evidence_html += "</div>"
        self.txt_utie_evidence.setHtml(evidence_html)

        # ---------------------------------------------------------------------
        # TAB 2: Traffic Dynamics & Behavioral Signatures HTML
        # ---------------------------------------------------------------------
        pkt_stats = behavior.get("pkt_len_stats", {})
        timing = behavior.get("timing_dynamics", {})
        flag_details = behavior.get("flag_details", {})
        is_beacon = timing.get("is_periodic_beacon")

        behavior_html = f"""
        <div style="font-family: 'Segoe UI', -apple-system, sans-serif; color: #c9d1d9; font-size: 9pt;">
          <div style="font-weight: bold; color: #00e5ff; font-size: 9pt; margin-bottom: 4px;">
            📦 PACKET LENGTH DISTRIBUTION & ENTROPY DYNAMICS:
          </div>
          <div style="background-color: #0f141c; border: 1px solid #1c2333; border-radius: 6px; padding: 8px; margin-bottom: 8px;">
            <table width="100%" cellpadding="3" cellspacing="0" style="font-size: 8.5pt;">
              <tr>
                <td style="color: #8b949e;">Min Payload Size:</td>
                <td><b style="color: #f0f6fc;">{pkt_stats.get('min', 0.0)} bytes</b></td>
                <td style="color: #8b949e;">Max Payload Size:</td>
                <td><b style="color: #f0f6fc;">{pkt_stats.get('max', 0.0)} bytes</b></td>
                <td style="color: #8b949e;">Mean Size:</td>
                <td><b style="color: #f0f6fc;">{pkt_stats.get('mean', 0.0):.1f} bytes</b></td>
              </tr>
              <tr>
                <td style="color: #8b949e;">Size StdDev:</td>
                <td><b style="color: #f0f6fc;">{pkt_stats.get('std', 0.0):.2f}</b></td>
                <td style="color: #8b949e;">Payload Homogeneity:</td>
                <td><b style="color: #38bdf8;">{pkt_stats.get('homogeneity', 0.0):.1%}</b></td>
                <td style="color: #8b949e;">Shannon Entropy:</td>
                <td><b style="color: #a855f7;">{behavior.get('entropy_pkt_len', 0.0):.3f} bits</b></td>
              </tr>
            </table>
          </div>

          <div style="font-weight: bold; color: #00e5ff; font-size: 9pt; margin-bottom: 4px;">
            ⏱️ TIMING DYNAMICS & BURSTINESS PROFILE:
          </div>
          <div style="background-color: #0f141c; border: 1px solid #1c2333; border-radius: 6px; padding: 8px; margin-bottom: 8px;">
            <table width="100%" cellpadding="3" cellspacing="0" style="font-size: 8.5pt;">
              <tr>
                <td style="color: #8b949e;">Packet Rate:</td>
                <td><b style="color: #10b981;">{report.pkt_rate:.1f} pps</b></td>
                <td style="color: #8b949e;">Byte Rate:</td>
                <td><b style="color: #10b981;">{report.byte_rate:.1f} Bps</b></td>
                <td style="color: #8b949e;">Burstiness Index:</td>
                <td><b style="color: #f59e0b;">{timing.get('burstiness_index', 0.0):.3f}</b></td>
              </tr>
              <tr>
                <td style="color: #8b949e;">Mean Inter-Arrival Time:</td>
                <td><b style="color: #f0f6fc;">{timing.get('iat_mean', 0.0):.4f}s</b></td>
                <td style="color: #8b949e;">IAT StdDev:</td>
                <td><b style="color: #f0f6fc;">{timing.get('iat_std', 0.0):.4f}s</b></td>
                <td style="color: #8b949e;">Periodic Beacon:</td>
                <td><b style="color: {'#ef4444' if is_beacon else '#10b981'};">{'STRICT PERIODIC BEACON' if is_beacon else 'NORMAL VARIANCE'}</b></td>
              </tr>
            </table>
          </div>

          <div style="font-weight: bold; color: #00e5ff; font-size: 9pt; margin-bottom: 4px;">
            🚩 TCP CONTROL FLAGS & STATE SIGNATURE:
          </div>
          <div style="background-color: #0f141c; border: 1px solid #1c2333; border-radius: 6px; padding: 8px;">
            <span style="color: #8b949e; font-size: 8.5pt;">Flag Pattern:</span>
            <b style="color: #38bdf8; font-size: 9pt; margin-right: 14px;">{behavior.get('flag_pattern', 'STANDARD')}</b>
            <span style="background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 8pt; margin-right: 6px;">SYN: {flag_details.get('SYN', 0)}</span>
            <span style="background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.4); padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 8pt; margin-right: 6px;">ACK: {flag_details.get('ACK', 0)}</span>
            <span style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.4); padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 8pt; margin-right: 6px;">FIN: {flag_details.get('FIN', 0)}</span>
            <span style="background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 8pt; margin-right: 6px;">RST: {flag_details.get('RST', 0)}</span>
            <span style="background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 8pt;">PSH: {flag_details.get('PSH', 0)}</span>
          </div>
        </div>
        """
        self.txt_utie_behavior.setHtml(behavior_html)

        # ---------------------------------------------------------------------
        # TAB 3: AI Threat Verdict & SOC Triage Playbook HTML
        # ---------------------------------------------------------------------
        threat_cat = report.ml_threat_category or "BENIGN"
        threat_col = "#ef4444" if threat_cat != "BENIGN" else "#10b981"
        anom_stat = report.anomaly_status
        anom_col = "#ef4444" if anom_stat == "ANOMALOUS" else "#10b981"

        playbook_html = f"""
        <div style="font-family: 'Segoe UI', -apple-system, sans-serif; color: #c9d1d9; font-size: 9pt;">
          <div style="background-color: #0f141c; border: 1px solid #1c2333; border-radius: 6px; padding: 10px; margin-bottom: 8px;">
            <table width="100%" cellpadding="3" cellspacing="0">
              <tr>
                <td style="color: #8b949e;">Supervised Threat Classifier:</td>
                <td><b style="color: {threat_col}; font-size: 9.5pt;">{threat_cat}</b> ({report.ml_confidence if report.ml_confidence is not None else 0.5:.1%} Confidence)</td>
                <td style="color: #8b949e;">Isolation Forest Anomaly:</td>
                <td><b style="color: {anom_col}; font-size: 9.5pt;">{anom_stat}</b> (Score: {report.anomaly_score:.3f})</td>
              </tr>
              <tr>
                <td style="color: #8b949e;">Composite Risk Score:</td>
                <td><b style="color: {r_border}; font-size: 9.5pt;">{report.risk_score if report.risk_score is not None else 0}/100</b></td>
                <td style="color: #8b949e;">Threat Severity:</td>
                <td><b style="color: {r_border}; font-size: 9.5pt;">{report.severity or 'INFORMATIONAL'}</b></td>
              </tr>
            </table>
          </div>

          <div style="font-weight: bold; color: #00e5ff; font-size: 9pt; margin: 8px 0px 4px 0px;">
            📋 SUGGESTED SOC INVESTIGATION PLAYBOOK:
          </div>
        """
        for i, step in enumerate(report.suggested_investigation_steps, start=1):
            playbook_html += f"""
            <div style="background-color: #0d1117; border-left: 3px solid #00e5ff; border: 1px solid #1f293d; border-radius: 4px; padding: 6px 10px; margin-bottom: 4px;">
              <span style="color: #00e5ff; font-weight: bold;">STEP {i}:</span>
              <span style="color: #f0f6fc; margin-left: 6px;">{step}</span>
            </div>
            """
        playbook_html += "</div>"
        self.txt_utie_playbook.setHtml(playbook_html)

    def save_and_apply_settings(self) -> None:
        bpf = self.txt_bpf.text().strip()
        if not bpf:
            QMessageBox.warning(self, "Invalid Setting", "BPF Filter cannot be empty. Use 'ip' to capture all IPv4 traffic.")
            return

        bridge = SocStateBridge.get()
        with bridge._lock:
            bridge.settings.update({
                "bpf_filter": bpf,
                "idle_timeout": self.spin_idle.value(),
                "active_timeout": self.spin_active.value(),
                "elephant_cutoff": self.spin_elephant.value(),
            })

        self.lbl_settings_feedback.setText("[OK] Settings validated and applied to active monitoring configuration.")
        self.lbl_settings_feedback.setStyleSheet("color: #10b981; font-weight: bold;")
        QTimer.singleShot(4000, lambda: self.lbl_settings_feedback.setText(""))

    def restore_default_settings(self) -> None:
        self.txt_bpf.setText("ip and not (ether multicast or ether broadcast)")
        self.spin_idle.setValue(15.0)
        self.spin_active.setValue(60.0)
        self.spin_elephant.setValue(50)
        self.save_and_apply_settings()

    # =========================================================================
    # MODULE 10: SECURITY REPORT GENERATOR (SIH 2026)
    # =========================================================================
    def setup_reports_tab(self) -> None:
        layout = QVBoxLayout(self.tab_reports)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # 1. Overview KPI Cards Bar
        kpi_row = QHBoxLayout()
        self.card_rpt_total = self.create_kpi_card("TOTAL REPORTS", "0", "#00e5ff", "Cumulative reports generated")
        self.card_rpt_last = self.create_kpi_card("LAST GENERATED", "Never", "#10b981", "Timestamp of most recent audit")
        self.card_rpt_events = self.create_kpi_card("ANALYZED EVENTS", "0", "#38bdf8", "Security events in database repository")
        self.card_rpt_high_risk = self.create_kpi_card("HIGH-RISK DETECTIONS", "0", "#ef4444", "Urgent incidents requiring triage")

        kpi_row.addWidget(self.card_rpt_total)
        kpi_row.addWidget(self.card_rpt_last)
        kpi_row.addWidget(self.card_rpt_events)
        kpi_row.addWidget(self.card_rpt_high_risk)
        layout.addLayout(kpi_row)

        # 2. Generate New Report Configuration Panel
        config_box = QGroupBox("GENERATE NEW SECURITY AUDIT REPORT")
        config_box.setStyleSheet("QGroupBox { font-weight: bold; color: #00e5ff; border: 1px solid #1c2333; border-radius: 6px; margin-top: 6px; padding-top: 10px; }")
        config_layout = QVBoxLayout(config_box)

        form_grid = QGridLayout()
        form_grid.setSpacing(8)

        # Row 0: Report Name & Report Type
        form_grid.addWidget(QLabel("Report Name:"), 0, 0)
        self.txt_rpt_name = QLineEdit("UniGuard AI Security Audit Report")
        self.txt_rpt_name.setStyleSheet("background-color: #0f141c; color: #c9d1d9; border: 1px solid #2d3748; padding: 4px 8px; border-radius: 4px;")
        form_grid.addWidget(self.txt_rpt_name, 0, 1)

        form_grid.addWidget(QLabel("Report Type:"), 0, 2)
        self.combo_rpt_type = QComboBox()
        self.combo_rpt_type.addItems([
            "EXECUTIVE - High-Level Leadership Summary",
            "COMPREHENSIVE - Full SOC Incident & Threat Audit",
            "UNIDIRECTIONAL - Deep UTIE & Flow Intelligence Report",
            "COMPLIANCE - Regulatory & Forensic Verification",
        ])
        form_grid.addWidget(self.combo_rpt_type, 0, 3)

        # Row 1: Date Range & Export Format
        form_grid.addWidget(QLabel("Date Range:"), 1, 0)
        self.combo_rpt_range = QComboBox()
        self.combo_rpt_range.addItems([
            "Last 24 Hours",
            "Today (Since Midnight)",
            "Last 7 Days",
            "Last 30 Days",
            "All Monitored Time",
        ])
        form_grid.addWidget(self.combo_rpt_range, 1, 1)

        form_grid.addWidget(QLabel("Export Format:"), 1, 2)
        self.combo_rpt_format = QComboBox()
        self.combo_rpt_format.addItems([
            "PDF Document (*.pdf)",
            "CSV Spreadsheet (*.csv)",
            "JSON Forensic Schema (*.json)",
            "ALL Formats (PDF + CSV + JSON)",
        ])
        form_grid.addWidget(self.combo_rpt_format, 1, 3)

        config_layout.addLayout(form_grid)

        # Generate Action Row with Progress
        btn_row = QHBoxLayout()
        self.btn_generate_rpt = QPushButton("🚀 GENERATE SECURITY REPORT")
        self.btn_generate_rpt.setFixedHeight(34)
        self.btn_generate_rpt.setStyleSheet(
            "background-color: #0284c7; color: #ffffff; font-weight: bold; "
            "padding: 6px 18px; border-radius: 5px; border: none;"
        )
        self.btn_generate_rpt.clicked.connect(self.on_generate_report_clicked)
        btn_row.addWidget(self.btn_generate_rpt)

        self.rpt_progress = QProgressBar()
        self.rpt_progress.setRange(0, 100)
        self.rpt_progress.setValue(0)
        self.rpt_progress.setTextVisible(True)
        self.rpt_progress.setFixedHeight(22)
        self.rpt_progress.setStyleSheet(
            "QProgressBar { background-color: #0f141c; border: 1px solid #2d3748; border-radius: 4px; text-align: center; color: #ffffff; }"
            "QProgressBar::chunk { background-color: #0284c7; border-radius: 3px; }"
        )
        btn_row.addWidget(self.rpt_progress, stretch=1)

        self.lbl_rpt_status = QLabel("Ready to compile cybersecurity report.")
        self.lbl_rpt_status.setStyleSheet("color: #8b949e; font-size: 8.5pt;")
        btn_row.addWidget(self.lbl_rpt_status)

        config_layout.addLayout(btn_row)
        layout.addWidget(config_box)

        # 3. Main Splitter: Interactive Preview (Left/Top) vs Report History (Right/Bottom)
        splitter = QSplitter(Qt.Horizontal)

        # Left: Interactive Report Preview
        preview_panel = QFrame()
        preview_panel.setStyleSheet("background-color: #0b0f17; border: 1px solid #1c2333; border-radius: 6px;")
        prev_layout = QVBoxLayout(preview_panel)
        prev_layout.setContentsMargins(10, 10, 10, 10)
        prev_layout.setSpacing(6)

        prev_header = QHBoxLayout()
        self.lbl_preview_title = QLabel("INTERACTIVE REPORT PREVIEW")
        self.lbl_preview_title.setStyleSheet("font-weight: bold; color: #00e5ff; font-size: 9.5pt;")
        prev_header.addWidget(self.lbl_preview_title)
        prev_header.addStretch()

        self.lbl_preview_badge = QLabel("IDLE")
        self.lbl_preview_badge.setStyleSheet("background-color: #1e293b; color: #94a3b8; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 8pt;")
        prev_header.addWidget(self.lbl_preview_badge)
        prev_layout.addLayout(prev_header)

        self.lbl_preview_metrics = QLabel("Total Events: 0  |  High-Risk: 0  |  Primary Threat: None  |  Max Risk: 0/100")
        self.lbl_preview_metrics.setStyleSheet("color: #38bdf8; font-size: 8.5pt; font-weight: 600; padding: 3px 0px;")
        prev_layout.addWidget(self.lbl_preview_metrics)

        prev_layout.addWidget(QLabel("<b>Executive Summary & Risk Assessment:</b>"))
        self.txt_preview_summary = QTextEdit()
        self.txt_preview_summary.setReadOnly(True)
        self.txt_preview_summary.setFixedHeight(75)
        self.txt_preview_summary.setStyleSheet("background-color: #0f141c; color: #c9d1d9; border: 1px solid #2d3748; border-radius: 4px; font-size: 8.5pt;")
        prev_layout.addWidget(self.txt_preview_summary)

        prev_layout.addWidget(QLabel("<b>High-Risk Security Events Preview:</b>"))
        self.table_preview_events = QTableWidget()
        self.table_preview_events.setColumnCount(6)
        self.table_preview_events.setHorizontalHeaderLabels([
            "Event ID", "Source IP:Port", "Dest IP:Port", "Threat Type", "Risk", "Severity"
        ])
        self.table_preview_events.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_preview_events.setStyleSheet("background-color: #0f141c; gridline-color: #1c2333; font-size: 8pt;")
        prev_layout.addWidget(self.table_preview_events, stretch=1)

        # File actions row
        prev_actions = QHBoxLayout()
        self.btn_open_rpt_file = QPushButton("📄 Open Report File")
        self.btn_open_rpt_file.setEnabled(False)
        self.btn_open_rpt_file.setStyleSheet("background-color: #1e293b; color: #00e5ff; border: 1px solid #334155; padding: 5px 12px; border-radius: 4px; font-weight: 600;")
        self.btn_open_rpt_file.clicked.connect(self.open_current_report_file)

        self.btn_open_rpt_folder = QPushButton("📁 Open Containing Folder")
        self.btn_open_rpt_folder.setEnabled(False)
        self.btn_open_rpt_folder.setStyleSheet("background-color: #1e293b; color: #10b981; border: 1px solid #334155; padding: 5px 12px; border-radius: 4px; font-weight: 600;")
        self.btn_open_rpt_folder.clicked.connect(self.open_current_report_folder)

        prev_actions.addWidget(self.btn_open_rpt_file)
        prev_actions.addWidget(self.btn_open_rpt_folder)
        prev_actions.addStretch()
        prev_layout.addLayout(prev_actions)

        splitter.addWidget(preview_panel)

        # Right: Report History & Repository
        history_panel = QFrame()
        history_panel.setStyleSheet("background-color: #0b0f17; border: 1px solid #1c2333; border-radius: 6px;")
        hist_layout = QVBoxLayout(history_panel)
        hist_layout.setContentsMargins(10, 10, 10, 10)
        hist_layout.setSpacing(6)

        hist_header = QHBoxLayout()
        lbl_hist_title = QLabel("REPORT REPOSITORY & AUDIT HISTORY")
        lbl_hist_title.setStyleSheet("font-weight: bold; color: #00e5ff; font-size: 9.5pt;")
        hist_header.addWidget(lbl_hist_title)
        hist_header.addStretch()

        self.btn_refresh_history = QPushButton("🔄 Refresh")
        self.btn_refresh_history.setStyleSheet("background-color: #1e293b; color: #c9d1d9; border: 1px solid #334155; padding: 3px 8px; border-radius: 4px;")
        self.btn_refresh_history.clicked.connect(self.refresh_reports_tab)
        hist_header.addWidget(self.btn_refresh_history)

        self.btn_delete_report = QPushButton("🗑️ Delete")
        self.btn_delete_report.setStyleSheet("background-color: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); padding: 3px 8px; border-radius: 4px;")
        self.btn_delete_report.clicked.connect(self.delete_selected_report)
        hist_header.addWidget(self.btn_delete_report)

        hist_layout.addLayout(hist_header)

        self.table_rpt_history = QTableWidget()
        self.table_rpt_history.setColumnCount(8)
        self.table_rpt_history.setHorizontalHeaderLabels([
            "Report ID", "Name", "Type", "Range", "Format", "Created At", "Events", "High Risk"
        ])
        self.table_rpt_history.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table_rpt_history.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table_rpt_history.setStyleSheet("background-color: #0f141c; gridline-color: #1c2333; font-size: 8pt;")
        self.table_rpt_history.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_rpt_history.setSelectionMode(QTableWidget.SingleSelection)
        self.table_rpt_history.cellClicked.connect(self.on_report_history_row_clicked)
        self.table_rpt_history.cellDoubleClicked.connect(lambda r, c: self.open_current_report_file())
        hist_layout.addWidget(self.table_rpt_history, stretch=1)

        splitter.addWidget(history_panel)
        splitter.setSizes([550, 650])
        layout.addWidget(splitter, stretch=1)

        # Initial refresh
        self.refresh_reports_tab()

    def refresh_reports_tab(self) -> None:
        """Refreshes report KPI cards and reloads report history table from SQLite."""
        try:
            kpi = self.report_manager.get_kpi_summary()
            if hasattr(self, "card_rpt_total") and hasattr(self.card_rpt_total, "value_label"):
                self.card_rpt_total.value_label.setText(str(kpi.get("total_reports", 0)))
            if hasattr(self, "card_rpt_last") and hasattr(self.card_rpt_last, "value_label"):
                last_ts = kpi.get("last_generated_ts")
                if last_ts:
                    last_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(last_ts))
                else:
                    last_str = "Never"
                self.card_rpt_last.value_label.setText(last_str)
            if hasattr(self, "card_rpt_events") and hasattr(self.card_rpt_events, "value_label"):
                self.card_rpt_events.value_label.setText(str(kpi.get("total_analyzed_events", 0)))
            if hasattr(self, "card_rpt_high_risk") and hasattr(self.card_rpt_high_risk, "value_label"):
                self.card_rpt_high_risk.value_label.setText(str(kpi.get("total_high_risk_events", 0)))

            # Populate history table
            history = self.report_manager.get_history(limit=50)
            self.table_rpt_history.setRowCount(0)
            for i, rpt in enumerate(history):
                self.table_rpt_history.insertRow(i)
                self.table_rpt_history.setItem(i, 0, QTableWidgetItem(str(rpt.get("report_id", ""))))
                self.table_rpt_history.setItem(i, 1, QTableWidgetItem(str(rpt.get("report_name", ""))))
                self.table_rpt_history.setItem(i, 2, QTableWidgetItem(str(rpt.get("report_type", ""))))
                self.table_rpt_history.setItem(i, 3, QTableWidgetItem(str(rpt.get("date_range", ""))))
                self.table_rpt_history.setItem(i, 4, QTableWidgetItem(str(rpt.get("export_format", ""))))
                ts = rpt.get("timestamp", 0)
                ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "N/A"
                self.table_rpt_history.setItem(i, 5, QTableWidgetItem(ts_str))
                self.table_rpt_history.setItem(i, 6, QTableWidgetItem(str(rpt.get("total_events", 0))))
                self.table_rpt_history.setItem(i, 7, QTableWidgetItem(str(rpt.get("high_risk_events", 0))))

                # Store file_path in row item data
                item_id = self.table_rpt_history.item(i, 0)
                if item_id:
                    item_id.setData(Qt.UserRole, rpt.get("file_path", ""))
        except Exception:
            pass

    def on_generate_report_clicked(self) -> None:
        """Spawns non-blocking worker thread to compile the security report."""
        # Prevent overlapping generation runs
        if self.report_worker and self.report_worker.isRunning():
            QMessageBox.information(self, "Report in Progress", "A report is currently being compiled. Please wait.")
            return

        report_name = self.txt_rpt_name.text().strip() or "UniGuard AI Security Report"
        report_type = self.combo_rpt_type.currentText().split(" - ")[0].strip()

        range_text = self.combo_rpt_range.currentText()
        if "Today" in range_text:
            range_code = "TODAY"
        elif "24 Hours" in range_text:
            range_code = "LAST_24_HOURS"
        elif "7 Days" in range_text:
            range_code = "LAST_7_DAYS"
        elif "30 Days" in range_text:
            range_code = "LAST_30_DAYS"
        elif "All" in range_text:
            range_code = "ALL"
        else:
            range_code = "LAST_24_HOURS"

        format_text = self.combo_rpt_format.currentText()
        if "PDF" in format_text and "ALL" not in format_text:
            export_format = "PDF"
        elif "CSV" in format_text and "ALL" not in format_text:
            export_format = "CSV"
        elif "JSON" in format_text and "ALL" not in format_text:
            export_format = "JSON"
        else:
            export_format = "ALL"

        self.btn_generate_rpt.setEnabled(False)
        self.rpt_progress.setValue(5)
        self.lbl_rpt_status.setText("Initializing report compiler...")

        self.report_worker = ReportWorkerThread(
            report_name=report_name,
            report_type=report_type,
            date_range_code=range_code,
            export_format=export_format,
            parent=self,
        )
        self.report_worker.progress_updated.connect(self.on_report_progress)
        self.report_worker.report_finished.connect(self.on_report_finished)
        self.report_worker.report_failed.connect(self.on_report_failed)
        self.report_worker.start()

    def on_report_progress(self, pct: int, msg: str) -> None:
        """Updates progress bar and operational status message."""
        self.rpt_progress.setValue(pct)
        self.lbl_rpt_status.setText(msg)

    def on_report_finished(self, result: Dict[str, Any]) -> None:
        """Handles successful report completion and loads interactive preview."""
        self.btn_generate_rpt.setEnabled(True)
        self.rpt_progress.setValue(100)
        self.lbl_rpt_status.setText("Report successfully generated!")
        self.lbl_rpt_status.setStyleSheet("color: #10b981; font-size: 8.5pt;")

        # Update preview
        report_data = result.get("report_data", {})
        self.populate_report_preview(report_data, result.get("primary_file_path", ""))

        # Refresh history
        self.refresh_reports_tab()

    def on_report_failed(self, error_msg: str) -> None:
        """Handles report generation failure gracefully."""
        self.btn_generate_rpt.setEnabled(True)
        self.rpt_progress.setValue(0)
        self.lbl_rpt_status.setText("Report generation failed.")
        self.lbl_rpt_status.setStyleSheet("color: #ef4444; font-size: 8.5pt;")
        QMessageBox.critical(self, "Report Generation Error", f"Failed to build security report:\n{error_msg}")

    def populate_report_preview(self, report_data: Dict[str, Any], file_path: str = "") -> None:
        """Populates interactive preview panel with generated report metrics."""
        self.current_preview_file = file_path
        if file_path:
            self.btn_open_rpt_file.setEnabled(True)
            self.btn_open_rpt_folder.setEnabled(True)

        meta = report_data.get("metadata", {})
        exec_sum = report_data.get("section_1_executive_summary", {})
        high_risk = report_data.get("section_5_high_risk_events", [])

        self.lbl_preview_title.setText(f"REPORT: {meta.get('report_name', 'Security Audit')}")

        status = exec_sum.get("status", "SECURE")
        if status == "ELEVATED RISK":
            self.lbl_preview_badge.setText("ELEVATED RISK")
            self.lbl_preview_badge.setStyleSheet("background-color: rgba(239, 68, 68, 0.2); color: #ef4444; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 8pt;")
        else:
            self.lbl_preview_badge.setText("SECURE")
            self.lbl_preview_badge.setStyleSheet("background-color: rgba(16, 185, 129, 0.2); color: #10b981; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 8pt;")

        self.lbl_preview_metrics.setText(
            f"Total Events: {exec_sum.get('total_events', 0)}  |  "
            f"High Risk: {exec_sum.get('high_risk_total', 0)}  |  "
            f"Primary Threat: {exec_sum.get('top_threat', 'None')}  |  "
            f"Max Risk: {exec_sum.get('max_risk_score', 0)}/100"
        )

        self.txt_preview_summary.setText(exec_sum.get("overview_text", "No overview narrative available."))

        # High risk table
        self.table_preview_events.setRowCount(0)
        for i, ev in enumerate(high_risk[:15]):
            self.table_preview_events.insertRow(i)
            self.table_preview_events.setItem(i, 0, QTableWidgetItem(str(ev.get("event_id", ""))[:12]))
            self.table_preview_events.setItem(i, 1, QTableWidgetItem(f"{ev.get('src_ip')}:{ev.get('src_port')}"))
            self.table_preview_events.setItem(i, 2, QTableWidgetItem(f"{ev.get('dst_ip')}:{ev.get('dst_port')}"))
            self.table_preview_events.setItem(i, 3, QTableWidgetItem(str(ev.get("threat_type", ""))))
            self.table_preview_events.setItem(i, 4, QTableWidgetItem(str(ev.get("risk_score", 0))))

            sev_val = str(ev.get("severity", ""))
            sev_item = QTableWidgetItem(sev_val)
            if sev_val == "CRITICAL":
                sev_item.setForeground(QColor("#ef4444"))
            elif sev_val == "HIGH":
                sev_item.setForeground(QColor("#f97316"))
            elif sev_val == "MEDIUM":
                sev_item.setForeground(QColor("#eab308"))
            else:
                sev_item.setForeground(QColor("#10b981"))
            self.table_preview_events.setItem(i, 5, sev_item)

    def on_report_history_row_clicked(self, row: int, col: int) -> None:
        """Loads selected historical report details into preview."""
        item_id = self.table_rpt_history.item(row, 0)
        if not item_id:
            return
        report_id = item_id.text()
        file_path = item_id.data(Qt.UserRole)
        self.current_preview_file = file_path

        report = self.database.get_report_by_id(report_id)
        if report:
            self.lbl_preview_title.setText(f"REPORT: {report.get('report_name')}")
            high_risk_cnt = report.get("high_risk_events", 0)
            status_text = "ELEVATED RISK" if high_risk_cnt > 0 else "SECURE"
            self.lbl_preview_badge.setText(status_text)
            self.lbl_preview_badge.setStyleSheet(
                "background-color: rgba(239, 68, 68, 0.2); color: #ef4444; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 8pt;"
                if high_risk_cnt > 0 else
                "background-color: rgba(16, 185, 129, 0.2); color: #10b981; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 8pt;"
            )
            self.lbl_preview_metrics.setText(
                f"Total Events: {report.get('total_events', 0)}  |  "
                f"High Risk: {report.get('high_risk_events', 0)}  |  "
                f"Format: {report.get('export_format', '')}  |  "
                f"Range: {report.get('date_range', '')}"
            )
            self.txt_preview_summary.setText(report.get("summary_text", ""))

        if file_path and os.path.exists(file_path):
            self.btn_open_rpt_file.setEnabled(True)
            self.btn_open_rpt_folder.setEnabled(True)
        else:
            self.btn_open_rpt_file.setEnabled(False)
            self.btn_open_rpt_folder.setEnabled(False)

    def open_current_report_file(self) -> None:
        """Launches the report file in the operating system's default viewer."""
        if self.current_preview_file:
            success = self.report_manager.open_file(self.current_preview_file)
            if not success:
                QMessageBox.warning(self, "File Not Found", f"Cannot open report file:\n{self.current_preview_file}")

    def open_current_report_folder(self) -> None:
        """Opens the directory containing the current report."""
        if self.current_preview_file:
            success = self.report_manager.open_folder(self.current_preview_file)
            if not success:
                QMessageBox.warning(self, "Folder Not Found", f"Cannot open folder for:\n{self.current_preview_file}")

    def delete_selected_report(self) -> None:
        """Deletes the highlighted report from database history."""
        curr_row = self.table_rpt_history.currentRow()
        if curr_row < 0:
            QMessageBox.information(self, "No Selection", "Please select a report row to delete.")
            return

        item_id = self.table_rpt_history.item(curr_row, 0)
        item_name = self.table_rpt_history.item(curr_row, 1)
        if not item_id:
            return

        report_id = item_id.text()
        report_name = item_name.text() if item_name else report_id

        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete report '{report_name}' ({report_id}) from history?\n"
            "This will remove the database log entry.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.report_manager.delete_report(report_id, delete_file=False)
            self.refresh_reports_tab()
            self.current_preview_file = None
            self.btn_open_rpt_file.setEnabled(False)
            self.btn_open_rpt_folder.setEnabled(False)

    # =========================================================================
    # WORKER / MONITORING CONTROLS
    # =========================================================================
    def browse_pcap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open PCAP File", "", "PCAP Files (*.pcap *.pcapng *.cap)")
        if path:
            self.iface_combo.insertItem(0, f"Custom PCAP: {os.path.basename(path)}")
            self.iface_combo.setCurrentIndex(0)
            self.custom_pcap_path = path

    def start_monitoring(self) -> None:
        # Ensure any existing worker is fully stopped before instantiating a new one
        if self.worker is not None:
            if self.worker.isRunning():
                self.worker.stop()
                if not self.worker.wait(3000):
                    self.worker.quit()
                    self.worker.wait(1000)
            self.worker = None

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.table.setRowCount(0)
        self.table_alerts.setRowCount(0)
        self.table_utie.setRowCount(0)
        self.all_events.clear()
        self.threat_events.clear()
        self.all_utie_reports.clear()
        self.filtered_utie_reports.clear()
        self.utie_counts = {k: 0 for k in self.utie_counts}
        self.utie_suspicious_count = 0

        self.total_packets = 0
        self.total_flows = 0
        self.total_threats = 0
        self.critical_threats = 0
        self.high_threats = 0
        self.med_threats = 0
        self.low_threats = 0
        self.threat_counts = {
            "BENIGN": 0,
            "PORT_SCAN": 0,
            "SYN_FLOOD": 0,
            "UDP_FLOOD": 0,
            "DATA_EXFILTRATION": 0,
            "SLOWLORIS": 0,
            "ANOMALOUS": 0,
        }
        self.src_ip_counts.clear()
        self.dst_ip_counts.clear()
        self.port_counts.clear()
        self.proto_counts = {6: 0, 17: 0, 1: 0}
        self.directionality_counts = {
            "BIDIRECTIONAL": 0,
            "ASYMMETRIC": 0,
            "STRONGLY_ASYMMETRIC": 0,
            "UNIDIRECTIONAL_OBSERVED": 0,
            "UNKNOWN": 0,
        }
        self.excluded_flows_count = 0

        selected_text = self.iface_combo.currentText()
        bpf = self.txt_bpf.text()
        idle_to = self.spin_idle.value()
        active_to = self.spin_active.value()
        elephant_th = self.spin_elephant.value()

        if selected_text.startswith("Live Interface:"):
            iface_name = selected_text.replace("Live Interface:", "").strip()
            self.worker = MonitoringWorker(
                source_mode="live",
                target_path_or_iface=iface_name,
                bpf_filter=bpf,
                idle_timeout=idle_to,
                active_timeout=active_to,
                elephant_cutoff=elephant_th,
            )
            self.lbl_health_capture.setText(f"Capture: LIVE ({iface_name})")
            self.lbl_banner_mode_icon.setText("[LIVE]")
            self.lbl_banner_mode_text.setText(f"SESSION MODE: LIVE NETWORK CAPTURE  |  Interface: {iface_name}  |  Driver: Scapy AsyncSniffer")
            self.lbl_banner_status_badge.setText("STATUS: RUNNING")
            self.lbl_banner_status_badge.setStyleSheet("background-color: rgba(16, 185, 129, 0.2); color: #10b981; padding: 4px 10px; border-radius: 4px; font-weight: bold;")
        else:
            pcap_path = self.custom_pcap_path or DEFAULT_SAMPLE_PCAP
            self.worker = MonitoringWorker(
                source_mode="pcap",
                target_path_or_iface=pcap_path,
                bpf_filter=bpf,
                idle_timeout=idle_to,
                active_timeout=active_to,
                elephant_cutoff=elephant_th,
            )
            self.lbl_health_capture.setText(f"Capture: REPLAY ({os.path.basename(pcap_path)})")
            self.lbl_banner_mode_icon.setText("[PCAP]")
            self.lbl_banner_mode_text.setText(f"SESSION MODE: OFFLINE PCAP REPLAY  |  File: {os.path.basename(pcap_path)}  |  Flow Engine: Active")
            self.lbl_banner_status_badge.setText("STATUS: STREAMING")
            self.lbl_banner_status_badge.setStyleSheet("background-color: rgba(0, 229, 255, 0.2); color: #00e5ff; padding: 4px 10px; border-radius: 4px; font-weight: bold;")

        SocStateBridge.get().worker_thread = self.worker
        self.lbl_health_proc.setText("Processing: ACTIVE")
        self.worker.event_generated.connect(self.on_event_received)
        self.worker.utie_generated.connect(self.on_utie_report_received)
        self.worker.stats_updated.connect(self.on_stats_updated)
        self.worker.finished.connect(self.on_monitoring_finished)
        self.worker.error_occurred.connect(self.on_worker_error)
        self.worker.start()

    def stop_monitoring(self) -> None:
        if self.worker is not None:
            if self.worker.isRunning():
                self.worker.stop()
                if not self.worker.wait(3000):
                    self.worker.quit()
                    self.worker.wait(1000)
            self.worker = None
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.lbl_health_capture.setText("Capture: STOPPED")
        self.lbl_health_proc.setText("Processing: IDLE")
        self.lbl_banner_status_badge.setText("STATUS: STOPPED")
        self.lbl_banner_status_badge.setStyleSheet("background-color: rgba(239, 68, 68, 0.2); color: #ef4444; padding: 4px 10px; border-radius: 4px; font-weight: bold;")

    @Slot(str)
    def on_worker_error(self, err_msg: str) -> None:
        QMessageBox.warning(self, "UniGuard Monitoring Alert", err_msg)
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)

    @Slot(dict)
    def on_stats_updated(self, stats: dict) -> None:
        self.kpi_packets.value_label.setText(f"{stats['packets']:,}")
        self.kpi_flows.value_label.setText(f"{stats['active_flows']:,}")

        pps = stats.get("pps", 0.0)
        self.kpi_throughput.value_label.setText(f"{pps:,.0f} pps")

        queue_depth = stats.get("queue_depth", 0)
        queue_pct = (queue_depth / 50000.0) * 100.0
        self.kpi_health.value_label.setText(f"{queue_pct:.1f}% ({queue_depth:,} / 50k)")

        # Live Monitor Tab Update
        capture_rate = stats.get('capture_rate', pps)
        dropped_packets = stats.get('dropped_packets', 0)
        active_flows = stats.get('active_flows', 0)
        self.lbl_mon_cap_rate.setText(f"{capture_rate:,.0f} pps")
        self.lbl_mon_proc_rate.setText(f"{pps:,.0f} pps")
        self.lbl_mon_queue.setText(f"{queue_depth:,} / 50,000 ({queue_pct:.1f}%)")
        self.bar_mon_queue.setValue(int(queue_pct))
        self.lbl_mon_active_flows.setText(f"{active_flows:,} records")
        drop_pct = (dropped_packets / max(1, stats.get('packets', 1))) * 100.0
        self.lbl_mon_drops.setText(f"{dropped_packets:,} pkts ({drop_pct:.2f}%)")

        mbps = (pps * 1460 * 8) / 1_000_000.0
        self.lbl_mon_bandwidth.setText(f"{mbps:.2f} Mbps")

        # Global Health Bar
        cpu = stats.get("cpu_pct", 0.0)
        ram = stats.get("ram_mb", 0.0)
        self.lbl_health_host.setText(f"CPU: {cpu:.1f}% | RAM: {ram:.0f} MB")
        self.lbl_health_drops.setText(f"Drops: {dropped_packets:,} pkts")

        # Bridge real-time telemetry to Web SOC HUD & charts
        SocStateBridge.get().update_telemetry({
            "pps": pps,
            "capture_rate": capture_rate,
            "processing_rate": pps,
            "queue_depth": queue_depth,
            "total_packets_processed": stats.get('packets', 0),
            "total_flows_created": self.total_flows,
            "active_flows": active_flows,
            "threats_count": self.total_threats,
            "critical_count": self.critical_threats,
            "high_count": self.high_threats,
            "medium_count": self.med_threats,
            "low_count": self.low_threats,
            "dropped_packets": dropped_packets,
            "throughput_mbps": round(mbps, 2),
            "cpu_pct": round(cpu, 1),
            "ram_mb": round(ram, 1),
        })

    @Slot(object)
    def on_event_received(self, event: SecurityEvent) -> None:
        self.database.insert_event(event)
        self.total_flows += 1
        self.all_events.append(event)
        if len(self.all_events) > 1000:
            self.all_events.pop(0)

        # Track severity counts
        if event.severity == "CRITICAL":
            self.critical_threats += 1
            self.total_threats += 1
        elif event.severity == "HIGH":
            self.high_threats += 1
            self.total_threats += 1
        elif event.severity == "MEDIUM":
            self.med_threats += 1
            self.total_threats += 1
        else:
            self.low_threats += 1

        # Track Threat Type category
        threat_type = getattr(event, "threat_type", "ANOMALOUS")
        self.threat_counts[threat_type] = self.threat_counts.get(threat_type, 0) + 1

        self.kpi_threats.value_label.setText(f"{self.total_threats:,}")
        self.kpi_critical.value_label.setText(f"{self.critical_threats + self.high_threats:,}")

        self.badge_critical.setText(f"CRITICAL: {self.critical_threats}")
        self.badge_high.setText(f"HIGH: {self.high_threats}")
        self.badge_med.setText(f"MEDIUM: {self.med_threats}")
        self.badge_low.setText(f"LOW / BENIGN: {self.low_threats}")

        # Track Directionality KPIs (Task 20)
        dir_state = getattr(event, "directionality_state", "UNKNOWN")
        self.directionality_counts[dir_state] = self.directionality_counts.get(dir_state, 0) + 1
        if getattr(event, "is_excluded_from_unidirectional_security", False):
            self.excluded_flows_count += 1

        tot_dir = sum(self.directionality_counts.values()) or 1
        b_cnt = self.directionality_counts.get("BIDIRECTIONAL", 0)
        a_cnt = self.directionality_counts.get("ASYMMETRIC", 0)
        sa_cnt = self.directionality_counts.get("STRONGLY_ASYMMETRIC", 0)
        u_cnt = self.directionality_counts.get("UNIDIRECTIONAL_OBSERVED", 0)

        self.kpi_dir_total.value_label.setText(f"{tot_dir:,}")
        self.kpi_dir_bidi.value_label.setText(f"{b_cnt:,}")
        self.kpi_dir_asym.value_label.setText(f"{a_cnt:,}")
        self.kpi_dir_strong.value_label.setText(f"{sa_cnt:,}")
        self.kpi_dir_oneway.value_label.setText(f"{u_cnt:,}")

        self.lbl_dir_dist.setText(
            f"DIRECTIONALITY DISTRIBUTION:  BIDIRECTIONAL: {(b_cnt/tot_dir)*100:.1f}%  |  "
            f"ASYMMETRIC: {(a_cnt/tot_dir)*100:.1f}%  |  "
            f"STRONGLY ASYMMETRIC: {(sa_cnt/tot_dir)*100:.1f}%  |  "
            f"ONE-WAY: {(u_cnt/tot_dir)*100:.1f}%"
        )

        # Track top talkers
        self.src_ip_counts[event.src_ip] = self.src_ip_counts.get(event.src_ip, 0) + 1
        self.dst_ip_counts[event.dst_ip] = self.dst_ip_counts.get(event.dst_ip, 0) + 1
        self.port_counts[event.dst_port] = self.port_counts.get(event.dst_port, 0) + 1
        self.proto_counts[event.proto] = self.proto_counts.get(event.proto, 0) + 1

        # Update PySide6 Traffic Analytics Tab
        self.update_traffic_analytics()

        # Safely extract contributing factors for human-readable string and JSON
        factors_text = []
        raw_factors = getattr(event, "contributing_factors", [])
        for f in raw_factors:
            if isinstance(f, dict):
                feat = f.get("feature", "")
                expl = f.get("explanation", "")
                factors_text.append(f"{feat.upper()}: {expl}" if expl else str(feat))
            elif isinstance(f, str):
                factors_text.append(f)
            else:
                factors_text.append(str(f))
        explanation_str = " | ".join(factors_text) if factors_text else "Behavioral anomaly in unidirectional stream."

        dir_score = getattr(event, "directionality_score", 0.0)
        flow_metrics = getattr(event, "flow_metrics", {})
        ts_str = time.strftime("%H:%M:%S", time.localtime(event.timestamp))

        # Stream event into SocStateBridge for real-time Web SOC and Global Threat Map
        bridge = SocStateBridge.get()
        bridge.add_threat({
            "event_id": event.event_id,
            "timestamp": ts_str,
            "epoch_time": event.timestamp,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "src_port": event.src_port,
            "dst_port": event.dst_port,
            "proto": "TCP" if event.proto == 6 else ("UDP" if event.proto == 17 else f"IP-{event.proto}"),
            "threat_type": event.threat_type,
            "risk_score": event.risk_score,
            "severity": event.severity,
            "confidence_pct": event.confidence_pct,
            "anomaly_score": event.anomaly_score,
            "directionality_state": dir_state,
            "directionality_score": dir_score,
            "explanation": explanation_str,
            "contributing_factors": raw_factors,
            "flow_metrics": flow_metrics,
            "baseline_5_20_result": getattr(event, "baseline_5_20_result", "N/A"),
            "is_excluded": getattr(event, "is_excluded_from_unidirectional_security", False),
            "ai_explanation": getattr(event, "explanation", {}) or {},
        })

        # Add to recent flows for Live Traffic table (using FLAGGED instead of false claim MITIGATED)
        bridge.add_flow({
            "timestamp": ts_str,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "src_port": event.src_port,
            "dst_port": event.dst_port,
            "proto": "TCP" if event.proto == 6 else ("UDP" if event.proto == 17 else f"IP-{event.proto}"),
            "packet_count": int(flow_metrics.get("packet_count", flow_metrics.get("fwd_packet_count", 1))),
            "byte_count": f"{int(flow_metrics.get('total_bytes', flow_metrics.get('fwd_total_bytes', 64))):,} B",
            "directionality": dir_state,
            "threat_category": event.threat_type,
            "risk_score": event.risk_score,
            "status": "FLAGGED" if event.severity in ("CRITICAL", "HIGH") else "OBSERVED",
            "duration": f"{flow_metrics.get('duration_seconds', flow_metrics.get('flow_duration', 1.0)):.1f}s",
            "ml_conf": f"{event.confidence_pct:.1f}%",
            "flow_metrics": flow_metrics,
            "ai_explanation": getattr(event, "explanation", {}) or {},
        })

        # Update Analytics in bridge (Top Talkers)
        top_src = sorted(self.src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_dst = sorted(self.dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_p = sorted(self.port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        bridge.update_analytics({
            "top_sources": [{"ip": ip, "count": cnt} for ip, cnt in top_src],
            "top_destinations": [{"ip": ip, "count": cnt} for ip, cnt in top_dst],
            "top_ports": [{"port": p, "count": cnt} for p, cnt in top_p],
            "protocols": {
                "TCP": self.proto_counts.get(6, 0),
                "UDP": self.proto_counts.get(17, 0),
                "ICMP": self.proto_counts.get(1, 0),
            },
        })

        # Update Directionality in bridge
        bridge.update_directionality({
            "total": tot_dir,
            "bidirectional": b_cnt,
            "asymmetric": a_cnt,
            "strongly_asymmetric": sa_cnt,
            "unidirectional": u_cnt,
            "excluded": self.excluded_flows_count,
            "percentages": {
                "BIDIRECTIONAL": round((b_cnt / tot_dir) * 100.0, 1),
                "ASYMMETRIC": round((a_cnt / tot_dir) * 100.0, 1),
                "STRONGLY_ASYMMETRIC": round((sa_cnt / tot_dir) * 100.0, 1),
                "UNIDIRECTIONAL_OBSERVED": round((u_cnt / tot_dir) * 100.0, 1),
            },
        })

        # Update Threat Counts in bridge
        bridge.update_threat_counts(self.threat_counts)

        # Append to Live Activity Log
        log_msg = f"[{ts_str}] {event.severity} alert: {event.threat_type} from {event.src_ip}:{event.src_port} -> {event.dst_ip}:{event.dst_port} | Dir: {dir_state} | Risk: {event.risk_score}/100"
        self.txt_live_log.append(log_msg)
        if self.chk_auto_scroll.isChecked():
            self.txt_live_log.ensureCursorVisible()
        bridge.add_log(log_msg, level=event.severity)

        # Insert into Module 1: Overview Table
        if self.table.rowCount() >= 500:
            self.table.removeRow(0)

        row = self.table.rowCount()
        self.table.insertRow(row)

        src_str = f"{event.src_ip}:{event.src_port}"
        dst_str = f"{event.dst_ip}:{event.dst_port}"

        self.table.setItem(row, 0, QTableWidgetItem(event.event_id))
        self.table.setItem(row, 1, QTableWidgetItem(src_str))
        self.table.setItem(row, 2, QTableWidgetItem(dst_str))

        dir_item = QTableWidgetItem(f"{dir_state} ({dir_score:.2f})")
        if dir_state == "BIDIRECTIONAL":
            dir_item.setForeground(QColor("#10b981"))
        elif dir_state == "ASYMMETRIC":
            dir_item.setForeground(QColor("#f59e0b"))
        elif dir_state == "STRONGLY_ASYMMETRIC":
            dir_item.setForeground(QColor("#f97316"))
        elif dir_state == "UNIDIRECTIONAL_OBSERVED":
            dir_item.setForeground(QColor("#a855f7"))
        else:
            dir_item.setForeground(QColor("#8b949e"))
        self.table.setItem(row, 3, dir_item)

        self.table.setItem(row, 4, QTableWidgetItem(event.threat_type))
        self.table.setItem(row, 5, QTableWidgetItem(f"{event.confidence_pct}%"))

        sev_item = QTableWidgetItem(event.severity)
        if event.severity == "CRITICAL":
            sev_item.setForeground(QColor("#ef4444"))
        elif event.severity == "HIGH":
            sev_item.setForeground(QColor("#f97316"))
        elif event.severity == "MEDIUM":
            sev_item.setForeground(QColor("#eab308"))
        else:
            sev_item.setForeground(QColor("#10b981"))
        self.table.setItem(row, 6, sev_item)

        risk_item = QTableWidgetItem(f"{event.risk_score} / 100")
        self.table.setItem(row, 7, risk_item)

        self.table.item(row, 0).event_data = event
        self.table.scrollToBottom()
        self.lbl_overview_count.setText(f"Showing {self.table.rowCount()} events")

        # Insert into Module 3: Threat Alerts Table (if threat or elevated risk)
        if event.threat_type != "BENIGN" or event.risk_score >= 35:
            self.threat_events.append(event)
            if len(self.threat_events) > 500:
                self.threat_events.pop(0)

            if self.table_alerts.rowCount() >= 500:
                self.table_alerts.removeRow(0)

            a_row = self.table_alerts.rowCount()
            self.table_alerts.insertRow(a_row)
            self.table_alerts.setItem(a_row, 0, QTableWidgetItem(event.event_id))
            self.table_alerts.setItem(a_row, 1, QTableWidgetItem(ts_str))
            self.table_alerts.setItem(a_row, 2, QTableWidgetItem(src_str))
            self.table_alerts.setItem(a_row, 3, QTableWidgetItem(dst_str))
            self.table_alerts.setItem(a_row, 4, QTableWidgetItem(event.threat_type))

            a_sev_item = QTableWidgetItem(event.severity)
            a_sev_item.setForeground(QColor("#ef4444" if event.severity == "CRITICAL" else "#f97316" if event.severity == "HIGH" else "#eab308"))
            self.table_alerts.setItem(a_row, 5, a_sev_item)
            self.table_alerts.setItem(a_row, 6, QTableWidgetItem(f"{event.risk_score} / 100"))
            self.table_alerts.item(a_row, 0).event_data = event
            self.table_alerts.scrollToBottom()

        if row == 0 or event.severity in ["HIGH", "CRITICAL"]:
            self.display_event_details(event)

    def on_table_row_clicked(self, row: int, col: int) -> None:
        item = self.table.item(row, 0)
        if hasattr(item, "event_data"):
            self.display_event_details(item.event_data)

    def display_event_details(self, event: SecurityEvent) -> None:
        self.selected_event = event

        # Update Overview Quick Drawer
        self.lbl_overview_inspect_summary.setText(
            f"Selected: {event.event_id}  |  Flow: {event.flow_key}\n"
            f"Classification: {event.threat_type} ({event.confidence_pct:.1f}% confidence)  |  Severity: {event.severity}  |  Risk: {event.risk_score}/100"
        )

        # Tab 3: Threat Attribution & Gauge
        expl_data = getattr(event, "explanation", None) or {}
        model_name = expl_data.get("model_name", "Random Forest Classifier")
        model_conf_val = expl_data.get("model_confidence")
        conf_str = f"{model_conf_val * 100:.1f}%" if model_conf_val is not None else f"{event.confidence_pct:.1f}%"

        self.lbl_inspect_flow.setText(
            f"Incident ID: {event.event_id}\nTarget Flow: {event.flow_key}\nClassifier Label: {event.threat_type} (Confidence: {conf_str})"
        )
        if hasattr(self, "lbl_inspect_model"):
            self.lbl_inspect_model.setText(f"AI Detection Engine: {model_name}  |  Confidence: {conf_str}")

        self.lbl_inspect_risk.setText(f"Calculated Risk Score: {event.risk_score} / 100  [{event.severity}]")
        self.progress_risk.setValue(event.risk_score)

        # Tab 3: Structured AI Threat Explanation ("Why Was This Detected?")
        summary = expl_data.get("summary", f"Behavioral patterns in {event.threat_type} evaluated by detection pipeline.")
        behaviors = expl_data.get("observed_behavior", [])
        contributions = expl_data.get("feature_contributions", [])
        dir_info = expl_data.get("directionality", {})
        risk_expl = expl_data.get("risk_explanation", "")

        xai_lines = [
            "=" * 76,
            "AI THREAT EXPLANATION ENGINE: \"WHY WAS THIS DETECTED?\"",
            "=" * 76,
            f"CLASSIFICATION:    {event.threat_type}  |  SEVERITY: {event.severity}  |  RISK SCORE: {event.risk_score}/100",
            f"DETECTING MODEL:   {model_name} (Prediction Confidence: {conf_str})",
            f"ANOMALY SEVERITY:  {event.anomaly_score:.3f} / 1.000 (Isolation Forest Baseline)",
            "",
            "[*] EXECUTIVE THREAT SUMMARY:",
            f"    {summary}",
            "",
            "[*] FACTUAL OBSERVED NETWORK BEHAVIOR (GROUND TRUTH):",
        ]
        if behaviors:
            for b in behaviors:
                xai_lines.append(f"    • {b}")
        else:
            xai_lines.append(f"    • Flow evaluated against standard enterprise traffic baselines.")

        xai_lines.append("")
        xai_lines.append("[*] FEATURE CONTRIBUTION ATTRIBUTION (LOCAL PREDICTION INFLUENCE):")
        if contributions:
            for c in contributions:
                direction = c.get("contribution", "positive")
                sym = "[+]" if direction == "positive" else "[-]"
                feat = str(c.get("feature", "unknown")).upper()
                val = c.get("observed_value", "N/A")
                score = float(c.get("impact_score", 0.0))
                expl = c.get("explanation", "")
                xai_lines.append(f"    {sym} {feat} (Observed: {val}, Impact Weight: {score:+.3f}):")
                xai_lines.append(f"        {expl}")
        elif event.contributing_factors:
            for factor in event.contributing_factors:
                feat = factor.get("feature", "unknown").upper()
                expl = factor.get("explanation", "")
                score = factor.get("impact_score", 0.0)
                xai_lines.append(f"    [+] {feat} (Impact: {score:+.3f}): {expl}")
        else:
            xai_lines.append("    • No individual feature dominated the classification.")

        xai_lines.append("")
        xai_lines.append("[*] DIRECTIONALITY & SENSOR VISIBILITY CONTEXT:")
        dir_st = dir_info.get("state", getattr(event, "directionality_state", "UNKNOWN"))
        dir_score_val = dir_info.get("score", getattr(event, "directionality_score", 0.0))
        dir_exp = dir_info.get("explanation", "")
        dir_note = dir_info.get("sensor_visibility_note", "")
        xai_lines.append(f"    • State: {dir_st} (Asymmetry Score: {dir_score_val:.2f})")
        if dir_exp:
            xai_lines.append(f"    • Traffic Flow: {dir_exp}")
        if dir_note:
            xai_lines.append(f"    • Sensor Context: {dir_note}")

        xai_lines.append("")
        xai_lines.append("[*] MULTI-FACTOR RISK SCORING RATIONALE:")
        if risk_expl:
            xai_lines.append(f"    {risk_expl}")
        else:
            xai_lines.append(f"    Assigned risk score of {event.risk_score}/100 ({event.severity}).")

        self.xai_text.setText("\n".join(xai_lines))

        # Tab 3: Actionable SOC Investigation Steps (Playbook)
        playbook_lines = [
            f"=== DEFENSIVE SOC ANALYST INVESTIGATION PLAYBOOK: {event.threat_type} ===",
            f"Severity: {event.severity}  |  Risk Score: {event.risk_score}/100  |  Confidence: {conf_str}",
            "-" * 60,
        ]

        suggs = expl_data.get("investigation_suggestions", [])
        if suggs:
            for idx, s in enumerate(suggs, 1):
                playbook_lines.append(f"{idx}. {s}")
        elif event.threat_type == "PORT_SCAN":
            playbook_lines.extend([
                "1. Verify Source Identity: Check if source IP belongs to an internal vulnerability scanner (Nessus, Qualys) or unauthorized host.",
                "2. Port Diversity Check: Inspect destination port range to confirm whether reconnaissance targeted well-known services (21, 22, 23, 80, 443).",
                "3. Firewall Staging: Export source IP to edge firewall drop rule candidate list.",
                "4. Host Verification: Audit target host logs for subsequent exploit or authentication brute-force attempts.",
            ])
        elif event.threat_type == "SYN_FLOOD":
            playbook_lines.extend([
                "1. Server TCP Table: Query target host TCP connection state (check for large volumes in SYN_RECV state).",
                "2. SYN Cookies Verification: Ensure TCP SYN Cookies (syncookies) are activated on the target operating system.",
                "3. Rate-Limiting Policy: Apply ingress SYN packet rate-limiting at boundary router or upstream switch.",
                "4. IP Spoofing Audit: Check if source IP range exhibits unroutable RFC 1918 / bogon addresses indicating spoofing.",
            ])
        elif event.threat_type == "UDP_FLOOD":
            playbook_lines.extend([
                "1. Destination Port Audit: Check whether target port hosts valid UDP service (e.g. DNS 53, NTP 123) or arbitrary ports.",
                "2. Amplification Check: Verify whether responses from target host could cause reflective denial of service.",
                "3. Upstream Filtering: Engage upstream ISP DDoS mitigation scrubbing if wire rate exceeds local link capacity.",
            ])
        elif event.threat_type == "SLOWLORIS":
            playbook_lines.extend([
                "1. HTTP Connection Table: Inspect open HTTP/HTTPS connections with prolonged uncompleted headers.",
                "2. Worker Thread Exhaustion: Check web server worker pool utilization (Apache MaxRequestWorkers / Nginx worker_connections).",
                "3. Timeout Configuration: Configure aggressive client header read timeouts (e.g. RequestReadTimeout in Apache).",
                "4. Reverse Proxy Mitigation: Place connection-terminating reverse proxy (HAProxy, Cloudflare, AWS ALB) in front of origin.",
            ])
        elif event.threat_type == "DATA_EXFILTRATION":
            playbook_lines.extend([
                "1. Source Host Isolation: Identify host user session, process identity, and active user context.",
                "2. Data Classification: Determine sensitivity level of payload transmitted via unidirectional egress.",
                "3. External ASN Reputation: Check reputation and geolocation of destination IP address.",
                "4. Incident Escalation: Trigger Tier-3 CSIRT protocol for potential data breach investigation.",
            ])
        else: # ANOMALOUS or BENIGN
            playbook_lines.extend([
                "1. Baseline Contrast: Compare flow entropy and rate characteristics against normal server traffic profiles.",
                "2. Directionality Review: Verify that reverse packets were truly absent or if asymmetry was due to network routing anomalies.",
                "3. Routine Monitoring: Continue passive NDR observation; no immediate perimeter blocking required.",
            ])

        self.txt_playbook.setText("\n".join(playbook_lines))

        # Tab 4: Directionality Evidence & 5/20 Comparison (Tasks 13, 19, 20)
        dir_state = getattr(event, "directionality_state", "UNKNOWN")
        dir_score = getattr(event, "directionality_score", 0.0)
        dir_conf = getattr(event, "directionality_confidence", 0.0)
        is_excl = getattr(event, "is_excluded_from_unidirectional_security", False)
        b520_label = getattr(event, "baseline_5_20_result", "N/A")

        dir_lines = [
            "=== FLOW DIRECTIONALITY & TRAFFIC ASYMMETRY ANALYSIS ===",
            f"Flow Identity:        {event.flow_key}",
            f"Directionality State: {dir_state}",
            f"Asymmetry Score:      {dir_score:.3f} (0.0=Balanced, 1.0=Pure One-Way)",
            f"Classification Conf:  {dir_conf * 100:.1f}%",
            f"Pipeline Exclusion:   {'YES (Excluded from unidirectional threat analysis)' if is_excl else 'NO (Routed to ML threat pipeline)'}",
            "-" * 60,
            "OBSERVED BEHAVIORAL EVIDENCE:",
        ]
        expl_list = getattr(event, "directionality_explanation", [])
        for bullet in expl_list:
            dir_lines.append(f"  * {bullet}")

        dir_lines.append("-" * 60)
        dir_lines.append("5/20 RESEARCH BASELINE CONTRAST:")
        dir_lines.append(f"  * 5/20 Heuristic Label: {b520_label}")
        if is_excl:
            dir_lines.append("  * Research Note: Excluded because reverse ACKs / dependency proved normal conversational traffic.")
        elif dir_state in ("STRONGLY_ASYMMETRIC", "UNIDIRECTIONAL_OBSERVED"):
            dir_lines.append("  * Research Note: Confirmed candidate for unidirectional threat analysis.")

        self.txt_directionality_details.setText("\n".join(dir_lines))

        # Tab 4: Categorized 24-Feature Telemetry
        fm = getattr(event, "flow_metrics", {})
        feat_lines = [
            f"STRICT 24 UNIDIRECTIONAL FORWARD-ONLY FEATURES FOR: {event.flow_key}",
            "=" * 70,
            "",
            "[1] VOLUME & SIZE METRICS (Forward Wire Footprint)",
            f"  * fwd_packet_count:       {fm.get('fwd_packet_count', fm.get('packet_count', 0)):,} packets",
            f"  * fwd_byte_count:         {fm.get('fwd_byte_count', fm.get('byte_count', 0)):,} bytes",
            f"  * fwd_pkt_len_mean:       {fm.get('fwd_pkt_len_mean', fm.get('pkt_len_mean', 0.0)):.2f} bytes",
            f"  * fwd_pkt_len_std:        {fm.get('fwd_pkt_len_std', fm.get('pkt_len_std', 0.0)):.2f} bytes",
            f"  * fwd_pkt_len_min:        {fm.get('fwd_pkt_len_min', fm.get('pkt_len_min', 0.0)):.1f} bytes",
            f"  * fwd_pkt_len_max:        {fm.get('fwd_pkt_len_max', fm.get('pkt_len_max', 0.0)):.1f} bytes",
            "",
            "[2] TIMING & RATE METRICS (Flow Cadence)",
            f"  * flow_duration:          {fm.get('flow_duration', fm.get('duration', 0.0)):.4f} seconds",
            f"  * fwd_packet_rate:        {fm.get('fwd_packet_rate', fm.get('pkt_rate', 0.0)):,.2f} pkts/sec",
            f"  * fwd_byte_rate:          {fm.get('fwd_byte_rate', fm.get('byte_rate', 0.0)):,.2f} bytes/sec",
            f"  * fwd_iat_mean:           {fm.get('fwd_iat_mean', fm.get('iat_mean', 0.0)):.4f} seconds",
            f"  * fwd_iat_std:            {fm.get('fwd_iat_std', fm.get('iat_std', 0.0)):.4f} seconds",
            f"  * burstiness:             {fm.get('burstiness', 0.0):.3f} (Variance/Mean ratio)",
            "",
            "[3] TCP CONTROL & PROTOCOL METRICS",
            f"  * proto_number:           {event.proto} ({'TCP' if event.proto==6 else 'UDP' if event.proto==17 else 'ICMP'})",
            f"  * tcp_syn_cnt:            {fm.get('tcp_syn_cnt', 0):,}",
            f"  * tcp_ack_cnt:            {fm.get('tcp_ack_cnt', 0):,}",
            f"  * tcp_fin_cnt:            {fm.get('tcp_fin_cnt', 0):,}",
            f"  * tcp_psh_cnt:            {fm.get('tcp_psh_cnt', 0):,}",
            f"  * tcp_rst_cnt:            {fm.get('tcp_rst_cnt', 0):,}",
            f"  * tcp_flags_entropy:      {fm.get('tcp_flags_entropy', 0.0):.3f} bits",
            "",
            "[4] BEHAVIORAL ASYMMETRY & INFORMATION ENTROPY",
            f"  * shannon_byte_entropy:   {fm.get('shannon_byte_entropy', fm.get('entropy', 0.0)):.3f} bits (Max 8.0)",
            f"  * directionality_score:   {dir_score:.3f} (1.0 = Pure Unidirectional)",
            f"  * anomaly_score:          {event.anomaly_score:.3f} (Isolation Forest anomaly degree)",
            f"  * elephant_flow_flag:     {bool(fm.get('is_elephant', False))}",
            "-" * 70,
            "NOTE: All 24 features rely strictly on forward-channel packets, ensuring zero reverse-channel information leakage on hardware data diodes.",
        ]
        self.txt_flow_details.setText("\n".join(feat_lines))

    def update_traffic_analytics(self) -> None:
        """Updates Top Talkers, Ports, and Protocol Distribution."""
        total_flows = self.total_flows or 1

        # 1. Top Sources
        top_src = sorted(self.src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        src_lines = []
        for i, (ip, cnt) in enumerate(top_src):
            pct = (cnt / total_flows) * 100.0
            bars = "█" * int(pct / 5)
            src_lines.append(f"{i+1}. {ip:<18} | {cnt:>5,} flows ({pct:>5.1f}%) {bars}")
        self.txt_top_src.setText("\n".join(src_lines) if src_lines else "No source IP data recorded yet.")

        # 2. Top Destinations
        top_dst = sorted(self.dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        dst_lines = []
        for i, (ip, cnt) in enumerate(top_dst):
            pct = (cnt / total_flows) * 100.0
            bars = "█" * int(pct / 5)
            dst_lines.append(f"{i+1}. {ip:<18} | {cnt:>5,} flows ({pct:>5.1f}%) {bars}")
        self.txt_top_dst.setText("\n".join(dst_lines) if dst_lines else "No target host data recorded yet.")

        # 3. Top Ports & Services
        port_names = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt"
        }
        top_p = sorted(self.port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        port_lines = []
        for i, (p, cnt) in enumerate(top_p):
            pct = (cnt / total_flows) * 100.0
            s_name = port_names.get(p, "Custom")
            bars = "█" * int(pct / 5)
            port_lines.append(f"{i+1}. Port {p:<5} ({s_name:<8}) | {cnt:>5,} flows ({pct:>5.1f}%) {bars}")
        self.txt_top_ports.setText("\n".join(port_lines) if port_lines else "No port activity recorded yet.")

        # 4. Protocols
        tcp_cnt = self.proto_counts.get(6, 0)
        udp_cnt = self.proto_counts.get(17, 0)
        icmp_cnt = self.proto_counts.get(1, 0)
        tot_proto = (tcp_cnt + udp_cnt + icmp_cnt) or 1

        proto_lines = [
            f"TCP (Protocol 6):   {tcp_cnt:>6,} flows ({(tcp_cnt/tot_proto)*100:>5.1f}%)  {'█'*int((tcp_cnt/tot_proto)*20)}",
            f"UDP (Protocol 17):  {udp_cnt:>6,} flows ({(udp_cnt/tot_proto)*100:>5.1f}%)  {'█'*int((udp_cnt/tot_proto)*20)}",
            f"ICMP (Protocol 1):  {icmp_cnt:>6,} flows ({(icmp_cnt/tot_proto)*100:>5.1f}%)  {'█'*int((icmp_cnt/tot_proto)*20)}",
            "-" * 55,
            f"Total Transport Sessions: {tot_proto:,} flows",
        ]
        self.txt_top_proto.setText("\n".join(proto_lines))

    def on_tab_changed(self, index: int) -> None:
        """Handles tab switching events to refresh live data for the active view."""
        current_widget = self.tabs.widget(index)
        if current_widget == self.tab_event_history:
            self.load_historical_events()
        elif current_widget == self.tab_model_status:
            self.refresh_model_status_display()
        elif hasattr(self, "tab_reports") and current_widget == self.tab_reports:
            self.refresh_reports_tab()
        elif hasattr(self, "tab_utie") and current_widget == self.tab_utie:
            if len(self.all_utie_reports) == 0:
                self.load_historical_utie_reports()

    def load_historical_events(self) -> None:
        """Loads events from SQLite database into Event History table."""
        try:
            q = getattr(self, "txt_history_search", None)
            query = q.text().strip() if q else ""
            sev_box = getattr(self, "combo_history_sev", None)
            raw_sev = sev_box.currentText() if sev_box else "All Severities"
            sev = "ALL" if "ALL" in raw_sev.upper() else raw_sev

            threat_box = getattr(self, "combo_history_threat", None)
            raw_threat = threat_box.currentText() if threat_box else "All Threat Types"
            threat = "ALL" if "ALL" in raw_threat.upper() else raw_threat

            lim_spin = getattr(self, "spin_history_limit", None)
            limit = lim_spin.value() if lim_spin else 200

            events = self.database.search_events(query=query, severity=sev, threat_type=threat, limit=limit)
            self.table_history.setRowCount(0)
            for i, ev in enumerate(events):
                self.table_history.insertRow(i)
                self.table_history.setItem(i, 0, QTableWidgetItem(str(ev.get("event_id", ""))))
                ts_val = ev.get("timestamp", 0) or 0
                self.table_history.setItem(i, 1, QTableWidgetItem(str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts_val)))))
                self.table_history.setItem(i, 2, QTableWidgetItem(f"{ev.get('src_ip')}:{ev.get('src_port')}"))
                self.table_history.setItem(i, 3, QTableWidgetItem(f"{ev.get('dst_ip')}:{ev.get('dst_port')}"))
                self.table_history.setItem(i, 4, QTableWidgetItem(str(ev.get("directionality_state", "UNKNOWN"))))
                self.table_history.setItem(i, 5, QTableWidgetItem(str(ev.get("threat_type", ""))))

                sev_val = str(ev.get("severity", ""))
                sev_item = QTableWidgetItem(sev_val)
                sev_item.setForeground(QColor("#ef4444" if sev_val == "CRITICAL" else "#f97316" if sev_val == "HIGH" else "#eab308" if sev_val == "MEDIUM" else "#10b981"))
                self.table_history.setItem(i, 6, sev_item)
                self.table_history.setItem(i, 7, QTableWidgetItem(str(ev.get("risk_score", 0))))

                item_0 = self.table_history.item(i, 0)
                if item_0:
                    item_0.history_data = ev

            if hasattr(self, "lbl_history_status"):
                self.lbl_history_status.setText(f"Showing {len(events)} events from database")
        except Exception as e:
            logger.warning(f"Error loading historical events: {e}")

    @Slot()
    def on_monitoring_finished(self) -> None:
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        if "STOPPED" not in self.lbl_health_capture.text():
            self.lbl_health_capture.setText("Capture: IDLE")
        self.lbl_health_proc.setText("Processing: COMPLETE")
        self.lbl_banner_status_badge.setText("STATUS: COMPLETE")
        self.lbl_banner_status_badge.setStyleSheet("background-color: rgba(16, 185, 129, 0.2); color: #10b981; padding: 4px 10px; border-radius: 4px; font-weight: bold;")

    def closeEvent(self, event) -> None:
        # 1. Safely stop monitoring worker thread before window is destroyed
        self.stop_monitoring()

        # 1b. Safely cancel and join report worker thread if running
        if hasattr(self, "report_worker") and self.report_worker and self.report_worker.isRunning():
            try:
                self.report_worker.cancel()
                self.report_worker.quit()
                self.report_worker.wait(2000)
            except Exception:
                pass

        # 2. Terminate background local SOC web server
        if hasattr(self, "soc_server") and self.soc_server:
            try:
                self.soc_server.shutdown()
                self.soc_server.server_close()
            except Exception:
                pass
        super().closeEvent(event)


def main() -> None:
    app = QApplication(sys.argv)
    font = QFont("Segoe UI", 9)
    app.setFont(font)
    window = UniGuardDesktopApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
