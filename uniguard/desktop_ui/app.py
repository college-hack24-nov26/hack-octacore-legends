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
from typing import Optional, List, Dict, Any

from PySide6.QtCore import Qt, QThread, Signal, Slot, QUrl
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
)

import psutil

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
from sklearn import get_config, config_context

try:
    from PySide6.QtWebEngineWidgets import QWebEngineView
    WEBENGINE_AVAILABLE = True
except Exception:
    WEBENGINE_AVAILABLE = False


DARK_STYLESHEET = """
QMainWindow {
    background-color: #0b0e14;
}
QWidget {
    background-color: #0b0e14;
    color: #c9d1d9;
}
QFrame.kpi-card {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 10px;
}
QLabel.kpi-title {
    color: #8b949e;
    font-size: 10pt;
    font-weight: 600;
    text-transform: uppercase;
}
QLabel.kpi-value {
    color: #f0f6fc;
    font-size: 18pt;
    font-weight: bold;
}
QGroupBox {
    border: 1px solid #30363d;
    border-radius: 6px;
    margin-top: 10px;
    font-weight: bold;
    color: #58a6ff;
    padding-top: 15px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
}
QPushButton {
    background-color: #21262d;
    border: 1px solid #363b42;
    border-radius: 6px;
    color: #c9d1d9;
    padding: 6px 14px;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #30363d;
    border-color: #8b949e;
}
QPushButton#start-btn {
    background-color: #238636;
    color: #ffffff;
    border: 1px solid #2ea043;
}
QPushButton#start-btn:hover {
    background-color: #2ea043;
}
QPushButton#stop-btn {
    background-color: #da3633;
    color: #ffffff;
    border: 1px solid #f85149;
}
QPushButton#stop-btn:hover {
    background-color: #f85149;
}
QComboBox, QLineEdit, QSpinBox, QDoubleSpinBox {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 5px 10px;
    color: #c9d1d9;
}
QTableWidget {
    background-color: #161b22;
    border: 1px solid #30363d;
    gridline-color: #21262d;
    border-radius: 6px;
    selection-background-color: #1f6feb;
}
QHeaderView::section {
    background-color: #21262d;
    color: #8b949e;
    padding: 6px;
    border: none;
    font-weight: 600;
}
QTextEdit {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #7ee787;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 9.5pt;
}
QTabWidget::pane {
    border: 1px solid #30363d;
    background-color: #0d1117;
    border-radius: 6px;
}
QTabBar::tab {
    background-color: #161b22;
    color: #8b949e;
    padding: 8px 18px;
    margin-right: 4px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: 600;
    font-size: 9pt;
}
QTabBar::tab:selected {
    background-color: #21262d;
    color: #58a6ff;
    border-bottom: 2px solid #58a6ff;
}
QTabBar::tab:hover {
    background-color: #30363d;
    color: #f0f6fc;
}
"""


class MonitoringWorker(QThread):
    """Decoupled background worker thread processing PCAP or live network interface traffic."""

    event_generated = Signal(object)
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
                        if self.is_running:
                            self.event_generated.emit(event)
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
        self.selected_event: Optional[SecurityEvent] = None
        self.custom_pcap_path: Optional[str] = None

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

        self.init_ui()
        self.setStyleSheet(DARK_STYLESHEET)

    def init_ui(self) -> None:
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 12, 15, 12)
        main_layout.setSpacing(10)

        # 1. Header & Controls Bar
        header_layout = QHBoxLayout()

        title_label = QLabel("UNIGUARD AI")
        title_label.setStyleSheet("font-size: 14pt; font-weight: 800; color: #58a6ff; letter-spacing: 1px;")
        sub_label = QLabel("| High-Throughput Unidirectional NDR Platform")
        sub_label.setStyleSheet("color: #8b949e; font-size: 9.5pt;")

        header_layout.addWidget(title_label)
        header_layout.addWidget(sub_label)
        header_layout.addStretch()

        # Interface Selector
        self.iface_combo = QComboBox()
        self.iface_combo.addItem("Demo PCAP: sample_unidirectional.pcap")
        for iface in psutil.net_if_addrs().keys():
            self.iface_combo.addItem(f"Live Interface: {iface}")

        self.btn_select_pcap = QPushButton("Browse PCAP...")
        self.btn_select_pcap.clicked.connect(self.browse_pcap)

        self.btn_start = QPushButton("START MONITORING")
        self.btn_start.setObjectName("start-btn")
        self.btn_start.clicked.connect(self.start_monitoring)

        self.btn_stop = QPushButton("STOP")
        self.btn_stop.setObjectName("stop-btn")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_monitoring)

        header_layout.addWidget(self.iface_combo)
        header_layout.addWidget(self.btn_select_pcap)
        header_layout.addWidget(self.btn_start)
        header_layout.addWidget(self.btn_stop)

        self.btn_open_browser = QPushButton("🌐 OPEN FULL SOC IN BROWSER")
        self.btn_open_browser.setStyleSheet(
            "background: rgba(0, 229, 255, 0.15); color: #00e5ff; border: 1px solid rgba(0, 229, 255, 0.4); "
            "font-weight: 700; padding: 6px 14px; border-radius: 6px;"
        )
        self.btn_open_browser.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("http://127.0.0.1:8765/")))
        header_layout.addWidget(self.btn_open_browser)

        main_layout.addLayout(header_layout)

        # 2. KPI Summary Cards Bar
        kpi_layout = QHBoxLayout()
        kpi_layout.setSpacing(10)

        self.kpi_packets = self.create_kpi_card("PACKETS OBSERVED", "0", "#58a6ff")
        self.kpi_flows = self.create_kpi_card("ACTIVE FLOWS", "0", "#a371f7")
        self.kpi_throughput = self.create_kpi_card("THROUGHPUT", "0 pps", "#3fb950")
        self.kpi_threats = self.create_kpi_card("THREATS DETECTED", "0", "#f0883e")
        self.kpi_critical = self.create_kpi_card("HIGH / CRITICAL", "0", "#f85149")
        self.kpi_health = self.create_kpi_card("QUEUE HEALTH", "0.0% (0 / 50k)", "#58a6ff")

        kpi_layout.addWidget(self.kpi_packets)
        kpi_layout.addWidget(self.kpi_flows)
        kpi_layout.addWidget(self.kpi_throughput)
        kpi_layout.addWidget(self.kpi_threats)
        kpi_layout.addWidget(self.kpi_critical)
        kpi_layout.addWidget(self.kpi_health)

        main_layout.addLayout(kpi_layout)

        # 3. Master Tabbed Navigation (Modern SOC + Specialized Views)
        self.tabs = QTabWidget()

        if WEBENGINE_AVAILABLE:
            self.tab_web_soc = QWidget()
            web_layout = QVBoxLayout(self.tab_web_soc)
            web_layout.setContentsMargins(0, 0, 0, 0)
            self.web_engine_view = QWebEngineView()
            self.web_engine_view.setUrl(QUrl("http://127.0.0.1:8765/"))
            web_layout.addWidget(self.web_engine_view)
            self.tabs.addTab(self.tab_web_soc, "🌐 GLOBAL THREAT MAP & SOC COMMAND CENTER")

        self.tab_overview = QWidget()
        self.tab_live_monitor = QWidget()
        self.tab_threat_alerts = QWidget()
        self.tab_flow_analysis = QWidget()
        self.tab_traffic_analytics = QWidget()
        self.tab_model_status = QWidget()
        self.tab_event_history = QWidget()
        self.tab_settings = QWidget()

        self.setup_overview_tab()
        self.setup_live_monitor_tab()
        self.setup_threat_alerts_tab()
        self.setup_flow_analysis_tab()
        self.setup_traffic_analytics_tab()
        self.setup_model_status_tab()
        self.setup_event_history_tab()
        self.setup_settings_tab()

        self.tabs.addTab(self.tab_overview, "1. SECURITY OVERVIEW")
        self.tabs.addTab(self.tab_live_monitor, "2. LIVE MONITOR")
        self.tabs.addTab(self.tab_threat_alerts, "3. THREAT ALERTS")
        self.tabs.addTab(self.tab_flow_analysis, "4. FLOW ANALYSIS")
        self.tabs.addTab(self.tab_traffic_analytics, "5. TRAFFIC ANALYTICS")
        self.tabs.addTab(self.tab_model_status, "6. MODEL / AI STATUS")
        self.tabs.addTab(self.tab_event_history, "7. EVENT HISTORY")
        self.tabs.addTab(self.tab_settings, "8. SETTINGS")

        if WEBENGINE_AVAILABLE:
            self.tabs.setCurrentIndex(0)

        main_layout.addWidget(self.tabs, stretch=1)

        # 4. Global System Health Bar
        health_layout = QHBoxLayout()
        self.lbl_health_capture = QLabel("Capture: IDLE")
        self.lbl_health_proc = QLabel("Processing: IDLE")
        self.lbl_health_drops = QLabel("Drops: 0 pkts (0.00%)")
        self.lbl_health_host = QLabel("CPU: --% | RAM: -- MB")

        for lbl in [self.lbl_health_capture, self.lbl_health_proc, self.lbl_health_drops, self.lbl_health_host]:
            lbl.setStyleSheet("color: #8b949e; font-size: 8.5pt;")
            health_layout.addWidget(lbl)

        health_layout.addStretch()
        main_layout.addLayout(health_layout)

    def create_kpi_card(self, title: str, init_val: str, accent_color: str) -> QFrame:
        card = QFrame()
        card.setProperty("class", "kpi-card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)

        lbl_title = QLabel(title)
        lbl_title.setProperty("class", "kpi-title")
        lbl_val = QLabel(init_val)
        lbl_val.setProperty("class", "kpi-value")
        lbl_val.setStyleSheet(f"color: {accent_color};")

        layout.addWidget(lbl_title)
        layout.addWidget(lbl_val)
        card.value_label = lbl_val
        return card

    # ==========================================
    # TAB 1: SECURITY OVERVIEW
    # ==========================================
    def setup_overview_tab(self) -> None:
        layout = QVBoxLayout(self.tab_overview)
        layout.setContentsMargins(10, 10, 10, 10)

        # Threat Severity Badge Bar
        badge_layout = QHBoxLayout()
        self.badge_critical = QLabel("CRITICAL: 0")
        self.badge_critical.setStyleSheet("background-color: #f85149; color: white; padding: 4px 10px; border-radius: 4px; font-weight: bold;")
        self.badge_high = QLabel("HIGH: 0")
        self.badge_high.setStyleSheet("background-color: #da3633; color: white; padding: 4px 10px; border-radius: 4px; font-weight: bold;")
        self.badge_med = QLabel("MEDIUM: 0")
        self.badge_med.setStyleSheet("background-color: #d29922; color: white; padding: 4px 10px; border-radius: 4px; font-weight: bold;")
        self.badge_low = QLabel("LOW: 0")
        self.badge_low.setStyleSheet("background-color: #238636; color: white; padding: 4px 10px; border-radius: 4px; font-weight: bold;")

        badge_layout.addWidget(self.badge_critical)
        badge_layout.addWidget(self.badge_high)
        badge_layout.addWidget(self.badge_med)
        badge_layout.addWidget(self.badge_low)
        badge_layout.addStretch()
        layout.addLayout(badge_layout)

        # Overview Table (8 Columns: Added Directionality State)
        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels([
            "Event ID", "Source IP:Port", "Destination IP:Port", "Directionality", "Threat Category", "Confidence", "Severity", "Risk Score"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.cellClicked.connect(self.on_table_row_clicked)
        layout.addWidget(self.table)

    # ==========================================
    # TAB 2: LIVE MONITOR & NETWORK ACTIVITY
    # ==========================================
    def setup_live_monitor_tab(self) -> None:
        layout = QVBoxLayout(self.tab_live_monitor)
        layout.setContentsMargins(10, 10, 10, 10)

        group_box = QGroupBox("REAL-TIME HIGH-THROUGHPUT PIPELINE OBSERVABILITY")
        grid = QGridLayout(group_box)
        grid.setSpacing(15)

        self.lbl_mon_cap_rate = QLabel("Capture Wire Rate: 0 pps")
        self.lbl_mon_proc_rate = QLabel("Processing Pipeline Rate: 0 pps")
        self.lbl_mon_queue = QLabel("Analysis Queue Depth: 0 / 50,000")
        self.lbl_mon_active_flows = QLabel("Active Flow Records: 0")
        self.lbl_mon_drops = QLabel("Kernel Dropped Packets: 0")
        self.lbl_mon_bandwidth = QLabel("Estimated Throughput: 0.00 Mbps")

        for lbl in [self.lbl_mon_cap_rate, self.lbl_mon_proc_rate, self.lbl_mon_queue, self.lbl_mon_active_flows, self.lbl_mon_drops, self.lbl_mon_bandwidth]:
            lbl.setStyleSheet("font-size: 11pt; color: #f0f6fc; font-weight: bold;")

        grid.addWidget(self.lbl_mon_cap_rate, 0, 0)
        grid.addWidget(self.lbl_mon_proc_rate, 0, 1)
        grid.addWidget(self.lbl_mon_queue, 1, 0)
        grid.addWidget(self.lbl_mon_active_flows, 1, 1)
        grid.addWidget(self.lbl_mon_drops, 2, 0)
        grid.addWidget(self.lbl_mon_bandwidth, 2, 1)

        layout.addWidget(group_box)

        # Log Activity Console
        self.txt_live_log = QTextEdit()
        self.txt_live_log.setReadOnly(True)
        self.txt_live_log.setPlaceholderText("Live network activity, directionality exclusions, and elephant transitions stream here...")
        layout.addWidget(self.txt_live_log)

    # ==========================================
    # TAB 3: THREAT ALERTS & XAI TRIAGE
    # ==========================================
    def setup_threat_alerts_tab(self) -> None:
        layout = QHBoxLayout(self.tab_threat_alerts)
        layout.setContentsMargins(10, 10, 10, 10)

        splitter = QSplitter(Qt.Horizontal)

        # Left: Inspector
        left_box = QGroupBox("THREAT ATTRIBUTION & RISK GAUGE")
        left_layout = QVBoxLayout(left_box)

        self.lbl_inspect_flow = QLabel("Select an alert from the table to inspect details.")
        self.lbl_inspect_flow.setStyleSheet("font-size: 10pt; font-weight: bold; color: #f0f6fc;")
        self.lbl_inspect_flow.setWordWrap(True)

        self.lbl_inspect_risk = QLabel("Risk Score: -- / 100")
        self.lbl_inspect_risk.setStyleSheet("font-size: 11pt; font-weight: bold; color: #f85149;")

        self.progress_risk = QProgressBar()
        self.progress_risk.setRange(0, 100)
        self.progress_risk.setValue(0)
        self.progress_risk.setTextVisible(False)
        self.progress_risk.setStyleSheet("""
            QProgressBar { background-color: #21262d; border-radius: 4px; height: 10px; }
            QProgressBar::chunk { background-color: #f85149; border-radius: 4px; }
        """)

        left_layout.addWidget(self.lbl_inspect_flow)
        left_layout.addWidget(self.lbl_inspect_risk)
        left_layout.addWidget(self.progress_risk)
        splitter.addWidget(left_box)

        # Right: XAI
        right_box = QGroupBox("EXPLAINABLE AI (XAI) - ROOT CAUSE ATTRIBUTIONS")
        right_layout = QVBoxLayout(right_box)

        self.xai_text = QTextEdit()
        self.xai_text.setReadOnly(True)
        self.xai_text.setPlaceholderText("Explainability rationale will populate upon alert selection...")
        right_layout.addWidget(self.xai_text)
        splitter.addWidget(right_box)

        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 6)
        layout.addWidget(splitter)

    # ==========================================
    # TAB 4: FLOW DIRECTIONALITY & TELEMETRY (Task 20)
    # ==========================================
    def setup_flow_analysis_tab(self) -> None:
        layout = QVBoxLayout(self.tab_flow_analysis)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Directionality Dashboard KPI Cards
        dir_box = QGroupBox("FLOW DIRECTIONALITY & TRAFFIC ASYMMETRY ENGINE (TASK 20)")
        dir_layout = QVBoxLayout(dir_box)

        kpi_row = QHBoxLayout()
        self.kpi_dir_total = self.create_kpi_card("TOTAL EVALUATED", "0", "#58a6ff")
        self.kpi_dir_bidi = self.create_kpi_card("BIDIRECTIONAL (EXCLUDED)", "0", "#3fb950")
        self.kpi_dir_asym = self.create_kpi_card("ASYMMETRIC", "0", "#d29922")
        self.kpi_dir_strong = self.create_kpi_card("STRONGLY ASYMMETRIC", "0", "#f0883e")
        self.kpi_dir_oneway = self.create_kpi_card("ONE-WAY OBSERVED", "0", "#bc8cff")

        kpi_row.addWidget(self.kpi_dir_total)
        kpi_row.addWidget(self.kpi_dir_bidi)
        kpi_row.addWidget(self.kpi_dir_asym)
        kpi_row.addWidget(self.kpi_dir_strong)
        kpi_row.addWidget(self.kpi_dir_oneway)
        dir_layout.addLayout(kpi_row)

        self.lbl_dir_dist = QLabel("DIRECTIONALITY DISTRIBUTION: BIDIRECTIONAL: 0.0%  |  ASYMMETRIC: 0.0%  |  STRONGLY ASYMMETRIC: 0.0%  |  ONE-WAY: 0.0%")
        self.lbl_dir_dist.setStyleSheet("color: #58a6ff; font-weight: bold; font-size: 9.5pt; padding: 4px;")
        dir_layout.addWidget(self.lbl_dir_dist)

        layout.addWidget(dir_box)

        # Splitter: Left = Directionality Evidence & 5/20 Comparison, Right = 24-Feature Telemetry
        splitter = QSplitter(Qt.Horizontal)

        box_dir_expl = QGroupBox("DIRECTIONALITY EVIDENCE & 5/20 RESEARCH BENCHMARK (TASK 19 & 13)")
        layout_dir_expl = QVBoxLayout(box_dir_expl)
        self.txt_directionality_details = QTextEdit()
        self.txt_directionality_details.setReadOnly(True)
        self.txt_directionality_details.setPlaceholderText("Select any event from the overview table to view directionality evidence, asymmetry metrics, and 5/20 comparison...")
        layout_dir_expl.addWidget(self.txt_directionality_details)
        splitter.addWidget(box_dir_expl)

        box_telemetry = QGroupBox("STRICT 24-FEATURE UNIDIRECTIONAL TELEMETRY")
        layout_telemetry = QVBoxLayout(box_telemetry)
        self.txt_flow_details = QTextEdit()
        self.txt_flow_details.setReadOnly(True)
        self.txt_flow_details.setPlaceholderText("Select any alert to view full unidirectional 24-feature telemetry breakdown...")
        layout_telemetry.addWidget(self.txt_flow_details)
        splitter.addWidget(box_telemetry)

        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter, stretch=1)

    # ==========================================
    # TAB 5: TRAFFIC ANALYTICS & TOP TALKERS
    # ==========================================
    def setup_traffic_analytics_tab(self) -> None:
        layout = QGridLayout(self.tab_traffic_analytics)
        layout.setContentsMargins(10, 10, 10, 10)

        box_src = QGroupBox("TOP SOURCE IP ADDRESSES")
        layout_src = QVBoxLayout(box_src)
        self.txt_top_src = QTextEdit()
        self.txt_top_src.setReadOnly(True)
        layout_src.addWidget(self.txt_top_src)

        box_dst = QGroupBox("TOP DESTINATION IP ADDRESSES")
        layout_dst = QVBoxLayout(box_dst)
        self.txt_top_dst = QTextEdit()
        self.txt_top_dst.setReadOnly(True)
        layout_dst.addWidget(self.txt_top_dst)

        box_ports = QGroupBox("TOP TARGET PORTS")
        layout_ports = QVBoxLayout(box_ports)
        self.txt_top_ports = QTextEdit()
        self.txt_top_ports.setReadOnly(True)
        layout_ports.addWidget(self.txt_top_ports)

        box_proto = QGroupBox("PROTOCOL DISTRIBUTION")
        layout_proto = QVBoxLayout(box_proto)
        self.txt_top_proto = QTextEdit()
        self.txt_top_proto.setReadOnly(True)
        layout_proto.addWidget(self.txt_top_proto)

        layout.addWidget(box_src, 0, 0)
        layout.addWidget(box_dst, 0, 1)
        layout.addWidget(box_ports, 1, 0)
        layout.addWidget(box_proto, 1, 1)

    # ==========================================
    # TAB 6: MODEL / AI STATUS
    # ==========================================
    def setup_model_status_tab(self) -> None:
        layout = QVBoxLayout(self.tab_model_status)
        layout.setContentsMargins(10, 10, 10, 10)

        box = QGroupBox("ACTIVE MACHINE LEARNING & EXPLAINABILITY ENGINES")
        form = QFormLayout(box)
        form.setSpacing(12)

        form.addRow("Supervised Classifier:", QLabel("Random Forest (120 Estimators, Max Depth 16) [LOADED]"))
        form.addRow("Secondary Classifier:", QLabel("XGBoost (100 Trees, Learning Rate 0.10) [READY]"))
        form.addRow("Anomaly Engine:", QLabel("Isolation Forest (Contamination 0.04) [ONLINE]"))
        form.addRow("Explainability (XAI):", QLabel("SHAP TreeExplainer (Attribution Gate Active) [READY]"))
        form.addRow("Feature Schema:", QLabel("Strict 24 Unidirectional Vectors (Zero Reverse Leakage)"))
        form.addRow("Streaming Math:", QLabel("Welford's Algorithm (O(1) Streaming Variance/Mean)"))
        form.addRow("Sample Buffer Bound:", QLabel("K = 100 Packets / Flow (Memory < 2 KB per flow)"))

        layout.addWidget(box)
        layout.addStretch()

    # ==========================================
    # TAB 7: EVENT HISTORY
    # ==========================================
    def setup_event_history_tab(self) -> None:
        layout = QVBoxLayout(self.tab_event_history)
        layout.setContentsMargins(10, 10, 10, 10)

        ctrl_layout = QHBoxLayout()
        btn_refresh_history = QPushButton("Refresh Database Events")
        btn_refresh_history.clicked.connect(self.load_historical_events)
        ctrl_layout.addWidget(btn_refresh_history)
        ctrl_layout.addStretch()
        layout.addLayout(ctrl_layout)

        self.table_history = QTableWidget(0, 7)
        self.table_history.setHorizontalHeaderLabels([
            "Event ID", "Timestamp", "Source IP:Port", "Destination IP:Port", "Threat Type", "Severity", "Risk Score"
        ])
        self.table_history.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table_history)

    # ==========================================
    # TAB 8: SETTINGS & BPF POLICIES
    # ==========================================
    def setup_settings_tab(self) -> None:
        layout = QVBoxLayout(self.tab_settings)
        layout.setContentsMargins(10, 10, 10, 10)

        box = QGroupBox("CAPTURE POLICIES & HIGH-THROUGHPUT TUNING")
        form = QFormLayout(box)
        form.setSpacing(10)

        self.txt_bpf = QLineEdit("ip and not (ether multicast or ether broadcast)")
        self.spin_idle = QDoubleSpinBox()
        self.spin_idle.setValue(15.0)
        self.spin_idle.setRange(1.0, 300.0)

        self.spin_active = QDoubleSpinBox()
        self.spin_active.setValue(60.0)
        self.spin_active.setRange(5.0, 600.0)

        self.spin_elephant = QSpinBox()
        self.spin_elephant.setValue(50)
        self.spin_elephant.setRange(10, 1000)

        form.addRow("BPF Capture Filter:", self.txt_bpf)
        form.addRow("Flow Inactivity Timeout (s):", self.spin_idle)
        form.addRow("Flow Active Snapshot Timeout (s):", self.spin_active)
        form.addRow("Elephant Cutoff Threshold (pkts):", self.spin_elephant)

        layout.addWidget(box)
        layout.addStretch()

    # ==========================================
    # WORKER / MONITORING CONTROLS
    # ==========================================
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

        SocStateBridge.get().worker_thread = self.worker
        self.lbl_health_proc.setText("Processing: ACTIVE")
        self.worker.event_generated.connect(self.on_event_received)
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
        self.lbl_mon_cap_rate.setText(f"Capture Wire Rate: {capture_rate:,.0f} pps")
        self.lbl_mon_proc_rate.setText(f"Processing Pipeline Rate: {pps:,.0f} pps")
        self.lbl_mon_queue.setText(f"Analysis Queue Depth: {queue_depth:,} / 50,000")
        self.lbl_mon_active_flows.setText(f"Active Flow Records: {active_flows:,}")
        self.lbl_mon_drops.setText(f"Kernel Dropped Packets: {dropped_packets:,}")

        mbps = (pps * 1460 * 8) / 1_000_000.0
        self.lbl_mon_bandwidth.setText(f"Estimated Throughput: {mbps:.2f} Mbps")

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
        self.badge_low.setText(f"LOW: {self.low_threats}")

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
        })

        # Add to recent flows for Live Traffic table
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
            "status": "MITIGATED" if event.severity in ("CRITICAL", "HIGH") else "OBSERVED",
            "duration": f"{flow_metrics.get('duration_seconds', flow_metrics.get('flow_duration', 1.0)):.1f}s",
            "ml_conf": f"{event.confidence_pct:.1f}%",
            "flow_metrics": flow_metrics,
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
        bridge.add_log(log_msg, level=event.severity)

        # Rolling 500-row table cap
        if self.table.rowCount() >= 500:
            self.table.removeRow(0)

        row = self.table.rowCount()
        self.table.insertRow(row)

        src_str = f"{event.src_ip}:{event.src_port}"
        dst_str = f"{event.dst_ip}:{event.dst_port}"

        self.table.setItem(row, 0, QTableWidgetItem(event.event_id))
        self.table.setItem(row, 1, QTableWidgetItem(src_str))
        self.table.setItem(row, 2, QTableWidgetItem(dst_str))

        # Column 3: Directionality state (Task 10 & 20)
        dir_score = getattr(event, "directionality_score", 0.0)
        dir_item = QTableWidgetItem(f"{dir_state} ({dir_score:.2f})")
        if dir_state == "BIDIRECTIONAL":
            dir_item.setForeground(QColor("#3fb950")) # Green/Cyan
        elif dir_state == "ASYMMETRIC":
            dir_item.setForeground(QColor("#d29922")) # Yellow
        elif dir_state == "STRONGLY_ASYMMETRIC":
            dir_item.setForeground(QColor("#f0883e")) # Orange
        elif dir_state == "UNIDIRECTIONAL_OBSERVED":
            dir_item.setForeground(QColor("#bc8cff")) # Purple
        else:
            dir_item.setForeground(QColor("#8b949e")) # Gray
        self.table.setItem(row, 3, dir_item)

        self.table.setItem(row, 4, QTableWidgetItem(event.threat_type))
        self.table.setItem(row, 5, QTableWidgetItem(f"{event.confidence_pct}%"))

        sev_item = QTableWidgetItem(event.severity)
        if event.severity == "CRITICAL":
            sev_item.setForeground(QColor("#f85149"))
        elif event.severity == "HIGH":
            sev_item.setForeground(QColor("#ff7b72"))
        elif event.severity == "MEDIUM":
            sev_item.setForeground(QColor("#d29922"))
        else:
            sev_item.setForeground(QColor("#3fb950"))
        self.table.setItem(row, 6, sev_item)

        risk_item = QTableWidgetItem(f"{event.risk_score} / 100")
        self.table.setItem(row, 7, risk_item)

        self.table.item(row, 0).event_data = event
        self.table.scrollToBottom()

        if row == 0 or event.severity in ["HIGH", "CRITICAL"]:
            self.display_event_details(event)

        # Update Analytics tab every 10 events
        if self.total_flows % 10 == 0:
            self.update_traffic_analytics()

    def on_table_row_clicked(self, row: int, col: int) -> None:
        item = self.table.item(row, 0)
        if hasattr(item, "event_data"):
            self.display_event_details(item.event_data)

    def display_event_details(self, event: SecurityEvent) -> None:
        self.selected_event = event
        self.lbl_inspect_flow.setText(
            f"Event: {event.event_id}\nFlow: {event.flow_key}\nClassification: {event.threat_type} ({event.confidence_pct}%)"
        )
        self.lbl_inspect_risk.setText(f"Risk Score: {event.risk_score} / 100  [{event.severity}]")
        self.progress_risk.setValue(event.risk_score)

        # Tab 3: XAI Breakdown
        xai_lines = [
            f"[*] THREAT EXPLANATION FOR: {event.threat_type}",
            f"    Calculated Risk: {event.risk_score}/100 ({event.severity})",
            f"    Anomaly Severity Score: {event.anomaly_score:.3f} / 1.000",
            "-" * 60,
            "TOP CONTRIBUTING FORWARD BEHAVIORAL FACTORS:",
        ]

        for factor in event.contributing_factors:
            direction = factor.get("direction", "RISK_INCREASING")
            sym = "[+]" if direction == "RISK_INCREASING" else "[-]"
            fname = factor.get("feature", "unknown")
            expl = factor.get("explanation", "")
            impact = factor.get("impact_score", 0.0)
            xai_lines.append(f"  {sym} {fname.upper()}: {expl} (Weight: {impact:+.3f})")

        self.xai_text.setText("\n".join(xai_lines))

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
            f"Asymmetry Score:      {dir_score:.3f} (0.0=Balanced, 1.0=One-Way)",
            f"Classification Conf:   {dir_conf * 100:.1f}%",
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

        # Tab 4: Flow Analysis Breakdown
        flow_lines = [
            f"FLOW IDENTIFIER: {event.flow_key}",
            "=" * 60,
            f"Protocol Number:       {event.proto} ({'TCP' if event.proto==6 else 'UDP' if event.proto==17 else 'ICMP'})",
            f"Packets Observed:      {event.flow_metrics.get('packet_count', 0):,}",
            f"Total Bytes Egressed:  {event.flow_metrics.get('byte_count', 0):,} bytes",
            f"Flow Duration:         {event.flow_metrics.get('duration', 0):.4f} seconds",
            f"Mean Packet Rate:      {event.flow_metrics.get('pkt_rate', 0):,.2f} packets/sec",
            f"Mean Byte Rate:        {event.flow_metrics.get('byte_rate', 0):,.2f} bytes/sec",
            f"Shannon Entropy (L):   {event.flow_metrics.get('entropy', 0):.3f} bits",
        ]
        self.txt_flow_details.setText("\n".join(flow_lines))

    def update_traffic_analytics(self) -> None:
        """Updates Top Talkers and Protocol Distribution."""
        top_src = sorted(self.src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        self.txt_top_src.setText("\n".join([f"{ip}  ({cnt:,} flows)" for ip, cnt in top_src]))

        top_dst = sorted(self.dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        self.txt_top_dst.setText("\n".join([f"{ip}  ({cnt:,} flows)" for ip, cnt in top_dst]))

        top_p = sorted(self.port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        self.txt_top_ports.setText("\n".join([f"Port {p}  ({cnt:,} flows)" for p, cnt in top_p]))

        proto_lines = [
            f"TCP (Protocol 6):   {self.proto_counts.get(6, 0):,} flows",
            f"UDP (Protocol 17):  {self.proto_counts.get(17, 0):,} flows",
            f"ICMP (Protocol 1):  {self.proto_counts.get(1, 0):,} flows",
        ]
        self.txt_top_proto.setText("\n".join(proto_lines))

    def load_historical_events(self) -> None:
        """Loads events from SQLite database into Event History table."""
        events = self.database.get_recent_events(limit=200, min_risk=0)
        self.table_history.setRowCount(0)
        for i, ev in enumerate(events):
            self.table_history.insertRow(i)
            self.table_history.setItem(i, 0, QTableWidgetItem(ev["event_id"]))
            self.table_history.setItem(i, 1, QTableWidgetItem(str(time.strftime("%H:%M:%S", time.localtime(ev["timestamp"])))))
            self.table_history.setItem(i, 2, QTableWidgetItem(f"{ev['src_ip']}:{ev['src_port']}"))
            self.table_history.setItem(i, 3, QTableWidgetItem(f"{ev['dst_ip']}:{ev['dst_port']}"))
            self.table_history.setItem(i, 4, QTableWidgetItem(ev["threat_type"]))
            self.table_history.setItem(i, 5, QTableWidgetItem(ev["severity"]))
            self.table_history.setItem(i, 6, QTableWidgetItem(str(ev["risk_score"])))

    @Slot()
    def on_monitoring_finished(self) -> None:
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        if "STOPPED" not in self.lbl_health_capture.text():
            self.lbl_health_capture.setText("Capture: IDLE")
        self.lbl_health_proc.setText("Processing: COMPLETE")

    def closeEvent(self, event) -> None:
        # 1. Safely stop monitoring worker thread before window is destroyed
        self.stop_monitoring()

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
