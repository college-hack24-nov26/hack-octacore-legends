"""UniGuard AI - Local SOC REST & Static Server.

Provides a fast, lightweight local HTTP server bridging live packet telemetry,
database records, and real-time IP Geolocation with the modern Web SOC Frontend.
Runs embedded inside the desktop application and allows simultaneous browser access.
"""

from __future__ import annotations

import os
import json
import time
import mimetypes
import threading
from urllib.parse import urlparse, parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, Any, List
import psutil

from uniguard.intelligence.geolocation import GeoIPResolver
from uniguard.database.storage import SecurityDatabase
from uniguard.utie import (
    UnidirectionalTrafficIntelligenceEngine,
    SensorVisibilityContext,
    ObservationPoint,
    UTIEIntelligenceReport,
)


class SocStateBridge:
    """Thread-safe singleton bridge holding latest telemetry, analytics, and event buffers."""
    _instance: Optional[SocStateBridge] = None
    _lock = threading.Lock()

    def __init__(self):
        self.telemetry = {
            "pps": 0.0,
            "capture_rate": 0.0,
            "processing_rate": 0.0,
            "queue_depth": 0,
            "total_packets_processed": 0,
            "total_flows_created": 0,
            "active_flows": 0,
            "threats_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "dropped_packets": 0,
            "throughput_mbps": 0.0,
            "cpu_pct": 0.0,
            "ram_mb": 0.0,
        }
        self.recent_threats: List[Dict[str, Any]] = []
        self.recent_flows: List[Dict[str, Any]] = []
        self.recent_utie_reports: List[Dict[str, Any]] = []
        self.utie_engine = UnidirectionalTrafficIntelligenceEngine()
        self.analytics: Dict[str, Any] = {
            "top_sources": [],
            "top_destinations": [],
            "top_ports": [],
            "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0},
        }
        self.directionality: Dict[str, Any] = {
            "total": 0,
            "bidirectional": 0,
            "asymmetric": 0,
            "strongly_asymmetric": 0,
            "unidirectional": 0,
            "excluded": 0,
            "percentages": {
                "BIDIRECTIONAL": 0.0,
                "ASYMMETRIC": 0.0,
                "STRONGLY_ASYMMETRIC": 0.0,
                "UNIDIRECTIONAL_OBSERVED": 0.0,
            },
        }
        self.threat_counts: Dict[str, int] = {
            "BENIGN": 0,
            "PORT_SCAN": 0,
            "SYN_FLOOD": 0,
            "UDP_FLOOD": 0,
            "DATA_EXFILTRATION": 0,
            "SLOWLORIS": 0,
            "ANOMALOUS": 0,
        }
        self.pipeline_status = {
            "supervised": "Random Forest (120 Estimators, Max Depth 16) [ONLINE]",
            "secondary": "XGBoost (100 Trees, Learning Rate 0.10) [READY]",
            "anomaly": "Isolation Forest (Contamination 0.04) [ONLINE]",
            "xai": "SHAP TreeExplainer (Attribution Gate Active) [READY]",
            "feature_schema": "Strict 24 Unidirectional Vectors (Zero Reverse Leakage)",
            "streaming_math": "Welford's Algorithm (O(1) Streaming Variance/Mean)",
            "sample_buffer": "K = 100 Packets / Flow (Memory < 2 KB per flow)",
        }
        self.settings = {
            "bpf_filter": "ip and not (ether multicast or ether broadcast)",
            "idle_timeout": 15.0,
            "active_timeout": 60.0,
            "elephant_cutoff": 50,
        }
        self.logs: List[Dict[str, Any]] = []
        self.worker_thread = None
        self.database = SecurityDatabase()

    def get_pipeline_status(self) -> Dict[str, Any]:
        """Dynamically inspects real machine learning model files and pipeline components."""
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        models_dir = os.path.join(project_root, "models_saved")

        prep_path = os.path.join(models_dir, "preprocessor.joblib")
        rf_path = os.path.join(models_dir, "uniguard_rf_model.joblib")
        xgb_path = os.path.join(models_dir, "uniguard_xgb_model.joblib")
        iso_path = os.path.join(models_dir, "uniguard_isolation_forest.joblib")
        dir_iso_path = os.path.join(models_dir, "directionality_isolation_forest.joblib")

        status: Dict[str, Any] = {}

        # 1. Preprocessor (RobustScaler + LabelEncoder)
        if os.path.exists(prep_path):
            status["preprocessor"] = {
                "name": "FlowDataPreprocessor (RobustScaler + LabelEncoder)",
                "status": "ONLINE",
                "state": "Active in Pipeline",
                "features_count": 24,
                "file": "preprocessor.joblib",
                "size_kb": round(os.path.getsize(prep_path) / 1024, 1),
                "description": "Normalizes 24 unidirectional flow metrics and maps multi-class threat categories.",
            }
        else:
            status["preprocessor"] = {
                "name": "FlowDataPreprocessor",
                "status": "OFFLINE",
                "state": "Model File Missing",
                "file": "preprocessor.joblib",
                "description": "Preprocessor file not found on disk.",
            }

        # 2. Random Forest (Primary Supervised Threat Classifier)
        if os.path.exists(rf_path):
            status["supervised"] = {
                "name": "Random Forest Classifier",
                "role": "Primary Supervised Detector",
                "status": "ONLINE",
                "state": "Active in Production Pipeline",
                "architecture": "120 Estimators, Max Depth 16, Balanced Subsample",
                "classes": ["BENIGN", "PORT_SCAN", "SYN_FLOOD", "UDP_FLOOD", "DATA_EXFILTRATION", "SLOWLORIS"],
                "file": "uniguard_rf_model.joblib",
                "size_kb": round(os.path.getsize(rf_path) / 1024, 1),
                "description": "Primary multi-class cybersecurity classification engine evaluating unidirectional streams.",
            }
        else:
            status["supervised"] = {
                "name": "Random Forest Classifier",
                "role": "Primary Supervised Detector",
                "status": "OFFLINE",
                "state": "Model File Missing",
                "description": "uniguard_rf_model.joblib not found on disk.",
            }

        # 3. XGBoost (Secondary / Standby Classifier)
        if os.path.exists(xgb_path):
            status["secondary"] = {
                "name": "XGBoost Classifier",
                "role": "Secondary / Benchmark Detector",
                "status": "STANDBY",
                "state": "Available on Disk (Standby)",
                "architecture": "100 Estimators, Max Depth 6, Learning Rate 0.10",
                "file": "uniguard_xgb_model.joblib",
                "size_kb": round(os.path.getsize(xgb_path) / 1024, 1),
                "description": "Secondary gradient boosted tree model trained and available on disk for offline benchmarks.",
                "pipeline_note": "Primary pipeline executes Random Forest; XGBoost is available as an alternate benchmark.",
            }
        else:
            status["secondary"] = {
                "name": "XGBoost Classifier",
                "role": "Secondary Classifier",
                "status": "UNAVAILABLE",
                "state": "Not Installed / File Missing",
                "description": "uniguard_xgb_model.joblib not present.",
            }

        # 4. Isolation Forest Anomaly Detector
        if os.path.exists(iso_path):
            status["anomaly"] = {
                "name": "Isolation Forest Anomaly Detector",
                "role": "Unsupervised Behavioral Anomaly Scoring",
                "status": "ONLINE",
                "state": "Active in Production Pipeline",
                "architecture": "100 Estimators, Contamination 0.04",
                "file": "uniguard_isolation_forest.joblib",
                "size_kb": round(os.path.getsize(iso_path) / 1024, 1),
                "description": "Detects novel zero-day behavioral deviations in forward-only network traffic vectors.",
            }
        else:
            status["anomaly"] = {
                "name": "Isolation Forest Anomaly Detector",
                "status": "OFFLINE",
                "state": "Model File Missing",
                "description": "uniguard_isolation_forest.joblib not found.",
            }

        # 5. Directionality Engine (Task 20)
        if os.path.exists(dir_iso_path):
            status["directionality_model"] = {
                "name": "Directionality Isolation Forest & K-Means",
                "role": "Flow Directionality & Traffic Asymmetry Engine",
                "status": "ONLINE",
                "state": "Active in Flow Engine",
                "architecture": "100 Estimators, Contamination 0.05, 4 Archetypes",
                "file": "directionality_isolation_forest.joblib",
                "size_kb": round(os.path.getsize(dir_iso_path) / 1024, 1),
                "description": "Classifies Bidirectional, Asymmetric, Strongly Asymmetric, and Unidirectional flows.",
            }
        else:
            status["directionality_model"] = {
                "name": "Directionality Engine",
                "status": "HEURISTIC ONLY",
                "state": "Using 5/20 Heuristic Baseline",
                "description": "Fitted model not found; using heuristic rules.",
            }

        # 6. SHAP Explainability
        try:
            import shap
            shap_ready = True
        except ImportError:
            shap_ready = False

        status["xai"] = {
            "name": "SHAP TreeExplainer",
            "role": "Root Cause Feature Attribution",
            "status": "ONLINE" if shap_ready else "UNAVAILABLE",
            "state": "Attribution Gate Active" if shap_ready else "Library Not Found",
            "architecture": "TreeSHAP with Elephant-Flow Active-Timeout Gating",
            "description": "Extracts top contributing forward features and calculates risk-increasing impacts.",
        }

        # 7. Unidirectional Feature Schema
        status["feature_schema"] = {
            "name": "Strict 24 Unidirectional Vectors",
            "status": "ACTIVE",
            "state": "Zero Reverse Channel Information Leakage",
            "features_count": 24,
            "description": "Strict unidirectional forward-windowed features ensuring complete hardware diode compatibility.",
        }

        # 8. Streaming Math
        status["streaming_math"] = {
            "name": "Welford's Streaming Algorithm",
            "status": "ACTIVE",
            "state": "O(1) Streaming Variance/Mean per Flow Record",
            "description": "Computes rolling packet and byte rates in constant memory without storing full packet histories.",
        }

        return status

    @classmethod
    def get(cls) -> SocStateBridge:
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def update_telemetry(self, t_dict: Dict[str, Any]) -> None:
        with self._lock:
            self.telemetry.update(t_dict)

    def add_threat(self, threat: Dict[str, Any]) -> None:
        with self._lock:
            # Resolve geolocation coordinates
            geo = GeoIPResolver.resolve(threat.get("src_ip", ""))
            enriched = dict(threat)
            enriched.update({
                "latitude": geo["latitude"],
                "longitude": geo["longitude"],
                "country": geo["country"],
                "country_code": geo["country_code"],
                "city": geo["city"],
                "region": geo["region"],
                "asn": geo["asn"],
                "isp": geo["isp"],
            })
            self.recent_threats.insert(0, enriched)
            if len(self.recent_threats) > 100:
                self.recent_threats.pop()

    def add_flow(self, flow: Dict[str, Any]) -> None:
        with self._lock:
            self.recent_flows.insert(0, flow)
            if len(self.recent_flows) > 100:
                self.recent_flows.pop()

    def add_utie_report(self, report: Any) -> None:
        with self._lock:
            d = report.to_dict() if hasattr(report, "to_dict") else report
            self.recent_utie_reports.insert(0, d)
            if len(self.recent_utie_reports) > 100:
                self.recent_utie_reports.pop()

    def update_analytics(self, analytics_data: Dict[str, Any]) -> None:
        with self._lock:
            self.analytics.update(analytics_data)

    def update_directionality(self, dir_data: Dict[str, Any]) -> None:
        with self._lock:
            self.directionality.update(dir_data)

    def update_threat_counts(self, counts_data: Dict[str, int]) -> None:
        with self._lock:
            self.threat_counts.update(counts_data)

    def add_log(self, message: str, level: str = "INFO") -> None:
        with self._lock:
            self.logs.insert(0, {
                "timestamp": time.strftime("%H:%M:%S"),
                "level": level,
                "message": message,
            })
            if len(self.logs) > 100:
                self.logs.pop()


class SocHttpHandler(BaseHTTPRequestHandler):
    """Handles REST API queries and serves static web assets."""

    WEB_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "web_soc"))

    def log_message(self, format, *args):
        # Suppress routine HTTP 200 logging to keep terminal uncluttered
        pass

    def do_GET(self) -> None:
        bridge = SocStateBridge.get()

        # API Endpoints
        if self.path.startswith("/api/telemetry"):
            self.send_json_response(bridge.telemetry)
            return

        elif self.path.startswith("/api/threats"):
            self.send_json_response(bridge.recent_threats)
            return

        elif self.path.startswith("/api/map/threats"):
            # Return geolocated threat markers for the Global Threat Map
            self.send_json_response(bridge.recent_threats)
            return

        elif self.path.startswith("/api/flows"):
            self.send_json_response(bridge.recent_flows)
            return

        elif self.path.startswith("/api/analytics"):
            self.send_json_response(bridge.analytics)
            return

        elif self.path.startswith("/api/directionality"):
            self.send_json_response(bridge.directionality)
            return

        elif self.path.startswith("/api/threat-counts"):
            self.send_json_response(bridge.threat_counts)
            return

        elif self.path.startswith("/api/models/status"):
            self.send_json_response(bridge.get_pipeline_status())
            return

        elif self.path.startswith("/api/logs"):
            self.send_json_response(bridge.logs)
            return

        elif self.path.startswith("/api/events/history"):
            try:
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                limit = int(params.get("limit", [100])[0])
                min_risk = int(params.get("min_risk", [0])[0])
                severity = params.get("severity", ["ALL"])[0]
                threat_type = params.get("threat_type", ["ALL"])[0]
                query = params.get("query", [""])[0]

                events = bridge.database.search_events(
                    query=query,
                    severity=severity,
                    threat_type=threat_type,
                    min_risk=min_risk,
                    limit=limit,
                )
                self.send_json_response(events)
            except Exception as e:
                self.send_json_response([])
            return

        # =====================================================================
        # UTIE Endpoints (SIH 2026 Core Feature)
        # =====================================================================
        elif self.path.startswith("/api/utie/summary"):
            self.send_json_response(bridge.utie_engine.get_summary())
            return

        elif self.path.startswith("/api/utie/flows"):
            try:
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                limit = int(params.get("limit", [100])[0])
                directionality = params.get("directionality", ["ALL"])[0]
                query = params.get("query", [""])[0]
                min_risk = int(params.get("min_risk", [0])[0])

                reports = bridge.database.search_utie_reports(
                    query=query,
                    directionality=directionality,
                    min_risk=min_risk,
                    limit=limit,
                )
                if not reports and bridge.recent_utie_reports:
                    reports = bridge.recent_utie_reports[:limit]
                self.send_json_response(reports)
            except Exception:
                self.send_json_response([])
            return

        elif self.path.startswith("/api/utie/sensor-visibility"):
            self.send_json_response(bridge.utie_engine.sensor_context.to_dict())
            return

        elif self.path.startswith("/api/settings"):
            self.send_json_response(bridge.settings)
            return

        # Static File Serving
        clean_path = self.path.split("?")[0].lstrip("/")
        if not clean_path:
            clean_path = "index.html"

        file_path = os.path.join(self.WEB_ROOT, clean_path)

        # Security check: ensure path stays within WEB_ROOT
        if not os.path.abspath(file_path).startswith(self.WEB_ROOT) or not os.path.isfile(file_path):
            self.send_error(404, "File Not Found")
            return

        mime_type, _ = mimetypes.guess_type(file_path)
        mime_type = mime_type or "application/octet-stream"

        try:
            with open(file_path, "rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache, must-revalidate")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, f"Internal Error: {str(e)}")

    def do_POST(self) -> None:
        bridge = SocStateBridge.get()
        if self.path == "/api/capture/start":
            if bridge.worker_thread:
                bridge.worker_thread.is_running = True
            self.send_json_response({"status": "started"})
        elif self.path == "/api/capture/stop":
            if bridge.worker_thread:
                bridge.worker_thread.is_running = False
            self.send_json_response({"status": "stopped"})
        elif self.path == "/api/settings":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                new_settings = json.loads(body.decode("utf-8"))
                with bridge._lock:
                    bridge.settings.update(new_settings)
                self.send_json_response({"status": "updated", "settings": bridge.settings})
            except Exception as e:
                self.send_error(400, f"Invalid Settings Payload: {e}")
        elif self.path == "/api/utie/sensor-visibility":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                data = json.loads(body.decode("utf-8"))
                obs_str = data.get("observation_point", "PROMISCUOUS_TAP")
                try:
                    obs_pt = ObservationPoint[obs_str]
                except KeyError:
                    obs_pt = ObservationPoint.PROMISCUOUS_TAP
                ctx = SensorVisibilityContext(
                    observation_point=obs_pt,
                    sampling_rate=float(data.get("sampling_rate", 1.0)),
                    is_diode_enforced=bool(data.get("is_diode_enforced", False)),
                )
                bridge.utie_engine.set_sensor_context(ctx)
                self.send_json_response({"status": "updated", "sensor_visibility": ctx.to_dict()})
            except Exception as e:
                self.send_error(400, f"Invalid UTIE Sensor Payload: {e}")
        else:
            self.send_error(404, "Unknown API Action")

    def send_json_response(self, data: Any) -> None:
        try:
            body = json.dumps(data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self.send_error(500, f"JSON Error: {str(e)}")


class SocHttpServer(HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_soc_server(host: str = "127.0.0.1", port: int = 8765) -> Optional[HTTPServer]:
    """Spawns the local SOC HTTP server in a background daemon thread."""
    try:
        server = SocHttpServer((host, port), SocHttpHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True, name="SocHttpServerThread")
        server_thread.start()
        return server
    except Exception as e:
        print(f"[!] Warning: Could not bind SOC Web server on {host}:{port}: {e}")
        return None
