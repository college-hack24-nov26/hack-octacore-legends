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
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, Any, List
import psutil

from uniguard.intelligence.geolocation import GeoIPResolver
from uniguard.database.storage import SecurityDatabase


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
            self.send_json_response(bridge.pipeline_status)
            return

        elif self.path.startswith("/api/logs"):
            self.send_json_response(bridge.logs)
            return

        elif self.path.startswith("/api/events/history"):
            try:
                events = bridge.database.get_recent_events(limit=100, min_risk=0)
                self.send_json_response(events)
            except Exception as e:
                self.send_json_response([])
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


def start_soc_server(host: str = "127.0.0.1", port: int = 8765) -> HTTPServer:
    """Spawns the local SOC HTTP server in a background daemon thread."""
    server = HTTPServer((host, port), SocHttpHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    return server
