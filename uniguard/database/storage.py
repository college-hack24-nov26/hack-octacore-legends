"""Event Persistence and Database Storage for UniGuard AI.

Stores detected security events, flow behavioral statistics, and system alerts
in a fast, lightweight SQLite database.
"""

from __future__ import annotations

import sqlite3
import json
import os
import time
from typing import List, Dict, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from uniguard.detection.engine import SecurityEvent


DEFAULT_DB_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "uniguard_events.db")
)


class SecurityDatabase:
    """Manages SQLite storage for UniGuard AI alerts and flow telemetry."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or DEFAULT_DB_PATH
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        """Initializes database schema with indexing and WAL mode for fast SOC queries."""
        # Configure persistent WAL journal mode
        init_conn = sqlite3.connect(self.db_path, timeout=10.0)
        init_conn.execute("PRAGMA journal_mode=WAL;")
        init_conn.close()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    timestamp REAL NOT NULL,
                    flow_key TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dst_port INTEGER NOT NULL,
                    proto INTEGER NOT NULL,
                    threat_type TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    confidence_pct REAL NOT NULL,
                    anomaly_score REAL NOT NULL,
                    contributing_factors TEXT NOT NULL,
                    flow_metrics TEXT NOT NULL,
                    directionality_state TEXT DEFAULT 'UNKNOWN',
                    directionality_score REAL DEFAULT 0.0,
                    directionality_confidence REAL DEFAULT 0.0,
                    baseline_5_20_result TEXT DEFAULT 'N/A',
                    is_excluded INTEGER DEFAULT 0,
                    explanation_json TEXT DEFAULT '{}'
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_threat ON security_events(threat_type);")

            # UTIE Flow Intelligence Table (SIH 2026 Core Feature)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS utie_flow_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id TEXT UNIQUE NOT NULL,
                    timestamp REAL NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dst_port INTEGER NOT NULL,
                    proto INTEGER NOT NULL,
                    proto_name TEXT NOT NULL,
                    directionality TEXT NOT NULL,
                    directionality_confidence REAL NOT NULL,
                    sensor_visibility_type TEXT NOT NULL,
                    is_reverse_missing INTEGER DEFAULT 0,
                    packet_count INTEGER NOT NULL,
                    reverse_packet_count INTEGER,
                    byte_count INTEGER NOT NULL,
                    reverse_byte_count INTEGER,
                    duration REAL NOT NULL,
                    pkt_rate REAL NOT NULL,
                    byte_rate REAL NOT NULL,
                    anomaly_status TEXT NOT NULL,
                    anomaly_score REAL NOT NULL,
                    threat_category TEXT,
                    risk_score INTEGER,
                    severity TEXT,
                    evidence_json TEXT NOT NULL,
                    behavior_json TEXT NOT NULL,
                    investigation_json TEXT NOT NULL
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_utie_timestamp ON utie_flow_intelligence(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_utie_directionality ON utie_flow_intelligence(directionality);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_utie_threat ON utie_flow_intelligence(threat_category);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_utie_src ON utie_flow_intelligence(src_ip);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_utie_dst ON utie_flow_intelligence(dst_ip);")

            # Migrations for existing databases
            for col, col_type in [
                ("directionality_state", "TEXT DEFAULT 'UNKNOWN'"),
                ("directionality_score", "REAL DEFAULT 0.0"),
                ("directionality_confidence", "REAL DEFAULT 0.0"),
                ("baseline_5_20_result", "TEXT DEFAULT 'N/A'"),
                ("is_excluded", "INTEGER DEFAULT 0"),
                ("explanation_json", "TEXT DEFAULT '{}'"),
            ]:
                try:
                    cursor.execute(f"ALTER TABLE security_events ADD COLUMN {col} {col_type};")
                except sqlite3.OperationalError:
                    pass

            conn.commit()

    def insert_event(self, event: SecurityEvent) -> None:
        """Persists a SecurityEvent object to the database."""
        self.insert_events_batch([event])

    def insert_events_batch(self, events: List[SecurityEvent]) -> None:
        """Persists a batch of SecurityEvent objects inside a single high-speed transaction."""
        if not events:
            return
        records = [
            (
                e.event_id,
                e.timestamp,
                e.flow_key,
                e.src_ip,
                e.dst_ip,
                e.src_port,
                e.dst_port,
                e.proto,
                e.threat_type,
                e.risk_score,
                e.severity,
                e.confidence_pct,
                e.anomaly_score,
                json.dumps(e.contributing_factors),
                json.dumps(e.flow_metrics),
                getattr(e, "directionality_state", "UNKNOWN"),
                getattr(e, "directionality_score", 0.0),
                getattr(e, "directionality_confidence", 0.0),
                getattr(e, "baseline_5_20_result", "N/A"),
                1 if getattr(e, "is_excluded_from_unidirectional_security", False) else 0,
                json.dumps(getattr(e, "explanation", {}) or {}),
            )
            for e in events
        ]
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany(
                """
                INSERT OR IGNORE INTO security_events (
                    event_id, timestamp, flow_key, src_ip, dst_ip, src_port, dst_port,
                    proto, threat_type, risk_score, severity, confidence_pct,
                    anomaly_score, contributing_factors, flow_metrics,
                    directionality_state, directionality_score, directionality_confidence,
                    baseline_5_20_result, is_excluded, explanation_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                records,
            )
            conn.commit()

    def get_recent_events(self, limit: int = 100, min_risk: int = 0) -> List[Dict[str, Any]]:
        """Retrieves recent security events for the desktop table view."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM security_events 
                WHERE risk_score >= ? 
                ORDER BY timestamp DESC 
                LIMIT ?
                """,
                (min_risk, limit),
            )
            rows = cursor.fetchall()
            events = []
            for row in rows:
                item = dict(row)
                try:
                    item["contributing_factors"] = json.loads(item["contributing_factors"])
                except Exception:
                    item["contributing_factors"] = []
                try:
                    item["flow_metrics"] = json.loads(item["flow_metrics"])
                except Exception:
                    item["flow_metrics"] = {}
                try:
                    item["explanation"] = json.loads(item.get("explanation_json", "{}") or "{}")
                except Exception:
                    item["explanation"] = {}
                item.setdefault("directionality_state", "UNKNOWN")
                item.setdefault("directionality_score", 0.0)
                item.setdefault("directionality_confidence", 0.0)
                item.setdefault("baseline_5_20_result", "N/A")
                item.setdefault("is_excluded", 0)
                events.append(item)
            return events

    def search_events(
        self,
        query: str = "",
        severity: str = "ALL",
        threat_type: str = "ALL",
        min_risk: int = 0,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        """Searches and filters historical security events with multi-parameter criteria."""
        sql = "SELECT * FROM security_events WHERE risk_score >= ?"
        params: List[Any] = [min_risk]

        sev_clean = (severity or "").strip().upper()
        if sev_clean and sev_clean not in ("ALL", "ALL SEVERITIES", "ALL_SEVERITIES", "*"):
            sql += " AND UPPER(severity) = ?"
            params.append(sev_clean)

        threat_clean = (threat_type or "").strip().upper()
        if threat_clean and threat_clean not in ("ALL", "ALL THREAT TYPES", "ALL_THREAT_TYPES", "ALL THREAT CLASSES", "*"):
            sql += " AND UPPER(threat_type) = ?"
            params.append(threat_clean)

        if query:
            clean_q = f"%{query.strip()}%"
            sql += " AND (event_id LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR flow_key LIKE ? OR threat_type LIKE ?)"
            params.extend([clean_q, clean_q, clean_q, clean_q, clean_q])

        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            events = []
            for row in rows:
                item = dict(row)
                try:
                    item["contributing_factors"] = json.loads(item["contributing_factors"])
                except Exception:
                    item["contributing_factors"] = []
                try:
                    item["flow_metrics"] = json.loads(item["flow_metrics"])
                except Exception:
                    item["flow_metrics"] = {}
                try:
                    item["explanation"] = json.loads(item.get("explanation_json", "{}") or "{}")
                except Exception:
                    item["explanation"] = {}
                item.setdefault("directionality_state", "UNKNOWN")
                item.setdefault("directionality_score", 0.0)
                item.setdefault("directionality_confidence", 0.0)
                item.setdefault("baseline_5_20_result", "N/A")
                item.setdefault("is_excluded", 0)
                events.append(item)
            return events

    def get_event_explanation(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves structured AI threat explanation for a specific event ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT explanation_json FROM security_events WHERE event_id = ? LIMIT 1",
                (event_id,),
            )
            row = cursor.fetchone()
            if row and row["explanation_json"]:
                try:
                    return json.loads(row["explanation_json"])
                except Exception:
                    return None
            return None

    def get_summary_statistics(self) -> Dict[str, Any]:
        """Calculates aggregate statistics for the desktop dashboard header cards."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM security_events")
            total_events = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM security_events WHERE risk_score >= 35")
            total_threats = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM security_events WHERE severity IN ('HIGH', 'CRITICAL')")
            critical_threats = cursor.fetchone()[0]

            cursor.execute("SELECT threat_type, COUNT(*) as cnt FROM security_events GROUP BY threat_type")
            threat_distribution = {row["threat_type"]: row["cnt"] for row in cursor.fetchall()}

            cursor.execute("SELECT directionality_state, COUNT(*) as cnt FROM security_events GROUP BY directionality_state")
            directionality_distribution = {row["directionality_state"]: row["cnt"] for row in cursor.fetchall()}

            cursor.execute("SELECT COUNT(*) FROM security_events WHERE is_excluded = 1")
            excluded_flows = cursor.fetchone()[0]

            return {
                "total_flows_logged": total_events,
                "threats_detected": total_threats,
                "critical_alerts": critical_threats,
                "threat_distribution": threat_distribution,
                "directionality_distribution": directionality_distribution,
                "excluded_flows_count": excluded_flows,
            }

    # =========================================================================
    # UTIE Intelligence Database Operations (SIH 2026 Core Feature)
    # =========================================================================

    def insert_utie_report(self, report: Any) -> None:
        """Persists a single UTIEIntelligenceReport object to SQLite."""
        self.insert_utie_reports_batch([report])

    def insert_utie_reports_batch(self, reports: List[Any]) -> None:
        """Persists a batch of UTIEIntelligenceReport objects in a single transaction."""
        if not reports:
            return
        records = []
        for r in reports:
            # Can accept UTIEIntelligenceReport or dict
            d = r.to_dict() if hasattr(r, "to_dict") else r
            records.append((
                d["flow_id"],
                d.get("analysis_timestamp", time.time() if "time" in globals() else 0.0),
                d["src_ip"],
                d["dst_ip"],
                d["src_port"],
                d["dst_port"],
                d["proto"],
                d.get("proto_name", "UNKNOWN"),
                d["directionality"],
                d["directionality_confidence"],
                d.get("sensor_visibility", {}).get("visibility_type", "UNKNOWN") if isinstance(d.get("sensor_visibility"), dict) else "UNKNOWN",
                1 if d.get("sensor_visibility", {}).get("is_reverse_missing", False) else 0,
                d["packet_count"],
                d.get("reverse_packet_count"),
                d["byte_count"],
                d.get("reverse_byte_count"),
                d["duration"],
                d["pkt_rate"],
                d["byte_rate"],
                d["anomaly_status"],
                d["anomaly_score"],
                d.get("ml_threat_category"),
                d.get("risk_score"),
                d.get("severity"),
                json.dumps(d.get("directionality_evidence", [])),
                json.dumps(d.get("traffic_behavior_summary", {})),
                json.dumps(d.get("suggested_investigation_steps", [])),
            ))

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany(
                """
                INSERT OR IGNORE INTO utie_flow_intelligence (
                    flow_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                    proto, proto_name, directionality, directionality_confidence,
                    sensor_visibility_type, is_reverse_missing, packet_count,
                    reverse_packet_count, byte_count, reverse_byte_count,
                    duration, pkt_rate, byte_rate, anomaly_status, anomaly_score,
                    threat_category, risk_score, severity,
                    evidence_json, behavior_json, investigation_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                records,
            )
            conn.commit()

    def get_recent_utie_reports(self, limit: int = 100, directionality: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves recent UTIE flow intelligence reports with optional directionality filter."""
        sql = "SELECT * FROM utie_flow_intelligence"
        params: List[Any] = []
        dir_clean = (directionality or "").strip().upper()
        if dir_clean and dir_clean not in ("ALL", "ALL DIRECTIONALITIES", "ALL_DIRECTIONALITIES", "*"):
            sql += " WHERE UPPER(directionality) = ?"
            params.append(dir_clean)

        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            reports = []
            for row in rows:
                item = dict(row)
                try:
                    item["directionality_evidence"] = json.loads(item["evidence_json"])
                except Exception:
                    item["directionality_evidence"] = []
                try:
                    item["traffic_behavior_summary"] = json.loads(item["behavior_json"])
                except Exception:
                    item["traffic_behavior_summary"] = {}
                try:
                    item["suggested_investigation_steps"] = json.loads(item["investigation_json"])
                except Exception:
                    item["suggested_investigation_steps"] = []
                reports.append(item)
            return reports

    def search_utie_reports(
        self,
        query: Optional[str] = None,
        directionality: Optional[str] = None,
        min_risk: int = 0,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Searches UTIE reports across IP, port, flow_id, threat_category, and directionality."""
        sql = "SELECT * FROM utie_flow_intelligence WHERE 1=1"
        params: List[Any] = []

        if min_risk > 0:
            sql += " AND (risk_score IS NOT NULL AND risk_score >= ?)"
            params.append(min_risk)

        dir_clean = (directionality or "").strip().upper()
        if dir_clean and dir_clean not in ("ALL", "ALL DIRECTIONALITIES", "ALL_DIRECTIONALITIES", "*"):
            sql += " AND UPPER(directionality) = ?"
            params.append(dir_clean)

        if query and query.strip():
            q = f"%{query.strip()}%"
            sql += " AND (flow_id LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR threat_category LIKE ? OR proto_name LIKE ?)"
            params.extend([q, q, q, q, q])

        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            results = []
            for row in rows:
                item = dict(row)
                try:
                    item["directionality_evidence"] = json.loads(item["evidence_json"])
                except Exception:
                    item["directionality_evidence"] = []
                try:
                    item["traffic_behavior_summary"] = json.loads(item["behavior_json"])
                except Exception:
                    item["traffic_behavior_summary"] = {}
                try:
                    item["suggested_investigation_steps"] = json.loads(item["investigation_json"])
                except Exception:
                    item["suggested_investigation_steps"] = []
                results.append(item)
            return results

    def get_utie_summary_statistics(self) -> Dict[str, Any]:
        """Calculates aggregate statistics across stored UTIE records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM utie_flow_intelligence")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT directionality, COUNT(*) as cnt FROM utie_flow_intelligence GROUP BY directionality")
            dir_dist = {row["directionality"]: row["cnt"] for row in cursor.fetchall()}

            cursor.execute("SELECT COUNT(*) FROM utie_flow_intelligence WHERE (risk_score >= 35 OR threat_category NOT IN ('BENIGN', NULL))")
            suspicious = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM utie_flow_intelligence WHERE anomaly_status = 'ANOMALOUS'")
            anomalous = cursor.fetchone()[0]

            return {
                "total_flows_stored": total,
                "directionality_distribution": dir_dist,
                "suspicious_flows": suspicious,
                "anomalous_flows": anomalous,
            }
