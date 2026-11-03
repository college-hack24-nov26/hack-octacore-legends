"""Event Persistence and Database Storage for UniGuard AI.

Stores detected security events, flow behavioral statistics, and system alerts
in a fast, lightweight SQLite database.
"""

from __future__ import annotations

import sqlite3
import json
import os
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
                    is_excluded INTEGER DEFAULT 0
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_threat ON security_events(threat_type);")

            # Migrations for existing databases
            for col, col_type in [
                ("directionality_state", "TEXT DEFAULT 'UNKNOWN'"),
                ("directionality_score", "REAL DEFAULT 0.0"),
                ("directionality_confidence", "REAL DEFAULT 0.0"),
                ("baseline_5_20_result", "TEXT DEFAULT 'N/A'"),
                ("is_excluded", "INTEGER DEFAULT 0"),
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
                    baseline_5_20_result, is_excluded
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                item["contributing_factors"] = json.loads(item["contributing_factors"])
                item["flow_metrics"] = json.loads(item["flow_metrics"])
                item.setdefault("directionality_state", "UNKNOWN")
                item.setdefault("directionality_score", 0.0)
                item.setdefault("directionality_confidence", 0.0)
                item.setdefault("baseline_5_20_result", "N/A")
                item.setdefault("is_excluded", 0)
                events.append(item)
            return events

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
