"""SQLite persistence for normalized events and security findings."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional


class SecurityDatabase:
    """Manage the MVP SQLite database.

    Use a file path such as `data/security_monitor.db`. The parent directory
    is created automatically. Each method opens its own short-lived connection
    so the object can be used safely by simple scripts and Streamlit reruns.
    """

    def __init__(self, db_path: str = "data/security_monitor.db") -> None:
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).expanduser().resolve().parent.mkdir(
                parents=True, exist_ok=True
            )
        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        """Create tables and indexes if they do not already exist."""
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    timestamp TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    action TEXT,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_key TEXT NOT NULL UNIQUE,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    timestamp TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    severity TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    recommendation TEXT,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp)"
            )

    @staticmethod
    def _json(data: Mapping[str, Any]) -> str:
        return json.dumps(dict(data), default=str, sort_keys=True)

    @staticmethod
    def _finding_key(finding: Mapping[str, Any]) -> str:
        """Stable key prevents duplicate inserts when a batch is reprocessed."""
        identity = {
            "rule_id": finding.get("rule_id"),
            "timestamp": finding.get("timestamp"),
            "source_ip": finding.get("source_ip"),
            "destination_ip": finding.get("destination_ip"),
            "destination_port": finding.get("destination_port"),
            "evidence": finding.get("evidence", {}),
        }
        return json.dumps(identity, default=str, sort_keys=True)

    def insert_event(self, event: Mapping[str, Any]) -> int:
        """Insert one normalized event and return its database ID."""
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO events (
                    event_type, timestamp, source_ip, destination_ip,
                    destination_port, action, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.get("event_type", "UNKNOWN"),
                    event.get("timestamp"),
                    event.get("source_ip"),
                    event.get("destination_ip"),
                    event.get("destination_port"),
                    event.get("action"),
                    self._json(event),
                ),
            )
            return int(cursor.lastrowid)

    def insert_events(self, events: Iterable[Mapping[str, Any]]) -> int:
        """Insert a batch of normalized events; return number inserted."""
        rows = [
            (
                event.get("event_type", "UNKNOWN"),
                event.get("timestamp"),
                event.get("source_ip"),
                event.get("destination_ip"),
                event.get("destination_port"),
                event.get("action"),
                self._json(event),
            )
            for event in events
        ]
        if not rows:
            return 0
        with self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO events (
                    event_type, timestamp, source_ip, destination_ip,
                    destination_port, action, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        return len(rows)

    def insert_finding(self, finding: Mapping[str, Any]) -> int:
        """Insert one scored finding, or return the existing ID if duplicated."""
        key = self._finding_key(finding)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO findings (
                    finding_key, rule_id, title, description, timestamp,
                    source_ip, destination_ip, destination_port, severity,
                    risk_score, status, recommendation, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key,
                    finding.get("rule_id", "UNKNOWN"),
                    finding.get("title", "Untitled finding"),
                    finding.get("description"),
                    finding.get("timestamp"),
                    finding.get("source_ip"),
                    finding.get("destination_ip"),
                    finding.get("destination_port"),
                    finding.get("severity", "INFORMATIONAL"),
                    int(finding.get("risk_score", 0)),
                    finding.get("status", "OPEN"),
                    finding.get("recommendation"),
                    self._json(finding),
                ),
            )
            row = connection.execute(
                "SELECT id FROM findings WHERE finding_key = ?", (key,)
            ).fetchone()
            return int(row["id"])

    def insert_findings(self, findings: Iterable[Mapping[str, Any]]) -> int:
        """Insert findings and return the number of new rows."""
        inserted = 0
        for finding in findings:
            before = self.get_finding_id(finding)
            self.insert_finding(finding)
            if before is None:
                inserted += 1
        return inserted

    def get_finding_id(self, finding: Mapping[str, Any]) -> Optional[int]:
        key = self._finding_key(finding)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT id FROM findings WHERE finding_key = ?", (key,)
            ).fetchone()
            return int(row["id"]) if row else None

    def get_findings(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Return findings newest-first, with optional severity/status filters."""
        if limit <= 0:
            raise ValueError("limit must be greater than zero.")

        clauses = []
        params: List[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        if status:
            clauses.append("status = ?")
            params.append(status.upper())

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)

        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT * FROM findings
                {where}
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
                """,
                params,
            ).fetchall()

        results = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            results.append(item)
        return results

    def get_recent_events(self, limit: int = 500) -> List[Dict[str, Any]]:
        if limit <= 0:
            raise ValueError("limit must be greater than zero.")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM events
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        results = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            results.append(item)
        return results

    def update_finding_status(self, finding_id: int, status: str) -> bool:
        """Update workflow status; accepted values are OPEN, INVESTIGATING, CLOSED."""
        normalized = status.upper()
        if normalized not in {"OPEN", "INVESTIGATING", "CLOSED"}:
            raise ValueError("status must be OPEN, INVESTIGATING, or CLOSED.")

        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE findings SET status = ? WHERE id = ?",
                (normalized, finding_id),
            )
            return cursor.rowcount > 0

    def get_summary(self) -> Dict[str, int]:
        """Return event/finding totals and severity counts for dashboard cards."""
        summary = {
            "total_events": 0,
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "open": 0,
        }
        with self._connect() as connection:
            event_row = connection.execute(
                "SELECT COUNT(*) AS count FROM events"
            ).fetchone()
            finding_row = connection.execute(
                "SELECT COUNT(*) AS count FROM findings"
            ).fetchone()
            summary["total_events"] = int(event_row["count"])
            summary["total_findings"] = int(finding_row["count"])

            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
                row = connection.execute(
                    "SELECT COUNT(*) AS count FROM findings WHERE severity = ?",
                    (severity,),
                ).fetchone()
                summary[severity.lower()] = int(row["count"])

            row = connection.execute(
                "SELECT COUNT(*) AS count FROM findings WHERE status = 'OPEN'"
            ).fetchone()
            summary["open"] = int(row["count"])

        return summary
