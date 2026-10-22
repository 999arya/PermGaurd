"""Local SQLite scan history.

Stores scan summaries (NOT uploaded APKs) so the Comparison tab can rank
multiple analyses. Everything lives in a gitignored local file; the UI
provides a one-click "delete all scan data" action.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional

from .models import ScanResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id      TEXT PRIMARY KEY,
    scanned_at   TEXT NOT NULL,
    filename     TEXT,
    package_name TEXT,
    app_label    TEXT,
    category     TEXT,
    input_type   TEXT,
    scan_mode    TEXT,
    scan_depth   TEXT,
    risk_score   REAL,
    risk_level   TEXT,
    permission_count INTEGER,
    finding_count    INTEGER,
    critical_count   INTEGER,
    high_count       INTEGER,
    rule_versions    TEXT,
    result_json      TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_score ON scans(risk_score DESC);
"""


class ScanStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        parent = os.path.dirname(os.path.abspath(db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with self._conn() as con:
            con.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        return con

    def save(self, result: ScanResult, keep_full: bool = False) -> None:
        counts = result.severity_counts
        payload = result.model_dump(mode="json") if keep_full else None
        with self._conn() as con:
            con.execute(
                """
                INSERT OR REPLACE INTO scans
                (scan_id, scanned_at, filename, package_name, app_label,
                 category, input_type, scan_mode, scan_depth, risk_score,
                 risk_level, permission_count, finding_count, critical_count,
                 high_count, rule_versions, result_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    result.scan_id,
                    result.scan_finished_at or datetime.now(timezone.utc).isoformat(),
                    result.metadata.filename,
                    result.metadata.package_name,
                    result.metadata.app_label,
                    result.purpose.category if result.purpose else None,
                    result.metadata.input_type,
                    result.scan_mode,
                    result.scan_depth_used,
                    result.risk.score,
                    result.risk.level.value,
                    len(result.metadata.permissions),
                    len(result.findings),
                    counts.get("CRITICAL", 0),
                    counts.get("HIGH", 0),
                    json.dumps(result.rule_versions),
                    payload,
                ),
            )

    def list_scans(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._conn() as con:
            rows = con.execute(
                "SELECT scan_id, scanned_at, filename, package_name, app_label, "
                "category, input_type, scan_mode, scan_depth, risk_score, "
                "risk_level, permission_count, finding_count, critical_count, "
                "high_count FROM scans ORDER BY risk_score DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get(self, scan_id: str) -> Optional[dict[str, Any]]:
        with self._conn() as con:
            row = con.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return dict(row) if row else None

    def count(self) -> int:
        with self._conn() as con:
            return con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

    def delete_all(self) -> int:
        with self._conn() as con:
            n = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            con.execute("DELETE FROM scans")
        return n

    def delete(self, scan_id: str) -> bool:
        with self._conn() as con:
            cur = con.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        return cur.rowcount > 0
