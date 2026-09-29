"""Persistent storage of analysis reports.

The default backend is SQLite via the standard library (no dependencies).
A Mongo/MySQL backend can implement the same :class:`ResultStore` interface.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from models.result import Report


class ResultStore:
    """SQLite-backed report store."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def save(self, report: Report) -> int:
        cur = self._conn.execute(
            "INSERT INTO reports (target, generated_at, payload) VALUES (?, ?, ?)",
            (report.target, report.generated_at, json.dumps(report.to_dict(), ensure_ascii=False)),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def load(self, report_id: int) -> Report | None:
        row = self._conn.execute("SELECT payload FROM reports WHERE id = ?", (report_id,)).fetchone()
        return Report.from_dict(json.loads(row[0])) if row else None

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id, target, generated_at FROM reports ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [{"id": r[0], "target": r[1], "generated_at": r[2]} for r in rows]

    def close(self) -> None:
        self._conn.close()
