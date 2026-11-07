"""SQLite persistence for scan history. Uses parameterised queries throughout."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.getenv("SECURELENS_DB", "securelens.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   TEXT    NOT NULL,
    filename     TEXT,
    language     TEXT    NOT NULL,
    risk_score   INTEGER NOT NULL,
    finding_count INTEGER NOT NULL,
    ai_mode      TEXT,
    code         TEXT    NOT NULL,
    result_json  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
"""


@contextmanager
def connect(path: str | None = None):
    conn = sqlite3.connect(path or DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(path: str | None = None) -> None:
    with connect(path) as conn:
        conn.executescript(SCHEMA)


def save_scan(code: str, filename: str | None, payload: dict, path: str | None = None) -> int:
    active = [f for f in payload["findings"] if not f.get("false_positive")]
    with connect(path) as conn:
        cur = conn.execute(
            "INSERT INTO scans (created_at, filename, language, risk_score, finding_count, "
            "ai_mode, code, result_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                filename,
                payload["language"],
                payload["risk_score"],
                len(active),
                payload["ai"]["mode"],
                code,
                json.dumps(payload),
            ),
        )
        return cur.lastrowid


def list_scans(limit: int = 20, path: str | None = None) -> list[dict]:
    with connect(path) as conn:
        rows = conn.execute(
            "SELECT id, created_at, filename, language, risk_score, finding_count, ai_mode "
            "FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: int, path: str | None = None) -> dict | None:
    with connect(path) as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    data = dict(row)
    data["result"] = json.loads(data.pop("result_json"))
    return data


def delete_scan(scan_id: int, path: str | None = None) -> bool:
    with connect(path) as conn:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cur.rowcount > 0


def stats(path: str | None = None) -> dict:
    with connect(path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS scans, COALESCE(SUM(finding_count), 0) AS findings, "
            "COALESCE(ROUND(AVG(risk_score), 1), 0) AS avg_risk FROM scans"
        ).fetchone()
    return dict(row)
