"""
Module 4 — SQLite Storage

Handles schema creation and all read/write access to security.db. The
database is created automatically on first use.
"""

import os
import sqlite3
import sys
import uuid
from contextlib import contextmanager

import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS security_events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    username TEXT,
    event_type TEXT,
    status TEXT,
    service TEXT,
    request TEXT,
    raw_event TEXT
);

CREATE TABLE IF NOT EXISTS threat_alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    threat_type TEXT,
    source_ip TEXT,
    severity TEXT,
    description TEXT,
    detection_rule TEXT,
    related_event_count INTEGER,
    status TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON threat_alerts(timestamp);
"""


@contextmanager
def get_connection():
    conn = sqlite3.connect(settings.DB_PATH)
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Create the database and tables if they do not already exist."""
    with get_connection() as conn:
        conn.executescript(SCHEMA)
        conn.commit()


def clear_all():
    """Wipe both tables — used before loading a fresh demo dataset."""
    init_db()
    with get_connection() as conn:
        conn.execute("DELETE FROM security_events")
        conn.execute("DELETE FROM threat_alerts")
        conn.commit()


def insert_events(events):
    """Bulk-insert normalized events. Skips exact-duplicate rows."""
    if not events:
        return 0
    init_db()
    rows = []
    for e in events:
        rows.append((
            str(uuid.uuid4()),
            e["timestamp"].isoformat() if hasattr(e["timestamp"], "isoformat") else str(e["timestamp"]),
            e.get("source_ip"),
            e.get("username"),
            e.get("event_type"),
            e.get("status"),
            e.get("service"),
            e.get("request"),
            e.get("raw"),
        ))
    with get_connection() as conn:
        conn.executemany(
            "INSERT OR IGNORE INTO security_events "
            "(event_id, timestamp, source_ip, username, event_type, status, service, request, raw_event) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    return len(rows)


def insert_alerts(alerts):
    """Bulk-insert threat alerts."""
    if not alerts:
        return 0
    init_db()
    rows = []
    for a in alerts:
        rows.append((
            a["alert_id"],
            a["timestamp"].isoformat() if hasattr(a["timestamp"], "isoformat") else str(a["timestamp"]),
            a.get("threat_type"),
            a.get("source_ip"),
            a.get("severity"),
            a.get("description"),
            a.get("detection_rule"),
            a.get("related_event_count"),
            a.get("status", "New"),
        ))
    with get_connection() as conn:
        conn.executemany(
            "INSERT OR IGNORE INTO threat_alerts "
            "(alert_id, timestamp, threat_type, source_ip, severity, description, "
            "detection_rule, related_event_count, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    return len(rows)


def fetch_events(limit=None):
    init_db()
    with get_connection() as conn:
        query = "SELECT * FROM security_events ORDER BY timestamp DESC"
        if limit:
            query += f" LIMIT {int(limit)}"
        df = pd.read_sql_query(query, conn, parse_dates=["timestamp"])
    return df


def fetch_alerts(limit=None):
    init_db()
    with get_connection() as conn:
        query = "SELECT * FROM threat_alerts ORDER BY timestamp DESC"
        if limit:
            query += f" LIMIT {int(limit)}"
        df = pd.read_sql_query(query, conn, parse_dates=["timestamp"])
    return df


def update_alert_status(alert_id, new_status):
    init_db()
    with get_connection() as conn:
        conn.execute(
            "UPDATE threat_alerts SET status = ? WHERE alert_id = ?",
            (new_status, alert_id),
        )
        conn.commit()


def counts_summary():
    """Quick counts used by the dashboard home page."""
    init_db()
    with get_connection() as conn:
        total_events = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        total_alerts = conn.execute("SELECT COUNT(*) FROM threat_alerts").fetchone()[0]
        high_critical = conn.execute(
            "SELECT COUNT(*) FROM threat_alerts WHERE severity IN ('High','Critical')"
        ).fetchone()[0]
        unique_ips = conn.execute(
            "SELECT COUNT(DISTINCT source_ip) FROM security_events WHERE source_ip IS NOT NULL"
        ).fetchone()[0]
    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "high_critical": high_critical,
        "unique_ips": unique_ips,
    }
