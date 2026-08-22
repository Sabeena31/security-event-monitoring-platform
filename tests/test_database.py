import os
import sys
import tempfile
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings

# Redirect the DB to a temp file before importing the db module's users,
# so tests never touch the real demo database.
_tmp_dir = tempfile.mkdtemp()
settings.DB_PATH = os.path.join(_tmp_dir, "test_security.db")

from database import db  # noqa: E402


def setup_function(_):
    db.init_db()
    db.clear_all()


def test_init_db_creates_file():
    db.init_db()
    assert os.path.exists(settings.DB_PATH)


def test_insert_and_fetch_events():
    events = [{
        "timestamp": datetime(2026, 8, 22, 10, 0, 0),
        "source_ip": "1.1.1.1",
        "username": "admin",
        "event_type": "failed_login",
        "status": "failure",
        "service": "sshd",
        "request": None,
        "raw": "raw line",
    }]
    inserted = db.insert_events(events)
    assert inserted == 1
    df = db.fetch_events()
    assert len(df) == 1
    assert df.iloc[0]["source_ip"] == "1.1.1.1"


def test_insert_and_fetch_alerts():
    alerts = [{
        "alert_id": "ALT-TEST0001",
        "timestamp": datetime(2026, 8, 22, 10, 5, 0),
        "threat_type": "Brute Force",
        "source_ip": "1.1.1.1",
        "severity": "High",
        "description": "test alert",
        "detection_rule": "Brute Force Detection",
        "related_event_count": 5,
        "status": "New",
    }]
    inserted = db.insert_alerts(alerts)
    assert inserted == 1
    df = db.fetch_alerts()
    assert len(df) == 1
    assert df.iloc[0]["alert_id"] == "ALT-TEST0001"


def test_update_alert_status():
    alerts = [{
        "alert_id": "ALT-TEST0002",
        "timestamp": datetime(2026, 8, 22, 10, 5, 0),
        "threat_type": "Brute Force",
        "source_ip": "2.2.2.2",
        "severity": "High",
        "description": "test alert",
        "detection_rule": "Brute Force Detection",
        "related_event_count": 5,
        "status": "New",
    }]
    db.insert_alerts(alerts)
    db.update_alert_status("ALT-TEST0002", "Resolved")
    df = db.fetch_alerts()
    assert df.iloc[0]["status"] == "Resolved"


def test_counts_summary_empty():
    counts = db.counts_summary()
    assert counts["total_events"] == 0
    assert counts["total_alerts"] == 0
