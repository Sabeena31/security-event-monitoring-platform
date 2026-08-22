import os
import sys
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.engine import run_detection
from config import settings


def _make_failed_login_events(ip, count, gap_seconds=10, start=None, username="admin"):
    start = start or datetime(2026, 8, 22, 10, 0, 0)
    events = []
    for i in range(count):
        events.append({
            "timestamp": start + timedelta(seconds=i * gap_seconds),
            "source_ip": ip,
            "username": username,
            "event_type": "failed_login",
            "status": "failure",
            "service": "sshd",
            "request": None,
            "raw": f"fake failed login {i}",
        })
    return events


def test_below_threshold_no_brute_force_alert():
    events = _make_failed_login_events("1.2.3.4", settings.BRUTE_FORCE_ATTEMPTS - 1)
    alerts = run_detection(events)
    brute_force_alerts = [a for a in alerts if a["detection_rule"] == "Brute Force Detection"]
    assert len(brute_force_alerts) == 0


def test_at_threshold_triggers_brute_force_alert():
    events = _make_failed_login_events("1.2.3.4", settings.BRUTE_FORCE_ATTEMPTS)
    alerts = run_detection(events)
    brute_force_alerts = [a for a in alerts if a["detection_rule"] == "Brute Force Detection"]
    assert len(brute_force_alerts) == 1
    assert brute_force_alerts[0]["source_ip"] == "1.2.3.4"
    assert brute_force_alerts[0]["severity"] == "High"


def test_events_outside_window_do_not_trigger():
    events = _make_failed_login_events(
        "5.6.7.8", settings.BRUTE_FORCE_ATTEMPTS,
        gap_seconds=(settings.BRUTE_FORCE_WINDOW_MINUTES * 60) + 30,
    )
    alerts = run_detection(events)
    brute_force_alerts = [a for a in alerts if a["detection_rule"] == "Brute Force Detection"]
    assert len(brute_force_alerts) == 0


def test_suspicious_web_request_detection():
    start = datetime(2026, 8, 22, 12, 0, 0)
    events = []
    for i in range(settings.SUSPICIOUS_PATH_HITS):
        events.append({
            "timestamp": start + timedelta(seconds=i * 5),
            "source_ip": "9.9.9.9",
            "username": None,
            "event_type": "web_request",
            "status": "forbidden",
            "service": "apache",
            "request": "GET /phpmyadmin (403)",
            "raw": "fake web line",
        })
    alerts = run_detection(events)
    web_alerts = [a for a in alerts if a["detection_rule"] == "Suspicious Web Request"]
    assert len(web_alerts) == 1


def test_empty_events_returns_no_alerts():
    assert run_detection([]) == []
