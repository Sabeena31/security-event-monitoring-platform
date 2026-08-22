"""
Module 2 — Log Parser (Apache/web server logs)

Parses Apache "combined" style access log lines into structured dicts.
Malformed lines are skipped gracefully.
"""

import re
from datetime import datetime

# 203.0.113.5 - - [22/Aug/2026:10:31:22 +0000] "GET /admin HTTP/1.1" 404 512
LINE_RE = re.compile(
    r'^(?P<ip>[\d.]+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)

SUSPICIOUS_MARKERS = ["/admin", "/login", "/config", "/.env", "/wp-admin",
                       "/.git", "/phpmyadmin", "/backup", "/shell",
                       "/etc/passwd", "/xmlrpc.php"]


def _parse_timestamp(ts_str):
    try:
        return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except ValueError:
        return None


def parse_line(line):
    line = line.strip()
    if not line:
        return None

    m = LINE_RE.match(line)
    if not m:
        return None

    ts = _parse_timestamp(m.group("ts"))
    if ts is None:
        return None

    status = int(m.group("status"))
    path = m.group("path")

    if status == 200 or status == 304:
        status_bucket = "success"
    elif status == 404:
        status_bucket = "not_found"
    elif status in (401, 403):
        status_bucket = "forbidden"
    else:
        status_bucket = "other"

    event = {
        "timestamp": ts,
        "source_ip": m.group("ip"),
        "username": None,
        "event_type": "web_request",
        "status": status_bucket,
        "service": "apache",
        "request": f'{m.group("method")} {path} ({status})',
        "raw": line,
    }
    return event


def parse_access_log(path):
    """Parse a full access.log file. Returns (events, malformed_count)."""
    events = []
    malformed = 0
    try:
        with open(path, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                parsed = parse_line(line)
                if parsed is None:
                    malformed += 1
                else:
                    events.append(parsed)
    except FileNotFoundError:
        return [], 0
    return events, malformed
