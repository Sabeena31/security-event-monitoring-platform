"""
Module 2 — Log Parser (Linux authentication logs)

Parses sshd-style auth.log lines into structured dicts. Malformed lines are
skipped (and counted) rather than raising, per the error-handling
requirement.
"""

import re
from datetime import datetime

CURRENT_YEAR = datetime.now().year

# Aug 22 10:31:22 server sshd[1234]: Failed password for admin from 192.168.1.20 port 4521 ssh2
LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.+)$"
)

FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
SESSION_CLOSED_RE = re.compile(r"session closed for user (?P<user>\S+)")
INVALID_USER_RE = re.compile(r"invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")


def _parse_timestamp(month, day, time_str):
    try:
        dt = datetime.strptime(f"{CURRENT_YEAR} {month} {int(day):02d} {time_str}", "%Y %b %d %H:%M:%S")
        return dt
    except ValueError:
        return None


def parse_line(line):
    """Parse a single auth.log line. Returns a normalized dict, or None if
    the line is malformed/unrecognized (handled gracefully, never raises)."""
    line = line.strip()
    if not line:
        return None

    m = LINE_RE.match(line)
    if not m:
        return None

    ts = _parse_timestamp(m.group("month"), m.group("day"), m.group("time"))
    if ts is None:
        return None

    msg = m.group("msg")

    event = {
        "timestamp": ts,
        "source_ip": None,
        "username": None,
        "event_type": "auth_other",
        "status": "info",
        "service": "sshd",
        "request": None,
        "raw": line,
    }

    fm = FAILED_RE.search(msg)
    if fm:
        event["source_ip"] = fm.group("ip")
        event["username"] = fm.group("user")
        event["status"] = "failure"
        event["event_type"] = "invalid_user_attempt" if "invalid user" in msg else "failed_login"
        return event

    am = ACCEPTED_RE.search(msg)
    if am:
        event["source_ip"] = am.group("ip")
        event["username"] = am.group("user")
        event["status"] = "success"
        event["event_type"] = "successful_login"
        return event

    sm = SESSION_CLOSED_RE.search(msg)
    if sm:
        event["username"] = sm.group("user")
        event["status"] = "info"
        event["event_type"] = "logout"
        return event

    # Unrecognized but well-formed sshd line — keep as a generic event
    event["event_type"] = "auth_other"
    return event


def parse_auth_log(path):
    """Parse a full auth.log file. Returns (events, malformed_count)."""
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
