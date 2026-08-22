"""
Module 2 — Event Normalization

Merges auth-log and access-log events into one unified event stream with a
consistent schema so the detection engine doesn't need to know which log
type an event came from.
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings
from parser.auth_parser import parse_auth_log
from parser.apache_parser import parse_access_log

EVENT_FIELDS = [
    "timestamp", "source_ip", "username", "event_type",
    "status", "service", "request", "raw",
]


def load_and_normalize(auth_path=None, access_path=None):
    """Parse both log files and return (events, stats) where events is a
    list of normalized dicts (sorted by timestamp) and stats reports parse
    quality for transparency in the UI.
    """
    auth_path = auth_path or settings.AUTH_LOG_PATH
    access_path = access_path or settings.ACCESS_LOG_PATH

    auth_events, auth_malformed = parse_auth_log(auth_path)
    web_events, web_malformed = parse_access_log(access_path)

    events = auth_events + web_events
    events.sort(key=lambda e: e["timestamp"])

    # Deduplicate exact-duplicate raw lines with the same timestamp
    seen = set()
    deduped = []
    duplicates = 0
    for e in events:
        key = (e["timestamp"], e["raw"])
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        deduped.append(e)

    stats = {
        "auth_events": len(auth_events),
        "web_events": len(web_events),
        "auth_malformed": auth_malformed,
        "web_malformed": web_malformed,
        "duplicates_removed": duplicates,
        "total_events": len(deduped),
    }

    return deduped, stats
