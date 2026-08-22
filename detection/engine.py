"""
Module 3 — Detection Engine

Runs every rule in detection.rules against the normalized event stream and
returns a consolidated list of alert dicts, ready for storage.
"""

import os
import sys

import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detection.rules import ALL_RULES


def events_to_dataframe(events):
    if not events:
        return pd.DataFrame(columns=[
            "timestamp", "source_ip", "username", "event_type",
            "status", "service", "request", "raw",
        ])
    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def run_detection(events):
    """Run all detection rules against a list of normalized events.
    Returns a list of alert dicts, sorted by timestamp descending.
    """
    if not events:
        return []

    df = events_to_dataframe(events)

    alerts = []
    for rule_fn in ALL_RULES:
        alerts.extend(rule_fn(df))

    alerts.sort(key=lambda a: a["timestamp"], reverse=True)
    return alerts
