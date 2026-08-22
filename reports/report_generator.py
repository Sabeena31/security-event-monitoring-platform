"""
Module 5 — Report Generation

Builds summary statistics from the database and supports exporting
events/alerts to CSV.
"""

import os
import sys
from datetime import datetime

import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings
from database import db


def build_summary():
    """Return a dict of summary statistics for the Reports page."""
    events_df = db.fetch_events()
    alerts_df = db.fetch_alerts()

    summary = {
        "generated_at": datetime.now(),
        "total_events": len(events_df),
        "total_alerts": len(alerts_df),
    }

    if not alerts_df.empty:
        summary["threats_by_severity"] = alerts_df["severity"].value_counts().to_dict()
        summary["threats_by_type"] = alerts_df["threat_type"].value_counts().to_dict()
        summary["top_source_ips"] = alerts_df["source_ip"].value_counts().head(10).to_dict()
        summary["rules_triggered"] = alerts_df["detection_rule"].value_counts().to_dict()
    else:
        summary["threats_by_severity"] = {}
        summary["threats_by_type"] = {}
        summary["top_source_ips"] = {}
        summary["rules_triggered"] = {}

    if not events_df.empty:
        failed = events_df[events_df["event_type"].isin(["failed_login", "invalid_user_attempt"])]
        success = events_df[events_df["event_type"] == "successful_login"]
        web = events_df[events_df["service"] == "apache"]
        summary["failed_login_count"] = len(failed)
        summary["successful_login_count"] = len(success)
        summary["web_request_count"] = len(web)
        summary["most_active_ips"] = events_df["source_ip"].value_counts().head(10).to_dict()
    else:
        summary["failed_login_count"] = 0
        summary["successful_login_count"] = 0
        summary["web_request_count"] = 0
        summary["most_active_ips"] = {}

    return summary


def export_events_csv(path=None):
    path = path or os.path.join(settings.EXPORT_DIR, "security_events_export.csv")
    df = db.fetch_events()
    df.to_csv(path, index=False)
    return path


def export_alerts_csv(path=None):
    path = path or os.path.join(settings.EXPORT_DIR, "threat_alerts_export.csv")
    df = db.fetch_alerts()
    df.to_csv(path, index=False)
    return path


def build_text_report():
    """Render the summary as a simple, professional plain-text report
    (kept dependency-free — no PDF library required for the viva)."""
    s = build_summary()
    lines = []
    lines.append("SECURITY EVENT MONITORING & THREAT DETECTION PLATFORM")
    lines.append("Incident Summary Report")
    lines.append(f"Generated: {s['generated_at'].strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("-" * 60)
    lines.append(f"Total events analyzed : {s['total_events']}")
    lines.append(f"Total threats detected: {s['total_alerts']}")
    lines.append(f"Failed login attempts : {s['failed_login_count']}")
    lines.append(f"Successful logins     : {s['successful_login_count']}")
    lines.append(f"Web requests analyzed : {s['web_request_count']}")
    lines.append("")
    lines.append("Threats by severity:")
    for k, v in s["threats_by_severity"].items():
        lines.append(f"  - {k}: {v}")
    lines.append("")
    lines.append("Threats by type:")
    for k, v in s["threats_by_type"].items():
        lines.append(f"  - {k}: {v}")
    lines.append("")
    lines.append("Top source IPs (by alert count):")
    for k, v in s["top_source_ips"].items():
        lines.append(f"  - {k}: {v}")
    lines.append("")
    lines.append("Detection rules triggered:")
    for k, v in s["rules_triggered"].items():
        lines.append(f"  - {k}: {v}")
    lines.append("-" * 60)
    lines.append("Note: This report reflects rule-based detection on simulated")
    lines.append("logs for educational purposes, not a production SIEM finding.")
    return "\n".join(lines)


def export_text_report(path=None):
    path = path or os.path.join(settings.EXPORT_DIR, "incident_summary_report.txt")
    with open(path, "w") as f:
        f.write(build_text_report())
    return path
