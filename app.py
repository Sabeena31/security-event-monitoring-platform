"""
Security Event Monitoring & Threat Detection Platform
Main Streamlit application.

Run with:  streamlit run app.py
"""

import os
import sys
from datetime import datetime

import pandas as pd
import streamlit as st

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from config import settings
from generator.log_generator import write_logs
from parser.normalizer import load_and_normalize
from detection.engine import run_detection
from database import db
from dashboard import components, charts
from reports import report_generator

st.set_page_config(
    page_title="Security Event Monitoring & Threat Detection Platform",
    layout="wide",
    initial_sidebar_state="expanded",
)

components.inject_base_css()
db.init_db()


# ---------------------------------------------------------------- helpers
def run_full_pipeline(auth_count=300, access_count=300):
    """Log Generation -> Parsing -> Detection -> Storage, in one call."""
    try:
        write_logs(auth_count=auth_count, access_count=access_count)
        events, parse_stats = load_and_normalize()
        alerts = run_detection(events)

        db.clear_all()
        db.insert_events(events)
        db.insert_alerts(alerts)

        return {"ok": True, "parse_stats": parse_stats, "alert_count": len(alerts)}
    except Exception as exc:
        # Never expose a raw traceback to the user.
        return {"ok": False, "error": str(exc)}


# ---------------------------------------------------------------- sidebar
st.sidebar.title("Security Monitor")
st.sidebar.caption("Rule-based threat detection — student project")

page = st.sidebar.radio(
    "Navigate",
    ["Dashboard", "Security Events", "Threat Alerts", "Detection Rules", "Reports", "Settings / About"],
    label_visibility="collapsed",
)

st.sidebar.markdown("---")
st.sidebar.subheader("Demo Data")
num_events = st.sidebar.slider("Approx. log entries per source", 100, 800, 300, step=50)

if st.sidebar.button("Generate Demo Logs", use_container_width=True):
    with st.spinner("Generating logs, parsing, and running detection rules..."):
        result = run_full_pipeline(auth_count=num_events, access_count=num_events)
    if result["ok"]:
        st.sidebar.success(
            f"Loaded {result['parse_stats']['total_events']} events, "
            f"found {result['alert_count']} alerts."
        )
    else:
        st.sidebar.error("Could not generate demo data. Please try again.")

counts = db.counts_summary()
if counts["total_events"] == 0:
    st.sidebar.info("No data loaded yet. Click 'Generate Demo Logs' to begin.")


# ---------------------------------------------------------------- pages
def page_dashboard():
    st.title("Dashboard")
    counts = db.counts_summary()

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        components.metric_card("Total Events", counts["total_events"])
    with c2:
        components.metric_card("Threats Detected", counts["total_alerts"])
    with c3:
        components.metric_card("High / Critical Alerts", counts["high_critical"])
    with c4:
        components.metric_card("Unique Source IPs", counts["unique_ips"])

    st.write("")

    events_df = db.fetch_events()
    alerts_df = db.fetch_alerts()

    col_a, col_b = st.columns([2, 1])
    with col_a:
        components.section_header("Security Event Timeline")
        st.plotly_chart(charts.event_timeline_chart(events_df), use_container_width=True)
    with col_b:
        components.section_header("Threat Distribution")
        st.plotly_chart(charts.threat_distribution_chart(alerts_df), use_container_width=True)

    components.section_header("Threat Types")
    st.plotly_chart(charts.threat_types_chart(alerts_df), use_container_width=True)

    components.section_header("Recent Alerts")
    if alerts_df.empty:
        st.caption("No alerts yet. Generate demo logs to populate the dashboard.")
    else:
        recent = alerts_df.head(10).copy()
        recent["timestamp"] = pd.to_datetime(recent["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
        st.dataframe(
            recent[["timestamp", "threat_type", "source_ip", "severity", "status"]]
            .rename(columns={
                "timestamp": "Time", "threat_type": "Threat",
                "source_ip": "Source IP", "severity": "Severity", "status": "Status",
            }),
            use_container_width=True,
            hide_index=True,
        )


def page_security_events():
    st.title("Security Events")
    events_df = db.fetch_events()

    if events_df.empty:
        st.caption("No events loaded. Generate demo logs from the sidebar.")
        return

    with st.expander("Filters", expanded=True):
        f1, f2, f3, f4 = st.columns(4)
        with f1:
            ip_filter = st.selectbox("Source IP", ["All"] + sorted(events_df["source_ip"].dropna().unique().tolist()))
        with f2:
            type_filter = st.selectbox("Event Type", ["All"] + sorted(events_df["event_type"].dropna().unique().tolist()))
        with f3:
            status_filter = st.selectbox("Status", ["All"] + sorted(events_df["status"].dropna().unique().tolist()))
        with f4:
            service_filter = st.selectbox("Service", ["All"] + sorted(events_df["service"].dropna().unique().tolist()))

    filtered = events_df.copy()
    if ip_filter != "All":
        filtered = filtered[filtered["source_ip"] == ip_filter]
    if type_filter != "All":
        filtered = filtered[filtered["event_type"] == type_filter]
    if status_filter != "All":
        filtered = filtered[filtered["status"] == status_filter]
    if service_filter != "All":
        filtered = filtered[filtered["service"] == service_filter]

    st.caption(f"{len(filtered)} of {len(events_df)} events")

    display = filtered.copy()
    display["timestamp"] = pd.to_datetime(display["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
    st.dataframe(
        display[["timestamp", "source_ip", "username", "event_type", "status", "service", "request"]]
        .rename(columns={
            "timestamp": "Time", "source_ip": "Source IP", "username": "Username",
            "event_type": "Event Type", "status": "Status", "service": "Service", "request": "Request",
        }),
        use_container_width=True,
        hide_index=True,
        height=420,
    )

    with st.expander("View raw event"):
        if not filtered.empty:
            idx = st.number_input("Row index (from the table above, 0-based)", min_value=0,
                                   max_value=max(0, len(filtered) - 1), value=0)
            st.code(filtered.iloc[int(idx)]["raw_event"], language="text")


def page_threat_alerts():
    st.title("Threat Alerts")
    alerts_df = db.fetch_alerts()

    if alerts_df.empty:
        st.caption("No alerts yet. Generate demo logs from the sidebar.")
        return

    with st.expander("Filters", expanded=True):
        f1, f2, f3, f4 = st.columns(4)
        with f1:
            sev_filter = st.selectbox("Severity", ["All"] + settings.SEVERITY_LEVELS)
        with f2:
            type_filter = st.selectbox("Threat Type", ["All"] + sorted(alerts_df["threat_type"].dropna().unique().tolist()))
        with f3:
            ip_filter = st.selectbox("Source IP", ["All"] + sorted(alerts_df["source_ip"].dropna().unique().tolist()))
        with f4:
            status_filter = st.selectbox("Status", ["All"] + settings.ALERT_STATUSES)

    filtered = alerts_df.copy()
    if sev_filter != "All":
        filtered = filtered[filtered["severity"] == sev_filter]
    if type_filter != "All":
        filtered = filtered[filtered["threat_type"] == type_filter]
    if ip_filter != "All":
        filtered = filtered[filtered["source_ip"] == ip_filter]
    if status_filter != "All":
        filtered = filtered[filtered["status"] == status_filter]

    st.caption(f"{len(filtered)} of {len(alerts_df)} alerts")

    display = filtered.copy()
    display["timestamp"] = pd.to_datetime(display["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
    st.dataframe(
        display[["timestamp", "threat_type", "source_ip", "severity", "status", "related_event_count"]]
        .rename(columns={
            "timestamp": "Time", "threat_type": "Threat", "source_ip": "Source IP",
            "severity": "Severity", "status": "Status", "related_event_count": "Related Events",
        }),
        use_container_width=True,
        hide_index=True,
        height=320,
    )

    components.section_header("Alert Details")
    if filtered.empty:
        return

    alert_ids = filtered["alert_id"].tolist()
    selected_id = st.selectbox("Select an alert to inspect", alert_ids)
    row = filtered[filtered["alert_id"] == selected_id].iloc[0]

    rule_info = next((r for r in settings.DETECTION_RULES if r["name"] == row["detection_rule"]), None)

    d1, d2 = st.columns([2, 1])
    with d1:
        st.markdown(f"**What was detected:** {row['description']}")
        st.markdown(f"**Why it was detected:** Matched the *{row['detection_rule']}* rule "
                     f"({rule_info['threshold'] if rule_info else 'see Detection Rules page'}).")
        st.markdown(f"**Which rule triggered:** {row['detection_rule']}")
        st.markdown(f"**Related events:** {row['related_event_count']}")
        st.markdown(f"**Source IP:** {row['source_ip']}")
        st.markdown(
            "**Recommended investigation step:** Review the Security Events page filtered "
            f"by source IP `{row['source_ip']}` to inspect the underlying raw log entries, "
            "and consider blocking or rate-limiting the IP if the pattern is confirmed malicious."
        )
    with d2:
        new_status = st.selectbox("Update status", settings.ALERT_STATUSES,
                                   index=settings.ALERT_STATUSES.index(row["status"]) if row["status"] in settings.ALERT_STATUSES else 0)
        if st.button("Save status"):
            db.update_alert_status(selected_id, new_status)
            st.success("Status updated.")
            st.rerun()


def page_detection_rules():
    st.title("Detection Rules")
    st.caption(
        "Educational, rule-based detection logic — no machine learning. "
        "These thresholds are defined in config/settings.py."
    )
    for rule in settings.DETECTION_RULES:
        with st.container(border=True):
            c1, c2 = st.columns([3, 1])
            with c1:
                st.markdown(f"**{rule['name']}**")
                st.write(rule["description"])
                st.caption(f"Threshold: {rule['threshold']}")
            with c2:
                st.markdown(components.severity_badge(rule["severity"]), unsafe_allow_html=True)
                st.write("")
                st.caption(f"Status: {rule['status']}")


def page_reports():
    st.title("Reports")
    summary = report_generator.build_summary()

    c1, c2, c3 = st.columns(3)
    with c1:
        components.metric_card("Total Events", summary["total_events"])
    with c2:
        components.metric_card("Total Threats", summary["total_alerts"])
    with c3:
        components.metric_card("Failed Logins", summary["failed_login_count"])

    st.write("")
    col1, col2 = st.columns(2)
    with col1:
        components.section_header("Threats by Severity")
        if summary["threats_by_severity"]:
            st.table(pd.DataFrame(summary["threats_by_severity"].items(), columns=["Severity", "Count"]))
        else:
            st.caption("No data yet.")

        components.section_header("Top Source IPs")
        if summary["top_source_ips"]:
            st.table(pd.DataFrame(summary["top_source_ips"].items(), columns=["Source IP", "Alerts"]))
        else:
            st.caption("No data yet.")

    with col2:
        components.section_header("Threats by Type")
        if summary["threats_by_type"]:
            st.table(pd.DataFrame(summary["threats_by_type"].items(), columns=["Threat Type", "Count"]))
        else:
            st.caption("No data yet.")

        components.section_header("Detection Rules Triggered")
        if summary["rules_triggered"]:
            st.table(pd.DataFrame(summary["rules_triggered"].items(), columns=["Rule", "Alerts"]))
        else:
            st.caption("No data yet.")

    st.write("")
    components.section_header("Generate & Export")
    b1, b2, b3 = st.columns(3)
    with b1:
        if st.button("Generate Report (.txt)"):
            path = report_generator.export_text_report()
            with open(path, "r") as f:
                st.download_button("Download report", f.read(), file_name="incident_summary_report.txt")
    with b2:
        if st.button("Export Events (.csv)"):
            path = report_generator.export_events_csv()
            with open(path, "rb") as f:
                st.download_button("Download events CSV", f.read(), file_name="security_events_export.csv")
    with b3:
        if st.button("Export Alerts (.csv)"):
            path = report_generator.export_alerts_csv()
            with open(path, "rb") as f:
                st.download_button("Download alerts CSV", f.read(), file_name="threat_alerts_export.csv")


def page_settings():
    st.title("Settings / About")
    st.markdown("""
**Security Event Monitoring & Threat Detection Platform**

A Python-based, rule-based security log analysis and threat detection
system built as a student cybersecurity project. It simulates Linux
authentication logs and Apache web server logs, parses them into a
normalized event schema, applies five explainable detection rules, stores
results in SQLite, and presents everything through this dashboard.

**Technology:** Python, Streamlit, SQLite, Pandas, Plotly, Faker.

**Scope note:** This project uses simulated data and simple, transparent
detection rules for learning purposes. It is not a production-grade
intrusion detection system (SIEM) and does not claim production-level
detection accuracy.
    """)
    st.caption(f"Database location: {settings.DB_PATH}")


# ---------------------------------------------------------------- router
PAGES = {
    "Dashboard": page_dashboard,
    "Security Events": page_security_events,
    "Threat Alerts": page_threat_alerts,
    "Detection Rules": page_detection_rules,
    "Reports": page_reports,
    "Settings / About": page_settings,
}

PAGES[page]()
