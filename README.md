# Security Event Monitoring & Threat Detection Platform

A Python-based security log analysis and threat detection application built
as a student cybersecurity project. It simulates Linux authentication logs
and Apache web server logs, parses them into a normalized event schema,
applies **rule-based** threat detection, stores results in SQLite, and
presents everything through an interactive Streamlit dashboard.

## Problem Statement

Security teams generate large volumes of authentication and web-server
logs. Manually reviewing them for attack patterns — brute-force login
attempts, username enumeration, endpoint scanning, access to restricted
paths — is slow and error-prone. This project demonstrates how a small,
transparent set of detection rules can surface these patterns automatically
from raw log data.

## Objectives

- Generate realistic, simulated Linux auth logs and Apache access logs
- Parse raw logs into a structured, normalized event format
- Detect suspicious activity using simple, explainable rules (no ML)
- Persist events and alerts in a SQLite database
- Provide a searchable, filterable dashboard for events and alerts
- Generate summary reports and CSV exports

## Features

- One-click **Generate Demo Logs** button — end-to-end demo in seconds
- Five rule-based detection mechanisms (see below)
- Event Timeline, Threat Distribution, and Threat Type charts
- Filterable Security Events and Threat Alerts tables
- Alert triage workflow: New → Investigating → Resolved
- Alert detail view explaining what/why/which-rule/related-events
- Detection Rules reference page (useful for explaining the system in a viva)
- Reports page with summary statistics and CSV / text export
- Clean, restrained "enterprise tool" UI — not a neon hacker theme

## Architecture

```
Log Generation → Log Parsing → Event Normalization →
Rule-Based Threat Detection → Database Storage →
Report Generation → Streamlit Dashboard
```

Each stage is a separate, independently testable module.

## Technology Stack

- **Python 3** — core language
- **Streamlit** — web dashboard
- **SQLite** — structured storage (via the standard library `sqlite3`)
- **Pandas** — data processing
- **Plotly** — charts
- **Faker** — realistic simulated log data
- **pytest** — testing

## Project Structure

```
security-monitoring-platform/
├── app.py                      # Streamlit entry point
├── config/settings.py          # Thresholds, paths, rule catalogue
├── data/logs, exports, security.db
├── generator/log_generator.py  # Module 1 — simulated log generation
├── parser/
│   ├── auth_parser.py          # Module 2 — auth.log parsing
│   ├── apache_parser.py        # Module 2 — access.log parsing
│   └── normalizer.py           # Module 2 — unified event schema
├── detection/
│   ├── rules.py                # Module 3 — 5 detection rules
│   └── engine.py                # Module 3 — rule orchestration
├── database/db.py              # Module 4 — SQLite storage
├── reports/report_generator.py # Module 5 — summaries & CSV/text export
├── dashboard/
│   ├── components.py           # Module 6 — UI building blocks
│   └── charts.py                # Module 6 — Plotly charts
├── tests/                      # pytest suite
├── requirements.txt
└── README.md
```

## Installation

```bash
cd security-monitoring-platform
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## How to Run

```bash
streamlit run app.py
```

Then open the URL Streamlit prints (usually `http://localhost:8501`).

## How to Generate Demo Logs

1. Launch the app.
2. In the sidebar, adjust "Approx. log entries per source" if desired.
3. Click **Generate Demo Logs**.
4. The app will generate simulated auth/access logs, parse them, run all
   detection rules, and populate the database — the dashboard updates
   immediately.

## Detection Rules

| Rule | Description | Default Threshold | Severity |
|---|---|---|---|
| Brute Force Detection | Repeated failed SSH logins, same IP | 5+ in 5 minutes | High |
| Suspicious Login Activity | Failed logins across multiple usernames, same IP | 3+ usernames, 4+ attempts in 10 minutes | Medium |
| Suspicious Web Request | Repeated hits to scanning-related paths | 3+ in 10 minutes | Medium |
| Excessive 404 Requests | High volume of 404s, same IP | 8+ in 5 minutes | Low |
| Restricted Resource Access | Requests to /admin, /login, /config, /.env, etc. | 2+ in 10 minutes | Critical |

All thresholds live in `config/settings.py` and can be tuned there.

## Testing

```bash
pytest tests/ -v
```

Covers valid/invalid log parsing, brute-force threshold boundaries
(4 failed logins → no alert, 5 → alert), suspicious web request detection,
and database insertion/retrieval.

## Screenshots

_(Add screenshots of the Dashboard, Threat Alerts, and Reports pages here.)_

## Limitations

- Operates on **simulated** logs, not live production traffic
- Detection is purely rule/threshold-based — no anomaly detection or ML,
  and thresholds can be tuned but are not adaptive
- Not a replacement for a production SIEM; intended as an educational,
  explainable demonstration of log-analysis and detection concepts
- Single-node SQLite storage, not built for high-volume ingestion

## Future Enhancements

- Pluggable log sources (real syslog/Apache log ingestion)
- Optional lightweight anomaly scoring alongside the rule engine
- Role-based access and multi-user alert assignment
- PDF report export
- Alerting integrations (email/Slack webhook on Critical severity)
