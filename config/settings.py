"""
Central configuration for the Security Event Monitoring & Threat Detection Platform.

Keeping every tunable value in one place makes the detection logic easy to
explain in a viva: "the thresholds live in config/settings.py".
"""

import os

# --- Paths -------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_DIR = os.path.join(DATA_DIR, "logs")
EXPORT_DIR = os.path.join(DATA_DIR, "exports")
DB_PATH = os.path.join(DATA_DIR, "security.db")

AUTH_LOG_PATH = os.path.join(LOG_DIR, "auth.log")
ACCESS_LOG_PATH = os.path.join(LOG_DIR, "access.log")

for _d in (DATA_DIR, LOG_DIR, EXPORT_DIR):
    os.makedirs(_d, exist_ok=True)

# --- Detection thresholds ----------------------------------------------
# Rule 1: Brute Force Detection
BRUTE_FORCE_ATTEMPTS = 5
BRUTE_FORCE_WINDOW_MINUTES = 5

# Rule 2: Suspicious Login Activity (multiple usernames, same IP)
MULTI_USER_ATTEMPTS = 4
MULTI_USER_WINDOW_MINUTES = 10
MULTI_USER_DISTINCT_USERNAMES = 3

# Rule 3: Suspicious Web Requests (sensitive/suspicious paths)
SUSPICIOUS_PATH_HITS = 3
SUSPICIOUS_PATH_WINDOW_MINUTES = 10

# Rule 4: Excessive 404 Requests
EXCESSIVE_404_COUNT = 8
EXCESSIVE_404_WINDOW_MINUTES = 5

# Rule 5: Access to Restricted Resources
RESTRICTED_PATHS = ["/admin", "/login", "/config", "/.env", "/wp-admin", "/.git"]
RESTRICTED_HITS = 2
RESTRICTED_WINDOW_MINUTES = 10

SUSPICIOUS_PATHS = RESTRICTED_PATHS + [
    "/phpmyadmin", "/backup", "/shell", "/etc/passwd", "/xmlrpc.php",
]

# --- Severity ------------------------------------------------------------
SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]

RULE_SEVERITY = {
    "Brute Force Detection": "High",
    "Suspicious Login Activity": "Medium",
    "Suspicious Web Request": "Medium",
    "Excessive 404 Requests": "Low",
    "Restricted Resource Access": "Critical",
}

ALERT_STATUSES = ["New", "Investigating", "Resolved"]

# --- Detection rule catalogue (for the Detection Rules page) -----------
DETECTION_RULES = [
    {
        "name": "Brute Force Detection",
        "description": "Repeated failed SSH login attempts from the same source IP.",
        "threshold": f"{BRUTE_FORCE_ATTEMPTS}+ failed logins within {BRUTE_FORCE_WINDOW_MINUTES} minutes",
        "severity": "High",
        "status": "Active",
    },
    {
        "name": "Suspicious Login Activity",
        "description": "Failed authentication attempts against multiple distinct usernames from one IP, indicating username enumeration or credential stuffing.",
        "threshold": f"{MULTI_USER_DISTINCT_USERNAMES}+ usernames, {MULTI_USER_ATTEMPTS}+ attempts within {MULTI_USER_WINDOW_MINUTES} minutes",
        "severity": "Medium",
        "status": "Active",
    },
    {
        "name": "Suspicious Web Request",
        "description": "Repeated requests to known suspicious or scanning-related paths (e.g. /phpmyadmin, /shell, /xmlrpc.php).",
        "threshold": f"{SUSPICIOUS_PATH_HITS}+ hits within {SUSPICIOUS_PATH_WINDOW_MINUTES} minutes",
        "severity": "Medium",
        "status": "Active",
    },
    {
        "name": "Excessive 404 Requests",
        "description": "Unusually high number of HTTP 404 responses from a single IP, often indicative of directory/endpoint scanning.",
        "threshold": f"{EXCESSIVE_404_COUNT}+ 404s within {EXCESSIVE_404_WINDOW_MINUTES} minutes",
        "severity": "Low",
        "status": "Active",
    },
    {
        "name": "Restricted Resource Access",
        "description": "Repeated requests to restricted administrative paths such as /admin, /login, /config, /.env.",
        "threshold": f"{RESTRICTED_HITS}+ hits within {RESTRICTED_WINDOW_MINUTES} minutes",
        "severity": "Critical",
        "status": "Active",
    },
]
