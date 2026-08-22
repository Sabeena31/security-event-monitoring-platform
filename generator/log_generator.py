"""
Module 1 — Log Generator

Produces realistic, *simulated* Linux authentication logs (sshd-style) and
Apache-style access logs, including deliberately injected suspicious
activity so the detection engine (Module 3) has real patterns to catch.

Nothing here touches a real server — this is purely for demo purposes.
"""

import os
import random
import sys
from datetime import datetime, timedelta

from faker import Faker

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings

fake = Faker()

USERNAMES = ["admin", "root", "ubuntu", "deploy", "sabs", "guest", "test",
             "backup", "oracle", "postgres", "www-data", "developer"]

SUSPICIOUS_PATHS_POOL = settings.SUSPICIOUS_PATHS
NORMAL_PATHS = ["/", "/index.html", "/about", "/products", "/contact",
                "/api/status", "/static/style.css", "/favicon.ico", "/docs"]

HTTP_METHODS = ["GET", "GET", "GET", "POST"]


def _rand_ip(pool=None):
    if pool and random.random() < 0.4:
        return random.choice(pool)
    return fake.ipv4_public()


def generate_auth_log(num_entries=300, start_time=None):
    """Generate a list of raw sshd-style auth log lines (with a header
    line prefix similar to /var/log/auth.log) plus deliberate attack
    patterns: a brute-force IP and a username-enumeration IP.
    """
    start_time = start_time or (datetime.now() - timedelta(hours=6))
    lines = []
    t = start_time

    brute_ip = fake.ipv4_public()
    enum_ip = fake.ipv4_public()

    normal_count = max(0, num_entries - 40)

    events = []

    # Normal / background traffic
    for _ in range(normal_count):
        t = t + timedelta(seconds=random.randint(5, 240))
        ip = _rand_ip()
        user = random.choice(USERNAMES)
        pid = random.randint(1000, 32000)
        port = random.randint(1024, 65000)
        if random.random() < 0.75:
            events.append((t, f"sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"))
            events.append((t + timedelta(seconds=random.randint(30, 600)),
                            f"sshd[{pid}]: pam_unix(sshd:session): session closed for user {user}"))
        else:
            if random.random() < 0.3:
                bad_user = fake.user_name()
                events.append((t, f"sshd[{pid}]: Failed password for invalid user {bad_user} from {ip} port {port} ssh2"))
            else:
                events.append((t, f"sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"))

    # Injected brute-force attack: many failed logins, one IP, one/two users, tight window
    burst_start = start_time + timedelta(minutes=random.randint(30, 200))
    target_user = random.choice(["admin", "root"])
    for i in range(random.randint(8, 14)):
        ts = burst_start + timedelta(seconds=i * random.randint(5, 20))
        pid = random.randint(1000, 32000)
        port = random.randint(1024, 65000)
        events.append((ts, f"sshd[{pid}]: Failed password for {target_user} from {brute_ip} port {port} ssh2"))

    # Injected username enumeration: same IP, many distinct usernames
    enum_start = start_time + timedelta(minutes=random.randint(210, 300))
    for i in range(random.randint(6, 10)):
        ts = enum_start + timedelta(seconds=i * random.randint(10, 40))
        pid = random.randint(1000, 32000)
        port = random.randint(1024, 65000)
        bad_user = fake.user_name()
        events.append((ts, f"sshd[{pid}]: Failed password for invalid user {bad_user} from {enum_ip} port {port} ssh2"))

    events.sort(key=lambda e: e[0])
    for ts, body in events:
        lines.append(f"{ts.strftime('%b %d %H:%M:%S')} server {body}")

    return lines


def generate_access_log(num_entries=300, start_time=None):
    """Generate a list of Apache combined-log-format lines, with injected
    suspicious-path scanning and a 404 burst.
    """
    start_time = start_time or (datetime.now() - timedelta(hours=6))
    t = start_time

    scanner_ip = fake.ipv4_public()
    notfound_ip = fake.ipv4_public()

    events = []
    normal_count = max(0, num_entries - 30)

    for _ in range(normal_count):
        t = t + timedelta(seconds=random.randint(3, 180))
        ip = _rand_ip()
        method = random.choice(HTTP_METHODS)
        path = random.choice(NORMAL_PATHS)
        status = random.choices([200, 200, 200, 304, 404], weights=[70, 10, 5, 5, 10])[0]
        size = random.randint(200, 15000)
        events.append((t, ip, method, path, status, size))

    # Injected suspicious path scanning (admin/config/env probing)
    scan_start = start_time + timedelta(minutes=random.randint(20, 150))
    for i in range(random.randint(6, 12)):
        ts = scan_start + timedelta(seconds=i * random.randint(3, 15))
        path = random.choice(SUSPICIOUS_PATHS_POOL)
        status = random.choices([404, 403, 401], weights=[60, 30, 10])[0]
        events.append((ts, scanner_ip, "GET", path, status, random.randint(150, 900)))

    # Injected 404 burst (broad endpoint scanning)
    burst_start = start_time + timedelta(minutes=random.randint(180, 280))
    for i in range(random.randint(10, 18)):
        ts = burst_start + timedelta(seconds=i * random.randint(2, 10))
        path = "/" + fake.uri_path()
        events.append((ts, notfound_ip, "GET", path, 404, random.randint(150, 500)))

    events.sort(key=lambda e: e[0])
    lines = []
    for ts, ip, method, path, status, size in events:
        ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        line = f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" {status} {size}'
        lines.append(line)

    return lines


def write_logs(auth_count=300, access_count=300):
    """Generate both log types and write them to disk. Returns the paths."""
    start_time = datetime.now() - timedelta(hours=6)

    auth_lines = generate_auth_log(auth_count, start_time)
    access_lines = generate_access_log(access_count, start_time)

    with open(settings.AUTH_LOG_PATH, "w") as f:
        f.write("\n".join(auth_lines) + "\n")

    with open(settings.ACCESS_LOG_PATH, "w") as f:
        f.write("\n".join(access_lines) + "\n")

    return settings.AUTH_LOG_PATH, settings.ACCESS_LOG_PATH


if __name__ == "__main__":
    a, w = write_logs()
    print(f"Wrote auth log: {a}")
    print(f"Wrote access log: {w}")
