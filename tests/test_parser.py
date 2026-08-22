import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parser.auth_parser import parse_line as parse_auth_line
from parser.apache_parser import parse_line as parse_web_line


def test_valid_failed_login_line():
    line = "Aug 22 10:31:22 server sshd[1234]: Failed password for admin from 192.168.1.20 port 4521 ssh2"
    event = parse_auth_line(line)
    assert event is not None
    assert event["source_ip"] == "192.168.1.20"
    assert event["username"] == "admin"
    assert event["event_type"] == "failed_login"
    assert event["status"] == "failure"


def test_valid_invalid_user_line():
    line = "Aug 22 10:31:22 server sshd[1234]: Failed password for invalid user hacker from 10.0.0.5 port 2222 ssh2"
    event = parse_auth_line(line)
    assert event is not None
    assert event["event_type"] == "invalid_user_attempt"
    assert event["username"] == "hacker"


def test_valid_accepted_login_line():
    line = "Aug 22 10:31:22 server sshd[1234]: Accepted password for ubuntu from 10.0.0.5 port 2222 ssh2"
    event = parse_auth_line(line)
    assert event is not None
    assert event["status"] == "success"
    assert event["event_type"] == "successful_login"


def test_malformed_auth_line_returns_none():
    line = "this is not a valid syslog line at all"
    assert parse_auth_line(line) is None


def test_empty_auth_line_returns_none():
    assert parse_auth_line("") is None


def test_valid_apache_line():
    line = '203.0.113.5 - - [22/Aug/2026:10:31:22 +0000] "GET /admin HTTP/1.1" 404 512'
    event = parse_web_line(line)
    assert event is not None
    assert event["source_ip"] == "203.0.113.5"
    assert event["status"] == "not_found"
    assert "/admin" in event["request"]


def test_malformed_apache_line_returns_none():
    line = "not a valid apache log line"
    assert parse_web_line(line) is None
