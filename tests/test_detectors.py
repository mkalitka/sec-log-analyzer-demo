from datetime import datetime, timedelta

from seclog.detectors import (
    BruteForceDetector,
    PortScanDetector,
    SQLInjectionDetector,
    UnusualAccessDetector,
)
from seclog.models import Event, Finding, Severity


def make_event(ts, severity, src_ip, event_type, msg):
    return Event(
        timestamp=ts,
        severity=severity,
        src_ip=src_ip,
        event_type=event_type,
        msg=msg,
        raw=(f"[{ts.strftime('%Y-%m-%d %H:%M:%S')}]{severity.value} {src_ip} {event_type} {msg}"),
    )


def test_brute_force_detector():
    d = BruteForceDetector(threshold=3, window_seconds=3)
    base = datetime(2025, 1, 1, 0, 0, 0)
    for i in range(5):
        d.feed(
            make_event(
                base + timedelta(seconds=i * i),
                Severity.ERROR,
                "1.1.1.1",
                "FAILED_LOGIN",
                f"user=user{i}",
            )
        )
    findings: list[Finding] = d.flush()
    # Time delta increases quadratically, so only 3 events fall within the window
    assert len(findings) == 1
    assert len(findings[0].details["raw"]) == 3
    assert findings[0].src_ip == "1.1.1.1"


def test_port_scan_detector():
    d = PortScanDetector(threshold=3, window_seconds=3)
    base = datetime(2025, 1, 1, 0, 0, 0)
    for offset, port in enumerate([22, 25, 80, 443, 8080]):
        d.feed(
            make_event(
                base + timedelta(seconds=offset * offset),
                Severity.WARNING,
                "2.2.2.2",
                "PORT_SCAN_ATTEMPT",
                f"target={port}",
            )
        )
    findings: list[Finding] = d.flush()
    # Time delta increases quadratically, so only 3 events fall within the window
    assert len(findings) == 1
    assert len(findings[0].details["raw"]) == 3
    assert 80 in findings[0].details["ports"]


def test_sql_injection_detector():
    d = SQLInjectionDetector()
    e1 = make_event(
        datetime(2025, 1, 1, 0, 0, 0),
        Severity.ERROR,
        "3.3.3.3",
        "SQL_INJECTION_ATTEMPT",
        "user_input=' SELECT * FROM users WHERE 1=1;--",
    )
    e2 = make_event(
        datetime(2025, 1, 1, 0, 0, 1),
        Severity.ERROR,
        "4.4.4.4",
        "GET",
        "user_input=' UNION SELECT NULL,NULL--",
    )
    d.feed(e1)
    d.feed(e2)
    findings: list[Finding] = d.flush()
    assert len(findings) == 2
    assert findings[0].src_ip == "3.3.3.3"
    assert findings[1].src_ip == "4.4.4.4"


def test_unusual_access_detector():
    d = UnusualAccessDetector(sensitive_paths={"/secret"}, trusted_ips={"7.7.7.7"})
    e1 = make_event(
        datetime(2025, 1, 1, 0, 0, 0),
        Severity.WARNING,
        "5.5.5.5",
        "GET",
        "/secret 403",
    )
    e2 = make_event(
        datetime(2025, 1, 1, 0, 0, 1),
        Severity.WARNING,
        "6.6.6.6",
        "UNUSUAL_ACCESS",
        "/etc/passwd",
    )
    e3 = make_event(
        datetime(2025, 1, 1, 0, 0, 2),
        Severity.WARNING,
        "7.7.7.7",
        "UNUSUAL_ACCESS",
        "/root/.bashrc",
    )
    d.feed(e1)
    d.feed(e2)
    d.feed(e3)
    findings: list[Finding] = d.flush()
    assert len(findings) == 2
    assert findings[0].src_ip == "5.5.5.5"
    assert findings[1].src_ip == "6.6.6.6"
