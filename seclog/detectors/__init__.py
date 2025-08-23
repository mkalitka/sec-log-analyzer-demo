from collections.abc import Iterable

from ..models import Event, Finding
from .abstract import AbstractDetector
from .brute_force import BruteForceDetector
from .port_scan import PortScanDetector
from .sql_injection import SQLInjectionDetector
from .unusual_access import UnusualAccessDetector

__all__ = [
    "BruteForceDetector",
    "PortScanDetector",
    "SQLInjectionDetector",
    "UnusualAccessDetector",
]


def get_detectors(config: dict) -> list:
    brute = config["brute_force"]
    portscan = config["port_scan"]
    sqli = config["sql_injection"]
    sensitive = config["unusual_access"]
    return [
        BruteForceDetector(
            threshold=brute.get("threshold"),
            window_seconds=brute.get("window_seconds"),
        )
        if brute.get("enabled")
        else None,
        PortScanDetector(
            threshold=portscan.get("threshold"),
            window_seconds=portscan.get("window_seconds"),
        )
        if portscan.get("enabled")
        else None,
        SQLInjectionDetector() if sqli.get("enabled") else None,
        UnusualAccessDetector(
            sensitive_paths=sensitive.get("sensitive_paths"),
            trusted_ips=sensitive.get("trusted_ips"),
        )
        if sensitive.get("enabled")
        else None,
    ]


def run_detectors(
    events: Iterable[Event], detectors: Iterable[AbstractDetector]
) -> list[Finding]:
    detectors = [d for d in detectors if d is not None]
    for e in events:
        for d in detectors:
            d.feed(e)
    findings = []
    for d in detectors:
        findings.extend(d.flush())
    return findings
