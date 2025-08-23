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
    "get_detectors",
    "run_detectors",
]


def get_detectors(config: dict) -> list:
    """Instantiate detectors based on provided configuration."""
    bf = config["brute_force"]
    ps = config["port_scan"]
    sqli = config["sql_injection"]
    ua = config["unusual_access"]
    return [
        BruteForceDetector(
            threshold=bf.get("threshold"),
            window_seconds=bf.get("window_seconds"),
        )
        if bf.get("enabled")
        else None,
        PortScanDetector(
            threshold=ps.get("threshold"),
            window_seconds=ps.get("window_seconds"),
        )
        if ps.get("enabled")
        else None,
        SQLInjectionDetector() if sqli.get("enabled") else None,
        UnusualAccessDetector(
            sensitive_paths=ua.get("sensitive_paths"),
            trusted_ips=ua.get("trusted_ips"),
        )
        if ua.get("enabled")
        else None,
    ]


def run_detectors(events: Iterable[Event], detectors: Iterable[AbstractDetector]) -> list[Finding]:
    """Run all detectors on the provided events and return findings."""
    detectors = [d for d in detectors if d is not None]
    for e in events:
        for d in detectors:
            d.feed(e)
    findings = []
    for d in detectors:
        findings.extend(d.flush())
    return findings
