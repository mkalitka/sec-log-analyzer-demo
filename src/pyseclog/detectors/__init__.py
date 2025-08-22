from typing import Iterable
from ..models import Event, Finding
from .abstract import AbstractDetector


def run_rules(events: Iterable[Event], rules: Iterable[AbstractDetector]) -> list[Finding]:
    for e in events:
        for r in rules:
            r.feed(e)
    findings = []
    for r in rules:
        findings.extend(r.flush())
    return findings
