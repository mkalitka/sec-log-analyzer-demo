import re

from ..models import Event, Finding
from .abstract import AbstractDetector

SQLI_RE = re.compile(r"('|--|\bUNION\b|\bSELECT\b|\bOR\s+1=1\b)", re.IGNORECASE)


class SQLInjectionDetector(AbstractDetector):
    name = "sql_injection"

    def __init__(self):
        self.matches: list[Event] = []

    def feed(self, e: Event) -> None:
        if e.event_type != "SQL_INJECTION_ATTEMPT" and not SQLI_RE.search(e.msg):
            return
        self.matches.append(e)

    def flush(self) -> list[Finding]:
        return [
            Finding(
                detector=self.name,
                timestamp_first=e.timestamp,
                timestamp_last=e.timestamp,
                src_ip=e.src_ip,
                summary="Possible SQL injection pattern detected",
                details={"raw": e.raw},
            )
            for e in self.matches
        ]
