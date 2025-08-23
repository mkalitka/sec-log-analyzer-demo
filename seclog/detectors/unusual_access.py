from ..models import Event, Finding
from .abstract import AbstractDetector


class UnusualAccessDetector(AbstractDetector):
    name = "unusual_access"

    def __init__(self, sensitive_paths, trusted_ips):
        self.sensitive = sensitive_paths
        self.trusted_ips = trusted_ips
        self.matches: list[Event] = []

    def feed(self, e: Event):
        # include UNUSUAL_ACCESS event types or 403s on other sensitive paths
        path = e.msg.split()[0] if e.msg else ""
        if e.event_type == "UNUSUAL_ACCESS" or (
            e.event_type in {"GET", "POST"}
            and path in self.sensitive
            and "403" in e.msg
        ):
            if e.src_ip not in self.trusted_ips:
                self.matches.append(e)

    def flush(self):
        return [
            Finding(
                detector=self.name,
                timestamp_first=e.timestamp,
                timestamp_last=e.timestamp,
                src_ip=e.src_ip,
                summary=f"Access to sensitive resource: {e.msg.split()[0]}",
                details={"raw": e.raw},
            )
            for e in self.matches
        ]
