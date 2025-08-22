from collections import defaultdict, deque
from typing import DefaultDict, Deque
from datetime import timedelta
from ..models import Event, Finding, Severity
from .abstract import AbstractDetector


class BruteForceDetector(AbstractDetector):
    name = "brute_force"

    def __init__(self, threshold=3, window_seconds=300):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.match_buckets: DefaultDict[str, Deque[Event]] = defaultdict(deque)

    def feed(self, e: Event):
        if e.event_type != "FAILED_LOGIN":
            return
        dq = self.match_buckets[e.src_ip]
        dq.append(e)
        # Drop events outside window
        while dq and (e.timestamp - dq[0].timestamp) > self.window:
            dq.popleft()

    def flush(self):
        findings = []
        for ip, dq in self.match_buckets.items():
            if len(dq) >= self.threshold:
                findings.append(
                    Finding(
                        rule=self.name,
                        timestamp_first=dq[0].timestamp,
                        timestamp_last=dq[-1].timestamp,
                        src_ip=ip,
                        summary=f"{len(dq)} failed logins within {self.window.total_seconds():.0f}s",
                        details={
                            "count": len(dq),
                            "usernames": self._collect_users(dq),
                        },
                        severity=Severity.WARNING,
                    )
                )
        return findings

    def _collect_users(self, dq):
        users = []
        for e in dq:
            if "user=" in e.msg:
                users.append(e.msg.split("user=", 1)[1].strip())
        return list(dict.fromkeys(users))
