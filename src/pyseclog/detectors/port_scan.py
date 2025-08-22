from collections import defaultdict
from datetime import timedelta, datetime
from typing import DefaultDict, List, Tuple, Optional

from ..models import Event, Finding, Severity
from .abstract import AbstractDetector


class PortScanDetector(AbstractDetector):
    name = "port_scan"

    def __init__(self, threshold=3, window_seconds=600):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.ports_by_ip: DefaultDict[str, List[Tuple[datetime, Optional[int]]]] = (
            defaultdict(list)
        )

    def feed(self, e: Event):
        if e.event_type != "PORT_SCAN_ATTEMPT":
            return
        # parse port from message like "target=22"
        try:
            port = int(e.msg.split("target=", 1)[1])
        except Exception:
            port = None
        self.ports_by_ip[e.src_ip].append((e.timestamp, port))

    def flush(self):
        findings = []
        for ip, items in self.ports_by_ip.items():
            if len(items) >= self.threshold:
                items.sort(key=lambda x: x[0])
                timestamp_first, timestamp_last = items[0][0], items[-1][0]
                if (timestamp_last - timestamp_first) <= self.window:
                    ports = [p for _, p in items if p is not None]
                    findings.append(
                        Finding(
                            rule=self.name,
                            timestamp_first=timestamp_first,
                            timestamp_last=timestamp_last,
                            src_ip=ip,
                            summary=f"Port scan behavior: {len(items)} ports probed",
                            details={"ports": ports},
                            severity=Severity.WARNING,
                        )
                    )
        return findings
