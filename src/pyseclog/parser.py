import re
from datetime import datetime
from .models import Event, Severity

LINE_RE = re.compile(
    r"^\[(?P<timestamp>[\d-]{10}\s[\d:]{8})\]\s+"
    r"(?P<severity>INFO|WARNING|ERROR)\s+"
    r"(?P<src_ip>[0-9.]+)\s+"
    r"(?P<event_type>\S+)\s+"
    r"(?P<msg>.*)$"
)


def parse_line(line: str):
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    return Event(
        timestamp=datetime.strptime(m.group("timestamp"), "%Y-%m-%d %H:%M:%S"),
        severity=Severity(m.group("severity")),
        src_ip=m.group("src_ip"),
        event_type=m.group("event_type"),
        msg=m.group("msg"),
        raw=line.rstrip("\n"),
    )


def parse_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        for _, line in enumerate(f, 1):
            e = parse_line(line)
            if e:
                yield e
