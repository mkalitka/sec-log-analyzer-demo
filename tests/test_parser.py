from datetime import datetime

from seclog.models import Severity
from seclog.parser import parse_file, parse_line


def test_parse_line_valid():
    line = "[2025-01-01 00:00:00] WARNING 10.0.0.1 FAILED_LOGIN user=admin"
    event = parse_line(line)
    assert event is not None
    assert event.src_ip == "10.0.0.1"
    assert event.event_type == "FAILED_LOGIN"
    assert event.msg == "user=admin"
    assert event.severity == Severity.WARNING
    assert event.timestamp == datetime(2025, 1, 1, 0, 0, 0)


def test_parse_line_invalid():
    assert parse_line("") is None
    assert parse_line("[2025-01-01 00:00:00] WARNING") is None
    assert parse_line("invalid line") is None


def test_parse_file_reads_all(tmp_path):
    content = (
        "[2025-01-01 00:00:00] INFO 1.1.1.1 EVENT msg1\n"
        "[2025-01-01 00:00:01] ERROR 2.2.2.2 EVENT msg2\n"
    )
    p = tmp_path / "log.txt"
    p.write_text(content)
    events = list(parse_file(str(p)))
    assert len(events) == 2
    assert events[0].src_ip == "1.1.1.1"
