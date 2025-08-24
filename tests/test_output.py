import json
from datetime import datetime

from seclog.models import Finding
from seclog.output import to_json, to_table


def sample_finding():
    return Finding(
        detector="test",
        timestamp_first=datetime(2025, 1, 1, 0, 0, 0),
        timestamp_last=datetime(2025, 1, 1, 0, 0, 1),
        src_ip="1.1.1.1",
        summary="something",
        details={"raw": ""},
    )


def test_to_table_no_findings():
    assert to_table([]) == "No suspicious activity detected."


def test_to_table_with_finding():
    output = to_table([sample_finding()])
    assert "Detector" in output and "test" in output


def test_to_json_no_findings():
    output = to_json([])
    data = json.loads(output)
    assert data == {"findings": []}


def test_to_json_with_finding():
    output = to_json([sample_finding()])
    data = json.loads(output)
    assert data["findings"][0]["detector"] == "test"
