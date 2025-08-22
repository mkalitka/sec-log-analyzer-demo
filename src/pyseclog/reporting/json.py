import json
from ..models import Finding


def to_json(findings):
    def enc(f: Finding):
        return {
            "rule": f.rule,
            "severity": f.severity.value,
            "ts_first": f.timestamp_first.isoformat(),
            "ts_last": f.timestamp_last.isoformat(),
            "src_ip": f.src_ip,
            "summary": f.summary,
            "details": f.details,
        }

    return json.dumps([enc(f) for f in findings], indent=2)
