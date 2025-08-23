import json

from ..models import Finding


def to_json(findings: list[Finding]) -> str:
    """Convert findings to a JSON string."""

    def enc(f: Finding):
        return {
            "detector": f.detector,
            "ts_first": f.timestamp_first.isoformat(),
            "ts_last": f.timestamp_last.isoformat(),
            "src_ip": f.src_ip,
            "summary": f.summary,
            "details": f.details,
        }

    return json.dumps(
        {
            "findings": [
                enc(f) for f in sorted(findings, key=lambda x: (x.timestamp_first, x.detector))
            ]
        },
        indent=2,
    )
