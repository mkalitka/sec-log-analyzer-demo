from ..models import Finding


def to_table(findings: list[Finding]) -> str:
    """Convert findings to a formatted table string."""
    if not findings:
        result = "No suspicious activity detected."
        return result

    headers = [
        "Detector",
        "First Seen",
        "Last Seen",
        "Source IP",
        "Summary",
    ]
    rows = [headers]
    for f in sorted(findings, key=lambda x: (x.timestamp_first, x.detector)):
        rows.append(
            [
                f.detector,
                f.timestamp_first.isoformat(sep=" ", timespec="seconds"),
                f.timestamp_last.isoformat(sep=" ", timespec="seconds"),
                f.src_ip or "-",
                f.summary,
            ]
        )
    col_widths = [max(len(row[i]) for row in rows) for i in range(len(headers))]
    row_format = " | ".join("{:<" + str(width) + "}" for width in col_widths)
    separator = "-+-".join("-" * width for width in col_widths)
    table_lines = [row_format.format(*rows[0]), separator]
    for row in rows[1:]:
        table_lines.append(row_format.format(*row))
    result = "\n".join(table_lines)
    return result
