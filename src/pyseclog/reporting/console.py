from ..models import Finding


def to_table(findings: list[Finding]) -> str:
    if not findings:
        result = "No suspicious activity detected."
        print(result)
        return result

    headers = ["Rule", "Severity", "First Seen", "Last Seen", "Source IP", "Summary"]
    rows = [headers]
    for f in sorted(findings, key=lambda x: (x.timestamp_first, x.rule)):
        rows.append([
            f.rule,
            f.severity.value,
            f.timestamp_first.isoformat(sep=" ", timespec="seconds"),
            f.timestamp_last.isoformat(sep=" ", timespec="seconds"),
            f.src_ip or "-",
            f.summary,
        ])
    col_widths = [max(len(row[i]) for row in rows) for i in range(len(headers))]
    row_format = " | ".join("{:<" + str(width) + "}" for width in col_widths)
    separator = "-+-".join("-" * width for width in col_widths)
    table_lines = [row_format.format(*rows[0]), separator]
    for row in rows[1:]:
        table_lines.append(row_format.format(*row))
    result = "\n".join(table_lines)
    return result
