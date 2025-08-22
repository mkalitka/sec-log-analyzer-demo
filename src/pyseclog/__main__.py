import argparse
from .config import get_detectors_config
from .parser import parse_file
from .detectors import run_rules
from .reporting.console import to_table
from .reporting.json import to_json


def main():
    ap = argparse.ArgumentParser(description="Security log analyzer demo")
    ap.add_argument("logfile", help="Path to log file")
    ap.add_argument("--config", "-c", default=None, help="Path to YAML config")
    ap.add_argument("--json", action="store_true", help="Output JSON instead of table")
    args = ap.parse_args()

    detectors = get_detectors_config(args.config)
    events = parse_file(args.logfile)
    findings = run_rules(events, detectors)

    if args.json:
        print(to_json(findings))
    else:
        print(to_table(findings))


if __name__ == "__main__":
    main()
