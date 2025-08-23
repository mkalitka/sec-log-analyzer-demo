import argparse

from .config import parse_config
from .detectors import get_detectors, run_detectors
from .parser import parse_file
from .reporting import to_json, to_table


def main():
    ap = argparse.ArgumentParser(prog="seclog", description="Security log analyzer demo")
    ap.add_argument("logfile", help="Path to log file")
    ap.add_argument("--config", "-c", default=None, help="Path to YAML config")
    ap.add_argument("--json", action="store_true", help="Output JSON instead of table")
    args = ap.parse_args()

    config = parse_config(args.config)
    detectors = get_detectors(config)
    events = parse_file(args.logfile)
    findings = run_detectors(events, detectors)

    if args.json:
        print(to_json(findings))
    else:
        print(to_table(findings))


if __name__ == "__main__":
    main()
