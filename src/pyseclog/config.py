import yaml
from .detectors.brute_force import BruteForceDetector
from .detectors.port_scan import PortScanDetector
from .detectors.sql_injection import SQLInjectionDetector
from .detectors.unusual_access import UnusualAccessDetector

DEFAULT_BRUTEFORCE_THRESHOLD = 3
DEFAULT_BRUTEFORCE_WINDOW_SECONDS = 300
DEFAULT_SENSITIVE_PATHS = {"/etc/passwd", "/var/log/auth.log", "/root/.bashrc", "/admin/panel"}
DEFAULT_TRUSTED_IPS = {}
DEFAULT_PORTSCAN_THRESHOLD = 3
DEFAULT_PORTSCAN_WINDOW_SECONDS = 300


def get_detectors_config(path=None):
    if path is not None:
        with open(path, "r") as f:
            cfg = yaml.safe_load(f)
    else:
        cfg = {}

    # Pull tunables from YAML config when present
    brute = cfg.get("brute_force", {})
    portscan = cfg.get("port_scan", {})
    sensitive = cfg.get("unusual_access", {})

    return [
        BruteForceDetector(
            threshold=brute.get("threshold", DEFAULT_BRUTEFORCE_THRESHOLD),
            window_seconds=brute.get("window_seconds", DEFAULT_BRUTEFORCE_WINDOW_SECONDS),
        ),
        PortScanDetector(
            threshold=portscan.get("threshold", DEFAULT_PORTSCAN_THRESHOLD),
            window_seconds=portscan.get("window_seconds", DEFAULT_PORTSCAN_WINDOW_SECONDS),
        ),
        SQLInjectionDetector(),
        UnusualAccessDetector(
            sensitive_paths=sensitive.get("sensitive_paths", DEFAULT_SENSITIVE_PATHS),
            trusted_ips=sensitive.get("trusted_ips", DEFAULT_TRUSTED_IPS)
        ),
    ]
