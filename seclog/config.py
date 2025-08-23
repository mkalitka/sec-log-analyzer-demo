import copy

import yaml

CONFIG_DEFAULTS = {
    "brute_force": {
        "enabled": True,
        "threshold": 3,
        "window_seconds": 10,
    },
    "port_scan": {
        "enabled": True,
        "threshold": 3,
        "window_seconds": 10,
    },
    "sql_injection": {
        "enabled": True,
    },
    "unusual_access": {
        "enabled": True,
        "sensitive_paths": {
            "/etc/passwd",
            "/var/log/auth.log",
            "/root/.bashrc",
            "/admin/panel",
        },
        "trusted_ips": {"127.0.0.1"},
    },
}


def validate_config(config: dict) -> dict:
    bf = config["brute_force"]
    if not isinstance(bf["enabled"], bool):
        raise ValueError(
            "'brute_force' configuration 'enabled' has an invalid type. Expected bool."
        )
    if not isinstance(bf["threshold"], int):
        raise ValueError(
            "'brute_force' configuration 'threshold' has an invalid type. Expected int."
        )
    if not isinstance(bf["window_seconds"], int):
        raise ValueError(
            "'brute_force' configuration 'window_seconds' has an invalid type. Expected int."
        )

    ps = config["port_scan"]
    if not isinstance(ps["enabled"], bool):
        raise ValueError(
            "'port_scan' configuration 'enabled' has an invalid type. Expected bool."
        )
    if not isinstance(ps["threshold"], int):
        raise ValueError(
            "'port_scan' configuration 'threshold' has an invalid type. Expected int."
        )
    if not isinstance(ps["window_seconds"], int):
        raise ValueError(
            "'port_scan' configuration 'window_seconds' has an invalid type. Expected int."
        )

    sqli = config["sql_injection"]
    if not isinstance(sqli["enabled"], bool):
        raise ValueError(
            "'sql_injection' configuration 'enabled' has an invalid type. Expected bool."
        )

    ua = config["unusual_access"]
    if not isinstance(ua["enabled"], bool):
        raise ValueError(
            "'unusual_access' configuration 'enabled' has an invalid type. Expected bool."
        )
    if not (
        isinstance(ua["sensitive_paths"], (list, set))
        and all(isinstance(x, str) for x in ua["sensitive_paths"])
    ):
        raise ValueError(
            "'unusual_access' configuration 'sensitive_paths' has an invalid type. Expected list or set of strings." # noqa: E501
        )
    if not (
        isinstance(ua["trusted_ips"], (list, set))
        and all(isinstance(x, str) for x in ua["trusted_ips"])
    ):
        raise ValueError(
            "'unusual_access' configuration 'trusted_ips' has an invalid type. Expected dict."
        )

    return config


def parse_config(path: str | None = None) -> dict:
    config = copy.deepcopy(CONFIG_DEFAULTS)
    if path is not None:
        with open(path, "r") as f:
            user_cfg = yaml.safe_load(f) or {}
        for key in config:
            if key in user_cfg and isinstance(user_cfg[key], dict):
                config[key].update(user_cfg[key])
    return validate_config(config)
