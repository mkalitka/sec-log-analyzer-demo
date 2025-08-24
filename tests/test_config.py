import copy

import pytest

from seclog.config import CONFIG_DEFAULTS, parse_config, validate_config


def test_validate_config_accepts_defaults():
    cfg = copy.deepcopy(CONFIG_DEFAULTS)
    validated = validate_config(cfg)
    assert validated["brute_force"]["threshold"] == 3


def test_validate_config_rejects_bad_type():
    cfg = copy.deepcopy(CONFIG_DEFAULTS)
    cfg["brute_force"]["enabled"] = "yes"
    with pytest.raises(ValueError):
        validate_config(cfg)


def test_parse_config_merges_user_file(tmp_path):
    yaml_cfg = "brute_force:\n  threshold: 5\n"
    p = tmp_path / "cfg.yml"
    p.write_text(yaml_cfg)
    cfg = parse_config(str(p))
    assert cfg["brute_force"]["threshold"] == 5
    assert cfg["port_scan"]["threshold"] == CONFIG_DEFAULTS["port_scan"]["threshold"]
