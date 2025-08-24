import copy

import pytest

from seclog.config import CONFIG_DEFAULTS, parse_config, validate_config


def test_validate_config_accepts_defaults():
    config = copy.deepcopy(CONFIG_DEFAULTS)
    validated = validate_config(config)
    assert validated["brute_force"]["threshold"] == 3


def test_validate_config_rejects_bad_type():
    config = copy.deepcopy(CONFIG_DEFAULTS)
    config["brute_force"]["enabled"] = "yes"
    with pytest.raises(ValueError):
        validate_config(config)


def test_parse_config_merges_user_file(tmp_path):
    yaml_config = "brute_force:\n  threshold: 5\n"
    p = tmp_path / "config.yaml"
    p.write_text(yaml_config)
    config = parse_config(str(p))
    assert config["brute_force"]["threshold"] == 5
    assert config["port_scan"]["threshold"] == CONFIG_DEFAULTS["port_scan"]["threshold"]
