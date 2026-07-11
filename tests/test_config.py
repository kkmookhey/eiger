from halcyon.config import load_settings


def test_vulnerable_mode_defaults_flags_off():
    s = load_settings({"HALCYON_MODE": "vulnerable"})
    assert s.mode == "vulnerable"
    assert s.sec_system_prompt_hardening is False
    assert s.sec_input_filter is False


def test_secure_mode_defaults_flags_on():
    s = load_settings({"HALCYON_MODE": "secure"})
    assert s.sec_system_prompt_hardening is True
    assert s.sec_input_filter is True


def test_explicit_flag_overrides_mode_profile():
    s = load_settings({"HALCYON_MODE": "vulnerable", "SEC_INPUT_FILTER": "on"})
    assert s.sec_input_filter is True
    assert s.sec_system_prompt_hardening is False


def test_defaults_when_unset():
    s = load_settings({})
    assert s.mode == "vulnerable"
    assert s.default_provider == "local"
    assert s.ollama_url == "http://localhost:11434"


def test_unknown_mode_raises():
    import pytest
    with pytest.raises(ValueError):
        load_settings({"HALCYON_MODE": "production"})
