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


def test_output_encoding_follows_mode():
    assert load_settings({"HALCYON_MODE": "vulnerable"}).sec_output_encoding is False
    assert load_settings({"HALCYON_MODE": "secure"}).sec_output_encoding is True
    assert load_settings({"HALCYON_MODE": "vulnerable", "SEC_OUTPUT_ENCODING": "on"}).sec_output_encoding is True


def test_rag_provenance_follows_mode():
    assert load_settings({"HALCYON_MODE": "vulnerable"}).sec_rag_provenance is False
    assert load_settings({"HALCYON_MODE": "secure"}).sec_rag_provenance is True


def test_artifact_verification_follows_mode():
    assert load_settings({"HALCYON_MODE": "vulnerable"}).sec_artifact_verification is False
    assert load_settings({"HALCYON_MODE": "secure"}).sec_artifact_verification is True


def test_tool_scope_enforcement_follows_mode():
    assert load_settings({"HALCYON_MODE": "vulnerable"}).sec_tool_scope_enforcement is False
    assert load_settings({"HALCYON_MODE": "secure"}).sec_tool_scope_enforcement is True


def test_mcp_flags_default_secure_in_secure_mode():
    from halcyon.config import load_settings
    s = load_settings({"HALCYON_MODE": "secure"})
    assert s.sec_mcp_desc_pinning is True
    assert s.sec_mcp_token_scoping is True


def test_mcp_flags_default_off_in_vulnerable_mode_and_override():
    from halcyon.config import load_settings
    s = load_settings({"HALCYON_MODE": "vulnerable"})
    assert s.sec_mcp_desc_pinning is False
    assert s.sec_mcp_token_scoping is False
    s2 = load_settings({"HALCYON_MODE": "vulnerable", "SEC_MCP_DESC_PINNING": "on"})
    assert s2.sec_mcp_desc_pinning is True
