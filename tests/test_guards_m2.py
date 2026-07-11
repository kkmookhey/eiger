from halcyon import guards
from halcyon.config import load_settings


def test_encode_output_escapes_when_encoding_on():
    s = load_settings({"HALCYON_MODE": "secure"})
    out = guards.encode_output('<img src=x onerror=alert(1)>', s)
    assert "<img" not in out and "&lt;img" in out


def test_encode_output_passthrough_when_off():
    s = load_settings({"HALCYON_MODE": "vulnerable"})
    payload = '<img src=x onerror=alert(1)>'
    assert guards.encode_output(payload, s) == payload


def test_m2_canary_in_vulnerable_prompt_not_hardened():
    assert guards.SYS_CANARY_M2 in guards.SYSTEM_WITH_TOKEN
    assert guards.SYS_CANARY_M2 not in guards.SYSTEM_BASE
