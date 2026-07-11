from halcyon.config import load_settings
from halcyon.llm import StubLLM, build_llm, OllamaProvider


def test_stub_returns_fixed_reply_and_captures_messages():
    llm = StubLLM("hello")
    out = llm.chat([{"role": "user", "content": "hi"}])
    assert out == "hello"
    assert llm.last_messages == [{"role": "user", "content": "hi"}]


def test_build_llm_defaults_to_local_ollama():
    s = load_settings({})
    llm = build_llm(s)
    assert isinstance(llm, OllamaProvider)


def test_build_llm_remote_requires_key():
    s = load_settings({})
    import pytest
    with pytest.raises(ValueError):
        build_llm(s, provider="remote", model="gpt-4o", api_key="")
