from typing import Protocol

import httpx

from halcyon.config import Settings


class LLM(Protocol):
    def chat(self, messages: list[dict]) -> str: ...


class StubLLM:
    def __init__(self, reply: str) -> None:
        self._reply = reply
        self.last_messages: list[dict] = []

    def chat(self, messages: list[dict]) -> str:
        self.last_messages = messages
        return self._reply


class OllamaProvider:
    def __init__(self, url: str, model: str) -> None:
        self._url = url.rstrip("/")
        self._model = model

    def chat(self, messages: list[dict]) -> str:
        resp = httpx.post(
            f"{self._url}/api/chat",
            json={"model": self._model, "messages": messages, "stream": False},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]

    def ping(self) -> bool:
        try:
            r = httpx.get(f"{self._url}/api/tags", timeout=5)
            return r.status_code == 200
        except httpx.HTTPError:
            return False


class RemoteProvider:
    def __init__(self, provider: str, api_key: str, model: str) -> None:
        if not api_key:
            raise ValueError("remote provider requires an api_key")
        self._provider = provider
        self._api_key = api_key
        self._model = model

    def chat(self, messages: list[dict]) -> str:
        if self._provider == "anthropic":
            return self._anthropic(messages)
        return self._openai(messages)

    def _openai(self, messages: list[dict]) -> str:
        resp = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {self._api_key}"},
            json={"model": self._model, "messages": messages},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    def _anthropic(self, messages: list[dict]) -> str:
        system = " ".join(m["content"] for m in messages if m["role"] == "system")
        turns = [m for m in messages if m["role"] != "system"]
        resp = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": self._model,
                "system": system,
                "messages": turns,
                "max_tokens": 1024,
            },
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]


def build_llm(
    settings: Settings,
    provider: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
) -> LLM:
    provider = provider or settings.default_provider
    if provider == "remote":
        return RemoteProvider("openai", api_key or "", model or "gpt-4o")
    if provider in ("openai", "anthropic"):
        return RemoteProvider(provider, api_key or "", model or "gpt-4o")
    return OllamaProvider(settings.ollama_url, model or settings.ollama_model)
