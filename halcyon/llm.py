import json
from dataclasses import dataclass
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
            timeout=60,
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
            timeout=60,
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
            timeout=60,
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
    if provider in ("remote", "openai"):
        return RemoteProvider("openai", api_key or "", model or "gpt-4o")
    if provider == "anthropic":
        return RemoteProvider("anthropic", api_key or "", model or "claude-3-5-sonnet-latest")
    return OllamaProvider(settings.ollama_url, model or settings.ollama_model)


@dataclass
class ToolCall:
    name: str
    args: dict


@dataclass
class FinalAnswer:
    text: str


class ToolLLM(Protocol):
    def next_step(self, messages: list[dict], tools: list[dict]) -> "ToolCall | FinalAnswer": ...


class StubToolLLM:
    def __init__(self, script: list) -> None:
        self._script = list(script)
        self._i = 0

    def next_step(self, messages: list[dict], tools: list[dict]) -> "ToolCall | FinalAnswer":
        step = self._script[self._i]
        self._i += 1
        return step


class OllamaToolProvider:
    """Keyless tool-calling provider backed by the shared Ollama service."""

    def __init__(self, url: str, model: str) -> None:
        self._url = url.rstrip("/")
        self._model = model

    def next_step(self, messages: list[dict], tools: list[dict]) -> "ToolCall | FinalAnswer":
        try:
            resp = httpx.post(
                f"{self._url}/api/chat",
                json={
                    "model": self._model,
                    "messages": messages,
                    "tools": [{"type": "function", "function": schema} for schema in tools],
                    "stream": False,
                },
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            return FinalAnswer(f"<error: {exc}>")
        message = data.get("message") or {}
        tool_calls = message.get("tool_calls")
        if tool_calls:
            function = tool_calls[0].get("function") or {}
            return ToolCall(str(function.get("name", "")), dict(function.get("arguments") or {}))
        return FinalAnswer(str(message.get("content", "")))


class OpenAIToolProvider:
    """Tool-calling provider for the OpenAI chat completions API."""

    def __init__(self, api_key: str, model: str) -> None:
        if not api_key:
            raise ValueError("openai tool provider requires an api_key")
        self._api_key = api_key
        self._model = model

    def next_step(self, messages: list[dict], tools: list[dict]) -> "ToolCall | FinalAnswer":
        try:
            resp = httpx.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={
                    "model": self._model,
                    "messages": messages,
                    "tools": [{"type": "function", "function": schema} for schema in tools],
                },
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            message = data["choices"][0]["message"]
            tool_calls = message.get("tool_calls")
            if tool_calls:
                function = tool_calls[0]["function"]
                args = json.loads(function.get("arguments") or "{}")
                return ToolCall(str(function.get("name", "")), dict(args))
            return FinalAnswer(str(message.get("content") or ""))
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
            return FinalAnswer(f"<error: {exc}>")


class AnthropicToolProvider:
    """Tool-calling provider for the Anthropic Messages API."""

    def __init__(self, api_key: str, model: str) -> None:
        if not api_key:
            raise ValueError("anthropic tool provider requires an api_key")
        self._api_key = api_key
        self._model = model

    def next_step(self, messages: list[dict], tools: list[dict]) -> "ToolCall | FinalAnswer":
        system = " ".join(str(m["content"]) for m in messages if m.get("role") == "system")
        turns = [
            {"role": "assistant" if m.get("role") == "assistant" else "user",
             "content": str(m.get("content", ""))}
            for m in messages if m.get("role") != "system"
        ]
        try:
            resp = httpx.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self._model,
                    "max_tokens": 1024,
                    "system": system,
                    "messages": turns,
                    "tools": [
                        {
                            "name": schema["name"],
                            "description": schema.get("description", ""),
                            "input_schema": schema.get("parameters", {}),
                        }
                        for schema in tools
                    ],
                },
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            return FinalAnswer(f"<error: {exc}>")
        content = data.get("content") or []
        for block in content:
            if block.get("type") == "tool_use":
                return ToolCall(str(block.get("name", "")), dict(block.get("input") or {}))
        for block in content:
            if block.get("type") == "text":
                return FinalAnswer(str(block.get("text", "")))
        return FinalAnswer("")


def build_tool_llm(
    settings: Settings,
    provider: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
) -> ToolLLM:
    provider = provider or settings.default_provider
    if provider == "openai":
        return OpenAIToolProvider(api_key or "", model or "gpt-4o")
    if provider == "anthropic":
        return AnthropicToolProvider(api_key or "", model or "claude-3-5-sonnet-latest")
    return OllamaToolProvider(settings.ollama_url, model or settings.ollama_model)
