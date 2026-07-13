from collections.abc import Mapping
from dataclasses import dataclass

_TRUE = {"1", "true", "on", "yes"}


def _flag(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUE


@dataclass(frozen=True)
class Settings:
    mode: str
    sec_system_prompt_hardening: bool
    sec_input_filter: bool
    sec_output_encoding: bool
    sec_rag_provenance: bool
    sec_artifact_verification: bool
    sec_tool_scope_enforcement: bool
    sec_mcp_desc_pinning: bool
    sec_mcp_token_scoping: bool
    ollama_url: str
    ollama_model: str
    database_url: str
    default_provider: str


def load_settings(env: Mapping[str, str]) -> Settings:
    mode = env.get("HALCYON_MODE", "vulnerable").strip().lower()
    if mode not in ("vulnerable", "secure"):
        raise ValueError(
            f"HALCYON_MODE must be 'vulnerable' or 'secure', got {mode!r}"
        )
    secure = mode == "secure"
    return Settings(
        mode=mode,
        sec_system_prompt_hardening=_flag(env, "SEC_SYSTEM_PROMPT_HARDENING", secure),
        sec_input_filter=_flag(env, "SEC_INPUT_FILTER", secure),
        sec_output_encoding=_flag(env, "SEC_OUTPUT_ENCODING", secure),
        sec_rag_provenance=_flag(env, "SEC_RAG_PROVENANCE", secure),
        sec_artifact_verification=_flag(env, "SEC_ARTIFACT_VERIFICATION", secure),
        sec_tool_scope_enforcement=_flag(env, "SEC_TOOL_SCOPE_ENFORCEMENT", secure),
        sec_mcp_desc_pinning=_flag(env, "SEC_MCP_DESC_PINNING", secure),
        sec_mcp_token_scoping=_flag(env, "SEC_MCP_TOKEN_SCOPING", secure),
        ollama_url=env.get("OLLAMA_URL", "http://localhost:11434"),
        ollama_model=env.get("OLLAMA_MODEL", "llama3.1:8b"),
        database_url=env.get("DATABASE_URL", ""),
        default_provider=env.get("DEFAULT_PROVIDER", "local"),
    )
