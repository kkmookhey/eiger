import logging
import os

from halcyon import crm_fixtures, kb_fixtures
from halcyon.bank import Bank
from halcyon.chroma_kb import ChromaKB
from halcyon.config import load_settings
from halcyon.llm import build_llm, build_tool_llm
from halcyon.mcp_host import http_host, in_memory_host
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.pg_store import PostgresStore, init_schema
from halcyon.web import create_app

_settings = load_settings(os.environ)
init_schema(_settings.database_url)
_store = PostgresStore(_settings.database_url)
_kb = ChromaKB()
_kb.seed(kb_fixtures.SEED)
_bank = Bank()
_vault = TokenVault({SERVER_CORE: "core-token-dev", SERVER_CRM: "crm-token-dev"})


def _factory(provider: str | None, model: str | None, api_key: str | None):
    return build_llm(_settings, provider, model, api_key)


def _tool_llm_factory(provider: str | None, model: str | None, api_key: str | None):
    return build_tool_llm(_settings, provider, model, api_key)


_mcp_core_url = os.environ.get("MCP_CORE_URL")
_mcp_crm_url = os.environ.get("MCP_CRM_URL")

if _mcp_core_url and _mcp_crm_url:
    _core_url: str = _mcp_core_url
    _crm_url: str = _mcp_crm_url
    logging.getLogger(__name__).info(
        "mcp_host_factory: using http_host over %s / %s", _core_url, _crm_url
    )

    def _mcp_host_factory(session_id: str):
        return http_host(_core_url, _crm_url, _vault, _store, _settings, session_id)
else:
    # Local single-process dev fallback: no deployed MCP containers to reach,
    # so run the same servers in-memory against this process's own fixtures.
    logging.getLogger(__name__).warning(
        "mcp_host_factory: using in_memory_host fallback (MCP_CORE_URL/MCP_CRM_URL not set)"
    )

    def _mcp_host_factory(session_id: str):
        return in_memory_host(_bank, _vault, crm_fixtures.SEED, _store, _settings, session_id)


app = create_app(_store, _settings, _factory, _kb, _bank, _tool_llm_factory, _mcp_host_factory)
