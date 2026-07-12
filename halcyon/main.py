import os

from halcyon import kb_fixtures
from halcyon.bank import Bank
from halcyon.chroma_kb import ChromaKB
from halcyon.config import load_settings
from halcyon.llm import build_llm, build_tool_llm
from halcyon.pg_store import PostgresStore, init_schema
from halcyon.web import create_app

_settings = load_settings(os.environ)
init_schema(_settings.database_url)
_store = PostgresStore(_settings.database_url)
_kb = ChromaKB()
_kb.seed(kb_fixtures.SEED)
_bank = Bank()


def _factory(provider: str | None, model: str | None, api_key: str | None):
    return build_llm(_settings, provider, model, api_key)


def _tool_llm_factory(provider: str | None, model: str | None, api_key: str | None):
    return build_tool_llm(_settings, provider, model, api_key)


app = create_app(_store, _settings, _factory, _kb, _bank, _tool_llm_factory)
