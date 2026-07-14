"""Live e2e over the real streamable-HTTP transport (Task 8/9 proof).

Skipped by default — mirrors how tests/test_store_postgres.py gates on a
live Postgres. Set RUN_MCP_HTTP_TESTS=1 to start both deployed ASGI apps
in-process (uvicorn in daemon threads) and exercise the full
http_host -> agent.run_mcp poisoning path against them.
"""

import os
import socket
import threading
import time

import anyio
import pytest
import uvicorn

from halcyon import agent, audit
from halcyon.config import load_settings
from halcyon.llm import FinalAnswer, StubToolLLM, ToolCall
from halcyon.mcp_deploy import CORE_ASGI, CRM_ASGI
from halcyon.mcp_host import http_host
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.store import InMemoryStore

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_MCP_HTTP_TESTS") != "1", reason="requires live MCP HTTP servers"
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve_in_thread(app, port: int) -> None:
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()


@pytest.fixture(scope="module")
def mcp_urls():
    core_port = _free_port()
    crm_port = _free_port()
    _serve_in_thread(CORE_ASGI, core_port)
    _serve_in_thread(CRM_ASGI, crm_port)
    time.sleep(2)
    return f"http://127.0.0.1:{core_port}/mcp", f"http://127.0.0.1:{crm_port}/mcp"


def test_http_host_poisoning_path_over_real_transport(mcp_urls):
    core_url, crm_url = mcp_urls

    async def main():
        vault = TokenVault({SERVER_CORE: "core-token-dev", SERVER_CRM: "crm-token-dev"})
        store = InMemoryStore()
        settings = load_settings({"HALCYON_MODE": "vulnerable"})
        llm = StubToolLLM([
            ToolCall("crm__get_customer", {"account": "acct-victim"}),
            ToolCall("core_banking__get_account_details", {"account": "acct-victim"}),
            FinalAnswer("Vera Payne, email victim@halcyon.test"),
        ])
        async with http_host(core_url, crm_url, vault, store, settings, "sess") as host:
            reply, calls = await agent.run_mcp(
                llm, "sess", "Tell me about acct-victim", host, store, settings
            )
        assert len(calls) == 2
        assert audit.has_event(store, "sess", "m6", audit.MCP_POISONED_INVOCATION)

    anyio.run(main)
