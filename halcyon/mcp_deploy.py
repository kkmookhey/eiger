"""Streamable-HTTP ASGI apps for the deployed MCP servers.

Task 8: wraps the same low-level `Server` factories used by the in-memory
graded path (Tasks 2-7) in real streamable-HTTP ASGI apps, so the
container-per-participant deployment can run `mcp-core-banking` and
`mcp-crm` as standalone services reachable over HTTP from `halcyon-web`.
"""

import os
from contextlib import asynccontextmanager

from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.types import Receive, Scope, Send

from halcyon import bank_fixtures, crm_fixtures
from halcyon.bank import Bank
from halcyon.mcp_servers.core_banking import build_core_banking_server
from halcyon.mcp_servers.crm import build_crm_server
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault


def _asgi(server: Server) -> Starlette:
    mgr = StreamableHTTPSessionManager(app=server, stateless=True, json_response=True)

    async def handle(scope: Scope, receive: Receive, send: Send) -> None:
        await mgr.handle_request(scope, receive, send)

    @asynccontextmanager
    async def lifespan(app: Starlette):  # type: ignore[no-untyped-def]
        async with mgr.run():
            yield

    return Starlette(routes=[Mount("/mcp", app=handle)], lifespan=lifespan)


def core_banking_app(bank: Bank, vault: TokenVault) -> Starlette:
    return _asgi(build_core_banking_server(bank, vault))


def crm_app(bank: Bank, vault: TokenVault, customers: dict) -> Starlette:
    return _asgi(build_crm_server(bank, vault, customers))


def _seeded_bank() -> Bank:
    bank = Bank()
    bank.seed(bank_fixtures.seed_for("demo"))
    return bank


def _vault() -> TokenVault:
    return TokenVault({
        SERVER_CORE: os.environ.get("CORE_BANKING_TOKEN", "core-token-dev"),
        SERVER_CRM: os.environ.get("CRM_TOKEN", "crm-token-dev"),
    })


# Module-level ASGI objects for uvicorn to import directly, e.g.:
#   uv run uvicorn halcyon.mcp_deploy:CORE_ASGI --host 0.0.0.0 --port 9001
#   uv run uvicorn halcyon.mcp_deploy:CRM_ASGI --host 0.0.0.0 --port 9002
CORE_ASGI: Starlette = core_banking_app(_seeded_bank(), _vault())
CRM_ASGI: Starlette = crm_app(_seeded_bank(), _vault(), crm_fixtures.SEED)
