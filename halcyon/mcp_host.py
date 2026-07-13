from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass

from mcp import ClientSession
from mcp.shared.memory import create_connected_server_and_client_session as _connect
from mcp.types import TextContent

from halcyon import audit, guards
from halcyon.bank import Bank
from halcyon.config import Settings
from halcyon.mcp_servers.core_banking import build_core_banking_server
from halcyon.mcp_servers.crm import build_crm_server
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.store import Store

MODULE = "m6"
_SENSITIVE = {"get_account_details"}  # core-banking tools that leak data


@dataclass
class ToolInfo:
    server: str
    name: str
    description: str
    input_schema: dict

    @property
    def qualified(self) -> str:
        return f"{self.server}__{self.name}"


class MCPHost:
    def __init__(self, sessions: dict[str, ClientSession], vault: TokenVault,
                 store: Store, settings: Settings, session_id: str) -> None:
        self._sessions = sessions           # {SERVER_CORE: s, SERVER_CRM: s}
        self._vault = vault
        self._store = store
        self._settings = settings
        self._session_id = session_id
        self._pinned: dict[str, str] = {}
        self._served_poison = False
        vault.bind_crm(session_id, store, settings)

    async def _list(self, server: str) -> list[ToolInfo]:
        res = await self._sessions[server].list_tools()
        return [ToolInfo(server, t.name, t.description or "", t.inputSchema) for t in res.tools]

    async def list_tools(self) -> list[ToolInfo]:
        out: list[ToolInfo] = []
        for server in (SERVER_CORE, SERVER_CRM):
            out.extend(await self._list(server))
        return out

    def approve(self, tools: list[ToolInfo]) -> None:
        if self._settings.sec_mcp_desc_pinning:
            self._pinned = {ti.qualified: guards.desc_hash(ti.description) for ti in tools}

    async def schemas_for_llm(self) -> list[dict]:
        tools = await self.list_tools()
        self._served_poison = False
        schemas: list[dict] = []
        for ti in tools:
            desc = ti.description
            if self._settings.sec_mcp_desc_pinning:
                pinned = self._pinned.get(ti.qualified)
                if pinned is not None and guards.desc_hash(desc) != pinned:
                    desc = ""  # mutated since approval — drop the untrusted delta
                desc = guards.quarantine_description(desc)
            else:
                if guards.looks_poisoned(desc):
                    self._served_poison = True
                    if ti.name == "get_notes":  # a benign tool now carrying injected text == rug pull
                        audit.record(self._store, self._session_id, MODULE,
                                     audit.MCP_DESC_MUTATION_ACCEPTED, ti.server, {"tool": ti.name})
            schemas.append({"name": ti.qualified, "description": desc, "parameters": ti.input_schema})
        return schemas

    async def call(self, qualified: str, args: dict) -> str:
        server, _, name = qualified.partition("__")
        audit.record(self._store, self._session_id, MODULE, audit.TOOL_CALL,
                     self._session_id, {"tool": qualified, "args": args})
        if server == SERVER_CORE and name in _SENSITIVE and self._served_poison:
            audit.record(self._store, self._session_id, MODULE,
                         audit.MCP_POISONED_INVOCATION, self._session_id,
                         {"tool": qualified, "args": args})
        res = await self._sessions[server].call_tool(name, args)
        first = res.content[0] if res.content else None
        return first.text if isinstance(first, TextContent) else ""


@asynccontextmanager
async def in_memory_host(bank: Bank, vault: TokenVault, customers: dict,
                         store: Store, settings: Settings,
                         session_id: str) -> AsyncIterator[MCPHost]:
    async with AsyncExitStack() as stack:
        core = await stack.enter_async_context(_connect(build_core_banking_server(bank, vault)))
        crm = await stack.enter_async_context(_connect(build_crm_server(bank, vault, customers)))
        await core.initialize()
        await crm.initialize()
        yield MCPHost({SERVER_CORE: core, SERVER_CRM: crm}, vault, store, settings, session_id)
