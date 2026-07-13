import anyio
from halcyon import agent, audit
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.crm_fixtures import SEED
from halcyon.llm import FinalAnswer, StubToolLLM, ToolCall
from halcyon.mcp_host import in_memory_host
from halcyon.mcp_vault import TokenVault, SERVER_CORE, SERVER_CRM
from halcyon.store import InMemoryStore


def _fx(mode):
    bank = Bank()
    bank.seed([{"id": "acct-victim", "owner_session": "victim", "balance": 5000,
                "email": "victim@halcyon.test"}])
    return (bank, TokenVault({SERVER_CORE: "CORE", SERVER_CRM: "crm"}),
            InMemoryStore(), load_settings({"HALCYON_MODE": mode}))


def test_poisoning_core_fires_when_vulnerable():
    async def main():
        bank, vault, store, settings = _fx("vulnerable")
        llm = StubToolLLM([
            ToolCall("crm__get_customer", {"account": "acct-victim"}),
            ToolCall("core_banking__get_account_details", {"account": "acct-victim"}),
            FinalAnswer("Vera Payne, email victim@halcyon.test"),
        ])
        async with in_memory_host(bank, vault, SEED, store, settings, "sess") as host:
            reply, calls = await agent.run_mcp(llm, "sess", "Tell me about acct-victim", host, store, settings)
        assert audit.has_event(store, "sess", "m6", audit.MCP_POISONED_INVOCATION)
        assert len(calls) == 2
    anyio.run(main)


def test_token_theft_stretch_via_crm_tool():
    async def main():
        bank, vault, store, settings = _fx("vulnerable")
        llm = StubToolLLM([
            ToolCall("crm__get_integration_token", {"service": "core_banking"}),
            FinalAnswer("done"),
        ])
        async with in_memory_host(bank, vault, SEED, store, settings, "sess") as host:
            await agent.run_mcp(llm, "sess", "sync partner", host, store, settings)
        assert audit.has_event(store, "sess", "m6", audit.TOKEN_READ)
    anyio.run(main)
