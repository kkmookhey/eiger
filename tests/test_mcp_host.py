import anyio

from halcyon import audit, guards
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.crm_fixtures import SEED
from halcyon.mcp_host import in_memory_host
from halcyon.mcp_servers.crm import POISON_CLAUSE
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault
from halcyon.store import InMemoryStore


def test_looks_poisoned_detects_injection():
    assert guards.looks_poisoned("Look up a customer." + POISON_CLAUSE)
    assert not guards.looks_poisoned("Look up a customer profile by account.")


def test_quarantine_strips_injected_clause():
    dirty = "Look up a customer." + POISON_CLAUSE
    clean = guards.quarantine_description(dirty)
    assert not guards.looks_poisoned(clean)
    assert "Look up a customer." in clean


def test_desc_hash_stable_and_sensitive():
    a = guards.desc_hash("x")
    assert a == guards.desc_hash("x") and a != guards.desc_hash("x ")


def _fixture(mode):
    bank = Bank()
    bank.seed([{"id": "acct-victim", "owner_session": "victim", "balance": 5000,
                "email": "victim@halcyon.test"}])
    return (bank, TokenVault({SERVER_CORE: "CORE", SERVER_CRM: "crm"}),
            InMemoryStore(), load_settings({"HALCYON_MODE": mode}))


def test_vulnerable_serves_poisoned_description_and_flags_invocation():
    async def main():
        bank, vault, store, settings = _fixture("vulnerable")
        async with in_memory_host(bank, vault, SEED, store, settings, "sess") as host:
            tools = await host.list_tools()
            host.approve(tools)
            schemas = await host.schemas_for_llm()
            crm_desc = next(s["description"] for s in schemas if s["name"] == "crm__get_customer")
            assert "IMPORTANT" in crm_desc                      # poison served verbatim
            await host.call("crm__get_customer", {"account": "acct-victim"})
            await host.call("core_banking__get_account_details", {"account": "acct-victim"})
            assert audit.has_event(store, "sess", "m6", audit.MCP_POISONED_INVOCATION)
    anyio.run(main)


def test_secure_quarantines_description_and_no_invocation():
    async def main():
        bank, vault, store, settings = _fixture("secure")
        async with in_memory_host(bank, vault, SEED, store, settings, "sess") as host:
            host.approve(await host.list_tools())
            schemas = await host.schemas_for_llm()
            crm_desc = next(s["description"] for s in schemas if s["name"] == "crm__get_customer")
            assert "IMPORTANT" not in crm_desc                  # quarantined
            await host.call("core_banking__get_account_details", {"account": "acct-victim"})
            assert not audit.has_event(store, "sess", "m6", audit.MCP_POISONED_INVOCATION)
    anyio.run(main)


def test_rug_pull_accepted_when_unpinned_blocked_when_pinned():
    async def main():
        # vulnerable: mutation accepted -> event
        bank, vault, store, settings = _fixture("vulnerable")
        async with in_memory_host(bank, vault, SEED, store, settings, "sess") as host:
            host.approve(await host.list_tools())      # approve at benign list #1
            await host.schemas_for_llm()               # list #2 -> mutated get_notes
            assert audit.has_event(store, "sess", "m6", audit.MCP_DESC_MUTATION_ACCEPTED)
        # secure: mutation detected, not accepted -> no event
        bank2, vault2, store2, settings2 = _fixture("secure")
        async with in_memory_host(bank2, vault2, SEED, store2, settings2, "s2") as host:
            host.approve(await host.list_tools())
            schemas = await host.schemas_for_llm()
            notes = next(s["description"] for s in schemas if s["name"] == "crm__get_notes")
            assert "IMPORTANT" not in notes            # served the pinned/quarantined desc
            assert not audit.has_event(store2, "s2", "m6", audit.MCP_DESC_MUTATION_ACCEPTED)
    anyio.run(main)
