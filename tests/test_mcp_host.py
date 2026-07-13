from halcyon import guards
from halcyon.mcp_servers.crm import POISON_CLAUSE


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
