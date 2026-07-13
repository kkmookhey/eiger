from halcyon.config import load_settings
from halcyon.mcp_vault import TokenVault, SERVER_CORE, SERVER_CRM
from halcyon.store import InMemoryStore
from halcyon import audit


def _vault():
    return TokenVault({SERVER_CORE: "CORE-SECRET", SERVER_CRM: "crm-tok"})


def test_cross_server_read_records_token_read_when_vulnerable():
    store = InMemoryStore()
    v = _vault()
    v.bind_crm("sess", store, load_settings({"HALCYON_MODE": "vulnerable"}))
    assert v.read_for_crm(SERVER_CORE) == "CORE-SECRET"
    assert audit.has_event(store, "sess", "m6", audit.TOKEN_READ)


def test_cross_server_read_denied_when_scoped():
    store = InMemoryStore()
    v = _vault()
    v.bind_crm("sess", store, load_settings({"HALCYON_MODE": "secure"}))
    assert v.read_for_crm(SERVER_CORE) is None
    assert not audit.has_event(store, "sess", "m6", audit.TOKEN_READ)


def test_own_token_read_never_flagged():
    store = InMemoryStore()
    v = _vault()
    v.bind_crm("sess", store, load_settings({"HALCYON_MODE": "secure"}))
    assert v.read_for_crm(SERVER_CRM) == "crm-tok"
    assert not audit.has_event(store, "sess", "m6", audit.TOKEN_READ)
