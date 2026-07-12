from halcyon import audit, tools
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.store import InMemoryStore


def _bank():
    b = Bank()
    b.seed([{"id": "acct-me", "owner_session": "me", "balance": 1000, "email": "me@x"},
            {"id": "acct-attacker", "owner_session": "attacker", "balance": 0, "email": "a@x"}])
    return b


def test_vulnerable_refund_to_unowned_is_unauthorized():
    b, s = _bank(), InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "vulnerable"})
    out = tools.execute("issue_refund", "me", {"to_account": "acct-attacker", "amount": 500}, b, s, settings)
    assert "500" in out
    assert audit.has_event(s, "me", "m5", audit.UNAUTHORIZED_TOOL_CALL)
    assert b.get("acct-attacker").balance == 500


def test_secure_refund_to_unowned_is_denied():
    b, s = _bank(), InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "secure"})
    out = tools.execute("issue_refund", "me", {"to_account": "acct-attacker", "amount": 500}, b, s, settings)
    assert "deni" in out.lower()
    assert not audit.has_event(s, "me", "m5", audit.UNAUTHORIZED_TOOL_CALL)
    assert b.get("acct-attacker").balance == 0


def test_update_email_on_unowned_records_modification_when_vulnerable():
    b, s = _bank(), InMemoryStore()
    b.seed([{"id": "acct-victim", "owner_session": "victim", "balance": 10, "email": "v@x"}])
    settings = load_settings({"HALCYON_MODE": "vulnerable"})
    tools.execute("update_email", "me", {"account": "acct-victim", "email": "attacker@x"}, b, s, settings)
    assert audit.has_event(s, "me", "m5", audit.UNAUTHORIZED_ACCOUNT_MODIFICATION)
    assert b.get("acct-victim").email == "attacker@x"
