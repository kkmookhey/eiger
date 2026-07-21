from halcyon import audit
from halcyon.store import InMemoryStore
from halcyon.validators import m8


def test_core_and_stretch_from_events():
    store = InMemoryStore()
    assert m8.validate(store, "s") == {"core": "fail", "stretch": "fail"}
    audit.record(store, "s", "m8", audit.GUARDRAIL_BYPASSED, "s")
    assert m8.validate(store, "s")["core"] == "pass"
    audit.record(store, "s", "m8", audit.GUARDRAIL_HARDENED_BLOCK, "s")
    assert m8.validate(store, "s") == {"core": "pass", "stretch": "pass"}
