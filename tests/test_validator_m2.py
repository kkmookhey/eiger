from halcyon import audit
from halcyon.store import InMemoryStore
from halcyon.validators import m2


def test_core_pass_on_beacon():
    s = InMemoryStore()
    audit.record(s, "p1", "m2", audit.XSS_BEACON, "p1")
    assert m2.validate(s, "p1")["core"] == "pass"


def test_stretch_pass_on_disclosure():
    s = InMemoryStore()
    audit.record(s, "p1", "m2", audit.SYSTEM_PROMPT_DISCLOSED, "p1")
    assert m2.validate(s, "p1")["stretch"] == "pass"


def test_both_fail_empty():
    assert m2.validate(InMemoryStore(), "p1") == {"core": "fail", "stretch": "fail"}
