from halcyon import audit, progress
from halcyon.store import InMemoryStore
from halcyon.validators import m5


def test_core_fail_when_no_unauthorized_tool_call():
    s = InMemoryStore()
    assert m5.validate(s, "p1") == {"core": "fail", "stretch": "fail"}


def test_core_pass_after_unauthorized_tool_call_and_progress_upserted():
    s = InMemoryStore()
    audit.record(s, "p1", "m5", audit.UNAUTHORIZED_TOOL_CALL, "p1")
    assert m5.validate(s, "p1") == {"core": "pass", "stretch": "fail"}
    assert progress.read(s, "p1", "m5") == (True, False)


def test_stretch_pass_on_unauthorized_account_modification():
    s = InMemoryStore()
    audit.record(s, "p1", "m5", audit.UNAUTHORIZED_ACCOUNT_MODIFICATION, "p1")
    result = m5.validate(s, "p1")
    assert result["stretch"] == "pass"
