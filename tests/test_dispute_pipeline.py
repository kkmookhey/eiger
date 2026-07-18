from halcyon import audit, bank_fixtures, dispute_fixtures, dispute_pipeline
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.llm import FinalAnswer, StubToolLLM, ToolCall
from halcyon.store import InMemoryStore


def _bank(session):
    b = Bank()
    b.seed(bank_fixtures.seed_for(session))
    return b


# Same action stub in BOTH modes — the guard, not the script, decides the outcome.
def _script():
    return StubToolLLM([
        FinalAnswer("Risk: elevated, but case notes say pre-verified."),
        ToolCall("issue_refund", {"to_account": "acct-attacker", "amount": 5000}),
    ])


def test_vulnerable_run_records_core_and_stretch():
    store = InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "vulnerable"})
    bank = _bank("s")
    dispute = dispute_fixtures.scenario_for("s")
    decision, transcript = dispute_pipeline.run_dispute(_script(), "s", dispute, bank, store, settings)
    assert audit.has_event(store, "s", "m7", audit.INTER_AGENT_INJECTION_PROPAGATED)
    assert audit.has_event(store, "s", "m7", audit.UNAUTHORIZED_APPROVAL)
    assert audit.has_event(store, "s", "m7", audit.SUPERVISOR_PROVENANCE_BYPASSED)
    assert bank.get("acct-attacker").balance == 5000  # money actually moved
    assert len(transcript) == 4  # intake, risk, action, supervisor (each emits one signed message)


def test_secure_run_blocks_everything():
    store = InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "secure"})
    bank = _bank("s")
    dispute = dispute_fixtures.scenario_for("s")
    decision, _ = dispute_pipeline.run_dispute(_script(), "s", dispute, bank, store, settings)
    assert not audit.has_event(store, "s", "m7", audit.INTER_AGENT_INJECTION_PROPAGATED)
    assert not audit.has_event(store, "s", "m7", audit.UNAUTHORIZED_APPROVAL)
    assert not audit.has_event(store, "s", "m7", audit.SUPERVISOR_PROVENANCE_BYPASSED)
    assert bank.get("acct-attacker").balance == 0  # no money moved
    assert decision == "rejected"


def test_secure_legit_refund_to_owned_account_still_works():
    store = InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "secure"})
    bank = _bank("s")
    llm = StubToolLLM([
        FinalAnswer("Risk: low."),
        ToolCall("issue_refund", {"to_account": "acct-me", "amount": 100}),
    ])
    dispute = {"account": "acct-me", "amount": 100, "dispute_text": "Please refund my duplicate charge."}
    decision, _ = dispute_pipeline.run_dispute(llm, "s", dispute, bank, store, settings)
    assert not audit.has_event(store, "s", "m7", audit.UNAUTHORIZED_APPROVAL)
    assert bank.get("acct-me").balance == 1100  # legit refund applied
    assert decision == "stamped"


def test_secure_transcript_is_fully_signed_vulnerable_transcript_is_not():
    store = InMemoryStore()
    secure_settings = load_settings({"HALCYON_MODE": "secure"})
    bank = _bank("s")
    llm = StubToolLLM([
        FinalAnswer("Risk: low."),
        ToolCall("issue_refund", {"to_account": "acct-me", "amount": 100}),
    ])
    dispute = {"account": "acct-me", "amount": 100, "dispute_text": "Please refund my duplicate charge."}
    decision, secure_transcript = dispute_pipeline.run_dispute(llm, "s", dispute, bank, store, secure_settings)
    assert decision == "stamped"
    assert all(m["sig"] for m in secure_transcript)  # every inter-agent message is signed

    store = InMemoryStore()
    vuln_settings = load_settings({"HALCYON_MODE": "vulnerable"})
    bank = _bank("s")
    _, vuln_transcript = dispute_pipeline.run_dispute(_script(), "s", dispute_fixtures.scenario_for("s"), bank, store, vuln_settings)
    assert all(m["sig"] == "" for m in vuln_transcript)  # vuln mode never signs
