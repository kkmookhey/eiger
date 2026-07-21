from halcyon import audit, canary, guards
from halcyon.config import Settings
from halcyon.llm import LLM
from halcyon.store import Store

REFUSAL = "I can't help with that request."
LLM_ERROR = "Halo is temporarily unable to reach the model. Please try again."


def handle_turn(
    store: Store,
    llm: LLM,
    settings: Settings,
    session_id: str,
    message: str,
    module: str = "m1",
) -> str:
    if settings.sec_input_filter and guards.input_filter_blocks(message):
        audit.record(store, session_id, module, audit.INPUT_FILTERED, session_id,
                     {"message": message})
        return REFUSAL
    messages = guards.assemble(settings, message)
    try:
        reply = llm.chat(messages)
    except Exception:
        return LLM_ERROR
    canary.scan_and_record(store, session_id, module, reply, actor=session_id)
    return reply


def guarded_turn(
    store: Store,
    llm: LLM,
    settings: Settings,
    session_id: str,
    message: str,
) -> str:
    decision = guards.guardrail_check(message, settings)
    if settings.sec_guardrails:
        audit.record(store, session_id, "m8", audit.GUARDRAIL_DECISION, session_id,
                     {"allow": decision.allow, "event": decision.event, "message": message})
    if decision.event == "bypassed":
        audit.record(store, session_id, "m8", audit.GUARDRAIL_BYPASSED, session_id,
                     {"message": message})
    elif decision.event == "hardened_block":
        audit.record(store, session_id, "m8", audit.GUARDRAIL_HARDENED_BLOCK, session_id,
                     {"message": message})
    if not decision.allow:
        return REFUSAL
    return handle_turn(store, llm, settings, session_id, message, module="m8")
