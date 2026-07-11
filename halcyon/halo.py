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
