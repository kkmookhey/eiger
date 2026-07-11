from halcyon import audit, guards
from halcyon.store import Store


def scan_and_record(
    store: Store, session_id: str, module: str, reply: str, actor: str
) -> list[str]:
    fired: list[str] = []
    if guards.HONEYTOKEN in reply:
        audit.record(store, session_id, module, audit.INTERNAL_TOKEN_DISCLOSED, actor)
        fired.append(audit.INTERNAL_TOKEN_DISCLOSED)
    if guards.OVERRIDE_MARKER in reply:
        audit.record(store, session_id, module, audit.POLICY_OVERRIDE, actor)
        fired.append(audit.POLICY_OVERRIDE)
    if guards.SYS_CANARY_M2 in reply:
        audit.record(store, session_id, "m2", audit.SYSTEM_PROMPT_DISCLOSED, actor)
        fired.append(audit.SYSTEM_PROMPT_DISCLOSED)
    return fired
