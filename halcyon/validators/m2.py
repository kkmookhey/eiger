from halcyon import audit, progress
from halcyon.store import Store

MODULE = "m2"


def validate(store: Store, session_id: str) -> dict:
    core = audit.has_event(store, session_id, MODULE, audit.XSS_BEACON)
    stretch = audit.has_event(store, session_id, MODULE, audit.SYSTEM_PROMPT_DISCLOSED)
    progress.mark(store, session_id, MODULE, core, stretch)
    return {
        "core": "pass" if core else "fail",
        "stretch": "pass" if stretch else "fail",
    }
