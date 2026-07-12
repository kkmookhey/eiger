from halcyon import audit, progress
from halcyon.store import Store

MODULE = "m5"


def validate(store: Store, session_id: str) -> dict:
    core = audit.has_event(store, session_id, MODULE, audit.UNAUTHORIZED_TOOL_CALL)
    stretch = audit.has_event(store, session_id, MODULE, audit.UNAUTHORIZED_ACCOUNT_MODIFICATION)
    progress.mark(store, session_id, MODULE, core, stretch)
    return {
        "core": "pass" if core else "fail",
        "stretch": "pass" if stretch else "fail",
    }
