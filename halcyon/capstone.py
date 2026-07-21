from halcyon import audit
from halcyon.store import Store

# Each module's core-exploit signal — mirrors the core condition in validators/*.py.
# The test test_core_events_map_stays_in_sync_with_validators guards against drift.
CORE_EVENTS: dict[str, list[str]] = {
    "m1": [audit.INTERNAL_TOKEN_DISCLOSED],
    "m2": [audit.XSS_BEACON],
    "m3": [audit.POISONED_CHUNK_IN_CONTEXT, audit.RAG_INJECTION_FIRED],
    "m4": [audit.MALICIOUS_ARTIFACT_IDENTIFIED],
    "m5": [audit.UNAUTHORIZED_TOOL_CALL],
    "m6": [audit.MCP_POISONED_INVOCATION],
    "m7": [audit.INTER_AGENT_INJECTION_PROPAGATED, audit.UNAUTHORIZED_APPROVAL],
    "m8": [audit.GUARDRAIL_BYPASSED],
}

_LAYERS = {
    "m1": "L0 chatbot", "m2": "L0 chatbot", "m3": "L1 RAG", "m4": "ML supply chain",
    "m5": "L2 agent", "m6": "L3 MCP", "m7": "L4 multi-agent", "m8": "L5 guardrail",
}
_ATTACKS = {
    "m1": "operator-token leak", "m2": "stored XSS", "m3": "RAG injection",
    "m4": "poisoned artifact", "m5": "confused-deputy refund", "m6": "MCP tool poisoning",
    "m7": "inter-agent approval", "m8": "guardrail bypass",
}


def residual_risk(store: Store, session_id: str) -> dict:
    modules = []
    for module, events in CORE_EVENTS.items():
        exploited = all(audit.has_event(store, session_id, module, e) for e in events)
        modules.append({
            "module": module, "layer": _LAYERS[module],
            "attack": _ATTACKS[module], "exploited": exploited,
        })
    exploited_count = sum(1 for m in modules if m["exploited"])
    return {"session": session_id, "modules": modules,
            "exploited_count": exploited_count, "total": len(modules)}
