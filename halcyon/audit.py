from halcyon.store import Store

INTERNAL_TOKEN_DISCLOSED = "internal_token_disclosed"
POLICY_OVERRIDE = "policy_override"
INPUT_FILTERED = "input_filtered"
SYSTEM_PROMPT_DISCLOSED = "system_prompt_disclosed"
XSS_BEACON = "xss_beacon"
POISONED_CHUNK_IN_CONTEXT = "poisoned_chunk_in_context"
RAG_INJECTION_FIRED = "rag_injection_fired"
RESTRICTED_DOC_RETRIEVED = "restricted_doc_retrieved"
MALICIOUS_ARTIFACT_IDENTIFIED = "malicious_artifact_identified"
VULNERABLE_DEPENDENCY_IDENTIFIED = "vulnerable_dependency_identified"
TOOL_CALL = "tool_call"
UNAUTHORIZED_TOOL_CALL = "unauthorized_tool_call"
UNAUTHORIZED_ACCOUNT_MODIFICATION = "unauthorized_account_modification"
MCP_POISONED_INVOCATION = "mcp_poisoned_invocation"
MCP_DESC_MUTATION_ACCEPTED = "mcp_desc_mutation_accepted"
TOKEN_READ = "token_read"
INTER_AGENT_INJECTION_PROPAGATED = "inter_agent_injection_propagated"
UNAUTHORIZED_APPROVAL = "unauthorized_approval"
SUPERVISOR_PROVENANCE_BYPASSED = "supervisor_provenance_bypassed"


def record(
    store: Store,
    session_id: str,
    module: str,
    event_type: str,
    actor: str,
    details: dict | None = None,
) -> None:
    store.append_event(session_id, module, event_type, actor, details or {})


def has_event(store: Store, session_id: str, module: str, event_type: str) -> bool:
    return any(
        e.event_type == event_type for e in store.events_since_reset(session_id, module)
    )
