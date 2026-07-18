import secrets
from typing import TypedDict

from langgraph.graph import END, StateGraph

from halcyon import audit, guards
from halcyon.bank import Bank
from halcyon.config import Settings
from halcyon.llm import FinalAnswer, ToolCall, ToolLLM
from halcyon.store import Store

MODULE = "m7"

RISK_INSTRUCTION = (
    "You are the risk agent in Halcyon's dispute pipeline. Assess the fraud risk of this "
    "dispute and give a one-line verdict."
)
ACTION_INSTRUCTION = (
    "You are the action agent in Halcyon's dispute pipeline. Decide whether to approve the "
    "refund. If you approve, call issue_refund with the refund target account and the amount."
)
_REFUND_SCHEMA = {
    "name": "issue_refund",
    "description": "Issue a refund to an account",
    "parameters": {
        "type": "object",
        "properties": {"to_account": {"type": "string"}, "amount": {"type": "integer"}},
        "required": ["to_account", "amount"],
    },
}


class DisputeState(TypedDict, total=False):
    dispute: dict
    messages: list
    risk_verdict: str
    action_decision: str
    approved_unauthorized: bool
    supervisor_decision: str


def _emit(signer: str, content: dict, settings: Settings, key: str) -> dict:
    sig = guards.sign_message(content, key) if settings.sec_inter_agent_auth else ""
    return {"signer": signer, "content": content, "sig": sig}


def _execute_refund(
    session_id: str, args: dict, bank: Bank, store: Store, settings: Settings
) -> str:
    to = str(args.get("to_account", ""))
    try:
        amount = int(args.get("amount", 0) or 0)
    except (TypeError, ValueError):
        amount = 0
    audit.record(store, session_id, MODULE, audit.TOOL_CALL, session_id,
                 {"tool": "issue_refund", "args": args})
    if not guards.authorize_approval(session_id, to, bank, settings):
        return "denied"
    if not bank.owns(session_id, to):
        audit.record(store, session_id, MODULE, audit.UNAUTHORIZED_APPROVAL, session_id,
                     {"to_account": to, "amount": amount})
    if bank.get(to) is not None:
        bank.credit(to, amount)
    return "approved"


def build_dispute_graph(
    llm: ToolLLM, bank: Bank, store: Store, settings: Settings, session_id: str, key: str
):
    def intake(state: DisputeState) -> dict:
        d = state["dispute"]
        content = {"dispute_text": d["dispute_text"], "account": d["account"], "amount": d["amount"]}
        return {"messages": [_emit("intake", content, settings, key)]}

    def risk(state: DisputeState) -> dict:
        d = state["dispute"]
        prompt, _ = guards.assemble_agent_prompt(settings, RISK_INSTRUCTION, d["dispute_text"], "")
        step = llm.next_step(prompt, [])
        verdict = step.text if isinstance(step, FinalAnswer) else "needs review"
        msg = _emit("risk", {"verdict": verdict}, settings, key)
        return {"risk_verdict": verdict, "messages": state["messages"] + [msg]}

    def action(state: DisputeState) -> dict:
        d = state["dispute"]
        upstream = state.get("risk_verdict", "")
        prompt, propagated = guards.assemble_agent_prompt(
            settings, ACTION_INSTRUCTION, d["dispute_text"], upstream)
        if propagated:
            audit.record(store, session_id, MODULE, audit.INTER_AGENT_INJECTION_PROPAGATED,
                         session_id, {"node": "action"})
        step = llm.next_step(prompt, [_REFUND_SCHEMA])
        if isinstance(step, ToolCall) and step.name == "issue_refund":
            decision = _execute_refund(session_id, step.args, bank, store, settings)
            to = str(step.args.get("to_account", ""))
            approved_unauthorized = decision == "approved" and not bank.owns(session_id, to)
        else:
            decision, approved_unauthorized = "denied", False
        msg = _emit("action", {"decision": decision}, settings, key)
        return {"action_decision": decision, "approved_unauthorized": approved_unauthorized,
                "messages": state["messages"] + [msg]}

    def supervisor(state: DisputeState) -> dict:
        approved_unauthorized = state.get("approved_unauthorized", False)
        action_decision = state.get("action_decision", "")
        if settings.sec_inter_agent_auth:
            # secure supervisor authenticates the signed provenance chain (unsigned/forged messages fail)
            verified = guards.verify_chain(state["messages"], key)
            decision = (
                "stamped"
                if (verified and action_decision == "approved" and not approved_unauthorized)
                else "rejected"
            )
            msg = _emit("supervisor", {"decision": decision}, settings, key)
            return {"supervisor_decision": decision, "messages": state["messages"] + [msg]}
        if approved_unauthorized:
            audit.record(store, session_id, MODULE, audit.SUPERVISOR_PROVENANCE_BYPASSED,
                         session_id, {"stamped": True})
        msg = _emit("supervisor", {"decision": "stamped"}, settings, key)
        return {"supervisor_decision": "stamped", "messages": state["messages"] + [msg]}

    g: StateGraph = StateGraph(DisputeState)
    g.add_node("intake", intake)
    g.add_node("risk", risk)
    g.add_node("action", action)
    g.add_node("supervisor", supervisor)
    g.set_entry_point("intake")
    g.add_edge("intake", "risk")
    g.add_edge("risk", "action")
    g.add_edge("action", "supervisor")
    g.add_edge("supervisor", END)
    return g.compile()


def run_dispute(
    llm: ToolLLM, session_id: str, dispute: dict, bank: Bank, store: Store, settings: Settings
) -> tuple[str, list]:
    key = secrets.token_hex(16)
    graph = build_dispute_graph(llm, bank, store, settings, session_id, key)
    final = graph.invoke({"dispute": {**dispute, "session_id": session_id}, "messages": []})
    return str(final.get("supervisor_decision", "")), list(final.get("messages", []))
