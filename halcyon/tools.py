from halcyon import audit, guards
from halcyon.bank import Bank
from halcyon.config import Settings
from halcyon.store import Store

SCHEMAS: list[dict] = [
    {"name": "get_balance", "description": "Get an account balance",
     "parameters": {"type": "object", "properties": {"account": {"type": "string"}},
                    "required": ["account"]}},
    {"name": "get_account_details", "description": "Look up an account's details",
     "parameters": {"type": "object", "properties": {"account": {"type": "string"}},
                    "required": ["account"]}},
    {"name": "transfer_funds", "description": "Transfer money to an account",
     "parameters": {"type": "object", "properties": {
         "to_account": {"type": "string"}, "amount": {"type": "integer"}},
         "required": ["to_account", "amount"]}},
    {"name": "issue_refund", "description": "Issue a refund to an account",
     "parameters": {"type": "object", "properties": {
         "to_account": {"type": "string"}, "amount": {"type": "integer"}},
         "required": ["to_account", "amount"]}},
    {"name": "update_email", "description": "Update an account's email",
     "parameters": {"type": "object", "properties": {
         "account": {"type": "string"}, "email": {"type": "string"}},
         "required": ["account", "email"]}},
]


def execute(name: str, session_id: str, args: dict, bank: Bank,
            store: Store, settings: Settings) -> str:
    audit.record(store, session_id, "m5", audit.TOOL_CALL, session_id,
                 {"tool": name, "args": args})
    if not guards.authorize_tool_call(session_id, name, args, bank, settings):
        return f"denied: {name} requires authorization / human approval"
    if name == "get_balance":
        a = bank.get(str(args.get("account", "")))
        return f"balance: {a.balance}" if a else "no such account"
    if name == "get_account_details":
        a = bank.get(str(args.get("account", "")))
        return f"account {a.id}: email={a.email} balance={a.balance}" if a else "no such account"
    if name in ("transfer_funds", "issue_refund"):
        to = str(args["to_account"])
        amount = int(args["amount"])
        if not bank.owns(session_id, to):
            audit.record(store, session_id, "m5", audit.UNAUTHORIZED_TOOL_CALL,
                         session_id, {"tool": name, "to_account": to, "amount": amount})
        if bank.get(to) is not None:
            bank.credit(to, amount)
        return f"{name}: moved {amount} to {to}"
    if name == "update_email":
        acct = str(args["account"])
        email = str(args["email"])
        if not bank.owns(session_id, acct):
            audit.record(store, session_id, "m5", audit.UNAUTHORIZED_ACCOUNT_MODIFICATION,
                         session_id, {"account": acct, "email": email})
        if bank.get(acct) is not None:
            bank.set_email(acct, email)
        return f"update_email: {acct} -> {email}"
    return f"unknown tool: {name}"
