from collections.abc import Callable

from halcyon.config import Settings
from halcyon.store import Store

SERVER_CORE = "core_banking"
SERVER_CRM = "crm"


class TokenVault:
    """Models per-server MCP token storage. Vulnerable = every server can read
    any token; secure (SEC_MCP_TOKEN_SCOPING) = a server reads only its own."""

    def __init__(self, tokens: dict[str, str]) -> None:
        self._tokens = dict(tokens)
        # Isolation default: read_for_crm resolves straight through to the raw
        # token store. Task 3's host binds a scoped wrapper via bind_crm.
        self.read_for_crm: Callable[[str], str | None] = lambda service: self._tokens.get(service)

    def own_token(self, server: str) -> str:
        return self._tokens.get(server, "")

    def read(
        self,
        requesting_server: str,
        target_service: str,
        session_id: str,
        store: Store,
        settings: Settings,
    ) -> str | None:
        from halcyon import audit, guards

        if requesting_server == target_service:
            return self._tokens.get(target_service)
        if not guards.authorize_token_access(requesting_server, target_service, settings):
            return None
        audit.record(
            store, session_id, "m6", audit.TOKEN_READ, requesting_server, {"target": target_service}
        )
        return self._tokens.get(target_service)

    def bind_crm(self, session_id: str, store: Store, settings: Settings) -> None:
        def read_for_crm(service: str) -> str | None:
            return self.read(SERVER_CRM, service, session_id, store, settings)

        self.read_for_crm = read_for_crm
