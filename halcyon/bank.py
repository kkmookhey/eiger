from dataclasses import dataclass, field


@dataclass
class Account:
    id: str
    owner_session: str
    balance: int
    email: str


@dataclass
class Bank:
    _accounts: dict[str, Account] = field(default_factory=dict)

    def get(self, account_id: str) -> Account | None:
        return self._accounts.get(account_id)

    def credit(self, account_id: str, amount: int) -> None:
        self._accounts[account_id].balance += amount

    def debit(self, account_id: str, amount: int) -> None:
        self._accounts[account_id].balance -= amount

    def set_email(self, account_id: str, email: str) -> None:
        self._accounts[account_id].email = email

    def owns(self, session_id: str, account_id: str) -> bool:
        a = self._accounts.get(account_id)
        return a is not None and a.owner_session == session_id

    def seed(self, fixtures: list[dict]) -> None:
        for f in fixtures:
            self._accounts[f["id"]] = Account(
                f["id"], f["owner_session"], f["balance"], f["email"])

    def clear(self) -> None:
        self._accounts = {}
