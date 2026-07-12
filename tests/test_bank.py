from halcyon.bank import Bank


def _seed(b):
    b.seed([{"id": "acct-me", "owner_session": "me", "balance": 1000, "email": "me@x"},
            {"id": "acct-victim", "owner_session": "victim", "balance": 5000, "email": "v@x"}])


def test_owns_and_mutations():
    b = Bank()
    _seed(b)
    assert b.owns("me", "acct-me") is True
    assert b.owns("me", "acct-victim") is False
    assert b.owns("me", "nope") is False
    b.credit("acct-me", 500)
    assert b.get("acct-me").balance == 1500
    b.set_email("acct-me", "new@x")
    assert b.get("acct-me").email == "new@x"


def test_clear():
    b = Bank()
    _seed(b)
    b.clear()
    assert b.get("acct-me") is None
