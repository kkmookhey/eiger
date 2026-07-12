from halcyon.kb import InMemoryKB


def test_retrieve_ranks_by_token_overlap():
    kb = InMemoryKB()
    kb.add("how to reset your card PIN at an ATM", "trusted")
    kb.add("branch opening hours and holidays", "trusted")
    hits = kb.retrieve("reset PIN card", "s1", k=1)
    assert len(hits) == 1 and "PIN" in hits[0].text


def test_add_sets_provenance_and_access():
    kb = InMemoryKB()
    c = kb.add("secret memo", "trusted", access="restricted", owner_session="ops")
    assert c.provenance == "trusted" and c.access == "restricted" and c.owner_session == "ops"


def test_clear_and_seed():
    kb = InMemoryKB()
    kb.add("x", "user")
    kb.clear()
    assert kb.retrieve("x", "s1") == []
    kb.seed([{"text": "alpha beta", "provenance": "trusted"}])
    assert kb.retrieve("alpha", "s1")[0].text == "alpha beta"
