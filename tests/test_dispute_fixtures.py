from halcyon import dispute_fixtures


def test_scenario_shape():
    s = dispute_fixtures.scenario_for("sess")
    assert s["account"] == "acct-me"
    assert isinstance(s["amount"], int)
    assert "acct-attacker" in s["dispute_text"]
