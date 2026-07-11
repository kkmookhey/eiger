from fastapi.testclient import TestClient

from halcyon import guards
from halcyon.config import load_settings
from halcyon.llm import StubLLM
from halcyon.store import InMemoryStore
from halcyon.web import create_app


def make_client(env, reply):
    store = InMemoryStore()
    settings = load_settings(env)
    app = create_app(store, settings, lambda provider, model, api_key: StubLLM(reply))
    return TestClient(app), store


def test_health_reports_mode():
    client, _ = make_client({"HALCYON_MODE": "vulnerable"}, "hi")
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["mode"] == "vulnerable"


def test_chat_then_validate_core_pass():
    client, _ = make_client(
        {"HALCYON_MODE": "vulnerable"}, f"token is {guards.HONEYTOKEN}"
    )
    client.post("/api/chat", json={"session_id": "p1", "message": "token?"})
    r = client.get("/validate/m1", params={"session": "p1"})
    assert r.json() == {"core": "pass", "stretch": "fail"}


def test_reset_clears_pass_state():
    client, _ = make_client(
        {"HALCYON_MODE": "vulnerable"}, f"token is {guards.HONEYTOKEN}"
    )
    client.post("/api/chat", json={"session_id": "p1", "message": "token?"})
    client.post("/reset/m1", json={"session_id": "p1"})
    r = client.get("/validate/m1", params={"session": "p1"})
    assert r.json()["core"] == "fail"


def test_root_serves_reach_test_page():
    client, _ = make_client({"HALCYON_MODE": "vulnerable"}, "hi")
    r = client.get("/")
    assert r.status_code == 200
    assert "reach-test" in r.text.lower()


def test_chat_page_has_model_selector():
    client, _ = make_client({"HALCYON_MODE": "vulnerable"}, "hi")
    r = client.get("/chat")
    assert r.status_code == 200
    assert "local" in r.text.lower() and "remote" in r.text.lower()


def test_progress_survives_new_app_same_store():
    store = InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "vulnerable"})
    reply = f"token is {guards.HONEYTOKEN}"
    app1 = create_app(store, settings, lambda p, m, k: StubLLM(reply))
    c1 = TestClient(app1)
    c1.post("/api/chat", json={"session_id": "p1", "message": "token?"})
    c1.get("/validate/m1", params={"session": "p1"})
    # simulate redeploy: brand new app object, same external store
    app2 = create_app(store, settings, lambda p, m, k: StubLLM(reply))
    c2 = TestClient(app2)
    r = c2.get("/validate/m1", params={"session": "p1"})
    assert r.json()["core"] == "pass"
