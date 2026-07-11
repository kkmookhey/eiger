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


def test_profile_set_and_beacon_records_xss():
    client, store = make_client({"HALCYON_MODE": "vulnerable"}, "hi")
    client.post("/api/profile", json={"session_id": "p1", "display_name": "<x>"})
    r = client.get("/beacon/xss", params={"session": "p1"})
    assert r.status_code == 200
    assert client.get("/validate/m2", params={"session": "p1"}).json()["core"] == "pass"


def test_csp_header_only_in_secure():
    vuln, _ = make_client({"HALCYON_MODE": "vulnerable"}, "hi")
    assert "content-security-policy" not in {k.lower() for k in vuln.get("/chat").headers}
    sec, _ = make_client({"HALCYON_MODE": "secure"}, "hi")
    assert "content-security-policy" in {k.lower() for k in sec.get("/chat").headers}


def test_chat_page_exposes_encoding_flag():
    vuln, _ = make_client({"HALCYON_MODE": "vulnerable"}, "hi")
    assert 'data-encoding="off"' in vuln.get("/chat").text
    sec, _ = make_client({"HALCYON_MODE": "secure"}, "hi")
    assert 'data-encoding="on"' in sec.get("/chat").text


def test_secure_csp_nonce_matches_app_script():
    import re

    sec, _ = make_client({"HALCYON_MODE": "secure"}, "hi")
    r = sec.get("/chat", params={"session": "p1"})
    m = re.search(r"'nonce-([^']+)'", r.headers["content-security-policy"])
    assert m, "CSP should carry a script nonce in secure mode"
    assert f'nonce="{m.group(1)}"' in r.text, "app <script> must carry the CSP nonce"


def test_display_name_rendered_raw_when_vulnerable_escaped_when_secure():
    payload = "<img src=x onerror=1>"
    vuln, _ = make_client({"HALCYON_MODE": "vulnerable"}, "hi")
    vuln.post("/api/profile", json={"session_id": "p1", "display_name": payload})
    assert payload in vuln.get("/chat", params={"session": "p1"}).text  # raw
    sec, _ = make_client({"HALCYON_MODE": "secure"}, "hi")
    sec.post("/api/profile", json={"session_id": "p1", "display_name": payload})
    body = sec.get("/chat", params={"session": "p1"}).text
    assert payload not in body and "&lt;img" in body  # escaped
