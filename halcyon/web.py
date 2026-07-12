import secrets
import time
from collections.abc import Callable
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel

from halcyon import guards, halo, kb_fixtures, m4_answers, rag
from halcyon.config import Settings
from halcyon.kb import KnowledgeBase
from halcyon.llm import LLM, OllamaProvider
from halcyon.store import Store
from halcyon.validators import m1, m2, m3, m4, m5

LLMFactory = Callable[[str | None, str | None, str | None], LLM]


class ChatIn(BaseModel):
    session_id: str
    message: str
    provider: str | None = None
    model: str | None = None
    api_key: str | None = None


class ResetIn(BaseModel):
    session_id: str


class ProfileIn(BaseModel):
    session_id: str
    display_name: str


class KbIn(BaseModel):
    session_id: str
    text: str


class AskIn(BaseModel):
    session_id: str
    query: str


class SubmitIn(BaseModel):
    session_id: str
    finding_type: str
    value: str


_VALIDATORS = {"m1": m1.validate, "m2": m2.validate, "m3": m3.validate, "m4": m4.validate, "m5": m5.validate}


def create_app(
    store: Store, settings: Settings, llm_factory: LLMFactory, kb: KnowledgeBase
) -> FastAPI:
    app = FastAPI(title="Halcyon")

    from starlette.requests import Request

    @app.middleware("http")
    async def _csp(request: Request, call_next):
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce
        resp = await call_next(request)
        if settings.sec_output_encoding:
            resp.headers["Content-Security-Policy"] = (
                f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; img-src 'self' data:"
            )
        return resp

    templates = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(),
    )

    _ollama_probe: dict[str, float | bool] = {"ts": 0.0, "up": False}

    def _ollama_up() -> bool:
        now = time.monotonic()
        if now - _ollama_probe["ts"] > 5.0:
            _ollama_probe["up"] = OllamaProvider(
                settings.ollama_url, settings.ollama_model
            ).ping()
            _ollama_probe["ts"] = now
        return bool(_ollama_probe["up"])

    @app.get("/health")
    def health() -> dict:
        ollama = _ollama_up()
        return {
            "status": "ok",
            "mode": settings.mode,
            "ollama": "up" if ollama else "down",
            "db": "up" if store.ping() else "down",
        }

    @app.post("/api/chat")
    def chat(body: ChatIn) -> dict:
        llm = llm_factory(body.provider, body.model, body.api_key)
        reply = halo.handle_turn(store, llm, settings, body.session_id, body.message)
        return {"reply": reply}

    @app.get("/validate/{module}")
    def validate(module: str, session: str) -> dict:
        validator = _VALIDATORS.get(module)
        if validator is None:
            return {"error": f"unknown module {module}"}
        return validator(store, session)

    @app.post("/reset/{module}")
    def reset(module: str, body: ResetIn) -> dict:
        store.write_reset_marker(body.session_id, module)
        if module == "m3":
            kb.clear()
            kb.seed(kb_fixtures.SEED)
        return {"status": "reset", "module": module}

    @app.post("/api/kb")
    def add_kb(body: KbIn) -> dict:
        kb.add(body.text, "user", owner_session=body.session_id)
        return {"status": "ok"}

    @app.post("/api/ask")
    def ask(body: AskIn) -> dict:
        reply, _ = rag.answer(
            kb, llm_factory(None, None, None), store, settings, body.session_id, body.query
        )
        return {"reply": reply}

    @app.get("/", response_class=HTMLResponse)
    def root() -> str:
        ollama = _ollama_up()
        return templates.get_template("reach.html").render(
            ollama=ollama, db=store.ping(), mode=settings.mode
        )

    @app.get("/chat", response_class=HTMLResponse)
    def chat_page(request: Request, session: str = "dev") -> str:
        name = store.get_profile(session)
        return templates.get_template("chat.html").render(
            output_encoding="on" if settings.sec_output_encoding else "off",
            display_name_html=guards.encode_output(name, settings),
            nonce=request.state.csp_nonce,
        )

    from fastapi.responses import Response

    from halcyon import audit

    _GIF = bytes.fromhex(
        "47494638396101000100800000ffffff00000021f90401000000002c00000000010001000002024401003b"
    )

    @app.post("/api/profile")
    def set_profile(body: ProfileIn) -> dict:
        store.set_profile(body.session_id, body.display_name)
        return {"status": "ok"}

    @app.get("/beacon/xss")
    def beacon(session: str) -> Response:
        audit.record(store, session, "m2", audit.XSS_BEACON, session)
        return Response(content=_GIF, media_type="image/gif")

    @app.post("/submit/m4")
    def submit_m4(body: SubmitIn) -> dict:
        correct = False
        if body.finding_type == "malicious_artifact":
            correct = m4_answers.normalize_hash(body.value) == m4_answers.POISONED_ARTIFACT_SHA256
            if correct:
                audit.record(store, body.session_id, "m4",
                             audit.MALICIOUS_ARTIFACT_IDENTIFIED, body.session_id)
        elif body.finding_type == "vulnerable_dependency":
            correct = m4_answers.normalize_package(body.value) == m4_answers.VULNERABLE_PACKAGE
            if correct:
                audit.record(store, body.session_id, "m4",
                             audit.VULNERABLE_DEPENDENCY_IDENTIFIED, body.session_id)
        return {"correct": correct}

    return app
