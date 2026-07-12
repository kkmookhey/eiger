# Eiger / Halcyon — Build Status & Resume Guide

**Last updated:** 2026-07-12 (end of session). **Read this first to resume.**

Companion docs: `README.md` (what Eiger is), `OPERATIONS.md` (deploy/run), `CLAUDE.md` in the parent `Blackhat` workspace (standing rules), `halcyon-lab-spec.md` (Blackhat workspace — the per-module source of truth), each slice's `docs/specs/*` + `docs/plans/*`.

---

## TL;DR

- **What:** a deliberately-vulnerable single-app teaching lab for a 2-day Black Hat course on adversarial AI. Fictional AI-neobank **Halcyon**; assistant **Halo**. Attacked across six layers (L0→L5) that grow module by module. Participants **Build / Break / Secure** each layer.
- **Repo:** `eiger`. Local: `/Users/kkmookhey/Projects/eiger`. Public remotes: `origin` = github.com/kkmookhey/eiger, `transilience` = github.com/transilienceai/eiger. Branch: `main`.
- **Built so far:** **M1 · M2 · M3 · M4** (all of Day 1) **+ M5** (first Day-2 module). All merged to `main`, each with a live end-to-end proof.
- **Tests:** `112 passed, 2 skipped` (the 2 skips are the Postgres + ChromaDB integration tests, gated by `TEST_DATABASE_URL` / `RUN_CHROMA_TESTS`). Ruff + mypy clean.
- **Next:** **M6 (MCP security)**, then M7 (multi-agent), M8 (guardrails+capstone), plus the **Ops fleet slice**. Then the module **decks** (deferred until the app was real).

---

## The build process (how every module is made)

Vertical slice per module (`Sn` builds `Mn`). Each slice runs this loop:

1. **Spec** — `superpowers:brainstorming` → design doc in `docs/specs/YYYY-MM-DD-halcyon-sN-*.md` (committed).
2. **Plan** — `superpowers:writing-plans` → TDD task plan in `docs/plans/*` (committed).
3. **Build** — `superpowers:subagent-driven-development`: a fresh **implementer** subagent per task (TDD), then a **reviewer** subagent per task; controller ledger at `.superpowers/sdd/progress.md`. Trivial flag-mirror tasks are verified inline instead of a full reviewer.
4. **Final review** — one **opus** whole-branch review before merge (catches things the per-task reviews and the JS-blind test suite miss — it has earned its keep every slice).
5. **e2e** — a live end-to-end proof (real model / real ChromaDB / real tool-calling).
6. **Merge** — ff-merge the slice branch to `main`, delete branch, push both remotes.

**Model tiers used:** implementers = haiku for pure transcription, sonnet for logic/integration; reviewers = sonnet; final whole-branch review = opus. Briefs/reports/diffs are handed to subagents as files under `.superpowers/sdd/` (gitignored).

### Load-bearing doctrine (do not route around)
- **Validate the mechanism, not the model's words.** Every pass/fail is a SQL/query over an **append-only audit log**, never a string match on model output.
- **One build + `SEC_*` flags.** `HALCYON_MODE = vulnerable | secure` sets a default profile; each `SEC_*` flag gates exactly one small, legible guard. **The diff between vulnerable and secure IS the lesson.**
- **Append-only log** with `module_reset` markers — validation counts events after the latest reset for `(session, module)`.
- **Deterministic tests** — every module's logic is testable with stubbed LLM/tool/embedding + in-memory store, no network. Real backends only in the e2e.

---

## Architecture & where things live

`halcyon/` package (FastAPI app; entrypoint `main.py` → `web.create_app`):

| Area | Files | Notes |
|---|---|---|
| Config / flags | `config.py` | `Settings` + `load_settings`; the 6 `SEC_*` flags below |
| Reliability spine | `store.py` (InMemory + Postgres via `pg_store.py`), `audit.py`, `progress.py`, `canary.py`, `schema.sql` | append-only log, reset markers, canary detectors |
| Guards | `guards.py` | all `SEC_*` guards live here (M1 assemble/filter, M2 encode, M3 assemble_rag, M5 authorize_tool_call) |
| Validators | `validators/m1.py … m5.py` | each = pure audit-log query → `{core, stretch}` |
| LLM | `llm.py` | `LLM.chat` (M1–M4) + `ToolLLM.next_step` (M5); Stub/Ollama/OpenAI/Anthropic |
| M1/M2 (L0) | `halo.py` | chat turn pipeline; templates/chat.html |
| M3 (L1 RAG) | `kb.py` (InMemoryKB), `chroma_kb.py` (prod), `rag.py`, `kb_fixtures.py` | KnowledgeBase interface |
| M4 (supply chain) | `artifacts.py` (loader), `scan_artifact.py` (static scanner), `m4_answers.py`, `labs/m4/` | no LLM; submit-the-finding |
| M5 (L2 agent) | `bank.py`, `tools.py`, `agent.py`, `bank_fixtures.py` | tool-calling agent |
| UI | `templates/chat.html`, `templates/reach.html` | one page, a panel per module; reply always via `textContent` (except M2's deliberate XSS surface) |

**Endpoints:** `GET /health` · `GET /` + `/chat` (UI) · `POST /api/chat` (M1/M2) · `POST /api/kb` + `POST /api/ask` (M3) · `POST /submit/m4` (M4) · `POST /api/agent` (M5) · `GET /validate/{module}` · `POST /reset/{module}`.

**`create_app(store, settings, llm_factory, kb, bank, tool_llm_factory)`** — note it grew a param per stateful module (kb for M3, bank + tool_llm_factory for M5). All call sites (tests' `make_client*`, `main.py`) pass all 6.

**Flags:** `HALCYON_MODE` + `SEC_SYSTEM_PROMPT_HARDENING` (M1/M2) · `SEC_INPUT_FILTER` (M1) · `SEC_OUTPUT_ENCODING` (M2) · `SEC_RAG_PROVENANCE` (M3) · `SEC_ARTIFACT_VERIFICATION` (M4) · `SEC_TOOL_SCOPE_ENFORCEMENT` (M5).

---

## What each module is (attack · flag · validator events)

| M | Layer | Core attack | Stretch | Flag(s) | Validator events (core / stretch) | e2e proof |
|---|---|---|---|---|---|---|
| M1 | L0 chatbot | direct prompt injection → leak operator honeytoken `HALCYON-OPS-7731` | policy override (marker `HALO-ACT-OVERRIDE`, non-contiguous in prompt) | SYSTEM_PROMPT_HARDENING, INPUT_FILTER | `internal_token_disclosed` / `policy_override` | live (llama3.1:8b, translate-to-French bypass) |
| M2 | L0 | stored XSS via app-echoed display name | system-prompt disclosure (canary `SYS-CANARY-M2-3390`, vuln-prompt only) | OUTPUT_ENCODING (escape + nonce-CSP) | `xss_beacon` / `system_prompt_disclosed` | live (real headless browser fired the beacon) |
| M3 | L1 RAG | indirect injection via unprovenance retrieval (marker `RAG-OWNED-7788`) | restricted-doc retrieval | RAG_PROVENANCE (quarantine user chunks + access scope) | `poisoned_chunk_in_context` ∧ `rag_injection_fired` / `restricted_doc_retrieved` | live (real ChromaDB + llama3.1:8b) |
| M4 | ML supply chain | find poisoned model artifact (pickle RCE) via static scanner | find vulnerable dep (`PyYAML==5.3.1`, CVE-2020-14343) | ARTIFACT_VERIFICATION (safetensors-only + hash-pin) | `malicious_artifact_identified` / `vulnerable_dependency_identified` | verified; RCE demo instructor-only (`docs/m4-instructor-demo.md`) |
| M5 | L2 agent | confused-deputy: move money to an unowned account | `update_email` on an unowned account (hijack) | TOOL_SCOPE_ENFORCEMENT (per-action ownership authz) | `unauthorized_tool_call` / `unauthorized_account_modification` | live (llama3.1:8b Ollama tool-calling, 4/4) |

M0 = Gandalf (hosted third-party warm-up) — nothing to build.

---

## Run / test / deploy

```bash
cd /Users/kkmookhey/Projects/eiger
uv run pytest -q                      # 112 passed, 2 skipped
uv run ruff check . && uv run mypy halcyon
# Local full stack:
docker compose up -d --build
docker compose exec ollama ollama pull llama3.1:8b   # first run
open http://localhost:8000/
# Postgres integration test: TEST_DATABASE_URL=... uv run pytest tests/test_store_postgres.py
# ChromaDB integration test: RUN_CHROMA_TESTS=1 uv run pytest tests/test_chroma_kb.py
```

**AWS deploy** — recipe in `OPERATIONS.md` → "AWS single-instance host". **Currently torn down (no running instances, billing stopped).** Profile `sara-sales`, acct 331145994818, region `ap-south-1`. **HARD LESSON: use an AMD instance (`r6a`/`m6a`), NOT Intel Sapphire-Rapids "i" families — Ollama's llama-server segfaults on Intel AMX under virtualization.** Account has a 5-vCPU standard-family quota (→ 4-vCPU cap). The ChromaDB embedding model (~80 MB) downloads on first `/api/ask`; the M5 agent + M3 RAG both work keyless via Ollama.

---

## NEXT: M6 — MCP security (L3)

The biggest jump so far: introduces **MCP servers as in-product targets** (`mcp-core-banking`, `mcp-crm`). Source of truth = `halcyon-lab-spec.md` §5 (M6) in the Blackhat workspace + `HANDOFF.md`. Patterns come from **DVMCP** and **mcp-breach-to-fix-labs** — *port their patterns into our flag+audit structure; never run them raw* (CLAUDE.md rule).

- **Vuln surfaces:** tool-description poisoning (hidden instructions in a tool's description) · rug pull (a tool mutates its description after approval) · tool shadowing (CRM server shadows a core-banking tool) · token theft (insecurely stored per-server tokens).
- **Flags:** `SEC_MCP_DESC_PINNING` (hash tool descriptions at approval), `SEC_MCP_TOKEN_SCOPING` (per-server token isolation).
- **Validator events:** `mcp_poisoned_invocation`, `mcp_desc_mutation_accepted`, `cross_server_shadow`, `token_read`.
- **Model tier:** BYOK (Day 2) — reuse the M5 `ToolLLM` interface + Ollama-keyless e2e path.
- **Reference pattern:** M5 (S5) is the closest precedent (agent + tools + audit). Reuse its structure.

**To resume tomorrow:** re-read this file + `halcyon-lab-spec.md` §5 (M6) + the S5 spec/plan as the template, then run the loop: brainstorm → spec (`docs/specs/2026-07-13-halcyon-s6-m6-mcp-*`) → plan → subagent-driven build → opus review → e2e → merge.

**Remaining after M6:** M7 (L4 multi-agent, LangGraph dispute pipeline, cascading injection), M8 (L5 guardrails + capstone), the **Ops slice** (22-container-per-participant fleet + the 5 rehearsed `OPERATIONS.md` commands + restricted DB role before the M4/M6 RCE labs + bake the embedding model into the image for offline local-LAN), then the **module decks M2–M8**.

---

## Deferred cleanups (non-blocking; from the ledger)

Tracked in `.superpowers/sdd/progress.md`. None block the course; revisit opportunistically or during the Ops slice.

- **Ops-slice items:** `/` + `/health` do a synchronous up-to-5s Ollama probe per request (cache it); db/ollama publish fixed host ports (will collide under the 22-instance fleet); bake the ChromaDB embedding model into the image for offline local-LAN; a restricted DB role before the M4/M6 RCE labs share Postgres; Dockerfile dep-layer cache order; add a `.dockerignore`.
- **Small code tidies:** `config.mode` not validated against `{vulnerable,secure}` (fail-open on typo — consider raising); `pg_store` duplicates the `"module_reset"` literal + redundant `conn.commit()`; `store.append_event` can forge a `module_reset` (add a guard now that reset endpoints exist); M1 input filter + M3 injection classifier are deliberately imperfect (teaching guards, but tunable); `build_llm` `provider="remote"` hardcodes OpenAI; scanner doesn't inspect old-style `INST`/`OBJ` opcodes; `Bank.debit` unused (no funding-source account); `agent.run`'s `module` param unused (m5 hardcoded in `tools.execute`).
- **Verification gaps:** BYOK (OpenAI/Anthropic) providers for both chat and tool-calling are wire-format-correct (claude-api-verified) but only smoke-tested with a real key at Day-2 time — do a live BYOK check when a key is available.

---

## Key facts for a fresh context

- Memory index: `blackhat-build-sequence.md` (in the auto-memory) has the running state and points here.
- The **parent Blackhat workspace** (`/Users/kkmookhey/Projects/Blackhat`) holds the course-level `HANDOFF.md`, `halcyon-lab-spec.md`, `CLAUDE.md`, and the decks/`training/` repo. It is NOT a git repo; `eiger` is the app repo.
- Honeytoken/markers (canaries): `HALCYON-OPS-7731` (M1), `HALO-ACT-OVERRIDE` (M1 stretch), `SYS-CANARY-M2-3390` (M2), `RAG-OWNED-7788` (M3), poisoned-artifact sha256 in `m4_answers.py` (M4).
