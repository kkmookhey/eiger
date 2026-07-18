# Eiger / Halcyon — Build Status & Resume Guide

**Last updated:** 2026-07-18 (end of session). **Read this first to resume.**

Companion docs: `README.md` (what Eiger is), `OPERATIONS.md` (deploy/run), `CLAUDE.md` in the parent `Blackhat` workspace (standing rules), `halcyon-lab-spec.md` (Blackhat workspace — the per-module source of truth), each slice's `docs/specs/*` + `docs/plans/*`.

---

## TL;DR

- **What:** a deliberately-vulnerable single-app teaching lab for a 2-day Black Hat course on adversarial AI. Fictional AI-neobank **Halcyon**; assistant **Halo**. Attacked across six layers (L0→L5) that grow module by module. Participants **Build / Break / Secure** each layer.
- **Repo:** `eiger`. Local: `/Users/kkmookhey/Projects/eiger`. Public remotes: `origin` = github.com/kkmookhey/eiger, `transilience` = github.com/transilienceai/eiger. Branch: `main`.
- **Built so far:** **M1 · M2 · M3 · M4** (all of Day 1) **+ M5 · M6 · M7** (Day-2 modules). **All merged to `main`** (M7 merged 2026-07-18, HEAD `2d5c5de`), each with a live end-to-end proof.
- **Tests:** `158 passed, 4 skipped` (the 4 skips are the Postgres + ChromaDB + 2 MCP-over-HTTP integration tests, gated by `TEST_DATABASE_URL` / `RUN_CHROMA_TESTS` / `RUN_MCP_HTTP_TESTS`). Ruff + mypy clean.
- **Next:** **M8 (guardrails + capstone)**, plus the **Ops fleet slice**. Then the module **decks** (deferred until the app was real).

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
| Guards | `guards.py` | all `SEC_*` guards live here (M1 assemble/filter, M2 encode, M3 assemble_rag, M5 authorize_tool_call, M6 desc_hash/quarantine_description/authorize_token_access) |
| Validators | `validators/m1.py … m6.py` | each = pure audit-log query → `{core, stretch}` |
| LLM | `llm.py` | `LLM.chat` (M1–M4) + `ToolLLM.next_step` (M5); Stub/Ollama/OpenAI/Anthropic |
| M1/M2 (L0) | `halo.py` | chat turn pipeline; templates/chat.html |
| M3 (L1 RAG) | `kb.py` (InMemoryKB), `chroma_kb.py` (prod), `rag.py`, `kb_fixtures.py` | KnowledgeBase interface |
| M4 (supply chain) | `artifacts.py` (loader), `scan_artifact.py` (static scanner), `m4_answers.py`, `labs/m4/` | no LLM; submit-the-finding |
| M5 (L2 agent) | `bank.py`, `tools.py`, `agent.py` (`run`), `bank_fixtures.py` | tool-calling agent |
| M6 (L3 MCP) | `mcp_servers/{core_banking,crm}.py` (real MCP SDK servers), `mcp_host.py` (async client/host — guards at call sites), `mcp_vault.py`, `crm_fixtures.py`, `mcp_deploy.py` (streamable-HTTP apps), `agent.run_mcp` | 2 real MCP servers behind the agent; in-memory transport in tests, streamable-HTTP in deploy |
| M7 (L4 multi-agent) | `dispute_pipeline.py` (`run_dispute`, real compiled LangGraph `StateGraph`: intake→risk→action→supervisor), `dispute_fixtures.py`, `validators/m7.py` | reuses `Bank`/`bank_fixtures`; deterministic `StubToolLLM` nodes in tests |
| UI | `templates/chat.html`, `templates/reach.html` | one page, a panel per module; reply always via `textContent` (except M2's deliberate XSS surface) |

**Endpoints:** `GET /health` (now also probes the MCP servers → `"mcp": up|down|in-process`) · `GET /` + `/chat` (UI) · `POST /api/chat` (M1/M2) · `POST /api/kb` + `POST /api/ask` (M3) · `POST /submit/m4` (M4) · `POST /api/agent` (M5) · `POST /api/mcp-agent` (M6) · `POST /api/dispute` (M7) · `GET /validate/{module}` · `POST /reset/{module}`.

**`create_app(store, settings, llm_factory, kb, bank, tool_llm_factory, mcp_host_factory)`** — unchanged by M7 (still 7 params; M7 reuses `bank`). It grew a param per stateful module (kb for M3, bank + tool_llm_factory for M5, mcp_host_factory for M6). All call sites (tests' `make_client*`, `main.py`) pass all 7. `main.py` selects `http_host` when `MCP_CORE_URL`+`MCP_CRM_URL` are set (deploy), else an in-process `in_memory_host` fallback (dev).

**Flags:** `HALCYON_MODE` + `SEC_SYSTEM_PROMPT_HARDENING` (M1/M2) · `SEC_INPUT_FILTER` (M1) · `SEC_OUTPUT_ENCODING` (M2) · `SEC_RAG_PROVENANCE` (M3) · `SEC_ARTIFACT_VERIFICATION` (M4) · `SEC_TOOL_SCOPE_ENFORCEMENT` (M5) · `SEC_MCP_DESC_PINNING` + `SEC_MCP_TOKEN_SCOPING` (M6) · `SEC_INTER_AGENT_AUTH` (M7).

---

## What each module is (attack · flag · validator events)

| M | Layer | Core attack | Stretch | Flag(s) | Validator events (core / stretch) | e2e proof |
|---|---|---|---|---|---|---|
| M1 | L0 chatbot | direct prompt injection → leak operator honeytoken `HALCYON-OPS-7731` | policy override (marker `HALO-ACT-OVERRIDE`, non-contiguous in prompt) | SYSTEM_PROMPT_HARDENING, INPUT_FILTER | `internal_token_disclosed` / `policy_override` | live (llama3.1:8b, translate-to-French bypass) |
| M2 | L0 | stored XSS via app-echoed display name | system-prompt disclosure (canary `SYS-CANARY-M2-3390`, vuln-prompt only) | OUTPUT_ENCODING (escape + nonce-CSP) | `xss_beacon` / `system_prompt_disclosed` | live (real headless browser fired the beacon) |
| M3 | L1 RAG | indirect injection via unprovenance retrieval (marker `RAG-OWNED-7788`) | restricted-doc retrieval | RAG_PROVENANCE (quarantine user chunks + access scope) | `poisoned_chunk_in_context` ∧ `rag_injection_fired` / `restricted_doc_retrieved` | live (real ChromaDB + llama3.1:8b) |
| M4 | ML supply chain | find poisoned model artifact (pickle RCE) via static scanner | find vulnerable dep (`PyYAML==5.3.1`, CVE-2020-14343) | ARTIFACT_VERIFICATION (safetensors-only + hash-pin) | `malicious_artifact_identified` / `vulnerable_dependency_identified` | verified; RCE demo instructor-only (`docs/m4-instructor-demo.md`) |
| M5 | L2 agent | confused-deputy: move money to an unowned account | `update_email` on an unowned account (hijack) | TOOL_SCOPE_ENFORCEMENT (per-action ownership authz) | `unauthorized_tool_call` / `unauthorized_account_modification` | live (llama3.1:8b Ollama tool-calling, 4/4) |
| M6 | L3 MCP | tool-description **poisoning** — a hidden instruction in a CRM tool's description induces an unintended cross-server data call | **rug pull** (description mutates post-approval) · **token theft** (cross-server token read) | DESC_PINNING (pin+verify+quarantine descriptions) + TOKEN_SCOPING (per-server token isolation, enforced host-side) | `mcp_poisoned_invocation` / `mcp_desc_mutation_accepted` ∨ `token_read` | live (real llama3.1:8b over real streamable-HTTP MCP: vuln core:pass → secure core:fail; gated `RUN_MCP_HTTP_TESTS` HTTP e2e). **BYOK** needed for the autonomous poison-following variant (llama won't chain it). |
| M7 | L4 multi-agent | cascading injection: dispute-text payload propagates across implicitly-trusted agents → action agent auto-approves a fraudulent refund to an unowned account | supervisor rubber-stamps the fraudulent action | INTER_AGENT_AUTH (sign+verify inter-agent msgs · quarantine untrusted dispute text · supervisor provenance check) | `inter_agent_injection_propagated` ∧ `unauthorized_approval` / `supervisor_provenance_bypassed` | live (real graph; vuln core:pass → secure core:fail) |

M0 = Gandalf (hosted third-party warm-up) — nothing to build.

---

## Run / test / deploy

```bash
cd /Users/kkmookhey/Projects/eiger
uv run pytest -q                      # 158 passed, 4 skipped
uv run ruff check . && uv run mypy halcyon
# Local full stack (now 5 services: web, db, ollama, mcp-core-banking, mcp-crm):
docker compose up -d --build
docker compose exec ollama ollama pull llama3.1:8b   # first run
open http://localhost:8000/
# Postgres integration test:   TEST_DATABASE_URL=... uv run pytest tests/test_store_postgres.py
# ChromaDB integration test:   RUN_CHROMA_TESTS=1 uv run pytest tests/test_chroma_kb.py
# MCP-over-HTTP integration:   RUN_MCP_HTTP_TESTS=1 uv run pytest tests/test_mcp_http.py   # real streamable-HTTP MCP e2e
```

**AWS deploy** — recipe in `OPERATIONS.md` → "AWS single-instance host". **Currently torn down (no running instances, billing stopped).** Profile `sara-sales`, acct 331145994818, region `ap-south-1`. **HARD LESSON: use an AMD instance (`r6a`/`m6a`), NOT Intel Sapphire-Rapids "i" families — Ollama's llama-server segfaults on Intel AMX under virtualization.** Account has a 5-vCPU standard-family quota (→ 4-vCPU cap). The ChromaDB embedding model (~80 MB) downloads on first `/api/ask`; the M5 agent + M3 RAG both work keyless via Ollama.

---

## M6 — MCP security (L3) — DONE (S6, merged 2026-07-18)

Introduced **real MCP SDK servers as in-product targets** (`mcp-core-banking`, `mcp-crm`) behind the Halo agent via an async `MCPHost` client layer where every guard lives at its call sites. Spec/plan: `docs/specs/2026-07-13-halcyon-s6-m6-mcp-security-design.md` + `docs/plans/2026-07-13-halcyon-s6-m6-mcp-security.md`. e2e evidence: `docs/e2e/2026-07-18-s6-m6-mcp-checklist.md`.

- **Built:** poisoning (core) + rug pull + token theft (stretch). **Shadowing deliberately deferred** (both flags already have a real guard without it).
- **Transport:** real MCP over the **SDK in-memory transport** in deterministic tests; real **streamable-HTTP** in deploy + a gated e2e (`RUN_MCP_HTTP_TESTS=1`). Same server code both paths.
- **Guards (host-side, so they grade identically on both transports):** `SEC_MCP_DESC_PINNING` pins+verifies+quarantines descriptions (kills rug pull + poisoning); `SEC_MCP_TOKEN_SCOPING` isolates per-server tokens in `MCPHost.call` (kills token theft).
- **Grading:** `mcp_poisoned_invocation` (core) / `mcp_desc_mutation_accepted` ∨ `token_read` (stretch) — all recorded host-side against the audit log, model-word-independent.
- **Live e2e proven:** real llama3.1:8b over real HTTP MCP → vuln `core:pass` → flip → secure `core:fail`. **Caveat:** llama (keyless floor) won't *autonomously* chain the poisoned tool-description instruction; the autonomous attack reproduces with **BYOK** (M6's intended tier). Mechanism otherwise proven by deterministic tests + the gated HTTP e2e.

## M7 — multi-agent (L4) — DONE (S7)

Introduced a real **LangGraph** fraud/dispute pipeline (`intake → risk → action → supervisor`, a compiled `StateGraph`) as the new attack surface: **cascading injection** — a customer-supplied dispute-text payload propagates across implicitly-trusted agents, and the downstream action agent auto-approves a fraudulent refund to an account (`acct-attacker`) the session doesn't own. Stretch: the supervisor rubber-stamps the fraudulent action instead of catching it. Built on `s7-m7-multi-agent`; **not yet merged** — merge follows the live e2e proof (per the standing "no merge without e2e" gate).

- **Guard:** `SEC_INTER_AGENT_AUTH` bundles three things — HMAC sign+verify on inter-agent messages, M3-style quarantine of untrusted customer dispute-text, and a supervisor-side provenance + `authorize_approval` ownership check.
- **Grading:** `inter_agent_injection_propagated` ∧ `unauthorized_approval` (core) / `supervisor_provenance_bypassed` (stretch) — audit-log events, model-word-independent.
- **Surface:** `POST /api/dispute {session_id, dispute_text, account, amount, provider?, model?, api_key?}` → `{decision, transcript}`. No new container, no compose change — an in-process pipeline reachable through the existing `web` service. `create_app` unchanged (still 7 params); reuses `Bank`/`bank_fixtures`. M1–M6 untouched.
- Deterministic tests use stubbed `StubToolLLM` nodes on the real compiled graph — no network in the suite.
- e2e checklist scaffolded at `docs/e2e/2026-07-18-s7-m7-multi-agent-checklist.md` (live-run fields to be filled at e2e time).

## NEXT: M8 (guardrails + capstone)

L5 production — the final layer, input/output guardrails + prompt firewall (`SEC_GUARDRAILS`) plus a capstone that threads the earlier modules together. Source of truth = `halcyon-lab-spec.md` (Blackhat workspace) + `HANDOFF.md`.

**M7 merge: DONE** (2026-07-18 — ff-merged `2d5c5de` to `main`, pushed both remotes, branch deleted, memory updated).

**To resume M8:** re-read this file + the M8 spec section (`halcyon-lab-spec.md` §5 M8), then run the loop: brainstorm → spec → plan → subagent-driven build → opus review → e2e → merge.

**Remaining after M8:** the **Ops slice** (22-container-per-participant fleet + the 5 rehearsed `OPERATIONS.md` commands + **per-participant MCP-server isolation** + restricted DB role before the M4/M6 RCE labs + bake the embedding model into the image for offline local-LAN + trim the `uv run` re-sync at web container start), then the **module decks M2–M8**.

---

## Deferred cleanups (non-blocking; from the ledger)

Tracked in `.superpowers/sdd/progress.md`. None block the course; revisit opportunistically or during the Ops slice.

- **Ops-slice items:** `/health` + `/` Ollama/MCP probes are now **cached (5s TTL)**; db/ollama publish fixed host ports (will collide under the 22-instance fleet); bake the ChromaDB embedding model into the image for offline local-LAN; a restricted DB role before the M4/M6 RCE labs share Postgres; Dockerfile dep-layer cache order; the web container's `uv run` CMD **re-syncs dev deps at startup** (~40s slow first boot — use the venv directly / `--no-dev`); add a `.dockerignore`.
- **M6-specific (fast-follow, tied to per-participant MCP isolation):** the CRM rug-pull "benign-at-approval" illusion is a **process-global** `state["lists"]` counter — on a *shared* HTTP `mcp-crm` it permanently mutates after the first-ever `list_tools`, and `/reset/m6` doesn't reset it (grading stays correct in both modes; only the demo narrative degrades on a shared container). Fixes when the Ops slice gives each participant their own MCP containers, or add a per-session/reset counter hook. Also: `mcp_poisoned_invocation` attribution is deliberately coarse (any served poison arms the next sensitive core call — mechanism-based, model-word-independent); `build_*_server` carry unused `bank`/`vault` params (signature symmetry); `quarantine_description` is sentence-granular (imperfect teaching guard, like M1/M3).
- **Small code tidies:** `config.mode` not validated against `{vulnerable,secure}` (fail-open on typo — consider raising); `pg_store` duplicates the `"module_reset"` literal + redundant `conn.commit()`; `store.append_event` can forge a `module_reset` (add a guard now that reset endpoints exist); M1 input filter + M3 injection classifier are deliberately imperfect (teaching guards, but tunable); `build_llm` `provider="remote"` hardcodes OpenAI; scanner doesn't inspect old-style `INST`/`OBJ` opcodes; `Bank.debit` unused (no funding-source account); `agent.run`'s `module` param unused (m5 hardcoded in `tools.execute`).
- **Verification gaps:** BYOK (OpenAI/Anthropic) providers for both chat and tool-calling are wire-format-correct (claude-api-verified) but only smoke-tested with a real key at Day-2 time — do a live BYOK check when a key is available.
- **M7-specific (minor):** `_execute_refund` records `unauthorized_approval` for a nonexistent target account (`acct-attacker`) then no-ops the credit, consistent with the same pattern in M5's `tools.py`; harmless — the mechanism-based grading is still correct.

---

## Key facts for a fresh context

- Memory index: `blackhat-build-sequence.md` (in the auto-memory) has the running state and points here.
- The **parent Blackhat workspace** (`/Users/kkmookhey/Projects/Blackhat`) holds the course-level `HANDOFF.md`, `halcyon-lab-spec.md`, `CLAUDE.md`, and the decks/`training/` repo. It is NOT a git repo; `eiger` is the app repo.
- Honeytoken/markers (canaries): `HALCYON-OPS-7731` (M1), `HALO-ACT-OVERRIDE` (M1 stretch), `SYS-CANARY-M2-3390` (M2), `RAG-OWNED-7788` (M3), poisoned-artifact sha256 in `m4_answers.py` (M4). M6 has no fixed token — the attack payload is the `POISON_CLAUSE` in `mcp_servers/crm.py` (the CRM `get_customer` description); tools are host-qualified `"<server>__<tool>"` (e.g. `core_banking__get_account_details`).
