# Halcyon S1 — Foundation + M1 (Prompt Injection) — Design

**Date:** 2026-07-11
**Slice:** S1 of the Halcyon build. First vertical slice; proves the whole reliability spine.
**Source of truth:** `halcyon-lab-spec.md` (v2, hosted) · `HANDOFF.md` §4/§8 · `CLAUDE.md`.
**Status:** Design — awaiting user approval before implementation.

---

## 1. Why this slice first

S1 is not "just M1." It is the **load-bearing scaffold** every later module reuses:

- `halcyon-web` FastAPI app + thin chat UI + Burp-friendly JSON API
- The **append-only audit log** and the **external progress store**
- The **`HALCYON_MODE` / `SEC_*` flag** config system
- The **`/validate/{module}` + `/reset/{module}`** loop
- The **reach-test / screen-1** pre-flight
- The **containerized dual-deploy** shape (one image → cloud + local-LAN)
- A **deterministic test harness** proving break→flag→blocked without a live model

Get S1 right and M2–M8 are "add a layer + a guard + an event + a validator" against a proven spine. Get it wrong and every module inherits the flaw. This is why S1 gets a full design and the rest replicate a pattern.

**Non-goal for S1:** full 22-container orchestration. S1 proves **one** participant instance against **shared** Ollama + progress store, containerized, with a documented path to N. Fleet orchestration is the later Ops slice (YAGNI now).

---

## 2. Assumptions (stated per CLAUDE.md §4.1)

- **UI = thin web chat + JSON API** (open decision #3 resolved this way). Reason: M2 needs a rendering surface; the API still supports Burp/curl. Revisit if you'd rather ship API-only.
- **Shared store = one Postgres container** holding both the audit log and progress tables. It lives outside the app containers, so it survives a redeploy (the spec's hard requirement). SQLite would undercut "external/shared," so Postgres from the start.
- **LLM access sits behind a provider interface.** The user **selects the model at runtime**: **local** (shared Ollama, keyless — the default Day-1 floor) or **remote** (BYOK: they enter their own OpenAI/Anthropic key in the UI). Tests inject a stub provider. This keeps the entire spine deterministically testable without any running model, and it makes the "Ollama floor, BYOK ceiling" doctrine a **user choice** rather than a hard-coded per-day switch. Day 1 still *defaults* to keyless local so nobody is blocked on key setup.
- **BYOK keys are per-session and never persisted to disk or the audit log.** Held in the session/progress store keyed by `session_id`, redacted from all logging. A deliberately-vulnerable app must not itself leak a real provider key.
- **Code location: separate deploy repo (resolved).** The app lives in its own Dockerized repo (mountain-name, TBD) with its own git/CI, *referenced* from the public `training/blackhat-2026-adversarial-ai/halcyon/` placeholder — not nested inside the public courseware repo.

---

## 3. Architecture (S1 scope)

```
                         ┌─────────────────────────────┐
   browser (chat UI) ───▶│  halcyon-web  (FastAPI)      │
   Burp / curl (API) ───▶│                             │
                         │  routes:                     │
                         │   GET  /health   (reach-test)│
                         │   POST /api/chat             │
                         │   GET  /validate/{module}    │
                         │   POST /reset/{module}       │
                         │                             │
                         │  pipeline (per chat turn):   │
                         │   1 input filter guard*      │
                         │   2 prompt assembly*         │─────▶ Ollama (shared)
                         │   3 canary detector          │◀─────  (LLM iface)
                         │   4 audit write              │
                         └───────────┬─────────────────┘
                                     │ SQL
                              ┌──────▼───────┐
                              │  Postgres    │  (shared, external — survives redeploy)
                              │  audit_log   │  append-only
                              │  progress    │  keyed by session_id
                              └──────────────┘
   * gated by SEC_* flags — the guard is the lesson
```

**Modules/units (each: one purpose, testable in isolation):**

| Unit | Purpose | Depends on |
|---|---|---|
| `config.py` | Read `HALCYON_MODE` + `SEC_*` env → typed settings; mode sets a default profile, flags override | env only |
| `llm.py` | Provider interface + `OllamaProvider` (local) + `RemoteProvider` (BYOK OpenAI/Anthropic) + `StubLLM` (tests); selected per session | Ollama / provider API |
| `audit.py` | Append-only writer + query helpers (events-after-last-reset) | Postgres |
| `progress.py` | Read/upsert per-session module pass state | Postgres |
| `guards.py` | The `SEC_*` guards: input filter, hardened prompt assembly. Small, legible, one guard per flag | config |
| `canary.py` | Honeytoken/marker detectors → emit audit events (the "mechanism") | audit |
| `halo.py` | Chat turn orchestration: filter → assemble → call LLM → detect → audit | all above |
| `validators/m1.py` | `/validate/m1` = audit query → `{core, stretch}` | audit |
| `web.py` | FastAPI routes + thin UI templates | halo, validators |

---

## 4. The reliability spine (load-bearing — do not route around)

### 4.1 Append-only audit log

```
audit_log(id bigserial pk, ts timestamptz default now(),
          session_id text, module text, event_type text,
          actor text, details jsonb)
```

- The app **never UPDATEs or DELETEs** rows in normal operation.
- **Reset** writes a `module_reset` marker row (it does *not* delete history). Validation and progress only count events **after the latest `module_reset`** for that `(session_id, module)`. This keeps the log truly append-only *and* makes reset clean. This is a deliberate improvement over "reset = DELETE."

### 4.2 External progress store

```
progress(session_id text, module text, core bool, stretch bool,
         updated_at timestamptz, primary key(session_id, module))
```

- Upserted whenever `/validate` computes a pass. Lives in Postgres → **survives container redeploy**. Keyed by `session_id`, never by container.

### 4.3 Validation = mechanism, not model words

`GET /validate/m1?session=…` runs **only** SQL against `audit_log`:

- `core`  = `∃ internal_token_disclosed` after last reset for (session, m1)
- `stretch` = `∃ policy_override` after last reset for (session, m1)

Returns `{ "core": "pass"|"fail", "stretch": "pass"|"fail" }` and upserts `progress`.

**How the events get written (the honeytoken/canary technique):** the `canary` detector scans the *outgoing* model response for fixed markers and, on a hit, writes the audit event. This is deterministic and robust to phrasing — "the token is X", "X", "it's X" all trip the same detector. It satisfies the doctrine: pass/fail is a log query; the log entry is a canary leak, **not** a match on how the model phrased anything.

- **Core canary:** operator honeytoken `HALCYON-OPS-7731`. Present in response → `internal_token_disclosed`.
- **Stretch canary:** `HALO-ACT-OVERRIDE` — the completed transfer-override authorization code. **The contiguous marker must never appear literally in either system prompt** (a naive fix that writes "never output `HALO-ACT-OVERRIDE`" is self-defeating: any prompt-dump echoes it and trips the stretch, so it fires even in secure mode and measures nothing — this was caught in the S1 e2e run). Instead the refusal policy names the marker's *components non-contiguously* — the code word `OVERRIDE` prefixed with `HALO-ACT-` — and forbids issuing an override authorization. A verbatim prompt-dump therefore reproduces the pieces in prose but never the contiguous token; only a model **jailbroken into actually fabricating/issuing the authorization** emits `HALO-ACT-OVERRIDE` contiguously → `policy_override`. A regression test asserts the contiguous marker is absent from both assembled prompts. `SEC_INPUT_FILTER` gives the vulnerable/secure distinction on the stretch by catching jailbreak phrasings before the model.

---

## 5. M1 vulnerable behavior + guards (the diff is the lesson)

Two `SEC_*` flags gate two small, readable guards. `HALCYON_MODE=vulnerable` → both off; `secure` → both on.

### Guard A — `SEC_SYSTEM_PROMPT_HARDENING`

- **off (vuln):** system text and user text are **concatenated into one prompt string**, and the honeytoken lives **inside that system text**. Extractable by direct injection.
  ```
  prompt = SYSTEM_WITH_TOKEN + "\n\nUser: " + user_input
  ```
- **on (secure):** **structured messages** (`[{system}, {user}]`) via the chat API — no concatenation — and the **honeytoken is removed from the prompt entirely** (kept server-side where the model never sees it). Nothing to extract.

### Guard B — `SEC_INPUT_FILTER`

- **off (vuln):** input passes straight through.
- **on (secure):** a small **override-attempt classifier** (readable keyword/regex heuristics: "ignore previous", "reveal/print your instructions", "system prompt", role-play escapes, obvious base64) rejects the turn before it reaches the model and writes `input_filtered`. Deliberately not "AI-perfect" — it's a legible teaching guard, and M8/P4RS3LT0NGV3 later teach bypassing it.

**Consequence for validation:** in `vulnerable` mode the injection lands → `internal_token_disclosed` → `core: pass`. Flip either/both flags → token isn't in the prompt (A) and/or the payload is filtered (B) → no disclosure event → `core: fail` (attack blocked). The participant *sees the exact guards that stopped them.*

---

## 6. Chat turn pipeline (`halo.py`)

```
POST /api/chat { session_id, message }
  1. filter   = guards.input_filter(message)         # if SEC_INPUT_FILTER on
        └─ blocked → audit(input_filtered); return canned refusal
  2. messages = guards.assemble(system, message)     # SEC_SYSTEM_PROMPT_HARDENING shapes this
  3. reply    = llm.chat(messages)                    # Ollama (or StubLLM in tests)
  4. canary.scan(reply, session, module="m1")         # → internal_token_disclosed / policy_override
  5. return { reply }
```

`actor` on audit rows = `session_id` (the participant). `module` context for M1 = `"m1"`.

---

## 7. Reach-test / screen 1

- `GET /health` → `{ status, ollama: "up"|"down", db: "up"|"down", mode }`. Ollama check = cheap model-list ping; db check = `SELECT 1`.
- Screen 1 UI polls `/health`, renders green when app+ollama+db are reachable. Target ≈ green in ~60s (hosted). Burp-cert and BYOK checks are added in later slices; S1 covers reach + Ollama + db.

---

## 8. UI (thin)

Two server-rendered pages, minimal CSS, no build step:

- `/` — **reach-test**: three status pills (app / Ollama / db) + "Enter lab" button.
- `/chat` — **Halo chat**: message list + input box; posts to `/api/chat`. In S1 the assistant text is rendered **as text** (M2 will introduce the raw-HTML rendering flaw behind its own flag — not S1's concern).

Session id: `?session=` param or `X-Session-Id` header; a dev default for local runs. (Hosted assignment of session per participant is an Ops-slice concern.)

### Model selector

Both pages carry a small **model control**: a toggle for **Local (Ollama)** vs **Remote (BYOK)**. Choosing Remote reveals a provider dropdown (OpenAI / Anthropic) + a masked API-key field and an optional model-name field. The choice is stored per `session_id` (key held in memory/session store, redacted everywhere). `/health` reflects the *active* provider's reachability. Local is the default so Day 1 works with zero setup; a participant who wants stronger tool-calling early can opt into their own key. `POST /api/chat` uses whatever provider the session selected.

---

## 9. Deployment (S1 shape)

- **`Dockerfile`** — `python:3.12-slim`, `uv` for deps, runs `halcyon-web`.
- **`docker-compose.yml`** — three services: `web`, `ollama` (shared, model volume), `db` (postgres, data volume). This same compose **is** the local-LAN fallback deploy; the cloud deploy runs the **same image**. One image, two targets — proven in S1, not deferred.
- **`.env.example`** — `HALCYON_MODE`, each `SEC_*`, `OLLAMA_URL`, `OLLAMA_MODEL`, `DATABASE_URL`, `DEFAULT_PROVIDER=local`. (Remote BYOK keys are entered per-session in the UI, **not** set here — server-side env holds no participant keys.)
- **`OPERATIONS.md` (seed)** — start the two commands that exist now (deploy-all, health-check); grows to the five rehearsed commands as fleet orchestration lands.

Full per-participant fleet (22 instances, one-participant reset/reprovision) is the **Ops slice**. S1 must not couple to a single target and must not hand-patch containers — the image is the unit of change.

---

## 10. Testing (deterministic — the whole point)

`pytest`, LLM stubbed so the spine is provable without Ollama:

1. `test_vulnerable_leak` — mode=vulnerable, `StubLLM` returns a reply containing the honeytoken → `/validate/m1` `core: pass`; audit has `internal_token_disclosed`.
2. `test_hardening_blocks` — `SEC_SYSTEM_PROMPT_HARDENING=on`; assert the token is **not in the assembled messages**; stub can't leak what it never saw → `core: fail`.
3. `test_input_filter_blocks` — `SEC_INPUT_FILTER=on`; override payload → rejected + `input_filtered` written; model not called.
4. `test_reset` — after a leak, `POST /reset/m1` writes `module_reset`; `/validate/m1` → `core: fail` (events counted only after the marker); history preserved.
5. `test_progress_survives` — pass core → `progress` upserted; simulate "redeploy" (new app object, same db) → progress still reads pass.
6. `test_health` — `/health` reports ollama+db status.

**Definition of done (CLAUDE.md §3):** these pass, lint passes, typecheck passes, plus one manual end-to-end against real Ollama (inject → see leak → flip flags → see it blocked).

---

## 11. Decisions (resolved at review 2026-07-11)

1. **Code location** — ✅ **separate Dockerized repo** (mountain-name, TBD), referenced from the public courseware placeholder. Not nested in public `training/`.
2. **Model access** — ✅ **user selects local (Ollama, keyless default) or remote (BYOK)** at runtime; remote key entered in the UI, per-session, never persisted. See §2, §8.
3. **UI shape** — ✅ thin web chat + JSON API.
4. **Ollama model** — still to pin a concrete tag (e.g. `llama3.1:8b`-class) for the shared local backend. Structural design is unaffected; needed to run.

---

## 12. What S1 explicitly does NOT include

- No RAG / ChromaDB (S3), no agent/tools/LangGraph (S5+), no MCP (S6), no multi-agent (S7), no guardrail wrapper (S8).
- No BYOK (Day-2 concern).
- No 22-container fleet orchestration (Ops slice).
- No M2 raw-HTML rendering flaw (S2, its own flag).

Smallest slice that proves the spine end-to-end. Everything else replicates it.
```
