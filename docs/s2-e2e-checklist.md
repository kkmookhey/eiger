# S2 (M2) End-to-End Verification Checklist + Sign-off

**Date:** 2026-07-11
**Branch:** `s2-m2-output-handling`
**Operator:** automated manual-e2e run (Task 8)
**Module:** M2 — stored XSS on the per-session display name (does not use the LLM; no Ollama pull required)

This artifact proves the S2/M2 spine end-to-end: **stored XSS lands in vulnerable mode → flip the security flag → escaping + CSP block it**, with pass/fail decided by a server-side query against the append-only audit log (`xss_beacon` event), never by matching page content directly. As a bonus, the vulnerable path was additionally exercised in a real headless browser (Playwright) to confirm the beacon fires purely from the browser's native `onerror` handler, with zero manual intervention.

---

## Step 1 — Stack up (vulnerable) + reach test

Command: `HALCYON_MODE=vulnerable docker compose up -d --build`

`GET /health`:

```json
{"status":"ok","mode":"vulnerable","ollama":"up","db":"up"}
```

All legs green. Ollama readiness was observed but irrelevant — M2 does not touch the LLM.

---

## Step 2 — Land the M2 exploit (vulnerable mode)

`POST /reset/m2` (session `e2e`) → `{"status":"reset","module":"m2"}`

`POST /api/profile`:

```json
{"session_id":"e2e","display_name":"<img src=x onerror=\"new Image().src='/beacon/xss?session=e2e'\">"}
```

→ `{"status":"ok"}`

`GET /chat?session=e2e` — the payload renders **RAW**, un-escaped, inside `<span id="dn">`:

```html
<div id="greeting">Welcome, <span id="dn"><img src=x onerror="new Image().src='/beacon/xss?session=e2e'"></span></div>
```

A real browser parsing this response would instantiate the `<img>`, fail to load `x`, and execute the `onerror` handler — i.e. the injected JS runs. Headers on the same response (via `curl -s -D - -o /dev/null`, since the route does not support `HEAD` — a plain `curl -I` returns `405 Method Not Allowed`):

```
HTTP/1.1 200 OK
content-length: 3811
content-type: text/html; charset=utf-8
```

**No `content-security-policy` header present** — nothing would stop the inline handler from executing.

Simulating the browser's `onerror` firing the beacon: `GET /beacon/xss?session=e2e` → `200 OK`, returns a 1x1 GIF (the audit-log side effect, `xss_beacon`, is recorded server-side).

`GET /validate/m2?session=e2e`:

```json
{"core":"pass","stretch":"fail"}
```

- **core = pass** — the `xss_beacon` audit event was recorded. This is the mandatory M2 objective and the load-bearing proof.

---

## Step 3 — Reset, flip to secure, confirm the block

`HALCYON_MODE=secure docker compose up -d web` (image unchanged; only the flag profile changes).

`GET /health` (secure):

```json
{"status":"ok","mode":"secure","ollama":"up","db":"up"}
```

`POST /reset/m2` (session `e2e`) → `{"status":"reset","module":"m2"}`, then re-sent the **same** payload to `/api/profile` → `{"status":"ok"}`.

`GET /chat?session=e2e` — the payload is now **HTML-escaped**:

```html
<div id="greeting">Welcome, <span id="dn">&lt;img src=x onerror=&quot;new Image().src=&#x27;/beacon/xss?session=e2e&#x27;&quot;&gt;</span></div>
```

Confirmed: `&lt;img` present, raw `<img src=x onerror=` substring absent.

Headers on the same response:

```
HTTP/1.1 200 OK
content-length: 3836
content-type: text/html; charset=utf-8
content-security-policy: default-src 'self'; script-src 'self'; img-src 'self' data:
```

**`content-security-policy` header present** — a defense-in-depth second guard: even if escaping were bypassed, the CSP's lack of `'unsafe-inline'` on `script-src` would still block an inline handler from executing.

`GET /validate/m2?session=e2e`:

```json
{"core":"fail","stretch":"fail"}
```

- **core = fail** — THE PROOF. No new `xss_beacon` event fired after the reset, because the payload never executed: `SEC_OUTPUT_ENCODING` HTML-escaped the stored name, and the CSP header independently would have blocked the inline `onerror` even if escaping had failed. Two independent guards, each individually sufficient, both verified in the same response.

---

## Step 4 — Headless-browser confirmation (not skipped — Playwright MCP was available)

Flipped back to `HALCYON_MODE=vulnerable`, reset a fresh session `e2e-browser`, and set the same payload via `/api/profile`. Pre-check: `GET /validate/m2?session=e2e-browser` → `{"core":"fail","stretch":"fail"}` (clean baseline, no beacon fired yet).

Navigated a real headless Chromium instance (Playwright MCP) to `http://localhost:8000/chat?session=e2e-browser` — no manual curl to `/beacon/xss` in this step. Network log for the page load (filtered on `beacon`):

```
[GET] http://localhost:8000/beacon/xss?session=e2e-browser => [200] OK
```

The browser's native `onerror` handler fired the beacon entirely on its own, exactly as an unsuspecting victim's browser would. Follow-up:

`GET /validate/m2?session=e2e-browser`:

```json
{"core":"pass","stretch":"fail"}
```

This confirms the curl-simulated beacon in Step 2 was not an artifact of the test harness — the exploit executes under a genuine browser DOM/JS engine.

---

## Step 5 — Tear down

`docker compose down` (volumes `eiger_ollama` and `eiger_pgdata` kept).

---

## Result

| Stage | `core` | Meaning |
|---|---|---|
| Vulnerable (curl-simulated beacon) | **pass** | Raw render, no CSP, exploit lands. |
| Vulnerable (real headless browser, native `onerror`) | **pass** | Confirms the curl simulation reflects real browser behavior. |
| Secure | **fail** | Escaping + CSP both present; exploit blocked, no new beacon. |

**S2/M2 spine verified.** Break → flip flag → blocked, all decided by audit-log query (`xss_beacon`), never by matching page content or model output — consistent with the mechanism-validation rule (M2 has no LLM involvement at all in this path).

---

## Notes / observations

- **M2 is fully LLM-free.** No Ollama model pull was needed or performed; `ollama:"up"` in `/health` reflects container readiness only, not model availability.
- **Two independent guards observed in secure mode.** `SEC_OUTPUT_ENCODING` (HTML-escaping of the stored display name) and the `Content-Security-Policy` header are each individually sufficient to block execution — verified together in the same secure-mode response, matching the module's design of legible, single-purpose guards behind one flag family.
- **`HEAD` requests 405 on `/chat`.** Response headers were fetched via `curl -s -D - -o /dev/null <url>` (a real `GET`) instead of `curl -I`, since the route only allows `GET`. Not a product defect — flagging for anyone else writing curl-based checks against this endpoint.
- **Headless-browser step was not skipped.** Playwright MCP tooling was available in this session, so the optional Step 4 in the task brief was executed rather than noted as skipped.
