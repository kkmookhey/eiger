# Eiger

Codebase for **Halcyon** — a deliberately-vulnerable, single-app teaching lab for a 2-day Black Hat course on adversarial AI. One fictional AI-first neobank ("Halcyon") whose assistant ("Halo") is attacked across six layers that grow module by module:

```
L0 chatbot → L1 RAG → L2 agent → L3 MCP servers → L4 multi-agent → L5 production
```

Participants **Build / Break / Secure** each layer. Named for the Eiger's north face — the hard, exposed climb.

> **Naming:** the *repo/codebase* is **Eiger**. The in-fiction target org stays **Halcyon** and the assistant stays **Halo** (baked into the courseware narrative).

## Doctrine (load-bearing)

1. **Validate the mechanism, not the model's words** — pass/fail is a query against an append-only audit log.
2. **One build + `SEC_*` flags** — `vulnerable` vs `secure` is a config flag; the diff is the lesson.
3. **Local floor, BYOK ceiling** — Ollama (keyless, default) or the participant's own key, selectable at runtime. Both online.
4. **Deterministic + resettable + self-service** — `/validate/{module}`, `/reset/{module}`, reach-test on screen 1.

**Deployment:** hosted, container-per-participant app instances, a shared Ollama backend, and an external progress store; the same images dual-deploy to cloud (primary) and a local-LAN server (fallback).

## Status

**M1 · M2 · M3 · M4 (all of Day 1) + M5 (first Day-2 module) built and merged** — 112 tests, each proven live end-to-end. Next: M6 (MCP security).

👉 **[`docs/STATUS.md`](docs/STATUS.md) is the single source of truth for build status and how to resume.** It covers the architecture, the per-module summary, how to run/test/deploy, the M6 starting point, and deferred cleanups.

Planning workspace / full course context lives in the `Blackhat` workspace (`halcyon-lab-spec.md`, `HANDOFF.md`, `CLAUDE.md`).
