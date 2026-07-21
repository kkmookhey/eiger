# Halcyon Lab Guides

Courseware for the 8 Halcyon teaching modules (M1–M8, layers L0→L5). Kept with the app so the exact endpoints/payloads stay versioned against the code they describe.

| File | Audience | Contents |
|---|---|---|
| [`test-runbook.md`](test-runbook.md) | **Trainer (QA)** | Copy-pasteable script to validate all 8 modules end-to-end: vulnerable sweep (attack → `core:pass`) then secure sweep (flip flag → blocked). Run this to confirm the lab is conference-ready. |
| [`trainer-guide.md`](trainer-guide.md) | **Trainer (facilitation)** | Per-module mechanism, **the solutions** (working exploits), expected `/validate` output, vuln→secure demo, teaching notes, model tier, gotchas. **Contains answers.** |
| [`participant-guide.md`](participant-guide.md) | **Participants** | Build/Break/Secure objectives per module with hints but **no solutions**. Safe to hand out. |

**Reference material (not for distribution):** `../STATUS.md` (build status + honeytokens/markers), `../e2e/*.md` (per-module live-proof evidence with exact proven payloads), `../m4-instructor-demo.md` (the sandboxed pickle-RCE demo), `../../OPERATIONS.md` (deploy/run).

**Start here to test:** `test-runbook.md` → Phase 0 (bring up the stack).
