# Halcyon S4 — M4 (ML / AI Supply Chain) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add M4 — a codebase supply-chain audit. Participants find a poisoned model artifact (pickle RCE, via a static opcode scanner) and a vulnerable pinned dependency (SCA), submit both, and study the `SEC_ARTIFACT_VERIFICATION` hardening. No Halo/LLM.

**Architecture:** A flag-gated in-app artifact loader (`artifacts.py`: `pickle.load` when vulnerable, safetensors-only + hash-pin when secure). A provided **static** opcode scanner (`scan_artifact.py`) — never deserializes. Deliberately-vulnerable material isolated under `labs/m4/`. Grading = a server-side check of submitted findings against known-bad answers, recorded to the audit log. Core = poisoned artifact identified; stretch = vulnerable dependency identified.

**Tech Stack:** unchanged (Python 3.12, FastAPI, pytest, ruff, mypy, uv). Stdlib `pickle`/`pickletools`/`hashlib` only.

## Global Constraints
- Same doctrine (append-only log; one build + flags; deterministic tests; validate the mechanism). All existing tests stay green.
- New flag `SEC_ARTIFACT_VERIFICATION` (mode-profiled). New module id `"m4"`.
- New events: `malicious_artifact_identified`, `vulnerable_dependency_identified`.
- **SAFETY: never `pickle.load` untrusted data anywhere in tests or the scanner.** The poisoned fixture is created by `pickle.dumps` (safe) and only ever *statically* analyzed. The vulnerable loader (`artifacts.py` vulnerable branch) is exercised in tests ONLY with a benign pickle.
- Do NOT change M1/M2/M3 behavior. Do NOT add the vulnerable dependency to the app's real `pyproject.toml`/`uv.lock` — it lives only in `labs/m4/requirements-vulnerable.txt`.
- Done per task: task tests pass under `uv run pytest`, `uv run ruff check .` clean, `uv run mypy halcyon` clean.

---

### Task 1: `SEC_ARTIFACT_VERIFICATION` flag
**Files:** Modify `halcyon/config.py`, `tests/test_config.py`.
- [ ] Add `sec_artifact_verification: bool` to `Settings` and `sec_artifact_verification=_flag(env, "SEC_ARTIFACT_VERIFICATION", secure),` to `load_settings`, mirroring the other flags. Add a 2-assertion test (vulnerable→False, secure→True). Full suite green; ruff+mypy clean.
- [ ] Commit `feat(m4): SEC_ARTIFACT_VERIFICATION flag`

---

### Task 2: `artifacts.py` — the flag-gated loader (the vulnerable code path)
**Files:** Create `halcyon/artifacts.py`, `tests/test_artifacts.py`.
**Interfaces:** `sha256_file(path) -> str`; `ArtifactError(Exception)`; `ALLOWED_HASHES: set[str]`; `load_artifact(path, settings) -> object`.
- [ ] **Step 1: Test** — `tests/test_artifacts.py` (uses a BENIGN pickle only):
```python
import pickle
from pathlib import Path

import pytest

from halcyon import artifacts
from halcyon.config import load_settings


def _benign_pickle(tmp_path) -> Path:
    p = tmp_path / "model.pkl"
    p.write_bytes(pickle.dumps({"weights": [1, 2, 3]}))
    return p


def test_vulnerable_loads_pickle(tmp_path):
    s = load_settings({"HALCYON_MODE": "vulnerable"})
    obj = artifacts.load_artifact(_benign_pickle(tmp_path), s)
    assert obj == {"weights": [1, 2, 3]}


def test_secure_rejects_non_safetensors(tmp_path):
    s = load_settings({"HALCYON_MODE": "secure"})
    with pytest.raises(artifacts.ArtifactError):
        artifacts.load_artifact(_benign_pickle(tmp_path), s)


def test_secure_rejects_unpinned_safetensors(tmp_path):
    s = load_settings({"HALCYON_MODE": "secure"})
    f = tmp_path / "x.safetensors"
    f.write_bytes(b"not-in-allowlist")
    with pytest.raises(artifacts.ArtifactError):
        artifacts.load_artifact(f, s)


def test_secure_accepts_pinned_safetensors(tmp_path, monkeypatch):
    s = load_settings({"HALCYON_MODE": "secure"})
    f = tmp_path / "ok.safetensors"
    f.write_bytes(b"trusted-bytes")
    monkeypatch.setattr(artifacts, "ALLOWED_HASHES", {artifacts.sha256_file(f)})
    assert artifacts.load_artifact(f, s) == b"trusted-bytes"
```
- [ ] **Step 2: Run — fails.**
- [ ] **Step 3: Implement** — `halcyon/artifacts.py`:
```python
import hashlib
import pickle  # noqa: S403 - deliberately vulnerable teaching path (vulnerable mode only)
from pathlib import Path

from halcyon.config import Settings


class ArtifactError(Exception):
    """Raised by the hardened loader when an artifact is refused."""


# Pinned sha256 allowlist of trusted safetensors artifacts (empty seed; ops adds hashes).
ALLOWED_HASHES: set[str] = set()


def sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_artifact(path: str | Path, settings: Settings) -> object:
    if settings.sec_artifact_verification:
        p = Path(path)
        if p.suffix != ".safetensors":
            raise ArtifactError(f"refused: only .safetensors permitted, got '{p.suffix}'")
        digest = sha256_file(p)
        if digest not in ALLOWED_HASHES:
            raise ArtifactError(f"refused: {digest} not in pinned allowlist")
        return p.read_bytes()  # teaching stub: a real reader would parse safetensors
    # VULNERABLE: arbitrary deserialization — loading a poisoned artifact executes code.
    with open(path, "rb") as f:
        return pickle.load(f)  # noqa: S301
```
- [ ] **Step 4: Run — passes; full suite green.** ruff+mypy clean (the `# noqa` comments keep ruff's S-rules quiet on the intentional path; if ruff isn't configured for bandit S-rules, the noqa is harmless).
- [ ] **Step 5: Commit** `feat(m4): flag-gated artifact loader (pickle vs safetensors+hashpin)`

---

### Task 3: `scan_artifact.py` — static pickle-opcode scanner
**Files:** Create `halcyon/scan_artifact.py`, `tests/test_scan_artifact.py`.
**Interfaces:** `scan(path) -> dict` returning `{"sha256": str, "dangerous": list[str], "malicious": bool}`. CLI: `python -m halcyon.scan_artifact <file>`. NEVER unpickles.
- [ ] **Step 1: Test** — `tests/test_scan_artifact.py`:
```python
import os
import pickle
from pathlib import Path

from halcyon import scan_artifact


class _Exploit:
    def __reduce__(self):
        return (os.system, ("echo pwned",))


def test_benign_pickle_is_clean(tmp_path):
    p = tmp_path / "benign.pkl"
    p.write_bytes(pickle.dumps({"a": 1}))
    result = scan_artifact.scan(p)
    assert result["malicious"] is False and result["dangerous"] == []


def test_malicious_pickle_flagged(tmp_path):
    p = tmp_path / "evil.pkl"
    p.write_bytes(pickle.dumps(_Exploit()))  # dumps does NOT execute; safe to create
    result = scan_artifact.scan(p)
    assert result["malicious"] is True
    assert any("os" in d or "REDUCE" in d for d in result["dangerous"])
    assert len(result["sha256"]) == 64
```
- [ ] **Step 2: Run — fails.**
- [ ] **Step 3: Implement** — `halcyon/scan_artifact.py`:
```python
import hashlib
import pickletools
import sys
from pathlib import Path

_DANGEROUS_MODULES = {"os", "subprocess", "sys", "builtins", "posix", "nt", "shutil",
                      "socket", "pty", "commands", "importlib"}


def scan(path: str | Path) -> dict:
    data = Path(path).read_bytes()
    dangerous: list[str] = []
    recent: list[str] = []  # recent string operands, for STACK_GLOBAL resolution
    try:
        for opcode, arg, _pos in pickletools.genops(data):
            name = opcode.name
            if name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "SHORT_BINSTRING",
                        "BINSTRING", "STRING") and isinstance(arg, str):
                recent.append(arg)
                recent[:] = recent[-2:]
            elif name == "GLOBAL" and isinstance(arg, str):
                mod = arg.split(" ")[0].split(".")[0]
                if mod in _DANGEROUS_MODULES:
                    dangerous.append(f"GLOBAL -> {arg}")
            elif name == "STACK_GLOBAL":
                mod = (recent[0] if recent else "").split(".")[0]
                if mod in _DANGEROUS_MODULES:
                    dangerous.append(f"STACK_GLOBAL -> {' '.join(recent)}")
            elif name == "REDUCE":
                dangerous.append("REDUCE (callable invocation)")
    except Exception as exc:  # noqa: BLE001 - malformed pickle is itself suspicious
        dangerous.append(f"parse error: {exc}")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "dangerous": dangerous,
        "malicious": bool(dangerous),
    }


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: python -m halcyon.scan_artifact <file>...")
        return 2
    for path in argv:
        r = scan(path)
        verdict = "MALICIOUS" if r["malicious"] else "clean"
        print(f"{path}  sha256={r['sha256']}  {verdict}")
        for d in r["dangerous"]:
            print(f"    ! {d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
```
- [ ] **Step 4: Run — passes.** ruff+mypy clean.
- [ ] **Step 5: Commit** `feat(m4): static pickle-opcode scanner`

---

### Task 4: `labs/m4/` fixtures + `m4_answers.py`
**Files:** Create `labs/m4/build_poisoned.py`, `labs/m4/artifacts/embedding_model.safetensors` (benign placeholder bytes), `labs/m4/artifacts/community_model.pkl` (poisoned, generated), `labs/m4/requirements-vulnerable.txt`, `labs/m4/README.md`, `halcyon/m4_answers.py`, `tests/test_m4_answers.py`.
- [ ] **Step 1:** `labs/m4/build_poisoned.py` — a script that writes the poisoned pickle deterministically:
```python
import os
import pickle
from pathlib import Path


class _Poisoned:
    def __reduce__(self):
        return (os.system, ("echo halcyon-m4-rce",))


def main() -> None:
    out = Path(__file__).parent / "artifacts" / "community_model.pkl"
    out.parent.mkdir(exist_ok=True)
    out.write_bytes(pickle.dumps(_Poisoned(), protocol=4))
    print("wrote", out, "sha256=", __import__("hashlib").sha256(out.read_bytes()).hexdigest())
```
Run it (`uv run python labs/m4/build_poisoned.py`), commit the generated `community_model.pkl`, and RECORD the printed sha256.
- [ ] **Step 2:** create `labs/m4/artifacts/embedding_model.safetensors` with benign placeholder bytes (e.g. `b"SAFE_PLACEHOLDER_TENSOR_DATA"`), and `labs/m4/requirements-vulnerable.txt`:
```
# Halcyon ML pipeline pins (M4 lab — audit me)
numpy==1.26.4
PyYAML==5.3.1
requests==2.31.0
```
(PyYAML 5.3.1 has CVE-2020-14343 — arbitrary code execution via `full_load`. This is the planted vulnerable dependency.)
- [ ] **Step 3:** `labs/m4/README.md` — brief participant instructions: run `python -m halcyon.scan_artifact labs/m4/artifacts/*`; run `pip-audit -r labs/m4/requirements-vulnerable.txt` (or look up the pins); submit findings via the M4 panel.
- [ ] **Step 4:** `halcyon/m4_answers.py` — server-side known-bad answers + normalizers:
```python
# Known-bad answers for M4 grading. Not exposed via any read endpoint.
POISONED_ARTIFACT_SHA256 = "<paste the sha256 printed by build_poisoned.py>"
VULNERABLE_PACKAGE = "pyyaml"  # PyYAML==5.3.1, CVE-2020-14343


def normalize_hash(value: str) -> str:
    return value.strip().lower().removeprefix("sha256:")


def normalize_package(value: str) -> str:
    return value.strip().lower().split("==")[0].split(">")[0].split("<")[0].replace("_", "-")
```
- [ ] **Step 5:** `tests/test_m4_answers.py` — assert the committed poisoned artifact's sha256 matches `POISONED_ARTIFACT_SHA256`, and normalizer behavior:
```python
from halcyon import m4_answers, scan_artifact


def test_poisoned_artifact_hash_matches_answer():
    r = scan_artifact.scan("labs/m4/artifacts/community_model.pkl")
    assert r["malicious"] is True
    assert r["sha256"] == m4_answers.POISONED_ARTIFACT_SHA256


def test_normalizers():
    assert m4_answers.normalize_package("PyYAML==5.3.1") == "pyyaml"
    assert m4_answers.normalize_hash("SHA256:ABCD") == "abcd"
```
- [ ] **Step 6:** Run — passes (this test ties the fixture to the answer). ruff+mypy clean.
- [ ] **Step 7: Commit** `feat(m4): labs/m4 audit fixtures + known-bad answers`

---

### Task 5: audit constants + M4 validator
**Files:** Modify `halcyon/audit.py`; create `halcyon/validators/m4.py`, `tests/test_validator_m4.py`; modify `halcyon/web.py` (register m4).
- [ ] Add to `audit.py`: `MALICIOUS_ARTIFACT_IDENTIFIED = "malicious_artifact_identified"`, `VULNERABLE_DEPENDENCY_IDENTIFIED = "vulnerable_dependency_identified"`.
- [ ] `halcyon/validators/m4.py` (mirror m1): MODULE="m4", core = `has_event MALICIOUS_ARTIFACT_IDENTIFIED`, stretch = `has_event VULNERABLE_DEPENDENCY_IDENTIFIED`, `progress.mark`.
- [ ] `web.py`: `from halcyon.validators import m1, m2, m3, m4`; add `"m4": m4.validate` to `_VALIDATORS`.
- [ ] `tests/test_validator_m4.py`: core-pass on artifact event; stretch-pass on dependency event; both-fail empty. Full suite green; ruff+mypy clean.
- [ ] Commit `feat(m4): M4 validator + audit constants`

---

### Task 6: web — `POST /submit/m4`
**Files:** Modify `halcyon/web.py`, `tests/test_web.py`.
**Interfaces:** `POST /submit/m4 {session_id, finding_type, value}` → checks `value` against `m4_answers` by `finding_type` (`"malicious_artifact"` → hash; `"vulnerable_dependency"` → package); on correct match records the corresponding event; returns `{"correct": bool}`.
- [ ] **Step 1: Test** — add to `tests/test_web.py`:
```python
def test_m4_submit_correct_findings():
    from halcyon import m4_answers
    client, _ = make_client({"HALCYON_MODE": "vulnerable"}, "hi")
    client.post("/submit/m4", json={"session_id": "p1", "finding_type": "malicious_artifact",
                                    "value": m4_answers.POISONED_ARTIFACT_SHA256})
    assert client.get("/validate/m4", params={"session": "p1"}).json()["core"] == "pass"
    client.post("/submit/m4", json={"session_id": "p1", "finding_type": "vulnerable_dependency",
                                    "value": "PyYAML==5.3.1"})
    assert client.get("/validate/m4", params={"session": "p1"}).json()["stretch"] == "pass"


def test_m4_submit_wrong_is_not_credited():
    client, _ = make_client({"HALCYON_MODE": "vulnerable"}, "hi")
    r = client.post("/submit/m4", json={"session_id": "p2", "finding_type": "malicious_artifact",
                                        "value": "deadbeef"})
    assert r.json()["correct"] is False
    assert client.get("/validate/m4", params={"session": "p2"}).json()["core"] == "fail"
```
- [ ] **Step 2: Run — fails.**
- [ ] **Step 3: Implement** — add a `SubmitIn(session_id: str, finding_type: str, value: str)` model and the route:
```python
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
```
- [ ] **Step 4: Run — passes; full suite green.** ruff+mypy clean.
- [ ] **Step 5: Commit** `feat(m4): /submit/m4 finding-check endpoint`

---

### Task 7: UI — M4 audit panel
**Files:** Modify `halcyon/templates/chat.html`, `tests/test_web.py`.
- [ ] Add an "M4 — Supply-chain audit" panel: short instructions (audit `labs/m4/`, run `python -m halcyon.scan_artifact`), an "Artifact sha256" input + submit button (`POST /submit/m4` `finding_type:"malicious_artifact"`), a "Vulnerable package" input + submit button (`finding_type:"vulnerable_dependency"`), and a `#m4status` line showing `correct: true/false` from the response (rendered via `textContent`). Reuse `sid`. Keep M1/M2/M3 controls intact. Add a test asserting the panel controls exist. Full suite green; ruff+mypy clean. Commit `feat(m4): supply-chain audit UI panel`.

---

### Task 8: verification + instructor-demo doc
**Files:** Create `docs/s4-e2e-checklist.md`, `docs/m4-instructor-demo.md`.
- [ ] Verify locally (no model needed): `uv run python -m halcyon.scan_artifact labs/m4/artifacts/*` flags the poisoned `.pkl` and prints its sha256; bring the app up; `POST /submit/m4` the correct artifact hash → `/validate/m4` core:pass; submit `PyYAML==5.3.1` → stretch:pass; submit wrong values → not credited. Record in `docs/s4-e2e-checklist.md`.
- [ ] `docs/m4-instructor-demo.md`: the **instructor-only** RCE demo script — in an isolated throwaway container, `HALCYON_MODE=vulnerable` + `python -c "from halcyon import artifacts, config; artifacts.load_artifact('labs/m4/artifacts/community_model.pkl', config.load_settings({'HALCYON_MODE':'vulnerable'}))"` executes the payload (prints `halcyon-m4-rce`); then show `HALCYON_MODE=secure` refuses it. Emphasize: never run this outside an isolated container. Commit `docs: S4 (M4) verification + instructor demo`.

---

## Self-Review
- Coverage: flag (T1), loader guard (T2), scanner (T3), fixtures+answers (T4), validator (T5), submit endpoint (T6), UI (T7), verification+demo (T8). ✅
- Safety: no `pickle.load` of untrusted data in tests/scanner; poisoned fixture created by `dumps`, only statically scanned; vulnerable loader tested with benign pickle only. ✅
- Determinism: submissions checked against server-side known-bad; scanner is pure static analysis. ✅
- M1/M2/M3 untouched: new module/endpoint/validator; `create_app` unchanged (no new constructor param — m4_answers is a module import). ✅
- Isolation: deliberately-vulnerable dep only in `labs/m4/requirements-vulnerable.txt`, never the app's real deps. ✅
- Risk to watch (reviewer): the sha256 in `m4_answers.py` must match the committed `community_model.pkl` (T4's test enforces this — confirm it's present and passing).
