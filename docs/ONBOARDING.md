# Anglerfish AI — onboarding

A 30-minute tour for a new contributor. After this you should know
where the code lives, how to run the gates, and which conventions
the project enforces beyond what the linters catch.

## 0. Get the repo running (10 min)

```bash
git clone https://github.com/retr0verride/Anglerfish-AI.git
cd Anglerfish-AI

python3.13 -m venv .venv
source .venv/bin/activate          # PowerShell: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pre-commit install --install-hooks

ruff check .
ruff format --check .
mypy
pytest
```

Python 3.11+ is required (3.13 is what CI runs against). Linux is the
production runtime. macOS and Windows are supported for development;
some integration tests are skipped on Windows where they need POSIX
signal plumbing.

If `pytest` exits non-zero on a clean clone, that's a bug — file it.
Every commit on `main` passes the full gate set.

## 1. Read these four docs in this order (10 min)

| Doc | What you get |
|---|---|
| [`README.md`](../README.md) | What Anglerfish is, why it exists, the two-NIC architecture in one diagram |
| [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) | Module-by-module tour, trust boundaries, the persistence layout |
| [`docs/ROADMAP.md`](ROADMAP.md) | Every stage, what's shipped, what's queued, the dependency graph |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | Gates, PR rules, the substage audit checklist |

The first three are reference; `CONTRIBUTING.md` is procedural. After
those you have enough context to understand any single source file
without reading every other file first.

## 2. Look at one design doc end to end (5 min)

Pick [`docs/design/STAGE_4_session_store.md`](design/STAGE_4_session_store.md).
It is the most representative example of how this project specs work:
problem statement, locked decisions, interface sketch, failure modes,
test plan, non-goals. Every shipped stage has one. New work follows
the same shape (the [STAGE_4_2 doc](design/STAGE_4_2_audit_tailer.md)
shows the same pattern for a substage).

If you are about to start non-trivial work, you write one of these
first, get a review, commit it, then implement against it. This is
the project's spec-before-code discipline.

## 3. Conventions the linters don't enforce (5 min)

These are the project-specific rules that take a day or two to absorb
from PR review. Knowing them up front saves the round trips.

**Stage numbering.** Work is organised into numbered stages (Stage 1
through Stage 13 per the roadmap). A stage that ships in multiple
slices uses `2A`, `2B`, `2C` (parallel slices) or `4.1`, `4.2`
(follow-up substages). Commit messages and docstrings reference
these numbers; the roadmap is the index.

**Substage audit.** Before committing any slice, run the checklist
in [`docs/AUDIT.md`](AUDIT.md) over the diff. It catches the things
ruff and mypy can't: invented interfaces, hallucinated behaviour,
filler comments, vacuous tests, sentinel-vs-`None` confusion, the
usual rope every contributor hangs themselves with at some point.

**Doc voice.** Direct. No em dashes. No hedging like "this method
attempts to..." or "This function tries to...". No editorialising
phrases ("opinionated about quality", "first-class", "out of the
box"). Match the existing style in [RUNBOOK](RUNBOOK.md) or
[ARCHITECTURE](ARCHITECTURE.md); if your prose reads like a marketing
page, it gets rewritten before merge.

**Audit-event taxonomy.** Every operator-relevant event writes a JSON
line to `/var/log/anglerfish/audit.jsonl` via `AuditLog.record(
event_type, **fields)`. Event types are dot-namespaced:
`lure.session_opened`, `bridge.defense_fired`, `dashboard.login_failure`,
`credentials.key_rotated`. New events follow the pattern
`<subsystem>.<verb>_<noun>` and get added to whatever surface
documents them (RUNBOOK for ops, THREAT_MODEL for adversary-relevant,
the design doc for new features).

**Async fixtures.** Most dashboard / sessions tests pull in an async
fixture chain: `session_store` (tmp-path SQLite) → `dashboard_state`
(wraps the store) → `client` (FastAPI TestClient). The fixtures live
in `tests/conftest.py`; copying their usage from any existing test
is the fastest way to start writing new ones.

**Single-purpose commits.** Each commit does one thing. Bug fix? Bug
fix. Refactor? Refactor. New feature? New feature. Don't mix. If you
catch unrelated cleanup while doing real work, that's a follow-up
commit. The Cowrie removal in 2026-05 is an example of a clean
single-purpose commit (`git show 3bd3120`); it touched 93 files but
every one of them was the same deletion concern.

**No backwards-compat hacks once a release ships.** Deprecation
windows exist (the Cowrie shim ran for the Stage 2 deprecation
window before being deleted), but once the window closes the
backwards-compat code goes. No silent fallbacks, no
`if hasattr(...)` guards for removed surfaces.

## What you do NOT need to read on day one

* The full bridge defense layer ([`src/anglerfish/bridge/defense.py`](../src/anglerfish/bridge/defense.py)
  + [`defense_patterns.py`](../src/anglerfish/bridge/defense_patterns.py)) — read when you touch it
* The threat-engine techniques ([`src/anglerfish/threat/techniques.py`](../src/anglerfish/threat/techniques.py))
  — read when you touch it
* Every design doc — read the one for the stage you are working on,
  reference the others as dependencies dictate
* The 116-file Stage 1 corpus ([`tests/llm_defense/corpus/`](../tests/llm_defense/corpus/))
  — this is the security regression suite; useful context but not
  required for most contributions

## When you are stuck

* `docs/RUNBOOK.md` covers day-2 operations
* `docs/THREAT_MODEL.md` covers what the project assumes about adversaries
* `docs/TODO.md` is the numbered log of deferred work (`TODO-N` references in code resolve here)
* The roadmap dependency graph in `docs/ROADMAP.md` shows which stages must land before others

If a doc disagrees with the code, the code is current and the doc is
stale — open a PR fixing the doc. Drift is a bug.
