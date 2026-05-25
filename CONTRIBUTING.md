# Contributing to Anglerfish AI

Thanks for considering a contribution. Anglerfish AI is a defensive
security tool that runs in adversarial conditions, so we're strict about
quality. The rules are short.

New to the repo? Start with [docs/ONBOARDING.md](docs/ONBOARDING.md) —
it walks you through the first 30 minutes (clone, gates, the four
docs to read, the conventions the linters don't catch).

## Quick start

```bash
git clone https://github.com/retr0verride/Anglerfish-AI.git
cd anglerfish-ai

python3.13 -m venv .venv
source .venv/bin/activate           # PowerShell: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pre-commit install --install-hooks
```

Python 3.11+ is required; 3.13 is what CI runs against by default.
Linux is the supported runtime target. macOS and Windows are supported
for development.

## Quality gates

Every commit must pass:

| Gate | Command |
|---|---|
| Lint | `ruff check .` |
| Format | `ruff format --check .` |
| Types | `mypy` |

Every push must additionally pass:

| Gate | Command |
|---|---|
| Tests + 90 % coverage | `pytest` |
| Dependency CVE scan | `pip-audit --skip-editable --strict` |
| Static security | `bandit -r src/anglerfish/ -c pyproject.toml` |

`pre-commit` enforces the commit-time gates locally. `pre-commit run --hook-stage pre-push` runs the push-time set. CI re-runs everything on pull requests and on `main`.

## Substage workflow (required)

Every slice commit, audit sweep, fix, or refactor follows the same five steps. The order matters: the audit is step 2, the gates are step 4. Gates do not substitute for the audit.

1. **Implement** the slice plus tests.
2. **Audit** the diff against [docs/AUDIT.md](docs/AUDIT.md). Walk every section; "no findings" is a valid result and must be stated per section.
3. **Apply** any cleanup inline (behaviour-preserving only). Behaviour-changing findings are logged as a new `TODO-N` in [docs/TODO.md](docs/TODO.md) and deferred.
4. **Gates**: `ruff check`, `ruff format --check`, `mypy --strict`, `pytest` (coverage stays at 90 %+).
5. **Commit** with an `Audit notes:` block at the end of the message:

```text
Audit notes:
- Cleanup: <one line per finding, or "no findings">
- Hallucination check: <verified X against Y, or "no findings">
- No slop: <findings or "no findings">
- Parser/validator: <findings or "no findings">
- Security: <findings or "no findings">
- Async: <findings or "no findings">
- Dependency: <findings or "no findings">
- Error handling: <findings or "no findings">
- Deferred: TODO-N (one-line description), or "none"
```

Slices without an `Audit notes:` block are reworked into a new commit, not amended. Quoting the gates is not a substitute. If a section truly does not apply (no new parsers, no new async code), say "n/a" with one sentence why.

## Branch + commit style

- `main` is always shippable. CI is required to merge.
- Branches: `feat/...`, `fix/...`, `docs/...`, `chore/...`.
- Conventional commits: `feat(bridge): add rate limiter`, `fix(lure): handle subsystem refusal`. Renovate uses these for changelog generation.

## Pull requests

The [PR template](.github/pull_request_template.md) enumerates the
checklist. Three rules deserve special attention:

1. **Strict typing.** Every new function carries a complete signature.
   `# type: ignore` is permitted only with an error code and a one-line
   reason. The `warn_unused_ignores` setting catches drift.

2. **No placeholder code.** New modules ship a real implementation with
   tests, or they don't ship. There is no `# TODO` left in production
   paths.

3. **Security-critical changes need a threat-model note** in the PR
   body. The template has the prompt. Reviewers will not merge without
   it for the listed surfaces (bridge, lure, credentials, sessions,
   wizard, firewall, systemd).

## Adding a runtime dependency

- Pin a sensible upper bound (`<major+1` or `<next-minor` if the library
  is pre-1.0).
- Add the rationale to the PR body. We've consciously kept the runtime
  dependency set small.
- If the dependency is optional for a single subsystem, put it in
  `[project.optional-dependencies]` under that subsystem's key.

## Tests

Tests live next to the subsystem they cover. Run a single subsystem's
tests with `pytest tests/<subsystem>/`. Coverage is enforced globally;
trivial getters can be covered by `tests/test_properties.py` rather than
inflated subsystem-specific tests.

## Security disclosures

See [SECURITY.md](SECURITY.md). **Do not** open a public issue for a
suspected vulnerability.

## Honest disclosure

Anglerfish AI is architected by a human and implemented with assistance
from Claude Code (Anthropic). Every PR is held to the same gates
regardless of authorship; the gates decide what merges, not the
assistant's confidence.
