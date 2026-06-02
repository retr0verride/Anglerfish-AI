# Code-review remediation ledger

Tracks the fixes from the 2026-06-01 whole-project code review
([`CODE_REVIEW_2026-06-01.md`](CODE_REVIEW_2026-06-01.md)) through to
closure. This pass implements the review's "Recommended next actions"
(the four High correctness bugs plus the rotation data-loss item); the
remaining Medium/Low findings stay catalogued in the review doc.

Each fix lands as its own commit on `review/code-review-remediation`,
test-first (a regression test that fails before and passes after), green
at commit, with an AUDIT.md-style notes block. High fixes are
independently re-verified before they are marked closed.

## Ledger

| ID | Finding | Sev | File | Status |
|----|---------|-----|------|--------|
| R1 | Commands dropped after dashboard restart (positional turn-diff vs empty post-restart accumulator) | high | `dashboard/audit_tailer.py` / `dashboard/state.py` | **closed** `28808bb` |
| R2a | `argument_patterns` match across unrelated command heads (false persistence/discovery hits) | high | `threat/techniques.py` | **closed** `94836a1` |
| R2b | T1098 flips `persistence_attempted` on read-only credential-file access | high | `threat/techniques.py` | **closed** `94836a1` |
| R3 | `stream_chat` holds the per-session budget lock across a caller-controlled loop (deadlock on reuse) | high | `llm/client.py` | **closed** `582a122` |
| R4a | `fetch_geolite_databases` lets httpx/parse errors escape its FetchError-only contract | high | `geo/fetch.py` | **closed** `44f716f` |
| R4b | `GeoLookup.lookup()` catch too narrow for its "never raises" contract (corrupt MMDB) | medium | `geo/lookup.py` | **closed** `44f716f` |
| R5 | Static-base honeytoken half-feature (read path + config field + docstrings, no producer) | high | `honeytokens/`, `config/models.py`, `sessions/` | **retired** `2501e3e` |
| R6 | Rotation leaves stale WAL sidecars that revert the new DB after an unclean shutdown | medium | `credentials/rotation.py` | **closed** `ffb8f36` |

## Adversarial verification + follow-ups

The High fixes were independently re-verified by adversarial reviewers
(one per fix, prompted to refute). R3 held clean. The pass found a real
gap in three and each was closed with a follow-up commit:

| Fix | Gap found | Follow-up |
|-----|-----------|-----------|
| R1 | rehydrate duplicated a turn on the crash-recovery replay path (offset rewind over an already-recorded line) | `d615137` idempotent replay guard |
| R2b | T1098 stopped matching `cp`/`mv`/`install`/`dd` writes to credential files (caught pre-fix) | `6328889` destination-anchored verbs |
| R4 | `tarfile.ReadError`/`OSError` still escaped FetchError-only; `ValidationError` still escaped lookup never-raises | `b9c1484` wrap extract/install + `_build_record` |

## Outcome

All six recommended fixes landed test-first on `review/code-review-remediation`,
each a single green commit with an audit-notes block, plus three
verification-driven follow-ups. Full suite: 2028 passed, 1 skipped,
93.6% coverage; mypy strict + ruff clean. The remaining Medium/Low
findings from the review stay catalogued in
[`CODE_REVIEW_2026-06-01.md`](CODE_REVIEW_2026-06-01.md) for a later pass.

## Owner decisions

- **R5 static honeytokens.** _Decision: retire the half-feature for this
  pass (delete the dead read path, the unused `static_base_paths` config
  field, and the docstrings that claim it ships). A real static-base
  capability returns later as its own design-doc'd stage, with the
  attribution model (shared tokens dilute per-session correlation) and
  the static-vs-per-session path-conflict resolved first._

## Process

Test-first per fix, single-purpose commit, green at commit, audit-notes
block. The Highs (R1, R2, R3, R4a) are re-verified by an independent
adversarial pass before closure. CI watched after push.
