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

## Outcome (High pass)

All six recommended fixes landed test-first on `review/code-review-remediation`,
each a single green commit with an audit-notes block, plus three
verification-driven follow-ups. mypy strict + ruff clean. PR #12.

## Medium pass

The 13 Medium findings not already closed by the High pass were fixed on
`review/code-review-medium` (stacked on the High branch), test-first,
single-purpose commits. Two were owner-decision forks (resolved to
"finish the feature"): M3 fs_context wired into the prompt, M9 data_dir
made the single base for all on-disk state.

| ID | Finding | Commit |
|----|---------|--------|
| M1 | Bridge-reported cwd never applied to the lure session | `c915db8` |
| M2 | `ls -l` size 0 for files `cat` serves content for | `2fb16e4` |
| M3 | `fs_context` sent every command but discarded by the bridge | `2566b54` |
| M4 | Oversized regex capture raised uncaught ValidationError | `cf20795` |
| M5 | systemctl unit names truncated at `-`/`.` | `cf20795` |
| M6 | Intent/embed generator token budgets unreachable from config | `4caf42e` |
| M7 | `/api/clusters` N+1 (2 queries per node) | `b2bbb2b` |
| M8 | Wizard accepted a remote-Ollama config the runtime rejects | `072ab0f` |
| M9 | `data_dir` half-wired base dir | `4b61b61` |
| M10 | Literal membership sets hand-duplicated in the tailer | `654318d` |
| M11 | Callback factory-owned-reader lifespan untested | (M11-M13) |
| M12 | HoneytokensConfig enabled-requires-callback invariant untested | (M11-M13) |
| M13 | `models/embedding.py` had no co-located test | (M11-M13) |

Full suite after both passes: 2051 passed, 1 skipped, 93.6% coverage;
bare mypy (incl. tests) + ruff clean. The ~69 Low findings remain
catalogued in [`CODE_REVIEW_2026-06-01.md`](CODE_REVIEW_2026-06-01.md) for
a later pass.

## Owner decisions

- **R5 static honeytokens.** _Decision: retire the half-feature for this
  pass (delete the dead read path, the unused `static_base_paths` config
  field, and the docstrings that claim it ships). A real static-base
  capability returns later as its own design-doc'd stage, with the
  attribution model (shared tokens dilute per-session correlation) and
  the static-vs-per-session path-conflict resolved first._

## Low pass

The ~69 Low findings were first reconciled against current `main` (both
prior passes merged) by parallel verification readers, so already-closed
items are not re-touched.

### Already closed by the High/Medium passes

systemctl unit truncation (M5), oversized regex capture (M4), intent/embed
token caps (M6), `data_dir` rebase (M9), tailer literal sets (M10), bridge
`cwd` consumption (M1), threat cross-command negative test (R2), callback
production-lifespan test (M11), `HoneytokensConfig` enabled-requires-callback
test (M12), `models/embedding.py` co-located test (M13), rotation
`sqlite3.Error`/`OSError` branch tests, geo `_MAX_BYTES` + HTTP-error tests
(R4). The HASSH non-ASCII path has a test but only asserts length/hex.

### Open buckets (worked in risk order)

**Bucket 0 - cleanup**

| ID | Finding | Status |
|----|---------|--------|
| L0 | Stray `.intel_tests.txt` artifact committed by accident | **closed** `cf32871` |

**Bucket 1 - behaviour/fidelity** (all test-first)

| ID | Finding | File | Status |
|----|---------|------|--------|
| B1 | Wasting jitter identical per chunk (fixed cadence) | `bridge/strategies/*` | **closed** `0bdb313` |
| B2 | `cd -` / `~user` produced `<cwd>/-`, `<cwd>/~user` | `bridge/service.py` | **closed** `d0f5fca` |
| B3 | `structured_chat` stashed bad output only on ValidationError | `llm/client.py` | **closed** `f3b7a60` |
| B4 | `_wasting_stats` scanned the whole log (continue vs break) | `dashboard/health.py` | **closed** `89cae7f` |
| B5 | `/api/threats` advertised 500 but facade caps at 200 | `dashboard/routes.py` | **closed** `97e9cda` |
| B6 | `_suppress_get_nowait` convoluted backpressure helper | `dashboard/state.py` | **closed** `971ab23` |
| B7 | Username trim inconsistent across auth records | `lure/server.py` | **closed** `a4c4288` |
| B8 | `ls -l` hardcoded the date, ignored `FakeEntry.mtime` | `lure/commands.py` | **closed** `84cd502` |
| B9 | `FetchResult.bytes_written` reported compressed size | `geo/fetch.py` | **closed** `b267faf` |
| B10 | Callback reject path reflected unescaped input into XML | `callback/routes.py` | **closed** `8975f58` |
| B11 | Audit `ts` stamped outside the lock + reserved-key clobber | `audit.py` | **closed** `9813948` |

B10 keeps the redundant `request_path` audit field (rendered by the
dashboard) with a comment. B11 also closed the audit concurrency / fsync /
reserved-key test gaps.

_Dead-code, duplication/drift, docstring-drift, and test-gap buckets land
below as they complete._

## Process

Test-first per fix, single-purpose commit, green at commit, audit-notes
block. The Highs (R1, R2, R3, R4a) are re-verified by an independent
adversarial pass before closure. CI watched after push. Low-pass dead-code
deletions vs. deliberate-extension-point markers are an owner decision,
captured under Owner decisions.
