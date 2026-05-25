# Audit trail backfill

The per-slice audit became binding with structured `Audit notes:`
commit-message blocks in commit `bfdf0e4` (2026-05-25), defined in
[CONTRIBUTING.md](../CONTRIBUTING.md) under "Substage workflow
(required)". Commits that pre-date the binding rule had their
audit work performed but did not use the structured block.

This file normalises the format retroactively. The underlying
audit was completed in the original commits; this file only
re-presents the findings in the structured per-section format so
`git log` plus this file together provide a consistent audit
trail across history.

Findings are derived verbatim from the original commit messages.
Commits are listed chronologically.

---

## `6330d4a` — docs: substage audit checklist + new-contributor onboarding tour

Created `docs/AUDIT.md` itself plus `docs/ONBOARDING.md`; cross-
linked from CONTRIBUTING.md and README.md. Not an audit pass; the
doc that defines the audit.

Audit notes:

- Cleanup: n/a (doc-only addition; no code paths touched).
- Hallucination check: n/a.
- No slop: n/a (prose).
- Parser/validator: n/a.
- Security: n/a.
- Async: n/a.
- Dependency: n/a.
- Error handling: n/a.
- Deferred: none.

---

## `4195707` — audit: apply substage audit checklist to recent commits

First pass under `docs/AUDIT.md`, retroactively covering Stage 5
slice 1 (`52a2bf7`), Stage 5 slice 2 (`6d07bf1`), and the Cowrie
removal (`3bd3120`).

Audit notes:

- Cleanup: replaced `roles_verified = 2` magic number in
  `cli/__main__.py` bridge serve with `len(LLMRole)` so the
  timeout scales automatically when Stage 8 adds EMBED. Dropped
  a dead try/finally in `tests/llm/test_client.py`.
- Hallucination check: `anglerfish/__init__.py` package docstring
  claimed the Splunk forwarder still exists (deleted in `3bd3120`);
  rewritten. `anglerfish/audit.py` "pair with Splunk HEC" pointer
  rewritten to "syslog forwarder, backup job, SIEM of choice";
  events list expanded from Stage-1 vintage (~3 entries) to the
  full current taxonomy. `credentials/storage.py:187` claimed
  dropped attempts go to Splunk - rewritten to point at the
  `lure.login_attempt` audit-log path. `models/session.py` +
  `models/__init__.py` similarly mentioned the forwarder as a
  consumer; both rewritten.
- No slop: rewrote `test_model_for_unknown_role_raises` docstring
  from "synthetic guard" hand-waving to describe what it actually
  protects (fail-loud invariant against silent new-role drift).
- Parser/validator: n/a.
- Security: `dashboard/__init__.py` DashboardState docstring
  predicted Stage 4.2 incorrectly ("forwarder-routed HTTP push");
  the actual ship was the audit-log tailer. Rewritten so future
  readers do not look for a non-existent code path.
- Async: n/a.
- Dependency: n/a.
- Error handling: n/a.
- Deferred: none.

---

## `dac107a` — audit(bridge): apply AUDIT.md to existing bridge subsystem

Retroactive cleanup over `src/anglerfish/bridge/`.

Audit notes:

- Cleanup: `bridge/server.py` hoisted `import hmac` from inside
  `_constant_time_equals` to module level (no circular concern).
  `bridge/service.py` dropped a 4-line changelog comment narrating
  removed type annotations; tightened `_record_defense_fire`
  docstring from sales prose to direct voice.
- Hallucination check: `bridge/defense.py` "OllamaClient cap"
  reference in OutputFilter.check docstring corrected to
  "LLMClient cap" (Stage 5 rename).
- No slop: reordered the severity isinstance check in
  `bridge/defense.py` to put the bool exclusion first for
  readability; expanded the manifest-read except-clause comment
  to spell out the handled cases.
- Parser/validator: no findings.
- Security: no findings.
- Async: no findings.
- Dependency: no findings.
- Error handling: added a reason to the only
  `# type: ignore[no-untyped-def]` in `bridge/server.py`
  (starlette's `dispatch` signature uses an untyped Callable for
  `call_next`).
- Deferred: none. Two findings flagged but explicitly not acted
  on (recorded in commit body): the `AIBridgeService` constructor's
  three back-to-back X-if-X-is-not-None ternaries (each has a
  distinct default factory; consolidation costs more than it
  saves), and the `bridge/server.py` docstring's audit-tailer
  parenthetical (informative, not editorialising).

---

## `97a8e79` — audit(lure): apply AUDIT.md to existing lure subsystem

Retroactive cleanup over `src/anglerfish/lure/`.

Audit notes:

- Cleanup: `lure/server.py` hoisted `hashlib` from inside
  `_password_hash_prefix`; dropped the local
  `from uuid import UUID as _UUID` that shadowed the module-level
  import. `lure/runner.py` merged two `__all__` declarations into
  one literal. `lure/session.py` added docstrings to the public
  methods (`update_cwd`, `record`, `command_count`).
  `lure/keys.py` rewrote module + `load_host_keys` docstrings to
  drop the stale "Stage 2A returns raw PEM, Stage 2B asyncssh
  server will consume" framing (both stages shipped).
  `lure/fakefs.py` hoisted two walrus-assigned mode constants
  (`_F664`, `_F444`) into the mode-constants block.
- Hallucination check: added an inline comment at the asyncssh
  `server_version` construction explaining why
  `banner_debian_version` is stripped (asyncssh requires RFC 4253
  softwareversion which forbids spaces); behaviour matches docs,
  helper is effectively dead - see TODO-4.
- No slop: `lure/bridge_client.py` renamed bare `data` in
  `_post_json` to `body` (consistent with the caller naming at
  lines 111 + 141). `lure/commands.py` renamed three uses of
  unqualified `result` to `listing`, `read_result`, and
  `dispatch_result`.
- Parser/validator: no findings.
- Security: no findings.
- Async: no findings.
- Dependency: no findings.
- Error handling: added inline comment on the `except BaseException`
  in `_write_key_bytes` explaining the rationale (Ctrl-C mid-write
  must still unlink the partial tmp file).
- Deferred: TODO-4 (lure banner Debian suffix), TODO-5 (per-IP
  limiter boundary tests).

---

## `b563cef` — audit(dashboard): apply AUDIT.md to existing dashboard subsystem

Retroactive cleanup over `src/anglerfish/dashboard/`, plus a
correction to `audit.py` missed in `4195707`.

Audit notes:

- Cleanup: `dashboard/websocket.py` dropped `nullcontext` import +
  the speculative `_ = nullcontext` "touch" hack. `dashboard/routes.py`
  hoisted `ALERT_STUBS` into top-level imports, inlined at its
  single call site, deleted the `_stubs_for_alerts` one-line
  helper. `dashboard/alerts.py` dropped the `_now` field from
  `_empty_page` (schema drift; no caller consults it); removed the
  now-unused datetime import.
- Hallucination check: `audit.py` fixed
  `bridge.scan_truncated` -> `bridge.defense_scan_truncated` in
  the event-type catalog (the emitted name was correct; the
  docstring was wrong).
- No slop: `dashboard/rate_limit.py` rewrote the inverted comment
  at line 94-96 ("Don't update the bucket on a refused attempt"
  was the opposite of what the next line did).
- Parser/validator: no findings.
- Security: no findings.
- Async: no findings.
- Dependency: no findings.
- Error handling: no findings.
- Deferred: none. Two agent-suggested refactors explicitly
  rejected with reasons in the commit body: `overrides.py` apply_*
  copy-paste loop would erase mypy strict coverage; `routes.py:292`
  duplicate kind-validation guard is intentional.

---

## `3133af6` — audit(sessions+credentials): apply AUDIT.md to existing code

Retroactive cleanup over `src/anglerfish/sessions/` and
`src/anglerfish/credentials/`. Behaviour-changing bug surfaced
here ships as the separate fix commit `23a58c0` below.

Audit notes:

- Cleanup: `sessions/store.py` hoisted `from datetime import UTC`
  from inside `_utcnow_iso()` to module level. `credentials/`
  module docstrings replaced em dashes with ASCII alternatives
  per the project doc-voice convention.
- Hallucination check: `sessions/__init__.py` docstring for
  `import_jsonl_into_store` rewritten to match post-Cowrie-removal
  reality (deprecated transition helper, not active populator).
  `sessions/migrate.py` corrected "Lines that fail Pydantic
  validation" claim to "Lines that fail JSON parsing"
  (`_iter_events` catches `json.JSONDecodeError` only).
  `credentials/__init__.py` dropped the false "optional offline-
  decrypt tool" rationale for exporting `CredentialCipher` (no
  such tool exists); replaced with the actual reason
  (`rotate_key` + test harnesses share the cipher's key derivation).
  `credentials/rotation.py` dropped the false "refuses to proceed
  when it can detect a live SQLite WAL" claim (no WAL-detection
  code anywhere); rewrote to describe the real safety mechanism
  (the CLI prompt-and-confirm-then-stop-services flow).
- No slop: `credentials/storage.py` tightened the
  "chmod is a partial no-op on Windows" filler comment to one
  direct sentence; rewrote the decryption-failure swallow comment
  to explain the scenario (mixed-key rows from a partial rotation).
- Parser/validator: TODO-6 logged for the `_scalar` helpers'
  silent-zero coercion of non-numeric scalars (in both
  `sessions/store.py` and `credentials/storage.py`). AUDIT.md
  flags it; the fix is behaviour-changing so deferred.
- Security: no findings.
- Async: no findings.
- Dependency: no findings.
- Error handling: no findings. Agent suggested adding
  "- invariant, not a runtime check" comments to every
  `# noqa: S101` line in both stores; rejected (15 of 16 instances
  are bare, bare is the codebase convention).
- Deferred: TODO-6 (silent-zero `_scalar` coercion); bug surfaced
  by the audit deferred to fix commit `23a58c0`.

---

## `23a58c0` — fix(sessions): migrate helper double-counted sessions.command_count

Surfaced by the `3133af6` audit. Shipped separately so the hygiene
diff stays reviewable. `_write_accumulator` upserted with the full
turns tuple (which set `sessions.command_count = N`) and then
looped `record_turn()` which incremented again, yielding `2 * N`.

Audit notes:

- Cleanup: n/a (fix scope only).
- Hallucination check: n/a.
- No slop: n/a.
- Parser/validator: n/a.
- Security: no new attack surface.
- Async: no findings.
- Dependency: no findings.
- Error handling: no findings.
- Deferred: none. Behaviour-fix shipped with a regression test
  that fails (`assert 6 == 3`) on the pre-fix code path.

---

## `598cf40` — audit(config+wizard): apply AUDIT.md to existing wizard subsystem

Retroactive cleanup over `src/anglerfish/wizard/`.

Audit notes:

- Cleanup: `wizard/wizard.py` hoisted
  `from anglerfish.dashboard.auth import hash_password` to
  module-level imports (was function-local; no circular concern).
  Added a reason to the
  `# type: ignore[union-attr]` for the keep-existing-hash branch.
- Hallucination check: `wizard/persistence.py` docstring previously
  claimed the file "deliberately excludes secrets" but the on-disk
  payload includes the dashboard admin password hash and the
  MaxMind licence key. Rewrote to state what is actually persisted
  and why (`--reconfigure` "blank to keep" semantics), with a
  pointer to TODO-7. `wizard/preflight.py` dropped a stale Splunk
  paragraph; added `render()` docstring. `wizard/render.py`
  trimmed a Cowrie-era port comment to one line.
  `wizard/answers.py` replaced a Cowrie/Splunk note on
  `threat_alert_webhook` with a direct description.
- No slop: same items as Cleanup above.
- Parser/validator: no findings.
- Security: TODO-7 logged for the SecretStr-vs-round-trip
  trade-off on `dashboard_admin_password_hash` and
  `maxmind_license_key`; the straightforward upgrade breaks the
  `--reconfigure` flow because `model_dump(mode="json")` masks
  SecretStr to `"**********"`.
- Async: no findings.
- Dependency: no findings.
- Error handling: no findings.
- Deferred: TODO-7 (SecretStr round-trip for wizard secret fields).

User-facing strings: `wizard/terms.py` and `wizard/__main__.py`
em dashes replaced (operator-visible surfaces only; the bulk
src/ sweep was re-scoped after the original "every em dash"
finding was too broad).

---

## `fef101f` — audit(threat+fingerprint+models): apply AUDIT.md to existing code

Retroactive cleanup over `src/anglerfish/threat/`,
`src/anglerfish/fingerprint/`, and `src/anglerfish/models/`.

Audit notes:

- Cleanup: `fingerprint/service.py` `Fingerprinter.aclose()` used
  `del self` as a placeholder; replaced with a one-line docstring.
- Hallucination check: no findings.
- No slop: same Cleanup item.
- Parser/validator: no findings.
- Security: `threat/scorer.py` persistence-attempted note (fed to
  the webhook alerter and rendered in the dashboard) had an em
  dash; replaced with a semicolon for the operator-surface tone
  rule.
- Async: `fingerprint/tor.py` `_reload_locked()` performs sync
  `stat` + `read_text` and was being called directly from async
  `_maybe_refresh` / `reload`, blocking the event loop while
  holding the asyncio.Lock. Wrapped the three call sites in
  `await asyncio.to_thread(...)`. Lock still serialises reloads;
  the loop stays responsive.
- Dependency: no findings.
- Error handling: no findings.
- Deferred: none. Models subsystem (credentials, fingerprint, geo,
  session, threat) reviewed with no findings - all frozen Pydantic
  models with `extra="forbid"` and explicit Field constraints.

---

## `8581ad3` — audit(llm+cli+audit+geo): apply AUDIT.md to remaining subsystems

Final pre-Stage-5 sweep over `src/anglerfish/llm/`,
`src/anglerfish/cli/`, `src/anglerfish/audit.py`,
`src/anglerfish/geo/`, and `src/anglerfish/config/`.

Audit notes:

- Cleanup: `cli/__main__.py` `bridge_serve()` re-imported `AuditLog`
  function-locally even though the top-of-file already imports it;
  duplicate dropped.
- Hallucination check: no findings.
- No slop: same Cleanup item.
- Parser/validator: no findings. `llm/` package reviewed - all
  frozen Pydantic models with `extra="forbid"`, narrow public API,
  explicit error hierarchy, parser at the LLM boundary validates
  response shape.
- Security: `cli/__main__.py` root Typer app help string had an
  em dash ("Anglerfish AI - AI-powered SSH honeypot.") - replaced
  with a colon. `cli/__main__.py` and `geo/fetch.py` "MaxMind
  licence key not configured" path em dashes replaced with
  semicolons (operator-visible log + CLI output).
- Async: no findings. `geo/lookup.py` already uses
  `asyncio.to_thread` for the sync `maxminddb` calls.
- Dependency: no findings.
- Error handling: `audit.py` event catalog had been brought
  current in `b563cef`; thread-safe RLock; never raises on write
  failure (logs + returns).
- Deferred: none. `cli/__main__.py` `del version` in the version
  callback left in place (Typer convention for marking a callback
  parameter intentionally unused). `config/models.py` field
  descriptions contain em dashes; left as-is - they are internal
  API docs, not rendered to operators by `anglerfish config show`
  (which dumps values, not descriptions).

---

## Stage 5 slices 3-6: `e5fd25b` through `a55b0bf`

Six slice commits shipped between the seven-batch retroactive
sweep above and the binding-rule landing in `bfdf0e4`:

- `e5fd25b` — slice 3: WarmPool
- `9ff2954` — slice 4a: `LLMClient.stream_chat()` primitive
- `5902df1` — slice 4b: bridge service + HTTP streaming, protocol v3
- `7cb6475` — slice 4c: lure consumes bridge `?stream=1`
- `1615780` — slice 5: per-session token budget
- `a55b0bf` — slice 6: structured_chat

These slices were audited en bloc in commit `1e5ccdf`
("audit(stage5): retroactive AUDIT.md pass over slices 3-6"),
which carries the structured `Audit notes:` block. Headline
findings from that audit:

- Doc hygiene: ARCHITECTURE.md sections 3.1 + 3.2 stale on
  protocol version and streaming; API_REFERENCE.md missing
  `?stream=1` + NDJSON shape + `fs_context`. Fixed inline.
- No slop: `data` -> `payload` rename in three new parsers
  (`structured_chat`, `_iter_stream_lines`, `_parse_stream_chunk`).
- Deferred: TODO-8 (bridge per-session state leaks if lure
  skips DELETE), TODO-9 (no per-chunk size cap on streaming path).

The full per-section audit notes for these slices live in the
`1e5ccdf` commit message; see `git show 1e5ccdf` for the
authoritative record.

---

## After `bfdf0e4`

Commits made on or after `bfdf0e4` (2026-05-25) include the
structured `Audit notes:` block in the commit message directly,
per [CONTRIBUTING.md](../CONTRIBUTING.md). This file does not
duplicate them; `git log --format=%B` is the source of truth from
that point forward.
