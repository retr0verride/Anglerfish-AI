# TODO log

Numbered, append-only log of deferred work that source code references
by `TODO-N`. Every `TODO-N` mentioned in a `NotImplementedError`,
comment, or doc must have an entry here. The companion test in
`tests/docs/test_todo_log.py` grep-checks the repo and fails the build
if a reference points at a missing number.

When closing an item: keep the number but mark it `(closed in <commit>)`.
Do not renumber; references in old commits would break.

## TODO-1: HTTP/HTTPS lure listener

`src/anglerfish/lure/http.py` ships as a `NotImplementedError` stub in
Stage 2A. The config field `ANGLERFISH_LURE__HTTP_LURE_ENABLED` exists
and the wizard prompts for it, but enabling the flag raises at startup
with a pointer back here.

The full design lives in a future stage; sketch only:

- Listener built on `aiohttp.web` to match the asyncssh lure's async
  shape.
- Serves a synthetic Apache or nginx-fronted PHP webapp with a small
  set of vulnerable-looking endpoints (CGI scripts, `/.env`,
  `/admin/login.php`, exposed `phpMyAdmin`).
- Routes attacker request bodies through the same `AIBridgeService`
  the SSH lure uses, with a separate prompt template for HTTP request
  context.
- Captures: source IP, request method + path, headers, body, JA3 if
  the listener is HTTPS.
- Per-IP rate limit and bait-NIC binding mirror the SSH lure.

Owner: TBD. Not on the active roadmap yet.

## TODO-2: systemd unit invokes `create_app` via uvicorn `--factory`

`systemd/anglerfish-dashboard.service` (or the equivalent invocation
of `uvicorn anglerfish.dashboard:create_app --factory`) cannot work
as written: `create_app` requires a positional `settings` argument
and uvicorn's `--factory` mode calls the factory with no arguments.
Production dashboard startup is broken on a clean install.

Two viable fixes:

- Add a zero-arg wrapper, e.g. `anglerfish.dashboard.uvicorn_factory`,
  that calls `load_settings()` then `create_app(settings)`. Update
  the systemd unit to point at the wrapper.
- Drop `--factory` and have the systemd unit run a small
  `anglerfish dashboard serve` subcommand that owns its own uvicorn
  instance (parallels how the lure already runs via
  `anglerfish lure serve`).

The second option is more consistent with the Stage 2 lure pattern
and surfaces config errors earlier. Pre-existing as of Stage 4; flagged
during the Stage 4 scoped re-review.

Owner: TBD. Verify the actual systemd unit text before picking a fix.

## TODO-3: first-class `anglerfish-lure.service` systemd unit (closed in pre-deploy sweep)

``systemd/anglerfish-lure.service`` shipped with the same
sandboxing primitives as the bridge unit:
``ProtectSystem=strict``, ``NoNewPrivileges``, ``RestrictNamespaces``,
``MemoryDenyWriteExecute``, ``SystemCallFilter=@system-service`` with
``SystemCallErrorNumber=EPERM``, ``ProtectKernel*``, ``LockPersonality``,
``RestrictSUIDSGID``, etc. ``CapabilityBoundingSet`` +
``AmbientCapabilities`` grant ``CAP_NET_BIND_SERVICE`` unconditionally
because operators may rebind the lure to standard SSH (port 22)
post-wizard via ``ANGLERFISH_LURE__LISTEN_PORT``; the default 2222
does not need it but granting unconditionally avoids a fail-to-bind
surprise after a port swap. ``ReadWritePaths`` includes
``/var/lib/anglerfish`` (for ``lure-keys/`` host-key generation) and
``/var/log/anglerfish`` (for audit-log appends).

Ordering: ``After=anglerfish-bridge.service`` +
``Requires=anglerfish-bridge.service`` since the lure forwards every
command to the bridge HTTP API; a bridge restart cascades to a lure
restart automatically.

ISO build wiring: ``iso/config/hooks/normal/0050-systemd-units.hook.chroot``
installs + enables the lure unit alongside bridge + dashboard, and
pre-creates ``/var/lib/anglerfish/lure-keys`` (mode 0700, owned by
``anglerfish``) so ``ensure_host_keys`` succeeds inside
``ProtectSystem=strict``. ``systemd/README.md`` + ``docs/RUNBOOK.md``
service tables list the new unit.

The unit reads bait-NIC listen host from
``ANGLERFISH_LURE__LISTEN_HOST`` in the env file (the wizard
populates it for static configs; DHCP configs leave it commented
and the operator fills the lease IP post-boot per the existing
runbook).

## TODO-4: lure SSH banner — Debian suffix never reaches the wire (closed in audit(stage9) sweep)

`src/anglerfish/lure/banner.py` exported `debian_banner()` which
built a full SSH identification string of the form
``SSH-2.0-OpenSSH_X.Yp1 Debian-Z+debWuV``. The Stage 2 design intent
(and the `banner_openssh_version` + `banner_debian_version` config
fields) was that the lure emit this full banner so the fingerprint
matched a recent Debian stable.

The actual call site stripped both the ``SSH-2.0-`` prefix
(asyncssh prepends it automatically) AND the ``Debian-...`` suffix
via ``.split(" ", 1)[0]``. The split existed because asyncssh's
``server_version`` parameter accepts only RFC 4253's
``softwareversion`` token, which forbids spaces. The Debian suffix
would have had to go in the optional ``comments`` field of the SSH
identification line, which asyncssh does not expose as a separate
parameter.

**Resolution**: chose the third option from the original three —
accept the limitation, delete the helper, drop the
``banner_debian_version`` config field, and update THREAT_MODEL to
reflect that only the OpenSSH version varies. Patching asyncssh
upstream or monkey-patching its banner generation were rejected as
fragile / upstream-coordination heavy for a fingerprint that real
attackers do not weigh heavily.

Files touched: `src/anglerfish/lure/banner.py` (deleted),
`tests/lure/test_banner.py` (deleted),
`src/anglerfish/lure/config.py` (dropped field),
`src/anglerfish/lure/server.py` (simplified banner construction),
`src/anglerfish/lure/__init__.py` (dropped re-export hint),
`docs/THREAT_MODEL.md` (updated fingerprint row).

## TODO-5: per-IP limiter explicit boundary tests (closed in audit(stage9) sweep)

`tests/lure/test_per_ip_limiter.py` lacked AUDIT.md's "boundary
conditions tested" coverage. Three test cases added in the closing
commit pin the documented behaviour:

- `test_empty_source_ip_treated_as_valid_distinct_key`: empty +
  whitespace IPs are separate buckets; the limiter does not (and
  should not) special-case them.
- `test_exact_edge_transition_at_max_concurrent`: the reject lands
  precisely at `concurrent == max_concurrent` (the predicate is
  `>= max` BEFORE the bump, so max → max + 1 admits would fire if
  the check moved by one).
- `test_same_tick_rapid_fire_does_not_double_count`: N admits at
  identical `now` count exactly N against the rpm window; the
  N+1th rejects on per_ip_rpm.

Test-only addition; no production code touched.

## TODO-6: `_scalar` helpers silently coerce non-numeric to 0 (closed in pre-deploy sweep)

The two ``_scalar`` helpers
(``SessionStore._scalar`` + ``CredentialStore._scalar``) now raise
``TypeError("_scalar expected numeric result, got <type> from SQL: <sql>")``
on the non-numeric path instead of returning 0 silently. Schema
corruption or a caller that gained a non-numeric column without
updating its callsite surfaces loudly. The ``row is None`` +
``row[0] is None`` paths still return 0 (legitimate empty-result
handling for ``SUM`` over an empty table and the like).

Both stores grew a focused regression test (``test_scalar_helper_
raises_typeerror_on_non_numeric_result``) that crosses the private
boundary deliberately - the defensive branch is otherwise only
reachable via a deliberately-non-numeric query, which no production
caller emits.

## TODO-7: `WizardAnswers` secret fields stored as bare `str`

`src/anglerfish/wizard/answers.py` declares both
``dashboard_admin_password_hash`` and ``maxmind_license_key`` as
``str | None``. Both are credentials and should ideally be
``SecretStr | None`` so they do not leak in tracebacks or repr
output.

The straightforward SecretStr upgrade breaks the persistence
round-trip:

- ``save_answers`` calls ``model_dump(mode="json")`` which by
  default serialises ``SecretStr`` as the literal string
  ``"**********"``.
- ``load_answers`` then validates the loaded payload back into a
  ``SecretStr`` whose ``.get_secret_value()`` returns
  ``"**********"``.
- The ``--reconfigure`` "blank to keep the previously-configured
  password" flow (wizard.py:340) depends on the saved hash
  round-tripping intact; the SecretStr default would silently
  replace it with the masked string.

Two viable fixes (both deferred):

- Custom ``@model_serializer`` on ``WizardAnswers`` that unwraps
  SecretStr fields to plaintext for the on-disk JSON (the file is
  already 0600 / trusted operator-only). This makes the SecretStr
  type cosmetic but preserves the repr-leak protection.
- Move secret-bearing fields out of ``WizardAnswers`` entirely so
  they live only in transient memory during the prompt + render
  flow and are never persisted; the wizard would prompt for the
  password every ``--reconfigure`` rather than offering "blank to
  keep".

Current protection: ``wizard.json`` is written 0600 in
``persistence.save_answers``, no code path logs the answers object
beyond the file path (verified during the Stage 5 audit sweep).
Surfaced during the Stage 5 retroactive audit sweep of the
config and wizard subsystems. Owner: TBD.

## TODO-8: bridge per-session state leaks if lure skips DELETE (closed in pre-deploy sweep)

Both the service-side per-session dicts
(``_budgets``, ``_last_clarification``, ``_wasted_ms``,
``_latest_threat``, ``_honeytoken_placed_for``,
``_source_ip_by_session``) and the HTTP server's
``sessions: dict[UUID, SessionContext]`` map are now drained by an
idle-timeout sweep mirroring the rate limiter's
``bucket_idle_eviction_s`` pattern:

- ``AIBridgeService._session_last_activity`` tracks the monotonic
  timestamp of each session's most-recent per-session API call.
- ``AIBridgeService.record_session_activity(session_id)`` is called
  by the HTTP server on every ``POST /api/v1/session`` and
  ``POST /api/v1/session/{id}/command`` request.
- ``AIBridgeService.evict_idle_sessions() -> list[UUID]`` drops
  every per-session dict entry whose timestamp is older than
  ``settings.bridge.session_idle_eviction_s`` (default 300s)
  and returns the evicted ids; the HTTP server drops the
  matching ``sessions`` map entries in lock-step.
- The eviction runs piggybacked on every per-command request so
  the cost is amortised across normal traffic - no background
  task, no extra IPC.

Default 300s matches the lure keepalive (3 missed * 60s = 180s)
plus a comfortable margin; operators with long-running interactive
engagements raise via ``ANGLERFISH_BRIDGE__SESSION_IDLE_EVICTION_S``.

Tests cover: per-session dict drain when a session ages past the
cutoff, live sessions surviving when others go stale,
``end_session_budget`` cleaning up the new activity timestamp, and
the integration path where a stale session returns 404 on the
next command request.

## TODO-9: per-chunk size cap on the bridge streaming response (closed in pre-deploy sweep)

Two enforcement layers landed in the pre-deploy sweep:

1. **Per-chunk cap** (``ollama.max_chunk_chars``, default 4096,
   max 65536). ``LLMClient._iter_stream_lines`` raises
   ``OllamaUnavailableError`` on any NDJSON chunk whose ``delta``
   exceeds the cap; the stream aborts cleanly before the chunk
   reflects to the lure terminal. The cap MUST be <=
   ``ollama.max_response_chars`` (a per-chunk cap above the
   whole-stream cap would let one chunk smuggle more bytes than
   the stream allows); ``AnglerfishSettings._validate_*`` enforces
   the invariant at config-load time.

2. **Accumulator bound** in ``AIBridgeService.handle_command_stream``:
   tracks the running character total and aborts the stream the
   first time the projected total exceeds
   ``ollama.max_response_chars``. The over-cap chunk is NEVER
   appended to the accumulator and NEVER yielded to the lure -
   the session record matches what shipped. Catches the N-small-
   chunks-summing-over-cap variant the per-chunk cap cannot see.

Tests:

- ``tests/llm/test_streaming.py``: oversized chunk raises with
  matching message; chunk at exactly the cap passes through
  (the abort is strictly greater).
- ``tests/config/test_settings.py``: chunk cap above response cap
  rejected at validation; chunk cap equal to response cap
  accepted.
- ``tests/bridge/test_service.py``: accumulator aborts after the
  projected total exceeds the cap, the over-cap chunk does NOT
  appear in the session record.

## Pre-deploy sweep

The pre-deploy sweep (kicked off 2026-05-26 after Stage 11
shipped) closes TODO-2, TODO-3, TODO-6, TODO-7, TODO-8, TODO-9.
TODO-6 closed first; the rest land sequentially.
