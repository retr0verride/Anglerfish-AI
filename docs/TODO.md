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

## TODO-2: systemd unit invokes `create_app` via uvicorn `--factory` (closed in pre-deploy sweep)

The pre-deploy sweep took the second option: dropped the
``uvicorn --factory`` invocation and added a first-class
``anglerfish dashboard serve`` subcommand that owns its own
uvicorn instance. This parallels the Stage 2 lure pattern (and
the just-shipped Stage 11 ``anglerfish callback serve`` pattern):
all three long-running units now follow the same shape -
``anglerfish <service> serve`` from the systemd ExecStart, settings
loaded explicitly, ValidationError surfaced as a structured
Console panel + ``typer.Exit(2)``.

Changes:

- ``src/anglerfish/cli/__main__.py``: new ``dashboard_app`` typer
  subgroup; ``dashboard serve`` command with optional
  ``--host`` / ``--port`` overrides (default to
  ``settings.dashboard.host`` / ``.port``); explicit settings
  load with the same error-handling shape as ``bridge serve``.
  ``proxy_headers=True`` preserved from the previous uvicorn
  invocation.
- ``systemd/anglerfish-dashboard.service``: ExecStart now points
  at ``/opt/anglerfish/venv/bin/anglerfish dashboard serve``;
  ``--host`` / ``--port`` flags drop out (the subcommand reads
  them from settings); ``--proxy-headers`` likewise (set inside
  the subcommand). Sandboxing primitives unchanged.
- ``tests/cli/test_dashboard_subcommand.py`` (new, 4 cases):
  the subgroup is registered + visible from ``--help``; the
  ``serve`` subcommand exposes ``--host`` + ``--port`` options;
  bad config (out-of-range port) surfaces as ``exit 2`` with
  the "Configuration error" panel (the regression test for the
  previously-broken ``--factory`` path which would have raised
  TypeError inside the worker).

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

## TODO-7: `WizardAnswers` secret fields stored as bare `str` (closed in pre-deploy sweep)

Both fields now type as ``SecretStr | None``:

- ``WizardAnswers.dashboard_admin_password_hash: SecretStr | None``
- ``WizardAnswers.maxmind_license_key: SecretStr | None``

Repr + traceback paths now show ``SecretStr('**********')``
instead of the bcrypt hash or the licence key, closing the
documented leak surface.

The round-trip regression the previous TODO entry warned about is
solved by a per-field ``@field_serializer(..., when_used="json")``
on ``WizardAnswers`` that unwraps the SecretStr to plaintext at
``model_dump(mode="json")`` time. ``save_answers`` writes the
plaintext into ``wizard.json`` (which is 0600 + root-owned in
production - the existing trust boundary); ``load_answers``
re-validates back into a SecretStr with the original value
intact. The ``--reconfigure`` "blank to keep" flow stays
functional because the loaded SecretStr round-trips with the
correct ``.get_secret_value()``.

Field-level length bounds (the previous ``min_length`` /
``max_length`` on the ``Field``) do NOT apply through SecretStr,
so a new ``@model_validator(mode="after")`` re-applies the
documented constraints (bcrypt hash in (0, 256], MaxMind key in
[8, 64]). Operator-pasted garbage that violates the bounds is
still rejected at construct time.

Callsite updates:

- ``render_env`` unwraps both SecretStrs with
  ``.get_secret_value()`` before writing the env file (the env
  file is the same 0600 trust boundary as wizard.json).
- ``prompt_for_answers`` wraps the bcrypt hash via
  ``SecretStr(hash_password(plain_password))`` and the MaxMind
  licence key via ``SecretStr(maxmind_key_raw)``; the prompt's
  default-string for re-display calls
  ``defaults.maxmind_license_key.get_secret_value()`` for that
  one purpose only.

Tests (``tests/wizard/test_persistence.py``, 3 new):

- ``test_secret_fields_round_trip_plaintext_through_save_and_load``:
  the bcrypt hash + licence key survive save/load with plaintext
  intact; the on-disk JSON does NOT contain pydantic's masked
  ``"**********"`` literal.
- ``test_secret_fields_repr_is_masked``: ``repr(answers)`` shows
  ``**********`` not the hash or key.
- ``test_secret_fields_length_bounds_enforced``: the re-applied
  length bounds reject empty / oversized inputs at construct.

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

## Pre-deploy sweep (closed 2026-05-26)

The pre-deploy sweep ran in one session after Stage 11 shipped
and closed all six deferred items in the locked order TODO-6 →
TODO-9 → TODO-8 → TODO-3 → TODO-2 → TODO-7. Each landed as its
own commit with a documented audit-notes block. Backlog is empty
as of this commit.

# Audit backlog (opened 2026-06-03)

The multi-agent security + deception audit (2026-06-03) surfaced the items
below. Unlike TODO-1..9 these are net-new findings, not Stage-2 deferrals.
They are numbered so source and commits can reference them by `TODO-N`.
None are started; severity is the audit's, not a promise of order.

## TODO-10: kernel identity is multi-sourced and inconsistent

The synthetic kernel string is hard-coded in several places with TWO
different releases, so an attacker who cross-checks them detects the
deception:

- `bridge/fallback.py:18-19` and `bridge/prompts.py:38` claim
  `6.1.0-26-amd64` (build `Debian 6.1.112-1 (2024-09-30)`).
- `lure/commands.py:202,209`, `lure/fakefs.py:237-239`, and
  `lure/fakefs.py:757` claim `6.1.0-18-amd64`
  (build `Debian 6.1.76-1 (2024-02-01)`).

`uname -r` served by the lure (6.1.0-18) disagrees with the bridge
fallback's `uname` (6.1.0-26, used during an Ollama outage) and with what
the LLM is told it is running (prompts.py → 6.1.0-26), so AI-narrated
kernel references contradict `/proc/version`. A scanner comparing
`uname -a`, `cat /proc/version`, and model-generated kernel mentions sees
more than one kernel.

Fix sketch: single-source the kernel identity (release, build string,
build date, compiler, the `/proc/version` line) into one module that all
consumers import (lure commands, fakefs, bridge fallback, the LLM prompt
context). Add a cross-source consistency test that fails if any consumer
drifts. Fold the persona overlay in: today an overlay only overrides
os-release, so persona swaps leave the kernel/uptime/uid story unchanged.

Status (2026-06-03): the kernel + uid surfaces are single-sourced in
`anglerfish/system_identity.py`. `uname` (lure + fallback), `/proc/version`,
the prompt's kernel/architecture facts, and `id` all read from it, so they
agree by construction; the fallback `uname -a` no longer emits the triple
`x86_64`, and the fallback `id` now includes `27(sudo)` to match the lure,
`/etc/group`, and the auth log. `tests/test_system_identity.py` guards drift.

Remaining under TODO-10: persona-aware identity. The single source is the
DEFAULT Debian box; personas that present a non-Debian OS (`dev-laptop` =
Pop!\_OS, `gpu-rig` / `ad-joined-workstation` = jammy) still inherit the
Debian kernel string and the prompt's "real Debian 12 server" framing, which
contradicts their os-release overlay. The synthetic clock / uptime spread
(`uptime` says 7 days in the fallback, ~14 in the fs-context hint) is
TODO-11.

## TODO-11: native date / time / session commands

The fake shell lacks (or statically fakes) `date`, `timedatectl`, `uptime`,
`w`, and `last`. On a real box these advance and agree with each other and
with boot time; static or missing output is a tell, and `last`/`w` with no
plausible session history is suspicious.

Fix sketch: implement them as deterministic synthetic commands driven by a
per-session synthetic clock and a synthetic wtmp/utmp, consistent with the
boot time and uptime the persona claims.

## TODO-12: off-box audit-log shipping

`/var/log/anglerfish/audit.jsonl` is the only tamper-evidence surface. An
attacker who roots the box can alter it before it is shipped anywhere.
install-to-disk persists it, but on-box only.

Fix sketch: an optional shipper (syslog/TLS, HTTPS, or object store) that
streams audit records off-box append-only, with backpressure and a
documented trust model. The on-box log stays the live surface; off-box is
the durable copy.

## TODO-13: in-memory counters reset on reboot

The per-IP rate limiter and per-session budgets live in memory. A reboot
(or the now-supported install-to-disk) resets them, so an attacker can
clear throttling by forcing a restart, and longitudinal per-IP counts
reset.

Fix sketch: persist the limiter and budget state to the sessions DB (now on
the durable data partition) with a periodic flush and a reload on start.

## TODO-14: --with-ollama model-pull orchestration

The ISO `--with-ollama` path installs Ollama and opens tcp/443 egress, but
nothing pulls the model, so the box boots with no model loaded. Verified:
no code calls `ollama pull`; it is only a hook comment. The egress fix is
necessary but not sufficient.

Fix sketch: either pre-pull the configured model into the image at build
time (size cost) or a first-boot oneshot that pulls it with progress and
retry. The wizard already captures the model name.

## TODO-15: curl|sh Ollama install is unpinned

The Ollama install hook uses the upstream `curl | sh` installer with no
version pin or checksum, a supply-chain and reproducibility gap.

Fix sketch: pin to a specific Ollama release (a versioned `.deb` or a
checksum-verified tarball from a pinned URL) and drop `curl | sh`.

## TODO-16: dashboard WebSocket has no Origin allow-list (stale finding, already implemented)

Resolved on inspection (2026-06-03): the defence already exists. The
2026-06-03 audit finding was stale. `dashboard/websocket.py` `_check_origin`
rejects any `/ws/events` upgrade whose `Origin` header is not in
`_allowed_origins` (the dashboard's own `http(s)://host:port` plus the
configurable `DashboardConfig.allowed_origins`, default empty = own origin
only), enforced before `accept()` with a dedicated 4403 close code; a
missing `Origin` is also rejected. An auth-cookie check follows (skipped in
open mode), and the origin check runs before it.

This shipped in the earlier dashboard audit (`b563cef`), not after. Covered
by `tests/dashboard/test_websocket_security.py` (8 cases: missing/unknown
origin rejected, default/custom origin accepted, locked-mode auth
accept/reject, logout invalidation, origin-before-auth ordering). No code
change required.

## TODO-17: ProtectProc + per-service user isolation

The services share the `anglerfish` user and do not set
`ProtectProc=invisible` / `ProcSubset=pid`, so a compromise of one service
can see the others' processes.

Fix sketch: dedicated users (or `DynamicUser`) per service plus
`ProtectProc=invisible` and `ProcSubset=pid` in the unit hardening,
re-verifying the ReadWritePaths still line up.

## TODO-18: bit-for-bit reproducible ISO

The build is pinned (container digest, dated bookworm) but not
bit-reproducible: timestamps and apt ordering vary run to run.

Fix sketch: set `SOURCE_DATE_EPOCH`, pin apt to a snapshot.debian.org
timestamp, and make the squashfs deterministic (sorted entries, fixed
mtimes). Verify two clean builds hash-match.

## TODO-19: models-surface API cosmetic tweaks

The cosmetic API / response-shape tweaks on the dashboard models surface
deferred from the 2026-06-01 code review (bucket 4, non-behavioural). See
`docs/CODE_REVIEW_2026-06-01.md` for the specific items.
