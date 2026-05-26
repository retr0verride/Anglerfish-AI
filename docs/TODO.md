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

## TODO-3: first-class `anglerfish-lure.service` systemd unit

The native SSH lure has no systemd unit in this tree. Stage 2 shipped
the lure as a CLI subcommand (`anglerfish lure serve`) and the ISO
build was never updated to enable it; the only auto-started bait-NIC
unit was `cowrie.service`, which the 2026-05 Cowrie removal deleted.
Production deployments need a proper unit:

- `systemd/anglerfish-lure.service` with the same sandboxing primitives
  as `anglerfish-bridge.service` (ProtectSystem=strict, SystemCallFilter,
  restricted capability bounding set; `CAP_NET_BIND_SERVICE` only if the
  lure listens below 1024).
- `iso/config/hooks/normal/0050-systemd-units.hook.chroot` installs +
  enables the unit alongside bridge / dashboard.
- The unit's `Environment=ANGLERFISH_LURE__LISTEN_HOST=...` must be
  populated from the wizard's rendered bait-NIC IP — either via a
  drop-in or by sourcing the env file (which already has
  `ANGLERFISH_LURE__*`).

Owner: TBD. Surfaced during the Cowrie removal; without this, every
deployment that runs the bait NIC needs a hand-rolled systemd unit.

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

## TODO-6: `_scalar` helpers silently coerce non-numeric to 0

`src/anglerfish/sessions/store.py::SessionStore._scalar` (line ~507)
and `src/anglerfish/credentials/storage.py::CredentialStore._scalar`
(line ~321) both run SQL ``COUNT(*)`` / ``SUM(...)`` style queries
and return ``int(value) if isinstance(value, (int, float)) else 0``.

The ``else 0`` clause cannot fire today: COUNT and SUM return
numeric types on every backend SQLite supports. The defensive
fallback masks a class of bug that would otherwise indicate schema
corruption or a query that was changed to return a non-numeric
column without updating the caller.

AUDIT.md "Parser-Validator -> Validation" calls out "no silent
truncation, no bare except". A correct fix raises a typed exception
(``TypeError(f"expected numeric scalar, got {type(value).__name__}")``)
on the non-numeric path. Risk: any caller relying on the silent-zero
behaviour for schema-changed columns breaks. Audit pass declined to
make the behaviour change inline; logged here for a follow-up.

Owner: TBD. Surfaced during the Stage 5 retroactive audit sweep of
the sessions + credentials subsystems.

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

## TODO-8: bridge per-session state leaks if lure skips DELETE

`AIBridgeService._budgets` (Stage 5 slice 5) and the existing
`bridge.server.sessions` dict are both populated at session open and
drained by the `DELETE /api/v1/session/{id}` endpoint. An attacker
who hangs up without a clean session-close (the lure's normal
behaviour on TCP reset is to send DELETE, but failures swallow) or
a bridge restart leaves entries behind:

- ``sessions`` grows by one ``SessionContext`` per orphaned session
  (~1 KB plus the per-session history window).
- ``_budgets`` grows by one ``TokenBudget`` per orphaned session
  (small but unbounded).

In practice the rate-limiter's bucket eviction (5-minute idle) and
the lure's keepalive (3 missed = disconnect) keep things bounded
in the hot path. A long-running bridge with attacker churn still
accumulates dead entries.

Two viable fixes (both deferred):

- Idle-timeout sweep on the sessions dict, mirroring the rate
  limiter's ``bucket_idle_eviction_s`` pattern. Drop budget +
  context for sessions with no commands in the last N minutes.
- Have the bridge HTTP middleware notice the lure-side
  ``X-Anglerfish-Last-Activity-At`` (a new header) and use it to
  prune. More plumbing, less reliable than a server-side sweep.

The pre-existing ``sessions`` leak predates Stage 5 (Stage 1A);
Stage 5 slice 5 added the symmetric ``_budgets`` leak. Surfaced
during the Stage 5 retroactive audit. Owner: TBD.

## TODO-9: per-chunk size cap on the bridge streaming response

`LLMClient.stream_chat` and `BridgeClient.command_stream` both
iterate NDJSON lines from the upstream without per-line size
enforcement. Ollama controls chunk size on the bridge side; the
lure trusts the bridge (and the bridge enforces overall
``ollama.max_response_chars`` only on the buffered path).

In the streaming path:

- `defense.scan_max_chars` is only applied to the assembled string
  after the stream completes; an oversized chunk could be
  reflected straight to the attacker terminal before the assembly
  pass runs.
- A pathological Ollama (compromised model output, attacker
  steering toward megabyte responses) could push the lure to
  buffer arbitrary memory inside a single chunk while
  ``aiter_lines`` waits for the next newline.

Fixes to consider:

- Add a `max_chunk_chars` config knob (mirrors `max_response_chars`)
  enforced inside ``_iter_stream_lines`` and ``_parse_stream_chunk``;
  raising on oversized chunks aborts the stream cleanly.
- Bound the assembled-text accumulator in `handle_command_stream`
  so a flood of small chunks cannot grow it past
  ``ollama.max_response_chars``.

Surfaced during the Stage 5 retroactive audit sweep. Owner: TBD.

## Deferred until the pre-deploy sweep

TODO-2, TODO-3, TODO-6, TODO-7, TODO-8, TODO-9 are explicitly
deferred to a dedicated sweep that runs before the first
production deployment (Stage 10/11 timeframe at earliest). The
audit(stage9) sweep closed TODO-4 + TODO-5 only.

Rationale per category:

- **Deploy blockers (TODO-2, TODO-3)**: the systemd unit work
  wants validation against a real deployment so we do not do it
  twice. The dashboard unit factory wrapper (TODO-2) is trivial
  in isolation; the lure systemd unit (TODO-3) needs ISO-hook
  plumbing + bait-NIC env wiring that is easier to get right
  when there is a live target to test against.

- **Behavior changes (TODO-6, TODO-7)**: the `_scalar` typed-
  exception swap and the `WizardAnswers` SecretStr upgrade
  both have non-trivial regression surface for small benefit.
  They deserve their own focused commit when an operator hits
  the specific failure mode they would prevent (silent
  schema-changed COUNT(*) returning 0; an audit log surfacing
  a wizard.json password hash in a traceback).

- **Robustness (TODO-8, TODO-9)**: bridge session/budget leaks
  on missed DELETE + per-chunk size cap on streaming. Both are
  scale problems for a pre-traffic tool. The rate-limiter +
  lure keepalive bound the leak in the hot path today; the
  defense layer's overall-response cap bounds the chunk
  oversize in the buffered path. Address when production
  traffic shape forces the issue or when the deploy-readiness
  sweep audits the failure-mode surface end-to-end.
