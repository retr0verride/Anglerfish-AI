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

## TODO-4: lure SSH banner — Debian suffix never reaches the wire

`src/anglerfish/lure/banner.py` exports `debian_banner()` which
builds a full SSH identification string of the form
``SSH-2.0-OpenSSH_X.Yp1 Debian-Z+debWuV``. The Stage 2 design intent
(and the `banner_openssh_version` + `banner_debian_version` config
fields) is that the lure emits this full banner to attackers so the
fingerprint matches a recent Debian stable.

The actual call site at `src/anglerfish/lure/server.py:761-766`
builds the banner inline and then strips both the ``SSH-2.0-`` prefix
(asyncssh prepends it automatically) AND the ``Debian-...`` suffix
via ``.split(" ", 1)[0]``. The split exists because asyncssh's
``server_version`` parameter accepts only RFC 4253's
``softwareversion`` token, which forbids spaces. The Debian suffix
would have to go in the optional ``comments`` field of the SSH
identification line, which asyncssh does not expose as a separate
parameter.

Net: ``banner_debian_version`` is configured but never reaches the
wire, the `debian_banner()` helper is effectively dead code (Stage
4.2 audit caught it), and attackers see ``OpenSSH_9.2p1`` rather than
the intended ``OpenSSH_9.2p1 Debian-2+deb12u3``.

Three possible fixes:

- Patch asyncssh (upstream PR or local monkey-patch) so it accepts
  a full identification line including comments. Most correct but
  upstream-coordination heavy.
- Bypass asyncssh's banner generation entirely by writing the
  identification line ourselves on the socket before handing off to
  asyncssh. Possible but fragile.
- Accept the limitation, delete the helper, drop the
  ``banner_debian_version`` config field, and update the wizard +
  THREAT_MODEL to reflect that only the OpenSSH version varies.

Owner: TBD. Surfaced during the Stage 5 retroactive audit sweep of
the lure subsystem. Behaviour-changing fix, not a hygiene cleanup.

## TODO-5: per-IP limiter explicit boundary tests

`tests/lure/test_per_ip_limiter.py` covers the limiter's general
behaviour but lacks AUDIT.md's "boundary conditions tested" coverage:

- Empty / whitespace-only ``source_ip`` (the limiter currently
  treats it as a valid distinct key; behaviour is undefined but the
  test suite never exercises it).
- Exact-edge transition: ``concurrent == max_concurrent - 1 →
  max_concurrent`` (the existing tests jump from "well under" to
  "well over").
- Same-timestamp rapid-fire admit/reject within one tick of
  ``time.monotonic()`` — verifies the per-minute window math does
  not double-count when several admits land in the same epoch
  microsecond.

Surfaced during the Stage 5 retroactive audit sweep of the lure
subsystem. Test-only addition; no production code touched. Owner: TBD.
