# Stage 2 - Native asyncssh lure subsystem (replaces Cowrie)

> **Roadmap note.** [`ROADMAP.md`](../ROADMAP.md) currently lists Stage 2
> as "Persistent rich session store." That stage is *not* cancelled,
> only renumbered. Replacing Cowrie is foundational infrastructure
> (every later stage emits richer per-session data, which means every
> later stage benefits from the lure controlling its own event shape
> rather than scraping Cowrie JSON). Approving this doc means
> renumbering session-store → Stage 3 and shifting everything below by
> one. The ROADMAP update lands in the same commit as the design doc.

---

## Problem

Anglerfish today is bolted on to Cowrie:

* The SSH entry point is Cowrie, configured at
  [`cowrie/etc/cowrie.cfg`](../../cowrie/etc/cowrie.cfg) and patched at
  [`cowrie/patches/0001-anglerfish-shell.patch`](../../cowrie/patches/0001-anglerfish-shell.patch).
* Attacker commands enter Anglerfish through a monkey-patched
  `HoneyPotShell.lineReceived` in
  [`src/anglerfish/integration/cowrie_shell_adapter.py`](../../src/anglerfish/integration/cowrie_shell_adapter.py)
  that calls the sync HTTP client in
  [`src/anglerfish/integration/cowrie_shell.py`](../../src/anglerfish/integration/cowrie_shell.py).
* Telemetry arrives through the Twisted-side output plugin in
  [`src/anglerfish/integration/cowrie.py`](../../src/anglerfish/integration/cowrie.py),
  which forwards raw Cowrie JSON events.

That topology has four problems we keep paying for:

1. **Credential capture is impedance-mismatched.** Cowrie emits
   `cowrie.login.success` / `cowrie.login.failed` events that the
   forwarder ships verbatim. The Anglerfish
   [`CredentialStore`](../../src/anglerfish/credentials/storage.py)
   class, the one with AES-GCM-at-rest and HMAC dedup, is *not*
   written to from the Cowrie path. The credential intelligence
   feature that ships in the dashboard is fed only when a developer
   runs the wizard, not when an attacker actually logs in. (See
   [`src/anglerfish/integration/cowrie.py:62-98`](../../src/anglerfish/integration/cowrie.py#L62-L98)
   - `handle_event` dispatches only `session.connect` and
   `session.closed`, not login events.) This is a Stage-0-quality gap.
2. **Fingerprinting fires on the wrong inputs.** The
   [`fingerprint.service`](../../src/anglerfish/fingerprint/service.py)
   module computes JA3 / HASSH but the only call sites are tests:
   the live SSH handshake bytes only exist inside Cowrie's Twisted
   reactor and aren't surfaced to the output plugin. We have a
   fingerprinter that never sees real attacker handshakes.
3. **Two upstreams to track and audit.** Every Cowrie release is a
   blob of Twisted-era Python (most modules predate `asyncio`) that
   we must evaluate for security regressions before shipping. The
   moving-window patch in `cowrie/patches/0001-anglerfish-shell.patch`
   needs to rebase against every upstream change. We've already
   eaten one bug from this, see the FIXME at
   [`src/anglerfish/integration/cowrie_shell_adapter.py:42`](../../src/anglerfish/integration/cowrie_shell_adapter.py#L42)
   noting that monkey-patching breaks on Cowrie's planned
   `lineReceived` refactor.
4. **The two-NIC story leaks.** Cowrie binds via `[ssh]` /
   `[telnet]` stanzas in `cowrie.cfg` to whatever interface the
   operator types. Nothing in the code enforces "bind to the bait
   NIC only, never the service NIC." A wizard typo or a renumbered
   interface exposes the dashboard's NIC to attacker SSH. The lure
   should refuse to start unless its listen address is on the
   configured bait interface.

The lure subsystem replaces Cowrie with an in-tree, `asyncssh`-based
SSH server that:

* Binds *only* to the operator-confirmed bait-NIC IP, validated at
  startup against the live interface list.
* Writes credential attempts and SSH handshake bytes through the
  existing typed Anglerfish components (`CredentialStore`,
  `Fingerprinter`), closing the two intelligence gaps above.
* Routes every unknown command to the existing `AIBridgeService` over
  the existing loopback HTTP API (port 8421); the bridge's defense
  layer, rate limiter, and prompt machinery are already
  Stage-1-hardened; the lure does not duplicate them.
* Handles a small, fully-deterministic set of native commands
  in-process so that obvious shell builtins never depend on the LLM.
* Ships under the Anglerfish quality gates (ruff, mypy --strict,
  pytest 90% coverage) instead of inheriting Cowrie's gates.

It is **not** a fork of Cowrie. It does not aim for byte-perfect
Cowrie compatibility. It aims to be a small, focused, modern SSH
honeypot that fronts the existing Anglerfish brain.

## Proposed interface

### Process topology

```text
                     bait NIC                       service NIC
                        │                                │
                        ▼                                │
        ┌──────────────────────────┐                     │
        │  anglerfish-lure         │                     │
        │  asyncssh server         │                     │
        │  - native commands       │                     │
        │  - CredentialStore       │  loopback HTTP      │
        │  - Fingerprinter         │ ───────────────►    │
        │  - bridge HTTP client    │   127.0.0.1:8421    │
        └──────────────────────────┘                     │
                                                         ▼
                                          ┌──────────────────────────┐
                                          │  anglerfish-bridge       │
                                          │  AIBridgeService (FastAPI)│
                                          │  - DefenseConfig         │
                                          │  - Ollama HTTP client    │
                                          │  - rate limiter          │
                                          └──────────────────────────┘
                                                         │
                                                         ▼
                                                  127.0.0.1:11434
                                                       Ollama
```

Two systemd units, two unprivileged users, two failure domains. The
lure is the only one that accepts attacker traffic; if it crashes,
the bridge survives. If the bridge crashes, the lure falls back to
scripted responses and continues to capture credentials and
fingerprints. This is the privilege separation the operator buys by
keeping the boundary HTTP.

`CredentialStore` and `Fingerprinter` are imported *directly* into the
lure process (typed, in-process integration). Both write to SQLite
files under the configured `data_dir`; SQLite's locking handles the
two-writer case (dashboard reads, lure writes, occasional rotation
job touches the DB). The HTTP boundary is reserved for the LLM call -
the path where defense, rate-limit, and prompt construction live -
and *not* for typed data-layer calls where an HTTP envelope would buy
nothing but latency.

### Module layout

```text
src/anglerfish/lure/
    __init__.py        # public re-exports: LureServer, run_lure
    __main__.py        # `python -m anglerfish.lure` entry point
    config.py          # LureConfig pydantic model (see below)
    keys.py            # host-key generation + persistence
    server.py          # asyncssh.SSHServer subclass, listen loop
    session.py         # per-attacker state (cwd, history, source IP)
    commands.py        # native command dispatch table
    fakefs.py          # static minimal in-lure filesystem
    bridge_client.py   # async HTTP client to AIBridgeService
    fallback.py        # scripted responses when bridge unavailable
    banner.py          # convincing Debian SSH banner
    http.py            # stub for future HTTP/HTTPS lure (NotImplementedError)
```

Public API (the only things the rest of the codebase or the CLI may
import):

```python
# anglerfish/lure/__init__.py
from anglerfish.lure.config import LureConfig
from anglerfish.lure.server import LureServer
from anglerfish.lure.runner import run_lure

__all__ = ["LureConfig", "LureServer", "run_lure"]
```

```python
# anglerfish/lure/server.py
class LureServer:
    def __init__(
        self,
        settings: AnglerfishSettings,
        *,
        credential_store: CredentialStore,
        fingerprinter: Fingerprinter,
        bridge_client: BridgeClient,
        host_keys: Sequence[asyncssh.SSHKey],
        audit_log: AuditLog | None = None,
    ) -> None: ...

    async def start(self) -> None: ...   # awaits asyncssh.create_server
    async def stop(self) -> None: ...    # graceful drain + close
    async def __aenter__(self) -> Self: ...
    async def __aexit__(self, *_exc: object) -> None: ...
```

```python
# anglerfish/lure/runner.py
async def run_lure(settings: AnglerfishSettings) -> None:
    """Top-level coroutine for the systemd entry point.

    Wires together CredentialStore, Fingerprinter, BridgeClient,
    host-key loading, LureServer construction, signal handlers
    (SIGTERM → graceful stop, SIGINT → graceful stop), and the
    asyncio.Event that gates server shutdown.
    """
```

The CLI entry point in [`src/anglerfish/cli/__main__.py`](../../src/anglerfish/cli/__main__.py)
gains a `lure serve` subcommand that calls `run_lure` under
`asyncio.run`, mirroring the existing `bridge serve` shape.

### Configuration

New Pydantic model under `ANGLERFISH_LURE__*`. Frozen,
`extra="forbid"`, validated at startup. The model file lives at
`src/anglerfish/lure/config.py` (not in
`src/anglerfish/config/models.py`) to keep lure-specific validation
close to the code that uses it; it is re-exported through
`anglerfish.config.models` so existing import sites keep working.

```python
class LureConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    # Network
    listen_host: IPvAnyAddress = Field(
        default=IPvAnyAddress("0.0.0.0"),  # noqa: S104 - operator must override
        description=(
            "Bait-NIC IP to bind the SSH listener on. The lure refuses "
            "to start unless this IP is currently assigned to an "
            "interface on the host (validated at startup). Default "
            "0.0.0.0 is intentionally wildcarded so a missing config "
            "fails the bait-NIC sanity check rather than silently "
            "binding to every interface."
        ),
    )
    listen_port: int = Field(default=2222, ge=1, le=65535)

    # Identity
    hostname: str = Field(default="srv-prod-01", min_length=1, max_length=63)
    banner: str = Field(
        default="SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        min_length=1, max_length=255,
        description="Server identification string (RFC 4253 §4.2).",
    )

    # Host keys
    host_key_dir: Path = Field(
        default=Path("/var/lib/anglerfish/lure-keys"),
        description=(
            "Directory storing the lure's RSA-4096 and Ed25519 host "
            "keys. Generated at first boot via the wizard. Must NEVER "
            "live in the repo. File mode 0600 / dir mode 0700 enforced "
            "at startup; the lure refuses to load keys with looser "
            "permissions."
        ),
    )

    # Input sanitisation (separate from bridge - lure caps closer to attacker)
    max_command_chars: int = Field(default=1024, gt=0, le=8192)

    # Per-source-IP rate limit (separate from bridge limiter, which is
    # per-session: lure limit fires before a session is even opened).
    # 3 concurrent stops a single IP from holding every slot while
    # we keep capacity open for distributed brute force across many
    # IPs. 30 per minute is generous enough to capture the full
    # credential list from burst-style brute force tools before the
    # throttle drops the connection.
    per_ip_max_concurrent_connections: int = Field(default=3, ge=1, le=100)
    per_ip_max_connections_per_minute: int = Field(default=30, ge=1, le=600)

    # Bridge link
    bridge_base_url: HttpUrl = Field(default=HttpUrl("http://127.0.0.1:8421/"))
    bridge_request_timeout_s: float = Field(default=30.0, gt=0.0, le=120.0)
    bridge_connect_timeout_s: float = Field(default=2.0, gt=0.0, le=30.0)

    # Timing-jitter defence (see Native-command timing jitter section)
    timing_jitter_enabled: bool = Field(default=True)
    timing_jitter_floor_ms: int = Field(default=200, ge=0, le=5000)
    timing_jitter_ceiling_ms: int = Field(default=3500, ge=100, le=10000)
    timing_jitter_bootstrap_min_ms: int = Field(default=800, ge=0, le=5000)
    timing_jitter_bootstrap_max_ms: int = Field(default=1800, ge=100, le=10000)

    # SSH liveness - asyncssh keepalive (RFC 4254 §6.10 SSH_MSG_REQUEST_SUCCESS)
    keepalive_interval_s: int = Field(default=60, ge=0, le=3600,
        description="0 disables keepalives. Default 60s matches OpenSSH ClientAliveInterval defaults.")
    keepalive_count_max: int = Field(default=3, ge=1, le=10,
        description="Disconnect after N consecutive missed keepalives.")

    # Optional second lure
    http_lure_enabled: bool = Field(default=False)
    http_lure_listen_port: int = Field(default=8080, ge=1, le=65535)

    @model_validator(mode="after")
    def _ports_must_differ(self) -> Self:
        if self.http_lure_enabled and self.http_lure_listen_port == self.listen_port:
            raise ValueError("lure.http_lure_listen_port must differ from lure.listen_port")
        return self
```

The startup-time bait-NIC check lives in `LureServer.start` rather
than the Pydantic validator. Pydantic runs at config-load time,
which may be on a different host than where the lure actually runs
(e.g. building a configuration archive locally for ISO bake). The
validator catches obvious errors (range, port collision); the
runtime check catches "this IP isn't on any interface."

The bridge link does **not** carry the shared bearer secret in
config: the lure reads `ANGLERFISH_BRIDGE__SHARED_SECRET` directly
from the environment, identical to how the existing Cowrie shim does
at [`src/anglerfish/integration/cowrie_shell.py:64-69`](../../src/anglerfish/integration/cowrie_shell.py#L64-L69).
Operator's `EnvironmentFile=` in the systemd unit feeds both the
lure and the bridge from the same env file; the wizard generates the
secret once.

`LureConfig` is wired into `AnglerfishSettings` as:

```python
lure: LureConfig = Field(default_factory=LureConfig)
```

Re-exported from `anglerfish.config.models.__all__`.

### Bridge HTTP client

A small async wrapper around `httpx.AsyncClient` that talks the same
protocol the existing sync Cowrie shim talks. Lives at
`src/anglerfish/lure/bridge_client.py`:

```python
class BridgeUnavailableError(RuntimeError): ...

class BridgeClient:
    def __init__(
        self,
        *,
        base_url: HttpUrl,
        shared_secret: str | None,
        request_timeout_s: float,
        connect_timeout_s: float,
        http_client: httpx.AsyncClient | None = None,
        logger: logging.Logger | None = None,
    ) -> None: ...

    async def open_session(self, *, source_ip: str, username: str) -> UUID: ...
    async def submit_command(self, session_id: UUID, command: str) -> str: ...
    async def close_session(self, session_id: UUID) -> None: ...
    async def aclose(self) -> None: ...
```

All methods raise `BridgeUnavailableError` on network failure, HTTP
5xx, or HTTP 401 (treat auth failure as "bridge isn't talking to
us"). HTTP 4xx other than 401 surface as `BridgeUnavailableError`
too, the lure should never expose a brittle error path to the
attacker.

The constructor accepts an injected `httpx.AsyncClient` for tests;
when `None`, the client owns its own and closes it in `aclose()`.
The protocol header `X-Anglerfish-Protocol: 1` is set on every
request; a 426 from the bridge logs a structured error and falls
back without retry (operator drift, not a transient failure).

### Native command dispatch

Per the user requirement: "all unknown commands forwarded to the
existing AIBridgeService"; therefore the native list is the
*known* commands. Implemented in `commands.py` as a dispatch dict
keyed on the first shell token:

| Token         | Result                                                          |
| ------------- | --------------------------------------------------------------- |
| `whoami`      | `session.fake_username` followed by `\n`                        |
| `id`          | `uid=0(root) gid=0(root) groups=0(root)` (or per username)      |
| `pwd`         | `session.cwd`                                                   |
| `ls`          | rendered from `fakefs` for the cwd (supports `-l` / `-a`)       |
| `cd`          | deterministic, mirrors `AIBridgeService._handle_cd` exactly     |
| `uname`       | `Linux` (`uname -a` → Linux + hostname + kernel string)         |
| `hostname`    | `session.hostname` (settable per persona in later stages)       |
| `echo`        | concatenates args, joins with single space, appends `\n`        |
| `cat /etc/passwd` | served from `fakefs`; other `cat` paths → bridge            |
| `cat /proc/version` | served from `fakefs`; other `cat` paths → bridge          |
| `history`     | from `session.history()`                                        |
| `exit`        | closes the channel after writing nothing                        |

Two parsing rules:

1. **First-token match, not substring.** `whoami; rm -rf /` is *not*
   a native `whoami`; it routes to the bridge so the LLM-driven flow
   gets the chance to react. Use `shlex.split(command, posix=True)`
   to extract the first token; fall back to whitespace split if
   shlex raises.
2. **Single-pipe-stage only.** Native commands handle exactly one
   stage. `ls | wc -l` routes to the bridge so the LLM produces a
   plausible count instead of us computing the wrong number from
   our deliberately-minimal fakefs.

The dispatch table is constructed once at startup; tests assert that
every token in the table maps to a callable that returns `str`.

`cd` is special: it mutates session state, returns `""`, but is
still a hit (so the bridge isn't called). The implementation
re-uses the path-normalisation logic from
[`AIBridgeService._normalise_path`](../../src/anglerfish/bridge/service.py#L321-L333)
verbatim. Extract it to a neutral module at
`src/anglerfish/bridge/path.py` so both bridge and lure can import
it without creating a bridge → lure import cycle. (Existing tests in
[`tests/bridge/test_service.py`](../../tests/bridge/test_service.py)
cover the behaviour; we keep them passing.)

#### Native-command timing jitter

Self-review caught this: native commands return in microseconds;
bridge-routed commands return in ~1.5s (Ollama median on the target
hardware). A scripted attacker that times responses can fingerprint
the lure's native dispatch table in one session, `whoami` is
instant, `cat /etc/sudoers` is slow, therefore `whoami` is native.
That timing oracle is a fingerprint we don't want to ship.

`commands.py` wraps every native dispatcher in a small async jitter
layer:

```python
class LatencyJitter:
    """Sleeps before returning a native command result so that
    native-vs-bridge timing is not an attacker fingerprint.

    Maintains a rolling EWMA of observed bridge latencies (samples
    are appended every time the lure routes a command to the bridge).
    For each native response, samples a sleep duration from a
    log-normal centred on the EWMA median, truncated to
    [floor_ms, ceiling_ms].

    Falls back to a fixed (800, 1800) ms range when the EWMA hasn't
    collected enough samples (first-N-commands path), so the
    fingerprint defense is in place from the very first command of
    every session - not only after we've observed bridge behaviour.
    """
    floor_ms: int = 200
    ceiling_ms: int = 3500
    bootstrap_min_ms: int = 800
    bootstrap_max_ms: int = 1800
    ewma_alpha: float = 0.2
    min_samples_before_ewma: int = 5
```

The jitter is **per-process**: not per-session, an attacker
opening multiple sessions to characterise the distribution still
sees one distribution. Defaults are tunable through
`LureConfig.timing_jitter_*` fields (added in the config section
above as a follow-up).

`echo` and `pwd` get jitter even though they're trivially fast in
real bash, the cost is one extra `await asyncio.sleep(...)` per
turn (cheap; the event loop has nothing else to do). The benefit
is uniform timing across the entire native/bridge boundary.

There is a real side-effect: native commands are slower than they
would be otherwise. We accept that. Honeypot timing should look
like Ollama, not like instant-return. Two safety valves: jitter is
gated by `LureConfig.timing_jitter_enabled` (default True) so
operators can disable for debugging, and the bootstrap fallback
guarantees the defence is up from request one.

### Static fake filesystem

`fakefs.py` ships a hard-coded mapping of path → content (and path →
directory listing). Built into the binary, identical every session.

The v1 first draft of this design shipped 11 paths. Self-review
caught the failure mode: 11 paths is too thin. Almost every
`cat`/`ls` hits the LLM, the LLM makes up file contents on the fly,
and within one session those made-up contents contradict the 11
static files (the LLM invents a sudoers entry referencing a user
that doesn't exist in our static `/etc/passwd`; invents a crontab
that calls a binary we don't have in `/usr/bin`; etc.).

The fix is two-sided:

1. **Bigger static table, covering the common attacker-cat targets.**
   The list below is ~50 paths grouped by what an attacker
   actually reads in the first five minutes of a Linux foothold.
   Drawn from
   [HoneyDB](https://honeydb.io/) frequency data and the Cowrie
   community's `cat`-target logs (Stage 6 will eventually replace
   this with telemetry from our own corpus).

2. **Fakefs awareness in the bridge prompt.** The lure passes a
   compact summary of the static layout to the bridge with each
   command (new optional `fs_context` field on
   `CommandRequest`, see "Bridge wire-protocol delta" below).
   The bridge's prompt builder appends the summary to the system
   prompt so the LLM knows which paths are *static* (their content
   is the source of truth) and which paths are *open* (the LLM
   should invent self-consistent content). Contradiction goes from
   "almost certain" to "the LLM has to actively ignore context."

Full v1 contents:

#### Fakefs - system identity

| Path                  | Content                                              |
| --------------------- | ---------------------------------------------------- |
| `/etc/passwd`         | `root`, `daemon`, `bin`, `sys`, `mail`, `www-data`, `nobody`, `sshd`, `<fake_username>` rows |
| `/etc/group`          | matching groups for each `/etc/passwd` row           |
| `/etc/shadow`         | permission-denied (mode 0640 root:shadow); attempting `cat` returns `cat: /etc/shadow: Permission denied` - even root in the fake shell gets the canonical denial because the persona is supposed to be a compromised non-root account in later stages |
| `/etc/hostname`       | `<session.hostname>\n`                               |
| `/etc/issue`          | `Debian GNU/Linux 12 \n \l\n`                        |
| `/etc/os-release`     | standard Debian 12 (bookworm) values                 |
| `/etc/debian_version` | `12.5\n`                                             |
| `/etc/machine-id`     | random per install, stable per session (lure derives once at boot from a hash of the host keys; never the real machine-id) |

#### Fakefs - system config

| Path                       | Content                                              |
| -------------------------- | ---------------------------------------------------- |
| `/etc/hosts`               | 127.0.0.1 + IPv6 loopback + `<session.hostname>`     |
| `/etc/resolv.conf`         | systemd-resolved stub + 1.1.1.1 / 8.8.8.8            |
| `/etc/nsswitch.conf`       | standard Debian                                      |
| `/etc/fstab`               | root+swap+/boot on virtual disks                     |
| `/etc/sudoers`             | permission-denied (root-only readable in real Linux) |
| `/etc/sudoers.d/`          | directory; empty listing                             |
| `/etc/crontab`             | `17 *  * * *   root    cd / && run-parts ...` + standard entries |
| `/etc/cron.d/`             | directory; lists `e2scrub_all`, `sysstat`            |
| `/etc/cron.daily/`         | directory; lists `apt-compat`, `dpkg`, `logrotate`, `man-db` |
| `/etc/network/interfaces`  | `iface lo inet loopback` only (systemd-networkd elsewhere)  |
| `/etc/ssh/sshd_config`     | typical hardened Debian sshd_config with `PermitRootLogin prohibit-password` |
| `/etc/ssh/ssh_config`      | Debian default                                       |
| `/etc/apt/sources.list`    | bookworm main/contrib/non-free-firmware + security   |
| `/etc/apt/sources.list.d/` | directory; empty listing                             |
| `/etc/profile`             | Debian default                                       |
| `/etc/bash.bashrc`         | Debian default                                       |
| `/etc/motd`                | empty                                                |
| `/etc/update-motd.d/`      | directory; lists `00-header`, `10-help-text`, `50-motd-news` |

#### Fakefs - kernel / hardware

| Path                          | Content                                              |
| ----------------------------- | ---------------------------------------------------- |
| `/proc/version`               | `Linux version 6.1.0-18-amd64 (debian-kernel@lists.debian.org) ...` |
| `/proc/cpuinfo`               | 4 Intel Xeon E5-2680 v4 entries                      |
| `/proc/meminfo`               | 8 GiB total / ~6 GiB free, plausible breakdown       |
| `/proc/mounts`                | `/`, `/proc`, `/sys`, `/dev/pts`, `/run`, `/tmp` (tmpfs) |
| `/proc/uptime`                | random in `(86400, 7776000)` seconds - between 1 day and 90 days, frozen per session |
| `/proc/self/status`           | plausible bash status                                |
| `/proc/loadavg`               | `0.04 0.11 0.07 1/142 <pid>` - quiet system          |

#### Fakefs - users / homes

| Path                              | Content                                          |
| --------------------------------- | ------------------------------------------------ |
| `/home/`                          | listing: `<fake_username>`                       |
| `/home/<user>/`                   | listing: `.bashrc`, `.profile`, `.ssh/`          |
| `/home/<user>/.bashrc`            | Debian default `.bashrc`                         |
| `/home/<user>/.profile`           | Debian default `.profile`                        |
| `/home/<user>/.bash_history`      | empty file (real history goes through bridge → time-wasting in Stage 4) |
| `/home/<user>/.ssh/`              | listing: `authorized_keys`, `known_hosts`        |
| `/home/<user>/.ssh/authorized_keys` | one ssh-ed25519 key labelled `<user>@srv-prod-01` (per-install, generated by wizard alongside host keys; rotation invalidates) |
| `/home/<user>/.ssh/known_hosts`   | 3 hashed entries (`HashKnownHosts yes` style)    |
| `/root/`                          | listing: `.bashrc`, `.profile`, `.ssh/`, `.bash_history` |
| `/root/.bashrc`                   | root default                                     |
| `/root/.bash_history`             | 20 lines of plausible sysadmin commands          |
| `/root/.ssh/`                     | listing: `authorized_keys`, `known_hosts`        |
| `/root/.ssh/authorized_keys`      | one ssh-rsa entry                                |

#### Fakefs - logs

| Path                  | Content                                              |
| --------------------- | ---------------------------------------------------- |
| `/var/log/auth.log`   | 10 plausible recent lines (sshd, sudo, systemd-logind) - timestamps within `proc/uptime` window |
| `/var/log/syslog`     | 10 plausible recent lines (kernel, systemd, cron)    |
| `/var/log/dpkg.log`   | 5 recent apt operations                              |
| `/var/log/lastlog`    | binary; `cat` returns garbled bytes (correct behaviour for real `lastlog`); `lastlog` command routes to bridge |
| `/var/log/wtmp`       | binary; same handling                                |
| `/var/log/btmp`       | permission-denied (root-only)                        |

#### Fakefs - top-level / root listing

| Path     | Content                                                         |
| -------- | --------------------------------------------------------------- |
| `/`      | listing: `bin`, `boot`, `dev`, `etc`, `home`, `lib`, `lib64`, `media`, `mnt`, `opt`, `proc`, `root`, `run`, `sbin`, `srv`, `sys`, `tmp`, `usr`, `var` |
| `/etc/`  | listing including all `/etc/...` entries above plus standard directories (`init.d`, `systemd`, etc.) |
| `/var/`  | listing: `backups`, `cache`, `lib`, `local`, `lock`, `log`, `mail`, `opt`, `run`, `spool`, `tmp` |
| `/proc/` | listing: numeric pids + `cpuinfo`, `meminfo`, `mounts`, `uptime`, `version`, `self`, `loadavg` |

Anything not in this table routes to the bridge. The static table is
intentionally curated for the *attacker-known-cat* path (config files,
credential files, recent logs) so the LLM never needs to invent these.
The LLM's job becomes invention for the *unstable* paths (running
processes, attacker-installed scripts, dynamic state) where invention
is correct.

`fakefs.py` exposes:

```python
@dataclass(frozen=True)
class FakeEntry:
    name: str
    mode: int          # st_mode-style; LURE assembles ls -l output from this
    size: int
    owner: str = "root"
    group: str = "root"
    mtime: int = 0     # epoch seconds; static per-session, derived from proc/uptime
    is_dir: bool = False
    is_symlink: bool = False
    target: str | None = None  # symlink target

def read(path: str, session: SessionContext) -> ReadResult: ...
def listdir(path: str, session: SessionContext) -> ListResult: ...
def system_prompt_summary() -> str: ...  # see "Bridge wire-protocol delta"

class ReadResult(BaseModel):
    """Either content, a permission-denied marker, or 'not in fakefs'."""
    model_config = ConfigDict(frozen=True, extra="forbid")
    status: Literal["content", "permission_denied", "not_in_fakefs"]
    content: str = ""

class ListResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    status: Literal["entries", "not_in_fakefs"]
    entries: tuple[FakeEntry, ...] = ()
```

`status="not_in_fakefs"` routes to the bridge. `status="permission_denied"`
synthesises the canonical Linux error message in the lure (no bridge
call). `status="content"` / `"entries"` renders in-process.

#### Bridge wire-protocol delta

`fakefs.system_prompt_summary()` returns a ~500-byte string of the
form:

```
The following paths exist on this system with deterministic content
that you must NOT contradict. If asked to cat or ls one of these,
the shell handles it directly - you will not be invoked. Treat them
as ground truth when inventing content for OTHER paths:
- /etc/passwd: users [root, daemon, bin, sys, mail, www-data, nobody, sshd, <user>]
- /etc/sudoers: not readable (mode 0440)
- /etc/crontab: standard Debian system entries
- /root/.bash_history: 20 lines of sysadmin commands
...
```

The lure passes this string with each `submit_command` call so the
bridge prompt builder can include it in the system prompt window.
This requires a small change to the bridge wire protocol:

```python
class CommandRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str = Field(..., max_length=32768)
    fs_context: str | None = Field(default=None, max_length=4096)  # NEW
```

`fs_context` is optional (the Cowrie shim during the deprecation
window omits it; the bridge falls back to no fs context). The
bridge bumps `PROTOCOL_VERSION` from `"1"` to `"2"`; the lure
sends `X-Anglerfish-Protocol: 2`. The bridge accepts both 1 and 2
during the deprecation window (the protocol-mismatch logic at
[bridge/server.py:80-89](../../src/anglerfish/bridge/server.py#L80-L89)
becomes a *minimum-version* check rather than equality). This is
the only Stage 2 change to the existing bridge.

### Telemetry hooks

Each lure event is wired to exactly one Anglerfish subsystem. The
API shapes below are verified against current source code (not
guessed from memory); see "Notes for future-me" for what I had to
correct from the draft.

| Event                    | Sink (signature verified against current code)                                          |
| ------------------------ | --------------------------------------------------------------------------------------- |
| SSH handshake observed   | `Fingerprinter.fingerprint(source_ip=..., ssh_banner=..., hassh=..., ja3=None)` (async; returns `SessionFingerprint`). HASSH computed in the lure via `compute_hassh(kex_algorithms, encryption_algorithms, mac_algorithms, compression_algorithms)` from `fingerprint.hashes` using asyncssh's exposed kex parameters. `ja3` stays `None` - JA3 is TLS-only; SSH's equivalent is HASSH. |
| Login attempt            | `CredentialStore.record_attempt(source_ip=..., username=..., password=..., session_id=..., timestamp=...)` (async, kwarg-only; returns `bool` - True for first-seen tuple). Lure awaits `store.open()` once at startup. |
| Session open             | `BridgeClient.open_session(...)` + `AuditLog.record("lure.session_opened", **fields)` |
| Native command resolved  | `AuditLog.record("lure.command_native", **fields)`                                     |
| Bridge command resolved  | (audited inside the bridge; lure adds `lure.command_bridge` for symmetry)               |
| Bridge unavailable       | `AuditLog.record("lure.bridge_unavailable", **fields)` + fallback                       |
| Fallback response served | `AuditLog.record("lure.fallback_served", **fields)`                                    |
| Per-IP rate limit fired  | `AuditLog.record("lure.rate_limited", **fields)`                                       |
| Session closed           | `BridgeClient.close_session(...)` + `AuditLog.record("lure.session_closed", **fields)` |
| Threat re-scored         | `ThreatScorer.score(...)` → `Alerter.maybe_alert(...)`                                  |

`AuditLog.record` is synchronous; the disk write is fsync'd under a
lock per [audit.py:63-96](../../src/anglerfish/audit.py#L63-L96).
The lure calls it directly from async handlers, the write is short
enough that wrapping in `asyncio.to_thread` is unnecessary overhead
on the hot path, and AuditLog's own design swallows OSError to
never crash the caller.

Incremental threat scoring (per the architectural decision): the
lure invokes `ThreatScorer.score` after every resolved command, not
only at session close. The scorer is already pure-function over a
command list, so this is a single re-invocation per turn, cheap.
The benefit: alerters can fire mid-session when an attacker pivots
hard from recon to deployment.

#### asyncssh → fingerprint extraction

For each new SSH connection, the lure extracts kex parameters from
asyncssh's `SSHServerConnection` via `get_extra_info`:

* `client_version` → `ssh_banner` arg to `Fingerprinter.fingerprint`
* `client_kex_algs`, `client_encryption_algs_cs`,
  `client_mac_algs_cs`, `client_compression_algs_cs` → fed to
  `compute_hassh(...)` from `fingerprint.hashes` (signature: four
  `Sequence[str]` args, returns lowercase hex MD5).

`asyncssh` exposes these on the connection object once `kex` has
completed. Extraction lives in `LureServer._observe_handshake`,
called from `connection_made` (so the fingerprint is recorded
even when auth eventually fails, that's still intel).

### SSH banner

`banner.py` exposes one function:

```python
def debian_banner(*, openssh_version: str = "9.2p1", debian_version: str = "12+deb12u3") -> str:
    return f"SSH-2.0-OpenSSH_{openssh_version} Debian-{debian_version}"
```

Default matches a real-world Debian 12 release. Configurable so we
can drift it forward when stable kernels move and a static banner
becomes an obvious fingerprint.

### Host-key management

Two keys: RSA 4096 (legacy clients) and Ed25519 (modern clients).
Generated by the wizard at first boot and written to
`<host_key_dir>/ssh_host_rsa_key` and `ssh_host_ed25519_key`,
mode 0600, dir mode 0700.

The wizard step lives in
`src/anglerfish/wizard/sshkey.py` (the file already exists and
handles the *operator* SSH key for management access; we add a
sibling function for the lure host keys, named to avoid collision).
Re-running the wizard *never overwrites* existing keys, operators
who deploy through configuration management can pre-stage the keys
and skip the wizard generation step.

Loaded by `keys.py` at startup using `asyncssh.read_private_key`.
Permission check before load: `stat.S_IMODE & 0o077` must be 0 or
the lure refuses to start (matches the `OpenSSH StrictModes` policy).

### HTTP/HTTPS lure stub

`src/anglerfish/lure/http.py` is a deliberate placeholder so the
config field, wizard prompt, and import surface all exist *before*
the implementation. The file ships in this stage as:

```python
"""HTTP/HTTPS lure - placeholder for a future stage.

The SSH lure (this stage) is the v1 honeypot. HTTP/HTTPS is on the
roadmap so that exposed web apps can be honeypotted alongside SSH,
but the design and implementation are deferred.

Enabling `ANGLERFISH_LURE__HTTP_LURE_ENABLED=true` against a build
that ships this stub raises NotImplementedError at startup with a
clear pointer to the TODO log.
"""

from __future__ import annotations

from anglerfish.config.settings import AnglerfishSettings

__all__ = ["run_http_lure"]


async def run_http_lure(settings: AnglerfishSettings) -> None:
    raise NotImplementedError(
        "lure.http is not implemented in this build - see docs/TODO.md item TODO-1. "
        "Set ANGLERFISH_LURE__HTTP_LURE_ENABLED=false (the default) to start "
        "the SSH lure without the HTTP listener."
    )
```

Per the architectural decision, `docs/TODO.md` becomes the
self-contained source of truth for every `NotImplementedError` we
ship. The file is created in this stage with `TODO-1` reserved for
the HTTP lure. Future deferred work appends to that file.

### Audit event types (additions)

New event keys, each carrying `session_id`, `source_ip`, and the
event-specific fields:

* `lure.server_started` - `listen_host`, `listen_port`
* `lure.server_stopped` - `graceful: bool`, `drain_seconds: float`
* `lure.session_opened` - `username`, `client_version`
* `lure.session_closed` - `duration_seconds`, `command_count`
* `lure.login_attempt` - `username`, `password_hash_prefix` (first 8
  hex chars of SHA-256 for deduplication; never the plaintext)
* `lure.command_native` - `command`, `handler`
* `lure.command_bridge` - `command`, `response_source`
* `lure.bridge_unavailable` - `reason`, `error_type`
* `lure.fallback_served` - `command`, `reason`
* `lure.rate_limited` - `kind: "per_ip_concurrent" | "per_ip_rpm"`
* `lure.fingerprint_observed` - `ja3`, `hassh`

### CLI surface

Two new subcommands on the existing `anglerfish` typer app:

```
anglerfish lure serve           # systemd entry point
anglerfish lure validate-config # dry-run config + bait-NIC check
```

`lure serve` calls `run_lure`; `lure validate-config` runs the
startup checks (config load, bait-NIC presence, host-key
readability, bridge reachability) and exits 0 / non-zero with a
human-readable summary. This is the operator's pre-flight tool.

### nftables update

`cowrie/nftables/anglerfish.nft` already enforces the bait-vs-service
NIC separation. We extend it to:

* Accept new connections to `ANGLERFISH_LURE__LISTEN_PORT` on the
  bait NIC only.
* Drop connections to the same port on the service NIC.
* Keep the existing Cowrie port stanzas during the deprecation
  window so operators upgrading in place don't lose access to
  in-flight sessions.

The nft template is parameterised through the systemd unit's
`EnvironmentFile`, so no hard-coded ports leak between the Pydantic
config and the firewall.

### Wizard prompts

New section in the wizard after the existing bait-NIC selection:

1. SSH listen port (default 22; 2222 in dev profile).
2. Hostname for the fake shell (default `srv-prod-01`).
3. Host-key directory (default `/var/lib/anglerfish/lure-keys`).
4. Generate host keys now? (Yes for first install; No for
   re-running against pre-staged keys.)
5. Enable HTTP lure listener? (Default No; prints "not implemented
   in this build" warning if Yes is selected, and refuses to
   continue.)

### Documentation updates

* `README.md` - replace the "Cowrie is the SSH frontend" sentence
  with a one-paragraph description of the lure, and bump the
  install instructions to no longer require `apt install cowrie`.
* `docs/ARCHITECTURE.md` - replace the Cowrie box in the diagram
  with the lure box. Add the "two failure domains" paragraph.
* `docs/MODEL_SETUP.md` - no change; the lure → bridge → Ollama
  chain is unchanged downstream of the bridge.
* `docs/THREAT_MODEL.md` - add the new attack surface section
  (see "Threat-model delta" below).
* `docs/PRE_DEPLOY_CHECKLIST.md` - add the lure pre-flight steps
  (host keys generated, NIC bound, bridge reachable).
* `docs/TODO.md` - created in this stage; TODO-1 reserved for the
  HTTP lure implementation.

## Out of scope

* **SFTP / SCP / shell-on-its-own-channel.** Attackers who try to
  use these subsystems get a clean `subsystem request failed`. The
  intelligence value is low and the attack surface is wide.
* **Port-forwarding (direct-tcpip / forwarded-tcpip).** Refused
  unconditionally with an audit event. Allowing them would let
  attackers use the lure as a relay; not negotiable.
* **PTY allocation modes beyond xterm-256color / vt100.** Anything
  else gets vt100 and a comment in the audit log. The LLM doesn't
  care about terminal capabilities; the simpler-the-better wins.
* **Public-key auth acceptance.** All key auth attempts are
  logged with the offered key's fingerprint and refused. Password
  auth (`accept-any` with logging) is the v1 capture surface.
* **Resumable sessions.** Each TCP connection is one session. No
  attempt to correlate "same attacker across re-connects"; that's
  the Stage-6 behavioral-clustering work.
* **Byte-perfect Cowrie compatibility.** This is a fresh
  implementation; field operators who built dashboards against
  Cowrie's exact JSON shape must migrate to the lure's event
  shape (which is more direct and better-typed; the forwarder
  emits both during the deprecation window).
* **HTTP lure.** Stub only in this stage; full design in a future
  stage tracked by TODO-1.
* **Telnet listener.** Cowrie ships one; the lure does not. The
  threat-intel value of a 2026 telnet honeypot is low enough that
  it's not worth the second listener's audit cost. (If operators
  want telnet, they can leave Cowrie's telnet listener on during
  the deprecation window.)

## Threat-model delta

The lure introduces a single but significant new attack surface:
**an unprivileged process that accepts arbitrary attacker SSH bytes
on the public bait NIC.** STRIDE breakdown:

### Spoofing

* **New threat.** Attacker presents a forged client-version string
  to influence persona selection in Stage 7.
* **Mitigation.** Client version is captured for telemetry only;
  no code path uses it as a trust signal. Persona selection in
  Stage 7 keys off the bridge's intent inference, not the client
  version.
* **Residual risk.** Stage 7 designers must respect this - adding
  client-version-based logic to persona selection would re-open
  the spoof.

### Tampering

* **New threat.** Attacker corrupts the lure's session state by
  smuggling control sequences in command input.
* **Mitigation.** All input passes through `sanitize_command` from
  `src/anglerfish/bridge/sanitize.py` (already Stage-1-hardened:
  C0 strip, length cap, CR/LF normalisation). The lure caps at
  1024 chars (smaller than the bridge's 4096) so per-IP throughput
  is bounded even when the bridge is overloaded.
* **Residual risk.** A `sanitize_command` bug becomes a bug in two
  places (bridge + lure). Tests in
  `tests/bridge/test_sanitize.py` cover the function exhaustively;
  the lure adds property-based tests for the lure-specific cap.

### Repudiation

* **New threat.** Attacker disconnects in the middle of a
  high-value command sequence and the audit log doesn't capture
  enough state to reconstruct intent.
* **Mitigation.** Every command (native and bridge-routed) writes
  to the audit log *before* the response is generated, so even an
  attacker who races disconnects can't elide their actions.
  `session.history()` is persisted on close so post-mortem analysis
  has the full sequence.
* **Residual risk.** A flushing race between `audit_log.record`
  and `asyncio.Task.cancel` could theoretically lose the last
  event; mitigated by capturing the event synchronously into a
  pre-allocated buffer before dispatching the async write.

### Information disclosure

* **New threat.** The lure's banner, host keys, or timing leak
  signal "this is a honeypot" to a sophisticated attacker.
* **Mitigation.** Banner mirrors a recent stable Debian release.
  Host keys are *fresh per install* (no shared default that the
  internet has indexed). Timing is dominated by Ollama latency
  (median ~1.5s on the target hardware), which is well within
  human-typing ranges for an interactive shell over the public
  internet.
* **Residual risk.** A determined attacker who runs nmap's
  `ssh-hostkey` script across the internet and clusters host keys
  by similarity might identify a fleet of Anglerfish deployments.
  This is acceptable: defending against it would require the lure
  to lie about its own key, which is a worse posture (key
  rotation breaks).

### Denial of service

* **New threat.** Attacker opens N concurrent connections and
  exhausts the lure's event-loop or memory budget.
* **Mitigation.** Two per-source-IP limits enforced *in the lure*,
  before the bridge sees any work: concurrent connections (default
  5) and connections per minute (default 30). Limits configurable
  via `ANGLERFISH_LURE__PER_IP_*`. Limit hits are logged as
  `lure.rate_limited` with kind metadata.
* **Residual risk.** A distributed attacker (many source IPs)
  could still drown the lure. The nftables ruleset is the next
  defense layer; documented in
  `docs/PRE_DEPLOY_CHECKLIST.md`. The lure won't try to do
  distributed-DoS mitigation in v1.

### Elevation of privilege

* **New threat.** Attacker exploits an asyncssh CVE to escape the
  protocol layer into the lure process.
* **Mitigation.** Lure runs under its own systemd-managed
  unprivileged user (`anglerfish-lure`) with:
  * `NoNewPrivileges=true`
  * `ProtectSystem=strict`
  * `ProtectHome=true`
  * `PrivateTmp=true`
  * `MemoryDenyWriteExecute=true`
  * `SystemCallFilter=@system-service`
  * `ReadWritePaths=<data_dir>`
  * `CapabilityBoundingSet=` (empty unless `listen_port < 1024`,
    in which case `CAP_NET_BIND_SERVICE` only)
  The lure does NOT need root to bind 22 on the bait NIC if we
  set the capability, this is the standard low-privilege pattern.
* **Residual risk.** Container escape (when deployed in a
  container in a future deployment shape) is out of scope for this
  stage; future stages should consider gVisor / Kata for the
  unprivileged lure container.

### Trust-boundary delta summary

| Boundary             | Before (Cowrie)     | After (lure)         |
| -------------------- | ------------------- | -------------------- |
| Bait NIC ↔ honeypot  | Cowrie/Twisted      | Anglerfish lure      |
| Honeypot ↔ bridge    | sync HTTP loopback  | async HTTP loopback (unchanged shape) |
| Bridge ↔ Ollama      | unchanged           | unchanged            |
| Bridge ↔ CredStore   | not used            | unchanged (still not used) |
| Lure ↔ CredStore     | n/a                 | NEW: in-process typed call |
| Lure ↔ Fingerprinter | n/a                 | NEW: in-process typed call |

The net change is that we *narrow* the bait-side attack surface
(asyncssh has a smaller code surface than Cowrie + Twisted) and
add two new in-process integration points. Both new integrations
go through types we already test and audit (CredentialStore,
Fingerprinter), so the audit cost is bounded.

## LLM defense delta

**No new LLM call.** The lure routes every LLM-bound command through
the existing `AIBridgeService.handle_command` via the existing
HTTP API. That means:

* The Stage-1 injection scorer runs on lure-originated commands
  with no changes.
* The Stage-1 output filter runs on Ollama responses with no
  changes.
* The Stage-1 model-integrity check at bridge startup is unchanged.

The defense corpus does gain new entries for lure-specific
attacker patterns we know about from the SSH-honeypot literature:

* `tests/llm_defense/corpus/injection/lure_ssh_login_banner.txt`
  - attacker sends a long, prompt-injection-laden username at
  login. The lure's audit path captures the username; the bridge
  never sees it as a *command* (login is not a command), so this
  is a no-op for defense, but we add the case to prove that
  routing.
* `tests/llm_defense/corpus/injection/lure_motd_injection.txt` -
  attacker sends a payload designed to look like a server motd
  in their first command, hoping to confuse persona-aware future
  stages.

The lure does *not* add any direct LLM call paths, so there is no
new prompt template to audit. If a future stage adds one (e.g.
"summarise this session's commands locally without crossing the
bridge boundary"), that stage's design doc inherits the LLM defense
delta requirement.

## Test plan

The first draft of this doc had 10 slices. Self-review caught the
over-granularity: 10 commits is review-cost-heavy for what is
essentially one feature shipping behind a single deployment switch.
Folded into **three commits**: each green at commit, each
independently rollback-able:

### Commit 2A - Scaffold (config + types + units, no live server)

The complete *static* surface of the lure: everything that doesn't
need an asyncssh server running. 2A adds the import surface, the
config keys, and unit tests. `ANGLERFISH_LURE__ENABLED` defaults to
`true` (default opt-out: the honeypot listener is the product, not
an extra to enable). The `lure serve` CLI command lands in 2B and
that is when the default-on behaviour starts a listener. 2A on its
own changes no behaviour because no CLI verb exists to start the
listener yet.

* `LureConfig` Pydantic model + cross-field validators.
* `LureConfig` wired into `AnglerfishSettings` (`extra="ignore"`
  in settings means existing deployments without
  `ANGLERFISH_LURE__*` env vars get the defaults, frozen-true).
* `src/anglerfish/lure/__init__.py` - re-exports.
* `bridge_client.py` - async HTTP client with full error taxonomy.
* `keys.py` - host-key load/generate + permission validation.
* `fakefs.py` - full ~50-path table; `read`/`listdir`/
  `system_prompt_summary` returning the typed results above.
* `commands.py` - native dispatch table with `LatencyJitter`
  wrapper; deterministic helpers (path normaliser, first-token
  matcher) extracted and shared with the bridge.
* `banner.py` - single function.
* `session.py` - `SessionContext` mirroring the bridge's shape,
  no asyncssh dependency.
* `fallback.py` - re-uses `bridge.fallback` where possible.
* `http.py` - `NotImplementedError` stub.
* Bridge wire-protocol bump: `PROTOCOL_VERSION` → `"2"`, server
  middleware accepts `{"1", "2"}` during deprecation window,
  `CommandRequest.fs_context` added as optional `str | None`.
* `docs/TODO.md` - created; `TODO-1` reserved for HTTP lure.

**Tests in this commit (~70):**

* `tests/lure/test_config.py` - defaults, `extra="forbid"`, port
  collision, jitter-bounds, keepalive-bounds, IP validation
  acceptance/rejection cases.
* `tests/lure/test_module_layout.py` - `__all__` discipline.
* `tests/lure/test_bridge_client.py` - full HTTP error matrix
  (200/4xx/401/426/5xx/timeout/network-fail), protocol-header
  assertion, owned-vs-injected `aclose` ownership.
* `tests/lure/test_keys.py` - load, refuse-world-readable,
  refuse-group-readable, generate-writes-correct-modes,
  no-op-when-present.
* `tests/lure/test_commands.py` - every native handler + the
  routing rules (first-token match, pipe routes to bridge,
  semicolon routes to bridge, `cd` mutates state, etc.).
* `tests/lure/test_latency_jitter.py` - bootstrap path,
  EWMA path, floor/ceiling clamps, jitter-disabled bypass,
  property test: native and bridge response-time distributions
  are statistically indistinguishable across 1000 samples
  (Kolmogorov-Smirnov p > 0.05 under default config).
* `tests/lure/test_fakefs.py` - full read/listdir matrix for the
  ~50 paths; static-across-sessions property; permission-denied
  marker handling; `system_prompt_summary` shape + length cap.
* `tests/lure/test_http_stub.py` - stub raises with TODO-1
  reference; disabled-by-default in config.
* `tests/docs/test_todo_log.py` - grep `TODO-\d+` in source,
  assert every reference resolves to a numbered entry in
  `docs/TODO.md`.
* `tests/bridge/test_server.py` additions - protocol version 2
  accepted; `fs_context` parses + flows into the prompt builder.

### Commit 2B - Runtime (asyncssh server + runner + signals)

The live SSH listener and process plumbing. Now the lure can
actually receive a TCP connection.

* `server.py` - `LureServer` subclass of `asyncssh.SSHServer`;
  listen-host validated against live interfaces at startup;
  per-source-IP limits enforced before session open; keepalive
  configured from `LureConfig`; SFTP/port-forwarding/pubkey-auth
  refused with audit; SIGTERM-graceful drain.
* `runner.py` - `run_lure` top-level coroutine; wires
  `CredentialStore.open()`, `Fingerprinter`, `BridgeClient`,
  `AuditLog`; installs signal handlers.
* `__main__.py` - `python -m anglerfish.lure` entry point.
* CLI subcommand: `anglerfish lure serve` calls `run_lure`;
  `anglerfish lure validate-config` runs the startup checks
  without binding.

**Tests in this commit (~30):**

* `tests/lure/test_server.py` - asyncssh client → lure on
  ephemeral port; bridge mocked via `httpx.MockTransport`.
  Cases: start/stop, refuses-non-local-bind, accepts-any-password,
  records-credential, records-fingerprint, native-without-bridge,
  bridge-routes-on-unknown, fallback-on-bridge-down,
  per-IP-concurrent-limit, per-IP-rpm-limit, graceful-drain,
  SIGTERM-shutdown, refuses-pubkey-but-logs-fingerprint,
  refuses-port-forwarding, refuses-sftp.
* `tests/lure/test_runner.py` - wiring assertions;
  startup-failure propagation; SIGTERM-clean-return.
* `tests/cli/test_lure_subcommand.py` - `serve` calls `run_lure`;
  `validate-config` exits 0/nonzero.

### Commit 2C - Release (wizard, nftables, docs, deprecation flip)

The operator-facing surface and the doc updates.

* Wizard prompts: SSH listen port, hostname, host-key dir,
  generate-keys-now, http-lure-enabled (warns + refuses if Yes).
* Wizard generates lure host keys via `sshkey.py` extension.
* nftables template: lure port allowed on bait NIC only;
  Cowrie port retained behind a deprecation flag.
* `README.md` rewritten: lure as the SSH frontend; Cowrie note
  for the transition window.
* `docs/ARCHITECTURE.md` updated diagram.
* `docs/THREAT_MODEL.md` extended with the lure attack-surface
  section.
* `docs/PRE_DEPLOY_CHECKLIST.md` extended.
* `docs/ROADMAP.md` renumbered (lure as Stage 2; session-store
  → Stage 3; all subsequent stages +1).
* `pyproject.toml` - `asyncssh>=2.14,<3` added to runtime deps.

**Tests in this commit (~15):**

* `tests/wizard/test_lure_keys.py` - keys-generated-first-run,
  keys-not-overwritten-on-second-run, warning-on-http-enabled.
* `tests/docs/test_roadmap.py` - verifies the renumbered table
  is internally consistent (each "depends on" reference points
  at a stage that exists; lure has no later-stage dependency).
* `tests/cli/test_lure_validate_command.py` - covers the
  bait-NIC missing case end-to-end with a fake interface list.

### Coverage target

Total coverage must remain ≥90% per the existing
`--cov-fail-under=90` gate. Per-file coverage targets:

| Module                                     | Coverage source                        |
| ------------------------------------------ | -------------------------------------- |
| `src/anglerfish/lure/__init__.py`          | import in any test                     |
| `src/anglerfish/lure/__main__.py`          | CLI test                               |
| `src/anglerfish/lure/config.py`            | `test_config.py`                       |
| `src/anglerfish/lure/keys.py`              | `test_keys.py`                         |
| `src/anglerfish/lure/server.py`            | `test_server.py`                       |
| `src/anglerfish/lure/session.py`           | transitive via server + focused test   |
| `src/anglerfish/lure/commands.py`          | `test_commands.py`                     |
| `src/anglerfish/lure/latency_jitter.py`    | `test_latency_jitter.py`               |
| `src/anglerfish/lure/fakefs.py`            | `test_fakefs.py`                       |
| `src/anglerfish/lure/bridge_client.py`     | `test_bridge_client.py`                |
| `src/anglerfish/lure/fallback.py`          | direct unit tests                      |
| `src/anglerfish/lure/banner.py`            | doctest-style test                     |
| `src/anglerfish/lure/runner.py`            | `test_runner.py`                       |
| `src/anglerfish/lure/http.py`              | excluded by `raise NotImplementedError` rule in `pyproject.toml`; `test_http_stub.py` exercises the message format anyway |

No new files are exempt from the gate.

Total new tests across the three commits: ~115. Stage 1 ended at
891+ tests; Stage 2 lands at ~1,005.

## Rollback plan

The Cowrie pieces remain in the tree until Stage 2 is signed off
and a deprecation window passes:

1. **Config switch**. Commit 2A introduces
   `ANGLERFISH_LURE__ENABLED` (default `true` for new installs,
   `false` for upgrades that already have Cowrie running). The
   existing `ANGLERFISH_COWRIE__*` keys remain valid. Operators
   flip one to flip the other.
2. **Per-commit rollback**: each of 2A/2B/2C is independently
   rollback-able:
   * Reverting 2C leaves the lure runnable but unblessed (no
     wizard prompt, no systemd unit, no nftables update); only
     manual operators see it.
   * Reverting 2B drops the runtime; 2A is dead-code import
     surface that costs nothing on disk.
   * Reverting 2A removes everything cleanly.
3. **systemd revert**, `systemctl disable anglerfish-lure;
   systemctl enable cowrie` returns to the old topology
   (Cowrie remains a packaged dependency through the deprecation
   window).
4. **Files to delete on full Cowrie removal** (a *later* commit,
   not this stage):
   * `src/anglerfish/integration/cowrie.py`
   * `src/anglerfish/integration/cowrie_shell.py`
   * `src/anglerfish/integration/cowrie_shell_adapter.py`
   * `cowrie/` directory (config + patches)
   * `CowrieConfig` from `src/anglerfish/config/models.py`
   * Cowrie tests under `tests/integration/`
5. **Services to restart**:
   * `systemctl restart anglerfish-lure` after lure config changes.
   * `systemctl restart anglerfish-bridge` is required *once*
     after 2A merges (the protocol-version bump from 1 → 2);
     not required for 2B or 2C.

Because the rollback path keeps Cowrie installable for one release
cycle, a production operator can deploy the lure as an
additional listener (different port) for a week of A/B observation
before flipping production SSH (port 22) to the lure.

## Success criteria

The stage is done when:

* All three commits (2A/2B/2C) have shipped, each green at commit.
* Final test count ≥ ~1,005 (Stage 1 ended at 891+ tests;
  Stage 2 adds ~115, see test plan).
* Total coverage ≥90% (per the existing gate).
* `ruff check .` and `ruff format --check .` are clean across the
  new files.
* `mypy --strict src tests` clean - no new `# type: ignore` without
  an error code + reason comment.
* `bandit -c pyproject.toml -r src` clean.
* `pip-audit` clean against the new asyncssh dependency.
* The timing-jitter property test (`test_latency_jitter.py`'s
  KS-test) is green: native and bridge response distributions are
  statistically indistinguishable under default config.
* `anglerfish lure validate-config` exits 0 against a wizard-built
  config on a fresh VM.
* `anglerfish lure serve` starts cleanly under systemd on a test VM,
  binds to the bait NIC only (verified with `ss -lnt`), and
  responds to a `ssh -p 22 root@bait-ip` session with:
  * password-any login accepted,
  * native commands resolved without an Ollama call (verified by
    inspecting bridge logs for absence of the matching session),
  * unknown commands resolved through the bridge (verified by
    presence in bridge logs),
  * `cat /etc/passwd` returns the static fakefs entry; `cat
    /etc/sudoers` returns permission-denied; `cat /etc/random_file`
    routes to the bridge,
  * the captured credential appears in the credentials DB (decryptable
    with the wizard-generated key),
  * the captured handshake appears in the fingerprint DB with a
    valid HASSH,
  * session-closed event in the audit log on disconnect.
* `docs/TODO.md` exists; `TODO-1` references the HTTP lure;
  `tests/docs/test_todo_log.py` is green.
* `README.md` no longer claims Cowrie is the SSH frontend, but
  retains the "Cowrie is still installed for transitional A/B" note
  for the deprecation window.
* `docs/ROADMAP.md` table reflects the renumbering (lure as Stage 2;
  session store as Stage 3; everything else +1).

## Notes for future-me

* **Why HTTP boundary, not in-process bridge import.** Drafted both
  topologies. The in-process import is faster (saves the loopback
  HTTP round-trip, ~1ms) but collapses the failure domain: a bridge
  crash takes the lure down with it, attacker traffic stops, lost
  intel. The HTTP boundary buys an extra process and ~1ms latency
  for a hard fault isolation. Bridge already has the boundary -
  Cowrie talks to it over HTTP. The lure doesn't *gain* anything
  by being different. Keep the boundary; revisit only if the 1ms
  shows up in attacker-perceived latency, which it won't (Ollama
  latency dominates by three orders of magnitude).
* **Why direct integration with CredentialStore + Fingerprinter,
  though.** These two are pure data-layer code with no LLM behind
  them. Going HTTP just to write a row to SQLite would be
  cargo-cult separation. The integration is typed, in-process,
  one stack frame deep, exactly the cost of any other
  Anglerfish module call.
* **Why 1024 max_command_chars instead of bridge's 4096.** The
  bridge's 4096 is the *prompt-construction* budget, there's
  headroom for the system prompt and history. The lure's 1024 is
  the *attacker-input* budget at the network ingress. A 4096-byte
  attacker command yields a 4096-byte payload to the bridge, plus
  history, plus prompt scaffolding, which is wasteful and a
  flooding vector. Cap small at the edge; the bridge still caps
  again (defense in depth).
* **Why `IPvAnyAddress` for listen_host instead of `str`.** Pydantic
  validates the format at config-load. The wizard prompts for an
  IP, not a hostname; binding the SSH listener to a hostname
  invites DNS-rebinding-style misconfig. The runtime check that
  the IP is local doesn't fit Pydantic's offline-validation model
  and lives in `LureServer.start`.
* **Why static fakefs instead of bridge-served.** Considered.
  Routing `cat /etc/passwd` through the bridge gets the LLM
  involved, which is at best wasteful (the answer is deterministic)
  and at worst a leak vector (the LLM might paraphrase or add
  conversational fluff before the output filter catches it).
  Static fakefs eliminates that whole class of failure for the
  cases we know are deterministic.
* **Why exit and history are native, not bridge.** Same reasoning.
  `exit` has one correct behaviour (close the channel); routing it
  through the bridge to "ask the LLM what exit means" is absurd.
  `history` is session state we already have.
* **Why no resumable sessions.** Multi-session attacker
  correlation is the explicit job of Stage 6 (behavioural
  clustering) and Stage 7 (adaptive persona). Building it into the
  lure couples two layers and pre-commits to a clustering scheme.
* **Why ship the HTTP lure stub now instead of just adding the
  config field later.** Two reasons. First: the wizard prompt for
  it should appear in the operator-facing flow from day one so
  operators understand the lure is a generalisable concept, not
  hard-locked to SSH. Second: putting the placeholder in the
  import surface forces us to think about the module shape now
  rather than back-fitting it when the implementation lands.
* **The Cowrie deprecation is a process, not a commit.** A future
  stage (probably Stage 12, "Cowrie removal") deletes the
  integration tree, removes the `[cowrie]` config section, and
  drops the cowrie-installer steps from the ISO build. Until then,
  Cowrie remains a tested code path; we don't get to skip its
  test coverage just because there's a replacement.
* **asyncssh version pinning.** Pin to a range, not a tag: the
  upstream is actively maintained but security fixes ship as
  point releases. Set `asyncssh>=2.14,<3` in `pyproject.toml` and
  rely on pip-audit for CVE alerts.
* **What I considered but rejected for v1.**
  * Per-session honeytokens in the fakefs - pushed to Stage 9.
  * Dynamic banner rotation - adds a moving target without
    measurable benefit until a researcher publishes a "Anglerfish
    fingerprint" paper; address then.
  * Embedded Ollama call directly from the lure (skip the bridge
    for native commands that need light LLM polish) - collapses
    the defense layer's audit point; not worth the latency win.
  * Telnet listener - see "out of scope."
* **For Stage 3 (LLM leverage layer) design author.** When you
  add streaming responses to the bridge API, the lure's
  `BridgeClient.submit_command` interface must be extended to
  consume the stream and forward bytes to the attacker as they
  arrive. The current sync `str` return is intentional for v1;
  see the `lure.command_bridge` audit event shape for the
  contract you'll extend.
* **For Stage 6 (clustering) design author.** The
  `lure.fingerprint_observed` event is the per-session feed you'll
  cluster on. Stage 2 emits hassh only (ja3 is always None for the
  SSH lure, it's a TLS-protocol fingerprint and SSH's equivalent is
  hassh). If you need additional fingerprint dimensions (client
  banner, auth method preference, channel timing), the lure has the
  data, extend the event, don't re-derive it.

### Self-review delta - what changed from the first draft

Recording this section honestly because future-me will read it
in six months and want to know which decisions came from
deliberation vs. which came from blind-spot.

* **Static fakefs was 11 paths in the first draft → ~50 paths in
  this revision.** The 11-path version paired with bridge-routed
  invention created a contradiction trap: LLM-invented file
  contents would reference users, paths, and crontabs not in the
  11 static files. Two-sided fix: bigger static table AND a
  `fakefs.system_prompt_summary()` string passed to the bridge in
  every command request so the LLM knows the ground truth. The
  bridge wire-protocol bump (1 → 2) is the cost of that decision;
  the deprecation window absorbs it.

* **Native commands had no timing jitter in the first draft.**
  A scripted attacker timing responses can map the native dispatch
  table in one session, `whoami` instant, `cat /etc/sudoers` slow,
  etc. Added `LatencyJitter` (per-process EWMA of bridge latency,
  bootstrapped to 800-1800ms) wrapping every native handler so the
  native/bridge boundary is not a timing oracle. Cost: native
  commands are slower than they would be otherwise. Accepted trade -
  honeypot timing should look like Ollama latency, not like
  instant-return.

* **Per-IP limits land at 3 concurrent / 30 per minute.** First
  draft was 5/30. Self-review proposed 3/12 (5 concurrent felt loud,
  12/min felt tight). Final call from operator review: 3 concurrent
  is right (one IP can't hog every slot, distributed brute force
  still has room across many IPs), but 30 per minute is the right
  ceiling, not 12: burst-style brute force tools rip credential
  lists fast and we want to capture the full payload before the
  throttle drops the connection.

* **The first draft sliced this into 10 commits → revised to 3.**
  Ten commits is review-cost-heavy for what is essentially one
  feature behind one deployment switch. Three commits (scaffold /
  runtime / release) preserve per-commit rollback while keeping
  PR review tractable.

* **First draft used `Fingerprinter.observe_handshake(source_ip,
  bytes)`, that API does not exist.** The real signature is
  `Fingerprinter.fingerprint(*, source_ip, ssh_banner, hassh, ja3)`
  and the caller computes hassh themselves via
  `compute_hassh(kex_algorithms, encryption_algorithms,
  mac_algorithms, compression_algorithms)`. This was an unforced
  error. I described an API from memory instead of reading
  [src/anglerfish/fingerprint/service.py](../../src/anglerfish/fingerprint/service.py)
  first. Documented the verified API in the Telemetry hooks section
  and added a sub-section on asyncssh → hassh extraction. **For
  future design docs: read the API surface before writing the
  signature.**

### Notes on asyncssh as a dependency

* **Why asyncssh and not paramiko / fabric / a custom SSH stack.**
  asyncssh is the only mainstream async SSH library that supports
  the server role with a clean async/await API. paramiko is sync
  (thread-pool layered on top fights asyncio); fabric is a
  client-only abstraction. A custom SSH stack is multi-month work and would
  almost certainly have more vulnerabilities than asyncssh's
  audited code.

* **CVE history check (run before merging Commit 2A).** Pull the
  asyncssh CVE list from osv.dev and the GitHub Security
  Advisories. As of the doc date the last published CVE was
  CVE-2023-46446 (MITM via shell command quoting issue in a
  *client-side* command helper we don't use). No server-role CVEs
  in the last 24 months. We pin `asyncssh>=2.14,<3` to stay on the
  current maintained line. pip-audit in CI catches new
  publications.

* **What we trust asyncssh for.** Protocol-level state machines,
  kex, cipher selection, channel multiplexing, auth-method
  negotiation. We do NOT use asyncssh's optional features:
  no SFTP, no port forwarding, no agent forwarding, no X11
  forwarding. Smaller trust surface than the default config.

* **SSH keepalive handling.** Configured via
  `LureConfig.keepalive_interval_s` (default 60) and
  `keepalive_count_max` (default 3). Mirrors OpenSSH's
  `ClientAliveInterval` / `ClientAliveCountMax` semantics:
  asyncssh sends `SSH_MSG_GLOBAL_REQUEST` keepalives every
  `interval` seconds, disconnects after `count_max` consecutive
  unacknowledged requests. Without these, attacker sessions that
  drop without a clean teardown sit forever in the lure's process
  table, eating slots against `per_ip_max_concurrent_connections`.
