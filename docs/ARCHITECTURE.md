# Anglerfish AI - Architecture

A walk through every module, every IPC boundary, and every trust
assumption. The goal of this document is that an engineer who has
never seen the codebase can read it and know which file to open
when something breaks.

For the high-altitude pitch see the [README](../README.md). For
threat-modelling each surface see [THREAT_MODEL.md](THREAT_MODEL.md).
For day-2 ops see [RUNBOOK.md](RUNBOOK.md).

---

## 1. Layout at a glance

```text
┌──────────────────── Anglerfish honeypot VM ────────────────────┐
│                                                                │
│   bait NIC ─────► Lure (native asyncssh, Stage 2)              │
│                       │   (Cowrie shim retained for the        │
│                       │    deprecation window)                 │
│                       │  POST /api/v1/command (bearer auth)    │
│                       ▼                                        │
│   anglerfish-bridge ─ AIBridgeService ──► OllamaClient ──► LLM │
│         │             │            │                           │
│         │             │            └► fallback (no-LLM)        │
│         │             ▼                                        │
│         │         BridgeRateLimiter (per-session + global)     │
│         │             │                                        │
│         │             ▼                                        │
│         │         SessionContext + history window              │
│         │             │                                        │
│         │             ▼                                        │
│         │         Threat engine (MITRE ATT&CK + alerter)       │
│         │             │                                        │
│         │             └────► CredentialStore (AES-GCM SQLite)  │
│         │             └────► Forwarder ──► Splunk HEC + JSONL  │
│         │             └────► Fingerprinter (banner / JA3 / Tor)│
│         │             └────► GeoLookup (MaxMind .mmdb)         │
│         │             └────► DashboardState (in-mem pub/sub)   │
│         │                          │                           │
│         ▼                          ▼                           │
│   audit log (jsonl)         anglerfish-dashboard               │
│                                FastAPI + WebSockets            │
│                                    │                           │
│                                    ▼                           │
│                            operators (service NIC)             │
└────────────────────────────────────────────────────────────────┘
```

Two NICs, two trust levels:

* **Bait NIC** - exposed to attacker traffic. The native asyncssh
  lure (`anglerfish.lure`) is the primary listener. The legacy
  Cowrie listener stays accepted in nftables through the deprecation
  window so operators upgrading in place can run both side-by-side.
  nftables drops all bait-NIC egress except DNS.
* **Service NIC** - operator-only. Reaches Ollama, Splunk HEC, the
  dashboard. nftables egress is restricted to the configured Ollama
  IP, the Splunk HEC URL, and DNS + NTP.

The bridge and dashboard both bind only the addresses the wizard
recorded; nothing in either listens on the bait NIC.

---

## 2. Modules

Source layout, top-down, with the file you'd open first for each
concern.

### 2.1 `config/`

[`anglerfish.config.models`](../src/anglerfish/config/models.py) is
the single source of truth. Every other module takes one of the
Pydantic models defined there. `load_settings()` reads
`/etc/anglerfish/anglerfish.env` via Pydantic Settings + dotenv.

Key models:

| Class                   | Purpose                                                              |
|-------------------------|----------------------------------------------------------------------|
| `AnglerfishSettings`    | Root. Aggregates every per-subsystem config.                         |
| `BridgeConfig`          | Bridge runtime: rate limits, prompt template, history window, shared secret. |
| `OllamaConfig`          | LLM endpoint, model tag, trusted-remote constraint, timeouts.        |
| `DashboardConfig`       | Host/port, session secret, admin user + bcrypt hash, allowed origins. |
| `CredentialsConfig`     | DB path + base64 AES key. Validators enforce a 32-byte key.          |
| `GeoConfig`             | MMDB paths + optional MaxMind licence key.                           |
| `SplunkConfig`          | HEC URL + token + JSONL fallback path.                               |
| `ThreatConfig`          | Alert threshold, webhook URL + timeout.                              |
| `FingerprintConfig`     | Tor-exit-list path + refresh interval.                               |

Secrets are `SecretStr`; logging them produces `**********`. The
encryption-key validator decodes base64 to confirm 32 bytes; the
admin-password-hash validator confirms a bcrypt prefix.

### 2.2 `bridge/`

The LLM middleware. Files:

| File                              | Responsibility                                                 |
|-----------------------------------|----------------------------------------------------------------|
| [`service.py`](../src/anglerfish/bridge/service.py) | `AIBridgeService` - the orchestrator. |
| [`client.py`](../src/anglerfish/bridge/client.py)   | `OllamaClient` - async HTTP client + JSON shapes. |
| [`prompts.py`](../src/anglerfish/bridge/prompts.py) | System-prompt template; appends sanitised user message. |
| [`sanitize.py`](../src/anglerfish/bridge/sanitize.py) | C0-control stripping + length cap (input + output). |
| [`rate_limit.py`](../src/anglerfish/bridge/rate_limit.py) | Per-session token bucket + global concurrency semaphore. |
| [`fallback.py`](../src/anglerfish/bridge/fallback.py) | Deterministic shell-error templates for the no-LLM path. |
| [`session.py`](../src/anglerfish/bridge/session.py) | `SessionContext` - cwd, history window, attacker metadata. |
| [`server.py`](../src/anglerfish/bridge/server.py)   | FastAPI app + bearer-token middleware. |
| [`errors.py`](../src/anglerfish/bridge/errors.py)   | Typed error hierarchy. |

Request lifecycle:

1. The lure's process handler intercepts an unknown command (one
   `NativeCommands` doesn't dispatch in-process). The Cowrie shell
   adapter takes the same path during the deprecation window.
2. The caller POSTs to the bridge with `X-Anglerfish-Protocol: 2`
   (lure) or `1` (Cowrie shim) and the bearer token. Connection is
   loopback only. The bridge accepts both protocol versions through
   the deprecation window.
3. The server middleware verifies the protocol version (426 on
   mismatch) and the bearer (constant-time compare; 401 on
   mismatch).
4. `AIBridgeService.handle_command`:
   * Calls `sanitize_command` (strips C0 ctrls except tab/LF; caps
     to `max_input_chars`).
   * Takes one slot from the per-session bucket + global semaphore;
     queues briefly if the global is full, returns a fallback if
     either gives up.
   * Builds messages via `build_messages` - system prompt is
     template-only (never interpolates attacker text), user message
     is the sanitised input.
   * Awaits `OllamaClient.chat`; on any exception falls back.
   * Caps the response silently (no marker).
   * Updates `SessionContext` history.

All structural defences are tested in
[`tests/bridge/test_prompt_injection.py`](../tests/bridge/test_prompt_injection.py).

### 2.3 `dashboard/`

FastAPI + WebSockets. Files:

| File                              | Responsibility                                                 |
|-----------------------------------|----------------------------------------------------------------|
| [`app.py`](../src/anglerfish/dashboard/app.py)     | `create_app` factory; wires SessionMiddleware + routers. |
| [`routes.py`](../src/anglerfish/dashboard/routes.py) | REST endpoints. Each is `Depends(require_auth)` except `/`, `/api/health`, `/api/login`, `/api/logout`, `/api/csrf`. |
| [`auth.py`](../src/anglerfish/dashboard/auth.py)   | bcrypt + signed cookie + HTTP Basic fallback. Routes `/api/login`, `/api/logout`, `/api/csrf`. |
| [`rate_limit.py`](../src/anglerfish/dashboard/rate_limit.py) | Per-IP token bucket for `/api/login`. |
| [`csrf.py`](../src/anglerfish/dashboard/csrf.py)   | Synchronizer-token helper for future state-changing endpoints. |
| [`websocket.py`](../src/anglerfish/dashboard/websocket.py) | `/ws/events` - origin check + auth check + per-client bounded queue. |
| [`state.py`](../src/anglerfish/dashboard/state.py) | In-memory pub/sub + bounded snapshot cache. |
| `templates/`, `static/`           | Jinja2 + JS for the SPA.                                       |

Auth model:

* **Open mode** (no `ADMIN_PASSWORD_HASH`): every endpoint is open;
  the page header shows a warning banner. Meant only for pre-wizard
  first boot. Basic auth is positively *rejected* in open mode -
  the dashboard can't validate when there's nothing to validate
  against.
* **Locked mode**: session cookie via `POST /api/login`, or HTTP
  Basic for tooling. The cookie is `SameSite=Strict`, `HttpOnly`,
  signed with `ANGLERFISH_DASHBOARD__SESSION_SECRET`.

Login is rate-limited by `LoginRateLimiter` (per-IP token bucket,
default 5 capacity + 1/12 s refill); 429 with `Retry-After` when
the bucket is empty. Successful login resets the bucket.

CSRF: `X-Anglerfish-CSRF` header validated against the session-bound
token from `GET /api/csrf`. The dashboard is JSON-only and SameSite
already kills cross-origin form rides; CSRF tokens land as
defence-in-depth.

WebSocket close codes: `4401` for missing/invalid auth, `4403` for
origin allowlist failure.

### 2.4 `forwarder/`

Splunk HEC + JSONL fallback.

| File                              | Responsibility                                                 |
|-----------------------------------|----------------------------------------------------------------|
| [`service.py`](../src/anglerfish/forwarder/service.py) | `Forwarder` - selects HEC; falls back to JSONL on failure. |
| [`hec.py`](../src/anglerfish/forwarder/hec.py)         | `SplunkHECClient` - async POSTs to `/services/collector/event`. |
| [`jsonl.py`](../src/anglerfish/forwarder/jsonl.py)     | Append-only writer with size-based rotation. |
| [`event.py`](../src/anglerfish/forwarder/event.py)     | `ForwarderEvent` envelope shared between backends. |
| [`factories.py`](../src/anglerfish/forwarder/factories.py) | Helpers to wrap session snapshots in events. |
| [`errors.py`](../src/anglerfish/forwarder/errors.py)   | Typed error hierarchy. |

The HEC token is `SecretStr`; only `get_secret_value()` is ever
written into the `Authorization` header. JSONL rotation defaults
to 100 MB and writes a stamped sibling file.

### 2.5 `threat/`

MITRE ATT&CK-tagged scoring.

| File                              | Responsibility                                                 |
|-----------------------------------|----------------------------------------------------------------|
| [`service.py`](../src/anglerfish/threat/service.py)     | `ThreatEngine` - orchestrator over scorer + alerter. |
| [`scorer.py`](../src/anglerfish/threat/scorer.py)       | Pure function: snapshot → `ThreatAssessment`. |
| [`techniques.py`](../src/anglerfish/threat/techniques.py) | Rule set: regex / keyword → ATT&CK technique ID + score. |
| [`alerter.py`](../src/anglerfish/threat/alerter.py)     | Idempotent webhook poster (one fire per session). |

The scorer is pure: same input → same output. The alerter is
best-effort: webhook timeouts are logged, never raised.

### 2.6 `credentials/`

Encrypted credential intelligence database.

| File                              | Responsibility                                                 |
|-----------------------------------|----------------------------------------------------------------|
| [`storage.py`](../src/anglerfish/credentials/storage.py) | `CredentialStore` - async SQLite with WAL. |
| [`crypto.py`](../src/anglerfish/credentials/crypto.py)   | `CredentialCipher` - AES-256-GCM with random 12-byte nonces. |
| [`rotation.py`](../src/anglerfish/credentials/rotation.py) | `rotate_key` - re-encrypts every row under a new key, atomic swap. |

Deduplication uses a HMAC-SHA-256 fingerprint over
`(source_ip, username, password)` so the dashboard can collapse
brute-force volleys without decrypting every row.

### 2.7 `fingerprint/`

| File                              | Responsibility                                                 |
|-----------------------------------|----------------------------------------------------------------|
| [`service.py`](../src/anglerfish/fingerprint/service.py) | `Fingerprinter` - composes the per-session record. |
| [`ssh.py`](../src/anglerfish/fingerprint/ssh.py)         | RFC 4253 banner parser. |
| [`hashes.py`](../src/anglerfish/fingerprint/hashes.py)   | JA3 + HASSH hash helpers. |
| [`tor.py`](../src/anglerfish/fingerprint/tor.py)         | Async-safe Tor-exit-list refresher. |

Tor exit list is refreshed every hour by default; failure to refresh
is logged and the previous list stays in effect.

### 2.8 `geo/`

| File                              | Responsibility                                                 |
|-----------------------------------|----------------------------------------------------------------|
| [`lookup.py`](../src/anglerfish/geo/lookup.py) | `GeoLookup` - async (via `to_thread`) wrapper over `maxminddb`. |
| [`fetch.py`](../src/anglerfish/geo/fetch.py)   | `fetch_geolite_databases` - SHA-verified MaxMind download. |

The fetcher refuses on SHA mismatch, on archive members with
parent-dir traversal, on archives exceeding a 200 MB ceiling, and
on archives without an `.mmdb` payload. The systemd unit
`anglerfish-geo-update.service` invokes the CLI subcommand
`anglerfish geo update`.

### 2.9 `wizard/`

First-boot Typer CLI. Files:

| File                              | Responsibility                                                 |
|-----------------------------------|----------------------------------------------------------------|
| [`__main__.py`](../src/anglerfish/wizard/__main__.py)   | Typer entrypoint + `--reconfigure`. |
| [`wizard.py`](../src/anglerfish/wizard/wizard.py)       | `prompt_for_answers` + `run_wizard` (orchestrator). |
| [`answers.py`](../src/anglerfish/wizard/answers.py)     | `WizardAnswers` + `WizardOutput` Pydantic models. Secrets never live here. |
| [`render.py`](../src/anglerfish/wizard/render.py)       | Renders env, nftables, cowrie.cfg, systemd-networkd, hostname, authorized_keys. |
| [`secrets.py`](../src/anglerfish/wizard/secrets.py)     | `generate_*` helpers for bridge secret, session secret, encryption key. |
| [`preflight.py`](../src/anglerfish/wizard/preflight.py) | Reachability probes for Ollama / Splunk / webhook. |
| [`persistence.py`](../src/anglerfish/wizard/persistence.py) | Atomic JSON save/load of `WizardAnswers` for `--reconfigure`. |
| [`network.py`](../src/anglerfish/wizard/network.py)     | Interface listing. |
| [`sshkey.py`](../src/anglerfish/wizard/sshkey.py)       | OpenSSH pubkey validator. |
| [`terms.py`](../src/anglerfish/wizard/terms.py)         | The responsible-use terms text. |

Every artefact write is atomic (`tmp + os.replace`). Secret-bearing
files land at `0600`, system config at `0640`, hostname at `0644`.

### 2.10 `cli/`

`anglerfish` entry point. Subcommands:

* `anglerfish config show` - dumps the loaded config with secrets
  masked. Useful for diagnosing wizard misconfig.
* `anglerfish bridge serve` - launches the bridge under uvicorn.
* `anglerfish credentials rotate-key` - see RUNBOOK §Credentials.
* `anglerfish geo update` - fetch GeoLite2; invoked by the systemd
  oneshot.
* `anglerfish banner` - the ASCII banner for terminal beautifying.

### 2.11 `audit.py`

Append-only JSONL audit log shared by every module. Each record:
`{ts, event_type, **fields}`. The file is opened, fsynced, closed
per write; the wrapper holds an `RLock` for thread safety. Failures
are caught and logged, never raised, because audit failures
should not stop honeypot operation.

### 2.12 `lure/` (Stage 2)

The native asyncssh SSH honeypot that replaced Cowrie. See
[`docs/design/STAGE_2_lure_subsystem.md`](design/STAGE_2_lure_subsystem.md)
for the full design.

* [`server.py`](../src/anglerfish/lure/server.py) - `LureServer`
  lifecycle wrapper, `_LureSSHServer` asyncssh subclass,
  `_process_handler` shell loop, per-IP rate limiter, bait-NIC
  validator.
* [`runner.py`](../src/anglerfish/lure/runner.py) - `run_lure`
  top-level coroutine; owns the dep graph + signal handlers.
* [`bridge_client.py`](../src/anglerfish/lure/bridge_client.py) -
  async HTTP client to `AIBridgeService` over loopback.
* [`commands.py`](../src/anglerfish/lure/commands.py) - native
  command dispatch (`whoami`, `id`, `pwd`, `ls`, `cd`, `uname`,
  `hostname`, `echo`, `cat`-of-known-paths, `history`, `exit`) plus
  `LatencyJitter` (per-process EWMA of bridge latency so native vs
  bridge response times are statistically indistinguishable).
* [`fakefs.py`](../src/anglerfish/lure/fakefs.py) - ~50-path static
  filesystem covering standard reconnaissance targets.
* [`keys.py`](../src/anglerfish/lure/keys.py) - RSA 4096 + Ed25519
  host-key generation, load, permission validation.
* [`config.py`](../src/anglerfish/lure/config.py) - `LureConfig`
  under `ANGLERFISH_LURE__*`. Default opt-out.
* [`http.py`](../src/anglerfish/lure/http.py) - `NotImplementedError`
  stub for the future HTTP/HTTPS lure (TODO-1).

The lure runs as a separate systemd unit from the bridge so a crash
in one process does not take the other down. Both run on the same
VM; the boundary is an HTTP call on loopback `:8421` with the
existing bearer token.

### 2.13 `integration/` (deprecated)

The Cowrie-side shim. Retained for the deprecation window so
operators upgrading in place can run both the lure and Cowrie. A
later commit deletes this module, the `cowrie/` directory, and the
related tests.

* [`cowrie.py`](../src/anglerfish/integration/cowrie.py) - Cowrie
  output plugin. Translates Cowrie events to bridge calls.
* [`cowrie_shell.py`](../src/anglerfish/integration/cowrie_shell.py)
  - sync HTTP client wrapper for the bridge (protocol v1).
* [`cowrie_shell_adapter.py`](../src/anglerfish/integration/cowrie_shell_adapter.py)
  - runtime monkey-patch of `HoneyPotShell.lineReceived` that
  intercepts unknown commands.

The patch ships two ways: a source patch under
[`cowrie/patches/`](../cowrie/patches/) applied at ISO-build time,
and the runtime monkey-patch as belt-and-braces. If both fail, the
honeypot still works, attackers see Cowrie's static replies, no
LLM.

---

## 3. IPC and protocols

### 3.1 Cowrie → bridge

* Loopback HTTP (`127.0.0.1:8421`).
* Bearer-token auth on every endpoint except `/api/health`.
* Protocol version header `X-Anglerfish-Protocol: 1`.
* JSON request bodies; responses are JSON envelopes carrying
  `text`, `source`, `latency_ms`.

### 3.2 Bridge → Ollama

* HTTP (loopback or one configured trusted IP).
* JSON to `/api/chat`. The bridge pins the model tag and history
  window from config.
* Timeout: `OllamaConfig.timeout_s` (default 30 s).
* No streaming: simpler error handling, modest latency cost.

### 3.3 Bridge → Splunk HEC

* HTTPS to the configured HEC URL.
* `Authorization: Splunk <token>` header.
* JSON event envelopes from `forwarder.event`.
* Failure ⇒ JSONL fallback; the forwarder records
  `forwarder.fallback_engaged` to the audit log.

### 3.4 Dashboard → bridge state

The dashboard does **not** call back into the bridge. The bridge
publishes events to `DashboardState` (in-process), and the dashboard
reads from it. This keeps the dashboard a pure consumer, restarts
of the dashboard don't perturb the bridge.

### 3.5 Dashboard ↔ browser

* HTTP for REST. JSON only.
* WebSocket at `/ws/events` for the live stream. The browser must
  send `Origin:` matching the configured allowlist; otherwise it
  receives close code `4403`.
* Auth via signed session cookie (browser) or HTTP Basic (tooling).
* CSRF token via `GET /api/csrf` + `X-Anglerfish-CSRF` header on
  any future state-changing call.

---

## 4. Trust boundaries

| Boundary                          | Direction      | Posture                                                                 |
|-----------------------------------|----------------|-------------------------------------------------------------------------|
| Bait NIC → Cowrie                 | inbound        | Untrusted. Everything beyond Cowrie's parser treats the input as hostile. |
| Cowrie → bridge                   | loopback only  | Trusted authentication via bearer token + protocol version.             |
| Bridge → Ollama                   | one IP literal | Trusted because it's loopback or a single operator-controlled IP.       |
| Bridge → Splunk HEC               | service NIC    | Trusted (operator infrastructure). HEC token is a `SecretStr`.          |
| Bridge → threat webhook           | service NIC    | Trusted; failures are logged, not retried.                              |
| Bridge → DashboardState           | in-process     | Trusted; no network boundary.                                           |
| Operator → dashboard              | service NIC    | Authenticated. Rate-limited login. CSRF + SameSite cookie.              |
| Operator → SSH on service NIC     | service NIC    | Authenticated; ED25519 pubkey only.                                     |
| MaxMind                           | egress         | Trusted via SHA-256 manifest verification on every download.            |
| Wizard → operator                 | tty1           | One-shot, atomic writes. The wizard refuses to run twice (`ConditionPathExists`). |

The honeypot's threat model is: **assume Cowrie is owned**.
Anglerfish's job is to make sure that buying Cowrie doesn't buy the
LLM, the credentials DB, the operator's network, or the Proxmox
management plane.

---

## 5. Persistence

| Path                                       | Owner             | Mode | What                                                  |
|--------------------------------------------|-------------------|------|--------------------------------------------------------|
| `/etc/anglerfish/anglerfish.env`           | root              | 0600 | Bearer secret + AES key + session secret + admin hash. |
| `/etc/anglerfish/wizard.json`              | root              | 0600 | Operator answers - secrets are **not** persisted here. |
| `/etc/anglerfish/nftables/anglerfish.nft`  | root              | 0640 | Firewall ruleset.                                      |
| `/etc/anglerfish/cowrie.cfg`               | root              | 0640 | Cowrie config (rendered from template).                |
| `/etc/systemd/network/10-bait.network`     | root              | 0644 | systemd-networkd for the bait NIC.                     |
| `/etc/systemd/network/20-service.network`  | root              | 0644 | systemd-networkd for the service NIC.                  |
| `/var/lib/anglerfish/credentials.db`       | anglerfish        | 0600 | SQLite + AES-GCM rows.                                 |
| `/var/lib/anglerfish/sessions.jsonl`       | anglerfish        | 0600 | Splunk JSONL fallback / session capture.               |
| `/var/lib/anglerfish/geo/GeoLite2-*.mmdb`  | anglerfish        | 0644 | MaxMind databases.                                     |
| `/var/log/anglerfish/audit.jsonl`          | anglerfish        | 0640 | Append-only operator audit trail.                      |
| `/opt/anglerfish/venv/`                    | root              | 0755 | The Python venv; immutable post-install.               |
| `/home/anglerfish-ops/.ssh/authorized_keys`| anglerfish-ops    | 0600 | Operator pubkey (single line).                         |

`wizard.json` and `anglerfish.env` are intentionally split: the
former is the operator's answer set that we can replay on
`--reconfigure`; the latter holds the generated secrets that must
**not** be reused across reconfigurations.

---

## 6. Observability

* **`journalctl -u <unit>`** for service stdout/stderr. The bridge
  emits structured log lines (`key=value`) suitable for log scraping.
* **`/var/log/anglerfish/audit.jsonl`** for operator-facing events.
* **Splunk HEC** for session-level intelligence; JSONL fallback if
  HEC is unreachable.
* **Dashboard `/api/stats`** for in-memory aggregates over the
  recent session window.
* **`anglerfish config show`** for the loaded configuration with
  secrets masked.

There is no metrics endpoint (no Prometheus exporter) at present.
Operators who want time-series should consume the Splunk feed.

---

## 7. Where to look when

| Symptom                                          | First file to open                                                       |
|--------------------------------------------------|--------------------------------------------------------------------------|
| LLM responses look wrong                         | [`bridge/prompts.py`](../src/anglerfish/bridge/prompts.py)               |
| Attacker input bypassed sanitisation             | [`bridge/sanitize.py`](../src/anglerfish/bridge/sanitize.py)             |
| Rate limit blocks too aggressively               | [`bridge/rate_limit.py`](../src/anglerfish/bridge/rate_limit.py)         |
| Bridge crashing on Ollama errors                 | [`bridge/client.py`](../src/anglerfish/bridge/client.py) + `errors.py`   |
| Dashboard rejects valid login                    | [`dashboard/auth.py`](../src/anglerfish/dashboard/auth.py)               |
| `429 Too Many Requests` on dashboard login       | [`dashboard/rate_limit.py`](../src/anglerfish/dashboard/rate_limit.py)   |
| WebSocket closes immediately                     | [`dashboard/websocket.py`](../src/anglerfish/dashboard/websocket.py)     |
| Credentials don't decrypt                        | [`credentials/crypto.py`](../src/anglerfish/credentials/crypto.py)       |
| Geo enrichment empty                             | [`geo/lookup.py`](../src/anglerfish/geo/lookup.py)                       |
| Threat alerts not firing                         | [`threat/alerter.py`](../src/anglerfish/threat/alerter.py)               |
| Splunk events stuck in JSONL                     | [`forwarder/hec.py`](../src/anglerfish/forwarder/hec.py)                 |
| Wizard wrote a wrong file                        | [`wizard/render.py`](../src/anglerfish/wizard/render.py)                 |
| ISO doesn't include a hook                       | [`iso/config/hooks/normal/`](../iso/config/hooks/normal/)                |
| systemd unit picks up the wrong path             | [`systemd/`](../systemd/)                                                |
