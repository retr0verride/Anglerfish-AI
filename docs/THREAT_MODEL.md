# Anglerfish AI — Threat Model

This document is the source of truth for what Anglerfish AI trusts, what
it doesn't, and how each trust boundary is enforced. It uses the
[STRIDE](https://en.wikipedia.org/wiki/STRIDE_model) categorisation
(Spoofing, Tampering, Repudiation, Information disclosure, Denial of
service, Elevation of privilege). Read this before opening a security
PR — the PR template references the model.

---

## Scope

| In scope | Out of scope |
|---|---|
| The Anglerfish AI Python package | Cowrie (upstream) |
| The first-boot wizard, systemd units, nftables ruleset | Ollama (upstream) |
| The live-build ISO recipe | Splunk Enterprise / Cloud |
| Operator-facing dashboard (REST + WebSocket) | The Linux kernel + Debian base |
| Bridge HTTP API (loopback) | MaxMind databases |

---

## Trust boundaries

```
                                  ┌─────────────────┐
                       Internet ──│  bait NIC       │
                                  └──────┬──────────┘
                                         │ DROP (nftables, only :22)
                                         │ except DNS egress
        ┌────────────────────────────────┼──────────────────────────┐
        │  ANGLERFISH VM                 │                          │
        │                                │                          │
        │  ┌───────────────────┐    ┌────▼────┐                     │
        │  │  Cowrie (Twisted) │────│ bridge  │  loopback only      │
        │  │  attacker shell   │    │ HTTP API│  + shared-secret    │
        │  └───────────────────┘    └────┬────┘    Bearer token     │
        │                                │                          │
        │  ┌───────────────────────────  │                          │
        │  │  AIBridgeService            │                          │
        │  │  + sanitise + rate-limit    │                          │
        │  │  + prompt template          │                          │
        │  │  + fallback                 │                          │
        │  └─────┬─────────────────┬─────┘                          │
        │        │                 │                                │
        │        ▼                 ▼                                │
        │   ┌────────┐         ┌──────────┐                         │
        │   │ Ollama │         │ Forwarder│ ──► Splunk HEC          │
        │   │ (loopb.│         │ JSONL fb │                         │
        │   │  or IP)│         └──────────┘                         │
        │   └────────┘                                              │
        │                                                           │
        │   ┌─────────────────────────────┐                         │
        │   │ Credentials DB (AES-GCM)    │                         │
        │   └─────────────────────────────┘                         │
        │                                                           │
        │   ┌─────────────────────────────┐                         │
        │   │ Dashboard (bcrypt + cookie) │  service NIC only       │
        │   │  /api/login, /ws/events     │  nftables-restricted    │
        │   └─────────────────────────────┘                         │
        └───────────────────────────────────────────────────────────┘
                                         │ ONLY :11434, :8088, dashboard port
                                         │ (nftables egress allow-list)
                                  ┌──────▼──────────┐
                       Operator ──│  service NIC    │── Splunk, Ollama, etc.
                                  └─────────────────┘
```

**Hostile zones** (attacker controls):
* Inbound traffic on the bait NIC.
* Anything inside Cowrie's faked filesystem / shell output.
* Anything the LLM produces (we don't trust the model).

**Trusted zones** (operator controls):
* The service NIC.
* The operator's browser session (after authenticated login).
* The Ollama instance (loopback) or the operator-configured trusted IP.
* The Splunk HEC endpoint the operator configured.

---

## STRIDE table

### Spoofing

| Threat | Surface | Mitigation |
|---|---|---|
| Attacker impersonates a legitimate Cowrie shell command to the bridge | `POST /api/v1/session/{id}/command` | (1) Bridge binds 127.0.0.1 only; (2) `Authorization: Bearer <shared_secret>` middleware with constant-time compare; (3) `X-Anglerfish-Protocol: 1` header check (426 on mismatch). |
| Attacker impersonates the operator over the dashboard | Dashboard REST + WebSocket | bcrypt-hashed password gate on `/api/login`; session cookie is `HttpOnly`, `SameSite=Strict`, signed with `session_secret` via `itsdangerous`. WebSocket upgrade re-checks the same cookie. |
| Cross-origin WebSocket subscription from a malicious page in the operator's browser | `/ws/events` | `Origin` header allow-list; missing or non-matching origin → close 4403. |
| Attacker tampers with the LLM endpoint (DNS rebinding) | Ollama config | Pydantic `OllamaConfig._validate_endpoint_host` rejects hostnames other than `localhost` even when `trusted_remote_host` is set. IP literal required. |

### Tampering

| Threat | Surface | Mitigation |
|---|---|---|
| Attacker tampers with captured commands en route to Splunk | Forwarder HEC submission | TLS to Splunk by default (`verify_tls=True`); HEC token in `Authorization` header; integrity is Splunk's responsibility on the wire. |
| Attacker modifies the credentials database file | `/var/lib/anglerfish/credentials.db` | File mode 0600 (POSIX). AES-GCM authentication tags detect modification on decrypt — tampered rows yield `ValueError`s the store silently drops on read. |
| Attacker rewrites the env file to redirect Ollama to attacker-controlled host | `/etc/anglerfish/anglerfish.env` | Mode 0600; only `root` can write. Even with write access, the loopback / trusted-IP validator at load time blocks the swap. |
| Attacker injects keys into the operator's authorized_keys via wizard input | `WizardAnswers.operator_ssh_pubkey` | `parse_ssh_pubkey` rejects any input containing `\n` or `\r`; whitelisted key types; bounded base64 length. |
| Attacker tampers with the audit log | `/var/log/anglerfish/audit.jsonl` | Append-only by convention. Operators wanting WORM should layer `chattr +a` or an external store. (Acknowledged limitation — we do not enforce write-once at the FS layer.) |

### Repudiation

| Threat | Surface | Mitigation |
|---|---|---|
| Operator claims they didn't rotate the credentials key | `anglerfish credentials rotate-key` | Records `credentials.key_rotated` in the audit log with row counts and backup path. |
| Operator claims they didn't log in (insider threat) | `/api/login` | `dashboard.login_success` and `dashboard.login_failure` audit records with source IP and username. |
| Operator claims a high-severity alert wasn't fired | Threat engine alerter | (Phase 9 wiring) `threat.alert_fired` audit record. |
| Wizard run history is unrecoverable | First-boot / `--reconfigure` | `wizard.run` audit record per execution. `wizard.json` itself persists the answer set, separately readable. |

### Information disclosure

| Threat | Surface | Mitigation |
|---|---|---|
| Credentials leak to disk in plaintext | Credentials DB | AES-256-GCM at rest; the AES key never persists in `WizardAnswers` (regenerated each wizard run). Tests assert env-file secrets do not appear in `wizard.json`. |
| Operator password leak from configuration backup | `anglerfish.env` | Stored as bcrypt hash only. The wizard never persists plaintext. |
| LLM leaks honeypot identity to the attacker | Bridge response | (1) Sanitised system prompt instructs the LLM not to acknowledge being a model / honeypot; (2) the bridge silently caps the response and never reveals when truncation happened; (3) reserved-marker regex in tests pins a regression target; (4) prompt-injection corpus in `tests/bridge/test_prompt_injection.py` exercises structural defences. We do not claim the LLM cannot be tricked, only that the bridge structurally separates system + user content. |
| Dashboard discloses session data to unauthenticated peers | `/api/*` | All endpoints except `/`, `/api/health`, `/api/login`, `/api/logout` require `Depends(require_auth)`. WebSocket upgrade re-checks. Open-mode is supported with an explicit warning — meant only for first-boot before the wizard runs. |
| Bridge endpoint discloses bridge's session UUIDs to unauthorised callers | `GET /api/v1/sessions` | Bearer-token middleware; loopback bind. |
| Forwarder error logs the operator's HEC token | Forwarder error path | `SplunkConfig.hec_token` is `SecretStr`; never `repr()`d into log lines. Code passes `.get_secret_value()` only when constructing the outbound header. |

### Denial of service

| Threat | Surface | Mitigation |
|---|---|---|
| Attacker floods Cowrie with commands to exhaust the LLM | Bridge command path | Two-layer rate limit: per-session token bucket + global concurrency semaphore in `BridgeRateLimiter`. When either trips, the attacker receives a scripted fallback response — the limiter is invisible. |
| Attacker pumps long commands to exhaust prompt budget | Bridge sanitiser | `sanitize_command` caps input at `bridge.max_input_chars` (4096 by default). |
| Attacker pumps long lines to fill disk via captured commands | JSONL fallback / session history | `JsonlSink` size-based rotation. Session history bounded by `bridge.history_window` (20 by default). |
| Attacker DoSes the dashboard via repeated logins | `/api/login` | bcrypt cost factor itself rate-limits credential checks. (Phase 4 wiring will add a per-IP token bucket as defence-in-depth.) |
| Attacker exhausts file descriptors via WebSocket connections | `/ws/events` | Per-subscriber bounded queue; slow consumers drop oldest events; max-active-session cap on `DashboardState`. |

### Elevation of privilege

| Threat | Surface | Mitigation |
|---|---|---|
| Attacker breaks out of the AI shell into real Cowrie commands | Cowrie integration | Cowrie's command registry is the fallback path; the LLM does not get to invoke arbitrary code. Cowrie's existing privilege model applies. |
| Compromised Cowrie pivots to the service network | Network egress | nftables rules drop all bait-NIC egress except DNS. Service NIC egress is allow-listed to Ollama, Splunk HEC, and the dashboard port only. |
| Compromised bridge calls Ollama with arbitrary endpoint | Ollama config | Loopback or one configured IP literal — enforced at Pydantic validation time. |
| Attacker uses Cowrie shell to write authorized_keys | Cowrie | Cowrie's fake filesystem is in-memory; operators don't ship persistence on the bait NIC. (Threat-engine `T1098` flags it for review regardless.) |
| Wizard runs as root and writes attacker-controlled paths | Wizard | All output paths validated; interface names rejected on quote injection in `render_nftables`. The wizard does not accept arbitrary path overrides on first boot (only on `--reconfigure` via explicit CLI flags). |
| Operator account elevates to root via sudo without audit | Operator SSH | The wizard creates `anglerfish-ops` as a non-root account. `sudo` membership is the operator's choice; we recommend `sudo` with logging. |

---

## Untrusted-input handling — checklist

Every code path that receives attacker-controlled data must observe the checklist. New code goes through it during review.

* **Sanitised before reaching a prompt template?** `sanitize_command` strips C0 controls and caps length.
* **Wrapped in its own role?** Attacker text only appears in a `role="user"` message; never substituted into the system prompt.
* **Capped on the way out?** Model responses go through `cap_output` before reaching the attacker.
* **Logged for forensics?** Every command turn lands in `CommandTurn` with timestamp + latency.
* **Encrypted at rest?** Credentials specifically; sessions are integrity-relevant but not secret.

---

## Crypto inventory

| Use | Algorithm | Key size | Construction |
|---|---|---|---|
| Credential record at-rest | AES-GCM | 256-bit | Fresh 12-byte nonce per record. `cryptography.hazmat.primitives.ciphers.aead.AESGCM`. |
| Credential dedup fingerprint | HMAC-SHA-256 | 256-bit | Key derived from the master AES key via `HMAC(master, "anglerfish-credentials-fingerprint-v1")`. |
| Dashboard session cookie | itsdangerous (Starlette) | ≥ 256-bit signing secret | `SessionMiddleware`. |
| Bridge bearer secret | URL-safe random | 256-bit | `secrets.token_urlsafe(32)`. Constant-time compared via `hmac.compare_digest`. |
| Operator login | bcrypt | cost ≥ default | `bcrypt.gensalt()` default cost. |
| ISO release signing | sigstore / cosign | (sigstore PKI) | Keyless OIDC via GitHub Actions. |

---

## Known limitations (acknowledged, not yet mitigated)

1. **Audit log is not write-once at the FS layer.** A root attacker can `cat /dev/null > audit.jsonl`. Operators wanting WORM should layer `chattr +a` or write to an external WORM target.
2. **No dashboard CSRF tokens.** Current state is read-only; when state-changing endpoints land, CSRF tokens will too. Tracked in Phase 4.
3. **Per-IP login rate limiting** falls back on bcrypt cost. A dedicated bucket lands in Phase 4.
4. **LLM is untrusted.** A sufficiently capable jailbreak attempt may extract "I am an AI" from the model. The bridge limits blast radius (output cap, fallback fall-through), but we do not claim model robustness.
5. **No supply-chain attestation on Python deps.** `pip install` is trusted to deliver upstream-published artefacts. Renovate / pip-audit are the current defence.

---

## Reporting

See [SECURITY.md](../SECURITY.md). Disclose privately to **retroverride@pm.me**.
