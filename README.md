<p align="center">
  <img src="assets/anglerfish-banner.png" alt="Anglerfish AI" width="100%" />
</p>

# Anglerfish AI

> AI-powered SSH honeypot. Deep-sea threat intelligence.

Anglerfish AI is a self-contained honeypot operating system. Boot the ISO,
complete the first-boot wizard, and an AI-driven SSH honeypot is running
in minutes. Attackers see a convincing fake Debian shell driven by a local
LLM. You see structured intelligence in Splunk, a live dashboard, a
MITRE ATT&CK-tagged threat timeline, and an encrypted credential database.

---

## ⚠️ Legal and ethical use

**Anglerfish AI is a defensive security research tool. By using it you
agree to the following:**

1. **Deploy only on networks you own or have explicit, written
   authorisation to operate a honeypot on.** Operating a honeypot on a
   third-party network may constitute unauthorised access,
   wiretapping, or computer fraud in your jurisdiction.
2. **You are responsible for compliance** with your local laws and the
   acceptable-use policies of your hosting provider, network operator,
   and registrar.
3. **Captured credentials, payloads, and shell sessions are sensitive
   data.** Treat them as such. They may include real credentials
   inadvertently submitted by misconfigured automation. The credential
   database is encrypted at rest with AES-GCM; do not export it in
   plaintext.
4. **No warranty.** Anglerfish AI is provided "AS IS"; see
   [LICENSE](LICENSE).

The first-boot wizard requires explicit acknowledgement of these terms
before any service is enabled.

---

## Architecture

```
                  ┌──────────────────────────────────────────────────────┐
                  │              ANGLERFISH AI VM                        │
                  │                                                      │
   bait NIC ──────┤  Lure (native asyncssh on :2222 by default)          │
   (hostile)      │      │  (Stage 2 - replaces Cowrie; both can run     │
                  │      │   side-by-side during the deprecation window) │
                  │      │ unknown commands  (HTTP, loopback :8421)      │
                  │      v                                               │
                  │  Bridge HTTP server                                  │
                  │      │                                               │
                  │      v                                               │
                  │  AIBridgeService ── sanitize → rate-limit → prompt   │
                  │      │              → Ollama → cap → fallback        │
                  │      v                                               │
                  │  ┌─────────────┐                                     │
                  │  │ Ollama LLM  │ <──── loopback or trusted IP ───── service NIC
                  │  └─────────────┘       (deepseek-coder default)      │
                  │      │                                               │
                  │      v                                               │
                  │  Threat engine ── MITRE ATT&CK tagger ── webhook     │
                  │      │                                               │
                  │      v                                               │
                  │  Forwarder ──► Splunk HEC  (JSONL fallback on disk)  │
                  │      │                                               │
                  │      v                                               │
                  │  Dashboard (FastAPI + WebSockets) ─── operator UI ── service NIC
                  │      │                                               │
                  │      v                                               │
                  │  Credentials DB (SQLite + AES-GCM, dedup via HMAC)   │
                  │  Fingerprinter (SSH banner, JA3, HASSH, Tor exits)   │
                  │  Geo lookup (MaxMind GeoLite2)                       │
                  └──────────────────────────────────────────────────────┘
```

The honeypot VM has two network interfaces:

* **Bait**: exposed to hostile traffic. Runs the lure SSH listener
  (Stage 2, native asyncssh) on the configured port. The Cowrie
  ports stay accepted through the deprecation window. Egress is
  dropped at nftables level except for DNS.
* **Service**: private, firewalled. Reaches Ollama (loopback or a
  single trusted IP), Splunk HEC, and the operator dashboard. Nothing
  else.

A compromised Anglerfish must not be able to pivot to other systems.
nftables rules generated at first boot enforce that egress on the
service interface is restricted to the configured Ollama, Splunk, and
dashboard endpoints only. See [`cowrie/nftables/anglerfish.nft`](cowrie/nftables/anglerfish.nft).

---

## Components

| Component       | Status        | Purpose                                                            |
| --------------- | ------------- | ------------------------------------------------------------------ |
| `config/`       | **shipped**   | Pydantic configuration models + settings loader                    |
| `bridge/`       | **shipped**   | Sanitise / rate-limit / Ollama client / fallback / orchestrator / HTTP server |
| `forwarder/`    | **shipped**   | Splunk HEC + atomic JSONL fallback with rotation                   |
| `threat/`       | **shipped**   | MITRE ATT&CK technique tagging + scorer + webhook alerter          |
| `fingerprint/`  | **shipped**   | SSH banner parser + JA3/HASSH hash helpers + Tor exit list         |
| `geo/`          | **shipped**   | MaxMind GeoLite2 wrapper (async via `to_thread`)                   |
| `credentials/`  | **shipped**   | SQLite + AES-GCM encrypted credential intelligence DB              |
| `dashboard/`    | **shipped**   | FastAPI + WebSocket UI with deep-sea bioluminescent theme          |
| `wizard/`       | **shipped**   | First-boot Typer wizard, generates secrets, writes `.env`          |
| `cli/`          | **shipped**   | `anglerfish` and `anglerfish-wizard` entry points + ASCII banner   |
| `models/`       | **shipped**   | Shared session / response / threat / fingerprint / geo / credential types |
| `lure/`         | **shipped**   | Native asyncssh SSH honeypot (Stage 2 replacement for Cowrie)      |
| `integration/`  | **deprecated** | Cowrie output-plugin shim (removed after the lure deprecation window) |
| `cowrie/`       | **deprecated** | Cowrie config template + output plugin (lure listener is the new default) |
| `iso/`          | **shipped**   | live-build recipe, hooks, build script                             |
| `systemd/`      | **shipped**   | Hardened unit files for every long-running service                 |

Every shipped Python module is gated on `ruff`, `mypy --strict`, and
`pytest --cov-fail-under=90`.

---

## Documentation

| Document                                         | What it covers                                                         |
| ------------------------------------------------ | ---------------------------------------------------------------------- |
| [`docs/PRODUCT.md`](docs/PRODUCT.md)             | Thesis, design principles, the seven capabilities, non-goals |
| [`docs/ROADMAP.md`](docs/ROADMAP.md)             | Eleven-stage build plan from foundation to full adaptive-deception     |
| [`docs/design/TEMPLATE.md`](docs/design/TEMPLATE.md) | Template each stage's design doc fills in before code is written       |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)   | Module-by-module walkthrough, IPC boundaries, where to look when       |
| [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md) | Bridge + dashboard REST endpoints, WebSocket protocol, integration examples |
| [`docs/INSTALL.md`](docs/INSTALL.md)             | Prerequisites, ISO + Proxmox/QEMU deployment, wizard walkthrough       |
| [`docs/MODEL_SETUP.md`](docs/MODEL_SETUP.md)     | Local LLM install: hardware sizing, Ollama tuning, three-tier model stack, integrity hashes |
| [`docs/proxmox.md`](docs/proxmox.md)             | Proxmox-specific bridge prep, VM config, GPU passthrough, snapshots    |
| [`docs/proxmox-lab.md`](docs/proxmox-lab.md)     | Strict-lab variant: air-gapped bait bridge, PCAP capture, snapshot/reset workflow |
| [`docs/PRE_DEPLOY_CHECKLIST.md`](docs/PRE_DEPLOY_CHECKLIST.md) | Top-to-bottom verification before exposing to attacker traffic         |
| [`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md) | Playbook for pivot, breach, audit-log gap, upstream CVE                |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md)             | Day-2 ops: credentials rotation, geo updates, 7 recovery scenarios     |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)   | STRIDE table, trust boundaries, crypto inventory, known limitations    |
| [`SECURITY.md`](SECURITY.md)                     | Vulnerability disclosure policy, supported versions, scope             |
| [`CONTRIBUTING.md`](CONTRIBUTING.md)             | Quality gates, branch/commit style, PR checklist                       |

---

## Quick start (development)

### Prerequisites

* Python 3.11+
* `pip` and `venv`
* For live LLM testing: a reachable Ollama instance (loopback or a
  trusted-remote IP)

### Install

```bash
git clone https://github.com/retr0verride/Anglerfish-AI.git
cd Anglerfish-AI

python3.11 -m venv .venv
source .venv/bin/activate                    # PowerShell: .\.venv\Scripts\Activate.ps1

pip install -e ".[dev]"
pre-commit install --install-hooks
```

### Run the quality gates

The pipeline is the source of truth. Every commit must pass these:

```bash
ruff check .
ruff format --check .
mypy
pytest                  # enforces --cov-fail-under=90
```

`pre-commit run --all-files` runs all of the above in one go.

### Inspect configuration

```bash
export ANGLERFISH_DASHBOARD__SESSION_SECRET="$(openssl rand -base64 32)"
export ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY="$(openssl rand -base64 32)"

anglerfish banner
anglerfish config show
anglerfish --version
```

### Run the bridge against a local Ollama

```bash
anglerfish bridge serve --host 127.0.0.1 --port 8421
```

### Run the dashboard against an empty state

```bash
uvicorn --factory anglerfish.dashboard.app:create_app \
        --host 127.0.0.1 --port 8420
```

### Run the first-boot wizard manually

```bash
anglerfish-wizard run --env /tmp/anglerfish.env
```

---

## Configuration reference

Configuration is read from environment variables prefixed `ANGLERFISH_`,
with `__` as the nested-section delimiter. A `.env` file in the working
directory is also honoured. See [`.env.example`](.env.example) for the
full list.

Two values are **required** with no default and must be supplied by
the operator (the first-boot wizard generates them):

| Variable                                  | Format                       |
| ----------------------------------------- | ---------------------------- |
| `ANGLERFISH_DASHBOARD__SESSION_SECRET`    | ≥32-character string         |
| `ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY`  | base64-encoded 32-byte key   |

### Ollama endpoint policy

The Ollama endpoint host is validated at config time:

* **Always accepted:** any loopback IP (`127.0.0.0/8`, `::1`) and the
  literal hostname `localhost`.
* **Conditionally accepted:** an IP literal (and **only** an IP
  literal) that matches the value of
  `ANGLERFISH_OLLAMA__TRUSTED_REMOTE_HOST`.
* **Always rejected:** every other hostname (including DNS names that
  happen to resolve to a trusted IP), every non-matching IP, and the
  unspecified address `0.0.0.0`.

This is a structural property. There is no override flag.

---

## Threat model and security boundaries

* **The honeypot is a target.** Attacker input is length-capped and
  stripped of C0 control characters before reaching a prompt template;
  every model response is silently capped to a configured maximum.
* **The LLM is untrusted.** Prompt injection from attacker commands is
  mitigated structurally: the attacker's text always lives in its own
  user message, and the system prompt instructs the model to treat any
  user message as a shell command, not as instructions.
* **Rate limiting is mandatory.** The bridge enforces a global
  concurrency cap plus a per-session token bucket. When either fires,
  the attacker still receives a plausible response (drawn from the
  scripted fallback set) so the limiter cannot be used as a probe.
* **Credentials are encrypted at rest.** AES-GCM under a key supplied
  via `ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY`. Deduplication uses
  HMAC-SHA256 fingerprints under a separate key derived from the
  master, so unique-counts and equality lookups never touch the
  plaintext.
* **Service network is one-way egress.** nftables rules allow
  connections only to the configured Ollama, Splunk HEC, and dashboard
  endpoints. Bait-interface egress is dropped entirely (except DNS).
* **systemd hardening.** Every long-running unit uses
  `ProtectSystem=strict`, `NoNewPrivileges`, an explicit
  `SystemCallFilter`, a minimised `CapabilityBoundingSet`, and
  `PrivateTmp`.

---

## MITRE ATT&CK coverage

The default rule set tags the following techniques. Add more by
constructing a custom `TechniqueRule` tuple and passing it to
`score_session`.

| Technique  | Description                                |
| ---------- | ------------------------------------------ |
| T1003      | OS Credential Dumping                      |
| T1016      | System Network Configuration Discovery     |
| T1018      | Remote System Discovery                    |
| T1033      | System Owner/User Discovery                |
| T1046      | Network Service Scanning                   |
| T1049      | System Network Connections Discovery       |
| T1053      | Scheduled Task/Job (persistence)           |
| T1057      | Process Discovery                          |
| T1059.004  | Unix Shell                                 |
| T1070      | Indicator Removal on Host                  |
| T1071      | Application Layer Protocol                 |
| T1082      | System Information Discovery               |
| T1083      | File and Directory Discovery               |
| T1098      | Account Manipulation (persistence)         |
| T1105      | Ingress Tool Transfer                      |
| T1136      | Create Account (persistence)               |
| T1496      | Resource Hijacking (cryptominers)          |
| T1543      | Create or Modify System Process (persistence) |

Sessions that touch persistence techniques get a +20 score bonus and
flip the `persistence_attempted` flag, which is what the alerter
watches.

---

## ISO build

```bash
sudo apt install live-build debootstrap squashfs-tools xorriso \
                 isolinux syslinux-common

sudo cp -r . /tmp/anglerfish-ai
sudo ./iso/build.sh
```

Produces `iso/build/anglerfish-ai-<version>.iso` plus a `.sha256`
checksum. See [`iso/README.md`](iso/README.md) for full details.

The ISO boots directly into a text console and runs the first-boot
wizard on tty1 before any networked service comes up.

---

## Repository layout

```
Anglerfish-AI/
├── src/anglerfish/
│   ├── bridge/           # Ollama AI middleware + rate limiting + HTTP server
│   ├── forwarder/        # Splunk HEC forwarding + JSONL fallback
│   ├── dashboard/        # FastAPI + WebSocket UI + templates + static
│   ├── threat/           # Threat scoring + MITRE ATT&CK tagging + alerter
│   ├── fingerprint/      # SSH/JA3/HASSH + Tor exit list
│   ├── geo/              # MaxMind GeoLite2 wrapper
│   ├── credentials/      # AES-GCM encrypted credential intelligence DB
│   ├── config/           # Pydantic config models
│   ├── models/           # Shared runtime data models
│   ├── wizard/           # First-boot configuration wizard
│   ├── lure/             # Native asyncssh SSH lure (Stage 2)
│   ├── integration/      # Cowrie output-plugin shim (deprecated)
│   └── cli/              # Entry points + ASCII banner
├── tests/                # pytest test suite (≥90% coverage gate)
├── cowrie/               # Cowrie cfg template + output plugin + nftables
├── iso/                  # live-build recipe + hooks + build script
├── systemd/              # Hardened systemd unit files
├── assets/               # SVG icon, ASCII art
├── docs/                 # Architecture diagrams, docs
├── pyproject.toml
├── .pre-commit-config.yaml
└── README.md
```

---

## Contributing

Before opening a PR:

1. Run `pre-commit run --all-files`. It catches every blocking issue
   locally. CI is a safety net, not a triage queue.
2. Public functions need full type signatures. Mypy runs in strict
   mode. `# type: ignore` is allowed only with an error code and a
   one-line reason.
3. No placeholder code on `main`. Either ship the implementation with
   tests or remove the module.
4. Put tests next to the subsystem they cover. Bridge tests in
   `tests/bridge/`, config tests in `tests/config/`, and so on.
5. For security-critical changes, include a threat-model note in the
   PR description: what changed, what is now newly trusted, and how
   that trust is bounded.

---

## Disclosure on implementation

Anglerfish AI is architected by a human and implemented with the
assistance of Claude Code (Anthropic). Every file is reviewed before
it lands. The quality pipeline (`ruff`, `mypy --strict`,
`pytest --cov-fail-under=90`) is what decides whether code ships, not
the assistant's confidence. Pull requests are held to the same gate.

---

## License

[MIT](LICENSE) © 2026 Anglerfish AI contributors
