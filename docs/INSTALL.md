# Installing Anglerfish AI

This guide walks from a fresh ISO download to a running honeypot.
It covers two install paths:

1. **Proxmox** — production. The honeypot runs as a VM with two
   bridges; the bait NIC is exposed to attacker traffic, the service
   NIC reaches operators + Ollama. Detailed in
   [proxmox.md](proxmox.md); this guide gives the short version and
   the cross-environment steps.
2. **QEMU smoke** — workstation. Useful for validating the ISO
   without committing rack space. Same wizard, same services, no
   real attacker traffic. See [`iso/smoke.sh`](../iso/smoke.sh).

If you intend to operate the honeypot on an internet-facing IP, read
[../SECURITY.md](../SECURITY.md) and the responsible-use clause in
the README first. The wizard refuses to proceed until you accept it.

---

## 1. Prerequisites

| Concern         | Requirement                                                       |
|-----------------|-------------------------------------------------------------------|
| ISO host        | A linux host with `live-build` (to build the ISO) **or** a release artefact downloaded from GitHub Releases. |
| LLM             | **Ollama co-located on the Anglerfish VM** (recommended — see [`PRODUCT.md`](PRODUCT.md) and [`MODEL_SETUP.md`](MODEL_SETUP.md)). Trusted-remote Ollama is supported via `trusted_remote_host` but adds operational complexity for no gain on single-honeypot deployments. |
| GPU             | NVIDIA card with ≥12GB VRAM passed through to the Anglerfish VM. RTX 3060 12GB is the reference. CPU-only works but inference is slow enough to break the deception. See [`proxmox.md`](proxmox.md) §1.3 for passthrough setup. |
| Operator access | An ED25519 SSH public key. The wizard installs it into the operator account; nothing else gets you back into the VM. |
| Optional        | A MaxMind licence key for first-boot GeoLite2 fetch. Without it, geo enrichment is empty until you stage `.mmdb` files manually. |

---

## 2. Get an ISO

### 2.1 From a GitHub release

Releases under
`https://github.com/retr0verride/Anglerfish-AI/releases` ship three
files per tag:

| File                                 | What it is                                  |
|--------------------------------------|---------------------------------------------|
| `anglerfish-ai-<version>.iso`        | The bootable image.                         |
| `anglerfish-ai-<version>.iso.sha256` | SHA-256 over the ISO.                       |
| `anglerfish-ai-<version>.iso.sig`    | Cosign keyless signature (when `--sign` was used). |
| `anglerfish-ai-<version>.iso.pem`    | The signing certificate (same).             |

Verify before deploying:

```bash
sha256sum -c anglerfish-ai-<version>.iso.sha256

# Cosign verification (keyless, OIDC-attested):
cosign verify-blob \
    --certificate anglerfish-ai-<version>.iso.pem \
    --signature   anglerfish-ai-<version>.iso.sig  \
    --certificate-identity-regexp 'https://github\.com/retr0verride/' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    anglerfish-ai-<version>.iso
```

`cosign verify-blob` exits 0 on a valid signature; anything else is
a refusal to trust the artefact. Stop and ask in #anglerfish.

### 2.2 Building locally

If you'd rather build from source — and you have a Debian or Ubuntu
host with `live-build`, `debootstrap`, `squashfs-tools`, `xorriso`,
`isolinux`, and `syslinux-common` installed:

```bash
git clone https://github.com/retr0verride/Anglerfish-AI.git
cd Anglerfish-AI
sudo ./iso/build.sh                  # produces build/anglerfish-ai-<version>.iso
sudo ./iso/build.sh --sign           # also signs with cosign (needs OIDC)
```

The build is reproducible to the extent that live-build allows;
package versions land in `build/manifest.txt` (live-build's default).

### 2.3 Build-time options

The build hooks read environment variables. All optional.

| Variable                    | Default | Meaning                                                    |
|-----------------------------|---------|------------------------------------------------------------|
| `ANGLERFISH_INSTALL_OLLAMA` | `0`     | When `1`, hook `0060` installs Ollama on-host (+5 GB ISO). |

**Recommendation for new deployments:** set `ANGLERFISH_INSTALL_OLLAMA=1`.
The slim-ISO path still works (you `curl | sh` Ollama in after first
boot per [`MODEL_SETUP.md`](MODEL_SETUP.md)), but the on-host install
is the canonical path now that Ollama runs co-located with the bridge
on a loopback endpoint. See [`proxmox.md`](proxmox.md) §1.3 for the
GPU-passthrough rationale and [`PRODUCT.md`](PRODUCT.md) for the
design principle.

```bash
# Build with Ollama baked in (recommended)
ANGLERFISH_INSTALL_OLLAMA=1 sudo ./iso/build.sh
```

Trusted-remote Ollama still works for the rare cases (multi-honeypot
fleet sharing one inference server, or operators with GPU constraints
forcing the LLM onto a separate box).

---

## 3. Install — Proxmox

See [proxmox.md](proxmox.md) for the full version. The short
version, assuming `vmbr-bait` and `vmbr-service` already exist:

```bash
# On the Proxmox host:
sudo ./proxmox/deploy.sh \
    --iso ./anglerfish-ai-0.1.0.iso \
    --vmid 9001 \
    --name anglerfish-honeypot

qm start 9001
qm terminal 9001    # serial console for the wizard
```

The script refuses to auto-create bridges (safety: a misconfigured
bridge could expose the management plane to attacker traffic). See
the bridge template in [proxmox.md §1.1](proxmox.md#11-create-the-two-linux-bridges).

---

## 4. Install — QEMU smoke

For a dry-run on your workstation:

```bash
./iso/smoke.sh ./build/anglerfish-ai-0.1.0.iso --memory 4G --cpus 4
```

Host port 2222 → guest Cowrie SSH. Host port 8420 → guest dashboard.
The qcow2 disk is persistent under `iso/smoke/`; delete it for a
clean run. `Ctrl-A x` to terminate QEMU.

---

## 5. First-boot wizard

The wizard runs on `tty1` (whether on the Proxmox console or under
QEMU's `-nographic`). The full prompt list:

| Step | Prompt                                                | What to provide                                              |
|------|-------------------------------------------------------|--------------------------------------------------------------|
| 1    | Responsible-use terms                                 | `y` after you read them. `n` aborts the install with exit 2. |
| 2    | VM hostname                                           | A friendly OS hostname (e.g. `anglerfish-1`).                |
| 3    | Bait interface                                        | The guest's view of the bait NIC, e.g. `ens18`.              |
| 4    | Service interface                                     | Guest's view of the service NIC, e.g. `ens19`.               |
| 5    | DHCP on each NIC                                      | `y` if your bridge has a DHCP server; otherwise prompts for static IP, gateway, DNS. |
| 6    | Operator UNIX username                                | The wizard creates this user; it's the only post-boot login. |
| 7    | Operator SSH public key                               | Paste an `ssh-ed25519 ...` line. Blank skips it.             |
| 8    | Dashboard admin username                              | Default `admin`.                                             |
| 9    | Dashboard admin password                              | Blank ⇒ open mode (only safe on a fully-isolated NIC).       |
| 10   | Ollama endpoint URL                                   | `http://127.0.0.1:11434/` (on-host) or `http://<gpu-host>:11434/`. |
| 11   | Trusted remote Ollama IP                              | Only if the URL is not loopback. Must match the URL's host.  |
| 12   | Ollama model tag                                      | Default `qwen3:14b` (Apache-2.0, Hugging Face). The bridge `ollama pull`s lazily. |
| 13   | Fake hostname for the AI shell                        | Default `srv-prod-01` — what the attacker sees in `hostname`. |
| 14   | Fake username for the AI shell                        | Default `root`.                                              |
| 15   | Splunk HEC                                            | `n` to skip; otherwise prompts for URL + token.              |
| 16   | Threat alert webhook URL                              | Optional.                                                    |
| 17   | MaxMind GeoLite2 licence key                          | Optional. Without it, geo lookups return empty records.      |

After the wizard:

* The env file is written to `/etc/anglerfish/anglerfish.env` (mode
  0600). Secrets are regenerated on every `--reconfigure`.
* nftables is loaded from `/etc/anglerfish/nftables/anglerfish.nft`.
* `getty@tty1` is re-enabled so you can log in on console.
* `anglerfish-geo-update.service` runs once if a licence key was
  supplied.
* Cowrie + the bridge + the dashboard start.

The bridge starts but **the fast-tier LLM model is not yet pulled** —
the wizard configures the model *tag* but the actual model blob
(several GB) is operator-controlled. The bridge will fail every
Ollama call until you complete the next step.

---

## 6. Set up the local LLM

SSH in over the service NIC and walk through
[`MODEL_SETUP.md`](MODEL_SETUP.md). Short version:

```bash
ssh anglerfish-ops@<service-ip>

# Tune Ollama for the honeypot workload (steps from MODEL_SETUP.md §3)
sudo systemctl edit ollama.service
# ... paste the [Service] block ...
sudo systemctl daemon-reload && sudo systemctl restart ollama.service

# Pull the three-tier stack (~13GB total)
ollama pull qwen2.5-coder:7b-instruct   # fast tier — used by Stage 1
ollama pull phi-4                        # deep tier — used by Stage 5+
ollama pull nomic-embed-text             # embed tier — used by Stage 6+

# Capture the fast-tier hash for the Stage 1 integrity check
sudo apt install -y jq
jq -r '.layers[] | select(.mediaType == "application/vnd.ollama.image.model") | .digest' \
    ~/.ollama/models/manifests/registry.ollama.ai/library/qwen2.5-coder/7b-instruct

# Add the hash to /etc/anglerfish/anglerfish.env:
#   ANGLERFISH_DEFENSE__MODEL_EXPECTED_HASH=sha256:<paste here>

# Restart the bridge so it verifies the hash and starts serving
sudo systemctl restart anglerfish-bridge.service
```

The full guide ([`MODEL_SETUP.md`](MODEL_SETUP.md)) covers hardware
sizing for non-RTX-3060 GPUs, the Stage 1 hash-rotation workflow when
you `ollama pull` an updated model, and the GPU-passthrough
prerequisites if you skipped them earlier.

---

## 7. Verify

From an operator host on the service NIC:

```bash
# 1. SSH operator login
ssh anglerfish-ops@<service-ip>

# 2. Dashboard health probe (always open, no auth)
curl -s http://<service-ip>:8420/api/health
# {"status":"ok","version":"0.1.0"}

# 3. Authenticated dashboard call
curl -s -u admin:<password> http://<service-ip>:8420/api/stats

# 4. Hit Cowrie on the bait NIC from a throwaway box
ssh -p 2222 root@<bait-ip>
```

If all four respond as expected, the install is healthy. Open the
dashboard in a browser at `http://<service-ip>:8420/` and log in
with the admin credentials you set in step 9 of the wizard.

---

## 8. Reconfiguring

The wizard supports `--reconfigure` for changing operator-facing
answers (IPs, model, webhook, geo key) without losing service state:

```bash
sudo anglerfish-wizard --reconfigure
```

Secrets in `/etc/anglerfish/anglerfish.env` regenerate on every run;
expect to restart `anglerfish-bridge.service` and `cowrie.service`
afterwards. The credentials DB keeps its encryption key unless you
rotate it explicitly via `anglerfish credentials rotate-key`.

---

## 9. Next steps

* **[PRE_DEPLOY_CHECKLIST.md](PRE_DEPLOY_CHECKLIST.md)** — twelve-section
  verification before exposing the honeypot to attacker traffic.
* **[MODEL_SETUP.md](MODEL_SETUP.md)** — full LLM setup, hardware
  sizing, hash-rotation workflow.
* **[RUNBOOK.md](RUNBOOK.md)** — day-2 operations: rotate keys, replay
  sessions, recover from common failures.
* **[INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md)** — playbook for
  unknown failure modes.
* **[ARCHITECTURE.md](ARCHITECTURE.md)** — what each module does, who
  talks to whom, what gets persisted.
* **[THREAT_MODEL.md](THREAT_MODEL.md)** — STRIDE walkthrough and the
  hardening that addresses each row.
* **[API_REFERENCE.md](API_REFERENCE.md)** — bridge and dashboard
  endpoints + WebSocket protocol for custom integrations.
