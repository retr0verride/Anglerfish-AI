# Installing Anglerfish AI

This guide walks from a fresh ISO download to a running honeypot. It
covers two install paths.

1. **Proxmox**: production. Deployment is split across two VMs. A
   **Model VM** holds the GPU and runs Ollama. The **honeypot VM** has
   no GPU; it takes attacker SSH traffic on its bait NIC, serves the
   operator dashboard on its service NIC, and calls the Model VM over
   the service network for every response. The full step-by-step
   walkthrough lives in [proxmox.md](proxmox.md). This guide gives the
   short version and the cross-environment steps; it does not duplicate
   proxmox.md.
2. **QEMU smoke**: workstation. Useful for validating the ISO without
   committing rack space. Same wizard, same services, no real attacker
   traffic. See [`iso/smoke.sh`](../iso/smoke.sh).

Loopback Ollama on the honeypot itself (`http://127.0.0.1:11434/`) is a
dev and test convenience only. Production is the split Model VM. The
canonical deployment is [proxmox.md](proxmox.md).

If you intend to operate the honeypot on an internet-facing IP, read
[../SECURITY.md](../SECURITY.md) and the responsible-use clause in the
README first. The wizard refuses to proceed until you accept it.

---

## 1. Prerequisites

| Concern         | Requirement                                                       |
|-----------------|-------------------------------------------------------------------|
| ISO host        | A linux host with `live-build` (to build the ISO) **or** a release artefact downloaded from GitHub Releases. |
| Model VM        | A separate VM that holds the GPU and runs Ollama. The honeypot calls it over the service network. Build it per [proxmox.md](proxmox.md) Steps 3 and 4 and [`MODEL_SETUP.md`](MODEL_SETUP.md). |
| GPU             | NVIDIA card with ≥12GB VRAM passed through to the **Model VM** (not the honeypot). RTX 3060 12GB is the reference. CPU-only works but inference is slow enough to break the deception. See [proxmox.md](proxmox.md) Step 2 for passthrough setup. |
| Service network | A `vmbr-service` link the honeypot uses to reach the Model VM on `:11434`. The honeypot's bait NIC never sees the Model VM. |
| Operator access | An ED25519 SSH public key (installed into the operator account the wizard creates). Optionally a console fallback password for the VM console. One of the two is how you get back into the VM. |
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

If you'd rather build from source, and you have a Debian or Ubuntu
host with `live-build`, `debootstrap`, `squashfs-tools`, `xorriso`,
`isolinux`, and `syslinux-common` installed:

```bash
git clone https://github.com/retr0verride/Anglerfish-AI.git
cd Anglerfish-AI
sudo ./iso/build.sh                  # produces build/anglerfish-ai-<version>.iso
sudo ./iso/build.sh --sign           # also signs with cosign (needs OIDC)
```

The default build is `--without-ollama`, which is what the split
topology wants. See §2.3 for when `--with-ollama` applies.

The build is reproducible to the extent that live-build allows;
package versions land in `build/manifest.txt` (live-build's default).

### 2.3 Build-time options

`iso/build.sh` takes `--with-ollama` and `--without-ollama` (default
`--without-ollama`). The flag wires through to the
`ANGLERFISH_INSTALL_OLLAMA` build env that hook `0060` reads.

| Flag                | Effect                                                         |
|---------------------|----------------------------------------------------------------|
| `--without-ollama`  | Default. Slim ISO. The honeypot does not bundle Ollama; it calls the Model VM. |
| `--with-ollama`     | Installs Ollama on-host (+~5 GB ISO). Loopback / dev path only. |

**Recommendation for the split topology: build `--without-ollama`.**
The honeypot in this deployment never runs the model and never touches
a GPU. Ollama lives on the Model VM, so there is no reason to bake it
into the honeypot image.

```bash
# Split topology (production): no on-host Ollama
sudo ./iso/build.sh --without-ollama
```

`--with-ollama` exists for the loopback dev and test path (Ollama
co-located on a single VM). It is not the production topology. See
[proxmox.md](proxmox.md) for the GPU-passthrough setup on the Model VM
and [`PRODUCT.md`](PRODUCT.md) for the local-LLM design principle.

---

## 3. Install - Proxmox

[proxmox.md](proxmox.md) is the full split-topology walkthrough: two
bridges, GPU passthrough, the Model VM, the honeypot VM, the wizard,
and end-to-end verification, in eight ordered steps. Follow it top to
bottom. This section is the short version of the honeypot-VM deploy
only.

Stand up the **Model VM first** (proxmox.md Steps 1 through 4) so you
have its service-network IP before the wizard asks for the Ollama
endpoint. Then, assuming `vmbr-bait` and `vmbr-service` exist and the
ISO was built `--without-ollama`:

```bash
# On the Proxmox host:
sudo ./proxmox/deploy.sh \
    --iso ./anglerfish-ai-0.1.0.iso \
    --vmid 9000 \
    --name anglerfish-honeypot

qm start 9000
qm terminal 9000    # serial console for the wizard
```

The script refuses to auto-create bridges (safety: a misconfigured
bridge could expose the management plane to attacker traffic). It also
refuses to run unless `vmbr-bait` and `vmbr-service` already exist, and
it does not start the VM. See the bridge template in
[proxmox.md Step 1](proxmox.md#step-1-host-networking-two-bridges).

`deploy.sh` flags: `--iso`, `--vmid`, `--name`, `--template`,
`--storage`, `--disk-storage`, `--memory`, `--cores`, `--dry-run`.

---

## 4. Install - QEMU smoke

For a dry-run on your workstation:

```bash
./iso/smoke.sh ./build/anglerfish-ai-0.1.0.iso --memory 4G --cpus 4
```

Host port 2222 → guest lure SSH. Host port 8420 → guest dashboard.
The qcow2 disk is persistent under `iso/smoke/`; delete it for a
clean run. `Ctrl-A x` to terminate QEMU.

---

## 5. First-boot wizard

The wizard runs on `/dev/console`. Drive it over the serial console
(`qm terminal <vmid>` on Proxmox, or QEMU `-serial`), where it is stable
text and pasting your SSH key is reliable; the Proxmox noVNC view mirrors
the same prompts as a read-only fallback. The full prompt list:

| Step | Prompt                                                | What to provide                                              |
|------|-------------------------------------------------------|--------------------------------------------------------------|
| 1    | Responsible-use terms                                 | `y` after you read them. `n` aborts the install with exit 2. |
| 2    | VM hostname                                           | A friendly OS hostname (e.g. `anglerfish-1`).                |
| 3    | Bait interface                                        | The guest's view of the bait NIC, e.g. `ens18`.              |
| 4    | Service interface                                     | Guest's view of the service NIC, e.g. `ens19`.               |
| 5    | DHCP on each NIC                                      | `y` if your bridge has a DHCP server; otherwise prompts for static IP, gateway, DNS. |
| 6    | Operator UNIX username                                | The wizard creates this account (in the `sudo` group); it's your post-boot login. POSIX name only (`^[a-z_][a-z0-9_-]*$`). |
| 7    | Operator SSH public key                               | Paste an `ssh-ed25519 ...` line, owned by the operator account. Blank skips it (then set a console password below, or you have no way in). |
| 8    | Dashboard admin username                              | Default `admin`.                                             |
| 9    | Dashboard admin password                              | Blank ⇒ open mode (only safe on a fully-isolated NIC).       |
| 10   | Ollama endpoint URL                                   | Production: `http://<model-ip>:11434/` (your Model VM). Dev/test loopback is `http://127.0.0.1:11434/`. |
| 11   | Trusted remote Ollama IP                              | Required when the URL is not loopback (the split topology). Enter `<model-ip>`; it must match the URL's host. |
| 12   | Ollama model tag                                      | Default `qwen3:14b` (Apache-2.0, Hugging Face). Pull it on the Model VM first; the bridge does not pull. |
| 13   | Fake hostname for the AI shell                        | Default `srv-prod-01`, what the attacker sees in `hostname`. |
| 14   | Fake username for the AI shell                        | Default `root`.                                              |
| 15   | Threat alert webhook URL                              | Optional.                                                    |
| 16   | MaxMind GeoLite2 licence key                          | Optional. Without it, geo lookups return empty records.      |
| 17   | Operator console fallback password                    | Asked last on the appliance (`--provision`). Hidden input; blank to skip. Works only at the VM console (sshd is key-only), so it is the rescue path if your SSH key fails. |

For the split topology, steps 10 and 11 both point at the Model VM. A
non-loopback endpoint URL is rejected unless the trusted-remote IP is
set and matches the URL's host. The host must be an IP literal; the
wizard rejects hostnames because DNS could change between validation
and use.

After the wizard:

* The env file is written to `/etc/anglerfish/anglerfish.env` (mode
  0600). Secrets are regenerated on every `--reconfigure`.
* nftables is loaded from `/etc/anglerfish/nftables/anglerfish.nft`.
* The operator account is created (`sudo` group) with the SSH key it
  owns and the optional console password.
* `getty@tty1` and `serial-getty@ttyS0` are re-enabled so you can log in
  on either the noVNC or the serial console.
* `anglerfish-geo-update.service` runs once if a licence key was
  supplied.
* The bridge, dashboard, and lure all start as systemd units
  (`anglerfish-bridge.service`, `anglerfish-dashboard.service`,
  `anglerfish-lure.service`). The lure unit runs `anglerfish lure
  serve` and is enabled on the ISO; no manual start is needed.

If you pointed the wizard at a Model VM that already has the model
pulled (see the next step), the bridge serves immediately. Otherwise
the wizard sets the model *tag* but the model blob (several GB) lives
on the Model VM, and the bridge fails every Ollama call until the
Model VM has the model.

---

## 6. Set up the local LLM

In the split topology, Ollama and the models live on the **Model VM**,
not the honeypot. If you followed [proxmox.md](proxmox.md) Step 4 you
already installed Ollama, applied the workload tuning, locked the
firewall to the honeypot, and pulled the model. If you have not, do it
now. SSH into the Model VM and pull the stack:

```bash
ssh <user>@<model-ip>

# Tune Ollama for the honeypot workload (MODEL_SETUP.md §2) and bind it
# to the service address only (proxmox.md Step 4 has the full drop-in).
sudo systemctl edit ollama.service
# ... paste the [Service] block ...
sudo systemctl daemon-reload && sudo systemctl restart ollama.service

# Pull the three-tier stack (~13GB total)
ollama pull qwen3:14b            # fast tier  - used by Stage 1
ollama pull phi-4               # deep tier  - used by Stage 5+
ollama pull nomic-embed-text    # embed tier - used by Stage 6+
```

The Stage 1 model-integrity pin reads Ollama's manifest from the
bridge's **local** filesystem. With Ollama on the Model VM the
honeypot has no manifest to read, so you either leave the pin unset
(the bridge logs `bridge.model_integrity_skipped` and starts) or sync
the Model VM's manifest tree to the honeypot. Both options are in
[proxmox.md Step 8](proxmox.md#step-8-day-2-operations) under
"Model-integrity pinning" and in [`MODEL_SETUP.md`](MODEL_SETUP.md) §5.

The full guide ([`MODEL_SETUP.md`](MODEL_SETUP.md)) covers hardware
sizing for non-RTX-3060 GPUs, the three-tier model picks, and the
hash-rotation workflow when you `ollama pull` an updated model.

---

## 7. Verify

From an operator host on the service NIC:

```bash
# 1. SSH operator login
ssh anglerfish-ops@<honeypot-service-ip>

# 2. Dashboard health probe (plain HTTP, always open, no auth)
curl -s http://<honeypot-service-ip>:8420/api/health
# {"status":"ok","version":"0.1.0"}

# 3. Authenticated dashboard call
curl -s -u admin:<password> http://<honeypot-service-ip>:8420/api/stats

# 4. Hit the lure on the bait NIC from a throwaway box
ssh -p 2222 root@<honeypot-bait-ip>
```

Confirm the honeypot can reach the Model VM. From the honeypot
(operator SSH):

```bash
curl -s http://<model-ip>:11434/api/tags
# JSON listing the models you pulled on the Model VM
```

If all of these respond as expected, the install is healthy. Coherent
shell output from the lure means the full chain works: lure to bridge
to Model VM and back. Open the dashboard in a browser at
`http://<honeypot-service-ip>:8420/` and log in with the admin
credentials you set in step 9 of the wizard. [proxmox.md Step
7](proxmox.md#step-7-verify-the-whole-chain) has the longer
chain-verification routine.

---

## 8. Reconfiguring

The wizard supports `--reconfigure` for changing operator-facing
answers (IPs, model, webhook, geo key) without losing service state:

```bash
sudo anglerfish-wizard --reconfigure
```

Add `--provision` to also apply operator-account changes (a new SSH key,
a changed username, or a console password); without it `--reconfigure`
only rewrites the config files.

Secrets in `/etc/anglerfish/anglerfish.env` regenerate on every run;
expect to restart `anglerfish-bridge.service`, `anglerfish-lure.service`,
and `anglerfish-dashboard.service` afterwards. The credentials DB keeps
its encryption key unless you rotate it explicitly via `anglerfish
credentials rotate-key`.

---

## 9. Next steps

* **[PRE_DEPLOY_CHECKLIST.md](PRE_DEPLOY_CHECKLIST.md)** - twelve-section
  verification before exposing the honeypot to attacker traffic.
* **[MODEL_SETUP.md](MODEL_SETUP.md)** - full LLM setup, hardware
  sizing, hash-rotation workflow.
* **[RUNBOOK.md](RUNBOOK.md)** - day-2 operations: rotate keys, replay
  sessions, recover from common failures.
* **[INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md)** - playbook for
  unknown failure modes.
* **[ARCHITECTURE.md](ARCHITECTURE.md)** - what each module does, who
  talks to whom, what gets persisted.
* **[THREAT_MODEL.md](THREAT_MODEL.md)** - STRIDE walkthrough and the
  hardening that addresses each row.
* **[API_REFERENCE.md](API_REFERENCE.md)** - bridge and dashboard
  endpoints + WebSocket protocol for custom integrations.
