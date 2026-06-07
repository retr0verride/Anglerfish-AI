# Deploying Anglerfish AI on Proxmox

This is a step-by-step guide to a running Anglerfish honeypot on a single
Proxmox host. Follow it top to bottom.

You will build **two VMs**:

* **Model VM** holds the GPU and runs the LLM (Ollama). Nothing
  attacker-facing runs here.
* **Honeypot VM** takes attacker SSH traffic on its bait NIC, serves the
  operator dashboard on its service NIC, and calls the Model VM for every
  response.

The honeypot never runs the model and never touches the GPU. Keeping the
model on its own VM keeps the GPU and the model runtime off the
internet-facing machine. The honeypot reaches the Model VM over the
service network only; nothing on the bait side can see it.

```text
        attackers
            │  SSH :2222
            ▼
   ┌──────────────────┐   service net    ┌──────────────────┐
   │   Honeypot VM    │  :11434 request   │    Model VM      │
   │  bait + service  │ ────────────────► │   GPU + Ollama   │
   │  no GPU          │ ◄──────────────── │                  │
   └──────────────────┘   model response  └──────────────────┘
            │ dashboard :8420
            ▼
        operators
```

---

## What you need

* A Proxmox VE 8.x host with:
  * A GPU you can pass through (NVIDIA assumed below).
  * At least two physical NICs: one for attacker traffic (the bait NIC),
    separate from the Proxmox management NIC.
  * Root shell access.
* The Anglerfish ISO (`anglerfish-ai-<version>.iso`) built by
  [`iso/build.sh`](../iso/build.sh) and verified against its `.sha256`.
  Build it `--without-ollama` (the honeypot does not run the model in
  this topology).
* A Debian 12 (`netinst`) ISO for the Model VM, uploaded to Proxmox
  `local` storage.

## The steps

1. Host networking: two bridges.
2. Host: enable GPU passthrough.
3. Build the Model VM.
4. Set up Ollama on the Model VM.
5. Deploy the Honeypot VM.
6. Run the first-boot wizard.
7. Verify the whole chain.
8. Day-2 operations, backups, teardown.

Each step ends with a check so you know it worked before moving on.

---

## Step 1: Host networking (two bridges)

Anglerfish is a two-NIC design. Create two Linux bridges on the Proxmox
host: one for attacker traffic (`vmbr-bait`), one for operators and the
model link (`vmbr-service`).

> `vmbr-bait` carries attacker traffic. Never back it with the Proxmox
> management NIC.

Edit `/etc/network/interfaces` on the host. Example with two free NICs
(`enp2s0f1` for bait, `enp2s0f2` for service):

```ini
auto vmbr-bait
iface vmbr-bait inet manual
    bridge-ports enp2s0f1
    bridge-stp off
    bridge-fd 0

auto vmbr-service
iface vmbr-service inet manual
    bridge-ports enp2s0f2
    bridge-stp off
    bridge-fd 0
```

Bring them up:

```bash
ifup vmbr-bait
ifup vmbr-service
```

You also need `qm`, `pvesm`, `jq`, and `awk` for the deploy script later:

```bash
apt install proxmox-ve jq gawk
```

**Check:** both bridges are up.

```bash
ip -br link show vmbr-bait vmbr-service
# both should read UP
```

---

## Step 2: Enable GPU passthrough on the host

This is a one-time host change. If `dmesg | grep -e DMAR -e IOMMU` already
shows IOMMU active and your GPU is bound to `vfio-pci`, skip to Step 3.

### 2a. Turn on IOMMU

Add the IOMMU flags to the kernel command line:

```bash
nano /etc/default/grub
# Intel host: add to GRUB_CMDLINE_LINUX_DEFAULT
#   intel_iommu=on iommu=pt
# AMD host:
#   amd_iommu=on iommu=pt
update-grub
```

Load the vfio modules at boot, then reboot:

```bash
printf 'vfio\nvfio_iommu_type1\nvfio_pci\n' >> /etc/modules
reboot
```

**Check:** IOMMU is on after reboot.

```bash
dmesg | grep -e DMAR -e IOMMU | head
# non-empty output = IOMMU active
```

### 2b. Bind the GPU to vfio-pci

Find the GPU's PCI address and its vendor:device IDs. A GPU usually has
two functions: the video controller and its HDMI-audio device. Bind both.

```bash
lspci -nn | grep -i nvidia
# 01:00.0 VGA compatible controller [0300]: NVIDIA ... [10de:2504]
# 01:00.1 Audio device [0403]: NVIDIA ...            [10de:228e]

echo "options vfio-pci ids=10de:2504,10de:228e" > /etc/modprobe.d/vfio.conf
update-initramfs -u
reboot
```

**Check:** the GPU is driven by `vfio-pci`, not the host's `nvidia`/
`nouveau` driver.

```bash
lspci -nnk -d 10de: | grep -A2 -i nvidia
# "Kernel driver in use: vfio-pci"
```

Note the PCI address (here `01:00`). You attach it to the Model VM next.

---

## Step 3: Build the Model VM

Create a minimal Debian VM on the service bridge. `q35` + OVMF (UEFI)
gives clean PCIe passthrough. Pick `<model-vmid>` (for example `9100`).

```bash
qm create <model-vmid> \
    --name ollama-model \
    --machine q35 --bios ovmf --efidisk0 local-lvm:1 \
    --memory 16384 --cores 4 \
    --scsihw virtio-scsi-single --scsi0 local-lvm:60 \
    --net0 virtio,bridge=vmbr-service \
    --ide2 local:iso/debian-12-netinst.iso,media=cdrom \
    --boot order=ide2 \
    --ostype l26

qm start <model-vmid>
```

Open the console (`qm terminal <model-vmid>` or the web UI) and install
Debian: minimal, no desktop. Give it a static address on the service
network (or set a DHCP reservation) so the honeypot's pin stays stable.
The rest of this guide calls that address `<model-ip>`.

Power off and attach the GPU you bound in Step 2b:

```bash
qm stop <model-vmid>
qm set <model-vmid> --hostpci0 01:00,pcie=1
qm start <model-vmid>
```

**Check:** size the RAM and disk to your model stack first. The
[`MODEL_SETUP.md`](MODEL_SETUP.md) hardware table sizes VRAM and models;
16GB RAM / 60GB disk fits the recommended three-model stack.

---

## Step 4: Set up Ollama on the Model VM

SSH into the Model VM (`ssh <user>@<model-ip>`). Install the GPU driver
first and confirm the VM sees the card:

```bash
sudo apt install -y nvidia-driver firmware-misc-nonfree
sudo reboot
# After reboot:
nvidia-smi
# Must list your GPU with VRAM before continuing. If this fails,
# passthrough is not working; recheck Step 2.
```

Install Ollama:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Bind Ollama to the service address only (never `0.0.0.0`) and apply the
workload tuning. Open a systemd drop-in:

```bash
sudo systemctl edit ollama.service
```

Paste:

```ini
[Service]
Environment="OLLAMA_HOST=<model-ip>:11434"
Environment="OLLAMA_NUM_PARALLEL=2"
Environment="OLLAMA_FLASH_ATTENTION=1"
Environment="OLLAMA_KV_CACHE_TYPE=q8_0"
Environment="OLLAMA_MAX_LOADED_MODELS=2"
Environment="OLLAMA_KEEP_ALIVE=-1"
```

Reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ollama.service
```

Pull your models (see [`MODEL_SETUP.md`](MODEL_SETUP.md) §3 for the picks;
`qwen3:14b` is the default fast tier):

```bash
ollama pull qwen3:14b
```

Lock the firewall so only the honeypot can reach the model API. Replace
`<honeypot-service-ip>` with the honeypot's service-NIC address (you will
know it after Step 6; set this rule then if you do not know it yet):

```bash
sudo apt install -y nftables
sudo tee /etc/nftables.conf >/dev/null <<'NFT'
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif "lo" accept
        tcp dport 22 accept                                   # operator SSH (tighten saddr to your mgmt host)
        ip saddr <honeypot-service-ip> tcp dport 11434 accept # Ollama API: honeypot only
    }
}
NFT
sudo systemctl enable --now nftables
```

**Check:** Ollama answers on the service address.

```bash
curl -s http://<model-ip>:11434/api/tags
# JSON listing your pulled models
```

---

## Step 5: Deploy the Honeypot VM

Build the ISO `--without-ollama` and verify it:

```bash
sha256sum -c anglerfish-ai-0.1.0.iso.sha256
```

Copy [`proxmox/deploy.sh`](../proxmox/deploy.sh) and
[`proxmox/anglerfish.json`](../proxmox/anglerfish.json) onto the Proxmox
host (for example `/root/anglerfish/`), then run:

```bash
sudo ./deploy.sh \
    --iso ./anglerfish-ai-0.1.0.iso \
    --vmid 9000 \
    --name anglerfish-honeypot
```

The script uploads the ISO, then runs `qm create` with the
[`anglerfish.json`](../proxmox/anglerfish.json) defaults (4GB RAM, 4
cores, 32GB disk, two virtio NICs on `vmbr-bait` and `vmbr-service`).
Common overrides:

| Flag                  | Default       | Use when                          |
|-----------------------|---------------|-----------------------------------|
| `--memory MIB`        | `4096`        | The lure needs more headroom      |
| `--cores N`           | `4`           | Higher session throughput         |
| `--disk-storage NAME` | `local-lvm`   | VM disk on different storage      |
| `--storage NAME`      | `local`       | ISO storage other than `local`    |
| `--dry-run`           | -             | Print the `qm create` line only   |

It refuses to run unless `vmbr-bait` and `vmbr-service` already exist, and
it does **not** start the VM. Start it so you can reach the console:

```bash
qm start 9000
qm terminal 9000     # serial console (recommended for the wizard)
```

`qm terminal` is the serial console the wizard runs on. Drive the wizard
there: it is stable text and pasting your SSH key is reliable. The web-UI
noVNC console mirrors the same prompts if you prefer to read there, but it
is read-only for the wizard (input comes from the serial line). Exit
`qm terminal` with `Ctrl-O`.

**Check:** the VM boots to the first-boot wizard's terms screen.

---

## Step 6: Run the first-boot wizard

The wizard runs on the serial console (`qm terminal`). Answer the prompts
in order. The two that matter for the split topology are the Ollama
endpoint and the trusted remote IP: point them at the Model VM.

| Prompt | What to enter |
|--------|---------------|
| Terms of responsible use | `y` to accept. |
| VM hostname | The OS hostname (not the fake shell hostname). |
| Bait interface | The attacker-facing NIC inside the guest (often `ens18`). |
| Service interface | The second NIC inside the guest. |
| DHCP on the bait NIC | `y` if the bait bridge has DHCP, else answer the static prompts. |
| DHCP on the service NIC | `y` if the service bridge has DHCP, else static. |
| Operator UNIX username | Your ops login (separate from the honeypot users). The wizard creates this account in the `sudo` group. POSIX name only. |
| Operator SSH public key | Paste an ED25519 pubkey, owned by the operator account. This is your post-boot entry. |
| Dashboard admin username | The dashboard login. |
| Dashboard admin password | Set one. Blank is open-mode, only safe on an isolated NIC. |
| **Ollama endpoint URL** | **`http://<model-ip>:11434/`** (your Model VM). |
| **Trusted remote Ollama IP** | **`<model-ip>`** (must match the endpoint host). |
| Ollama model tag | The model you pulled, for example `qwen3:14b`. |
| Fake hostname for the AI shell | The hostname the attacker sees. |
| Fake username for the AI shell | The username the attacker sees, for example `root`. |
| Threat alert webhook URL | Optional; blank to skip. |
| MaxMind GeoLite2 licence key | Optional; blank to skip. |
| Enable honeytokens | `n` unless you have read [`HONEYTOKENS.md`](HONEYTOKENS.md). |
| Enable counter-deception | `n` unless you have read the threat model section. |
| Operator console fallback password | Asked last. Hidden input; blank to skip. Console-only (sshd is key-only), so it is your rescue path if the SSH key fails. |

The endpoint host must be an IP literal. The wizard rejects hostnames
because DNS could change between validation and use.

When the wizard finishes you will see:

```text
[anglerfish] first-boot complete; restarting into multi-user.
```

The honeypot reboots, then `anglerfish-bridge`, `anglerfish-dashboard`,
and `anglerfish-lure` start automatically.

**Check:** note the honeypot's service-NIC IP (shown in the wizard or via
`ip -br addr` on the console). If you deferred the Model VM firewall rule
in Step 4, set it now with this IP.

---

## Step 7: Verify the whole chain

From an operator host on the service network:

```bash
# 1. Dashboard health (plain HTTP, no auth needed for this endpoint)
curl http://<honeypot-service-ip>:8420/api/health
# {"status":"ok","version":"0.1.0"}

# 2. Operator SSH on the service NIC
ssh <operator-user>@<honeypot-service-ip>
```

From a throwaway host on the bait network, drive the lure and confirm the
model answers:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 root@<honeypot-bait-ip>
# Type a few commands. Coherent shell-like output means the full chain
# works: lure -> bridge -> Model VM -> back to the session.
```

If responses are slow or canned, check the link to the Model VM from the
honeypot's service NIC:

```bash
# On the honeypot (operator SSH), confirm it can reach the model
curl -s http://<model-ip>:11434/api/tags
# Watch the bridge work the requests
sudo journalctl -u anglerfish-bridge.service -f
```

**Check:** the dashboard returns `status: ok`, and the lure produces
coherent output. The honeypot is live.

---

## Step 8: Day-2 operations

| Task | Command (on the honeypot VM) |
|------|------------------------------|
| Restart the bridge | `systemctl restart anglerfish-bridge.service` |
| Tail bridge logs | `journalctl -u anglerfish-bridge.service -f` |
| Check all services | `systemctl status anglerfish-bridge anglerfish-dashboard anglerfish-lure` |
| Rotate the credentials key | `anglerfish credentials rotate-key --new-key $(openssl rand -base64 32)` |
| Force a fresh geo download | `systemctl start anglerfish-geo-update.service` |
| Re-run the wizard (keeps the DBs) | `anglerfish-wizard --reconfigure` |
| View masked configuration | `anglerfish config show` |
| Inspect the audit log | `cat /var/log/anglerfish/audit.jsonl \| jq` |

These commands live in the venv at `/opt/anglerfish/venv/bin/`; symlinks
under `/usr/local/bin/` keep them on your PATH.

### Model-integrity pinning (optional)

The Stage 1 model-integrity check
([`MODEL_SETUP.md`](MODEL_SETUP.md) §5) pins each model's layer hash. It
reads Ollama's manifest from the honeypot's **local** filesystem
([`src/anglerfish/bridge/defense.py:638-650`](../src/anglerfish/bridge/defense.py#L638-L650)),
and in this topology those manifests live on the Model VM. You have two
options:

1. **Skip the pin.** Leave `ANGLERFISH_DEFENSE__*_MODEL_EXPECTED_HASH`
   unset. The bridge logs `bridge.model_integrity_skipped` and starts.
   The honeypot does not manage the model anyway.
2. **Keep the pin.** Copy the Model VM's manifest tree to the honeypot
   read-only (rsync over the service link) and point
   `ANGLERFISH_DEFENSE__OLLAMA_MANIFEST_DIR` at the copy. Re-sync on every
   `ollama pull`.

### Backups

`vzdump` / `pve-backup` captures full-VM snapshots for disaster recovery.
For the smaller "move the operator state" workflow (credentials,
sessions, audit log), use [`proxmox/backup.sh`](../proxmox/backup.sh):

```bash
./backup.sh \
    --host <operator-user>@<honeypot-service-ip> \
    --out ./backups/anglerfish-$(date +%Y-%m-%d).tar.gz \
    --gpg-recipient ops@example.com
```

Restore onto a fresh honeypot VM that has booted through the wizard at
least once:

```bash
./restore.sh \
    --host <operator-user>@<new-service-ip> \
    --in   ./backups/anglerfish-2026-06-05.tar.gz.gpg \
    --gpg
```

### Tearing down

```bash
qm stop 9000  && qm destroy 9000     # honeypot
qm stop 9100  && qm destroy 9100     # model VM
```

`vzdump` snapshots survive `qm destroy`; the deploy script does not touch
them.

---

## Smoke-test the ISO before deploying (optional)

To boot the ISO under QEMU on a workstation first,
[`iso/smoke.sh`](../iso/smoke.sh) wires the bait + service NICs:

```bash
./iso/smoke.sh ./anglerfish-ai-0.1.0.iso --memory 4G
```

Host port 2222 maps to the guest lure, host port 8420 to the dashboard.
`Ctrl-A x` terminates QEMU. The harness uses a persistent
`iso/smoke/anglerfish.qcow2`; delete it for a clean run.
