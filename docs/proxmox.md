# Deploying Anglerfish AI on Proxmox

This guide walks you from a clean Proxmox 8.x host to a running
Anglerfish AI honeypot VM. It assumes you already have:

* A Proxmox VE host with at least one physical NIC dedicated to
  attacker traffic (the bait NIC), separate from the host's
  management NIC.
* A pre-built ISO (`anglerfish-ai-<version>.iso`) produced by
  [`iso/build.sh`](../iso/build.sh) and verified against its
  `.sha256` (and `.sig` if `--sign` was used).
* SSH access to the Proxmox shell as `root` and to the eventual
  honeypot VM's service NIC.

The honeypot is a two-NIC design:

```text
         attackers
             │
             ▼
   ┌───────────────────┐         ┌──────────────────────┐
   │   bait NIC        │  lure   │    LLM bridge        │
   │  vmbr-bait        │◀───────▶│    /var/lib/...      │
   └───────────────────┘         │    dashboard         │
                                 └──────────┬───────────┘
                                            │ service NIC
                                            ▼
                                       operators + Ollama
```

`vmbr-bait` is exposed to attacker traffic and must NEVER be on the
Proxmox management bridge. `vmbr-service` is the operator-facing
side and reaches Ollama and the dashboard.

---

## 1. Host preparation

### 1.1 Create the two Linux bridges

On the Proxmox host, add bridges to `/etc/network/interfaces`. The
deploy script intentionally refuses to auto-create them, wiring a
bridge to the wrong physical NIC could put your management plane
on the attacker side.

Example: a host with two free NICs (`enp2s0f1` for bait,
`enp2s0f2` for service):

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

Verify:

```bash
ip -br link show vmbr-bait vmbr-service
```

### 1.2 Tooling

The deploy script needs `qm`, `pvesm`, `jq`, and `awk`, install if
not present:

```bash
apt install proxmox-ve jq gawk
```

### 1.3 GPU passthrough (for local LLM)

There are two supported topologies for where the model runs. Pick one
before wiring the GPU:

* **Co-located (this section, §1.3).** GPU passed to the honeypot VM,
  Ollama on loopback. Simplest, lowest latency, and the model-integrity
  pin works with no extra steps. The cost is that the GPU and model
  runtime sit on the same VM that takes attacker traffic.
* **Split (§1.4).** GPU passed to a separate Ollama VM that the honeypot
  calls over the service NIC (`trusted_remote_host`). Keeps the GPU and
  model runtime off the internet-facing VM, one isolation hop from the
  bait segment. The cost is a second VM, a firewall rule, and a choice
  about model-integrity pinning. Prefer this when isolating the model
  runtime matters more than setup simplicity.

The rest of §1.3 is the co-located path. For the split path skip to §1.4.

Anglerfish can run the local LLM via Ollama co-located with the bridge
for loopback-only inference. That means **the GPU is passed through to
the Anglerfish VM**: not to any sibling VM (Kali, replay VM, etc.).

Three reasons:

1. **Simplicity.** The Ollama endpoint validator
   ([`src/anglerfish/config/models.py:255-279`](../src/anglerfish/config/models.py#L255-L279))
   defaults to loopback; remote-Ollama via `trusted_remote_host` works
   but adds a second VM, a firewall rule, and the model-integrity
   tradeoff in §1.4. Co-located is the fewest moving parts. The split
   path (§1.4) buys isolation in exchange for that complexity; choose
   per your threat model, not by default.
2. **Mixed-role hygiene.** Hosting the defender's LLM on the same
   VM as your attacker/replay tooling crosses defender and attacker
   infrastructure. Even in a lab, that's bad hygiene, if the
   attacker VM is ever compromised by something you replay, your
   honeypot's LLM is on the same box.
3. **Latency + nftables simplicity.** Loopback is ~0.2ms; cross-VM
   service-net inference is ~1-5ms + TCP overhead. And co-located
   keeps the nftables egress policy at "dashboard, nothing else";
   no Ollama port to allow.

A GPU can only be passed through to one VM at a time on Proxmox.
Switch it to Anglerfish:

```bash
# Find the GPU's PCI address on the host
lspci -nn | grep -i nvidia
# 01:00.0 VGA compatible controller [0300]: NVIDIA Corporation GA106 [GeForce RTX 3060] [10de:2504]

# If GPU is currently attached to another VM, detach first
qm set <other-vmid> --delete hostpci0

# Attach to the Anglerfish VM (replace 01:00 with your actual PCI address)
qm set <anglerfish-vmid> --hostpci0 01:00,pcie=1,x-vga=1

# Boot the VM
qm start <anglerfish-vmid>
```

Inside the Anglerfish VM, install the NVIDIA driver and verify:

```bash
sudo apt install -y nvidia-driver firmware-misc-nonfree
sudo reboot

# After reboot
nvidia-smi
# Should show your card with VRAM available
```

Once `nvidia-smi` works inside the guest, proceed with the model
install per [`MODEL_SETUP.md`](MODEL_SETUP.md).

**When you'd legitimately keep the GPU elsewhere:**

* Multiple Anglerfish honeypots sharing one inference server (use
  `trusted_remote_host` in that case).
* AI-assisted attack research on the attacker VM (you want local LLMs
  for exploit generation). Then run smaller CPU-mode Ollama on
  Anglerfish for the honeypot's hot path.
* Hardware budget for two GPUs. Not the common case.

None of those apply to a single-honeypot lab using the co-located
topology. For the split topology, the GPU goes to the dedicated model
VM instead (§1.4).

---

### 1.4 Split topology: dedicated Ollama VM

This is the §1.3 alternative: the GPU and Ollama run on their own VM,
and the honeypot calls it over the service NIC. Both VMs live on the
one Proxmox host. The honeypot reaches the model VM over `vmbr-service`;
nothing on the bait side can see it.

The honeypot never executes attacker input or model output, so the
attacker cannot reach this VM directly. The split still earns its keep:
the GPU and the Ollama runtime sit one isolation hop from the
attacker-facing surface instead of on it. The attacker's only influence
on the model is the prompt text the bridge forwards.

#### Host: confirm IOMMU + vfio (one-time)

GPU passthrough needs IOMMU enabled. If `dmesg | grep -e DMAR -e IOMMU`
already shows it active and the GPU is bound to `vfio-pci`, skip to the
VM build.

```bash
# Intel host: add to GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub
#   intel_iommu=on iommu=pt
# AMD host:
#   amd_iommu=on iommu=pt
nano /etc/default/grub
update-grub

# Load the vfio modules at boot
printf 'vfio\nvfio_iommu_type1\nvfio_pci\n' >> /etc/modules
reboot
```

After reboot, bind the GPU to `vfio-pci` so the host driver does not
claim it. Pass both the GPU function and its HDMI-audio function:

```bash
lspci -nn | grep -i nvidia
# 01:00.0 VGA ... [10de:2504]    01:00.1 Audio ... [10de:228e]
echo "options vfio-pci ids=10de:2504,10de:228e" > /etc/modprobe.d/vfio.conf
update-initramfs -u && reboot
```

#### Build the model VM

```bash
# Minimal Debian VM on the service bridge. q35 + OVMF gives clean PCIe
# passthrough; size RAM/disk to your model stack (see MODEL_SETUP.md).
qm create <ollama-vmid> \
    --name ollama-model \
    --machine q35 --bios ovmf --efidisk0 local-lvm:1 \
    --memory 16384 --cores 4 \
    --scsihw virtio-scsi-single --scsi0 local-lvm:60 \
    --net0 virtio,bridge=vmbr-service \
    --cdrom local:iso/debian-12-netinst.iso \
    --ostype l26

qm start <ollama-vmid>
# Install Debian (minimal, no desktop) from the console, then power off
# to attach the GPU.
qm stop <ollama-vmid>

# Detach the GPU from any other VM first, then attach it here.
qm set <ollama-vmid> --hostpci0 01:00,pcie=1
qm start <ollama-vmid>
```

Give this VM a static address on the service network (or a DHCP
reservation) so the honeypot's endpoint pin stays stable. The steps
below call it `<ollama-ip>`.

#### Configure the model VM

```bash
# Inside the model VM
sudo apt install -y nvidia-driver firmware-misc-nonfree
sudo reboot
nvidia-smi          # must show the GPU before continuing

curl -fsSL https://ollama.com/install.sh | sh
```

Bind Ollama to the service address only, never `0.0.0.0`, and apply the
workload tuning from [`MODEL_SETUP.md`](MODEL_SETUP.md) §3:

```bash
sudo systemctl edit ollama.service
```

```ini
[Service]
Environment="OLLAMA_HOST=<ollama-ip>:11434"
Environment="OLLAMA_NUM_PARALLEL=2"
Environment="OLLAMA_FLASH_ATTENTION=1"
Environment="OLLAMA_KV_CACHE_TYPE=q8_0"
Environment="OLLAMA_MAX_LOADED_MODELS=2"
Environment="OLLAMA_KEEP_ALIVE=-1"
```

```bash
sudo systemctl daemon-reload && sudo systemctl restart ollama.service
```

Pull the models per [`MODEL_SETUP.md`](MODEL_SETUP.md) §4, then firewall
the API so only the honeypot's service IP can reach it:

```bash
sudo apt install -y nftables
sudo tee /etc/nftables.conf >/dev/null <<'NFT'
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif "lo" accept
        tcp dport 22 accept                                   # operator SSH (tighten saddr to mgmt)
        ip saddr <honeypot-service-ip> tcp dport 11434 accept # Ollama: honeypot only
    }
}
NFT
sudo systemctl enable --now nftables
```

#### Point the honeypot at the model VM

In the first-boot wizard, give the Ollama endpoint as
`http://<ollama-ip>:11434/`; the wizard then asks for the trusted
remote IP and pins it. Equivalently, in `/etc/anglerfish/anglerfish.env`:

```bash
# The endpoint host must be an IP literal. The wizard and the runtime
# both reject hostnames: DNS could change between validation and use.
ANGLERFISH_OLLAMA__BASE_URL=http://<ollama-ip>:11434/
ANGLERFISH_OLLAMA__TRUSTED_REMOTE_HOST=<ollama-ip>
```

The honeypot's egress firewall already allows 11434 outbound on the
service NIC, so no honeypot-side firewall change is needed.

#### Model-integrity pinning in split mode

The Stage 1 model-integrity check
([`MODEL_SETUP.md`](MODEL_SETUP.md) §6) reads Ollama's manifest from the
honeypot's **local** filesystem
([`src/anglerfish/bridge/defense.py:638-650`](../src/anglerfish/bridge/defense.py#L638-L650)).
With Ollama on a separate VM those manifests are not local, so you pick:

1. **Skip the pin.** Leave `ANGLERFISH_DEFENSE__*_MODEL_EXPECTED_HASH`
   unset. The bridge logs `bridge.model_integrity_skipped` and starts.
   You lose the local hash pin, but the honeypot does not manage the
   model anyway.
2. **Keep the pin.** Copy the model VM's manifest tree to the honeypot
   read-only (rsync over the service link) and point
   `ANGLERFISH_DEFENSE__OLLAMA_MANIFEST_DIR` at the copy. Re-sync on
   every `ollama pull`.

Co-located (§1.3) keeps the pin with no extra work. That is the one
capability the split topology trades for the stronger isolation.

---

## 2. Deploy the VM

Copy [`proxmox/deploy.sh`](../proxmox/deploy.sh) and
[`proxmox/anglerfish.json`](../proxmox/anglerfish.json) onto the
Proxmox host (e.g. `/root/anglerfish/`), then run:

```bash
sudo ./deploy.sh \
    --iso ./anglerfish-ai-0.1.0.iso \
    --vmid 9001 \
    --name anglerfish-honeypot
```

Optional overrides:

| Flag                    | Default                  | When you'd use it                |
|-------------------------|--------------------------|----------------------------------|
| `--template PATH`       | `./anglerfish.json`      | Custom VM defaults               |
| `--storage NAME`        | `local`                  | ISO storage other than `local`   |
| `--disk-storage NAME`   | `local-lvm`              | VM disk on a different storage   |
| `--memory MIB`          | `4096`                   | LLM model + lure need headroom   |
| `--cores N`             | `4`                      | Per LLM throughput needs         |
| `--dry-run`             | -                        | Print the `qm create` line only  |

The script:

1. Refuses to start unless `vmbr-bait` and `vmbr-service` already exist.
2. Uploads the ISO to `local:iso/...` if not present.
3. Calls `qm create` with the template-driven defaults plus your
   `--vmid`/`--name`.

It does **not** start the VM. Start it manually so you can attach
to the console for the first-boot wizard:

```bash
qm start 9001
qm terminal 9001    # serial console, or use the Proxmox web UI
```

---

## 3. First-boot wizard

The wizard runs on `tty1` and asks for:

| Prompt                            | What to enter                                                  |
|-----------------------------------|----------------------------------------------------------------|
| VM hostname                       | A friendly OS hostname; never the fake shell hostname.         |
| Bait interface                    | The NIC name inside the guest (typically `ens18` / `enp0s18`). |
| Service interface                 | Second NIC inside the guest.                                   |
| DHCP per NIC                      | Pick `y` if your bridge has a DHCP server reachable.           |
| Operator user / SSH pubkey        | Use an ED25519 pubkey; this is your only post-boot entry.      |
| Dashboard admin user / password   | The dashboard locks itself once you supply a password.         |
| Ollama endpoint                   | Trusted-remote URL or `http://127.0.0.1:11434/` for on-host.   |
| MaxMind licence key               | Optional; the geo-update unit downloads on first boot.         |

After the wizard finishes, you should see:

```text
[anglerfish] first-boot complete; restarting into multi-user.
```

The wizard's `ExecStartPost` re-enables `getty@tty1` so your next
console login lands on the standard tty.

---

## 4. Verify

From your operator host (reachable over the service bridge):

```bash
# SSH operator login on the service NIC
ssh anglerfish-ops@<service-ip>

# Dashboard health (always open; doesn't require auth)
curl -k https://<service-ip>:8420/api/health
# {"status":"ok","version":"0.1.0"}

# Driving the lure from a throwaway IP
ssh -p 2222 root@<bait-ip>
```

If the dashboard responds and the lure greets you on `2222`, the
honeypot is live.

---

## 5. Backups

`pve-backup` (the built-in `vzdump`) captures full-VM snapshots
and is the right tool for disaster recovery. For the smaller
"replay the operator state" workflow, moving credentials,
sessions, audit log between VMs, use the included
[`proxmox/backup.sh`](../proxmox/backup.sh):

```bash
./backup.sh \
    --host anglerfish-ops@<service-ip> \
    --out ./backups/anglerfish-$(date +%Y-%m-%d).tar.gz \
    --gpg-recipient ops@example.com
```

The script SSHes in, runs `sudo tar` on the relevant files, and
optionally GPG-encrypts the tarball locally. Wire it into a
systemd-timer or `pve-cron` for nightly runs.

To restore onto a freshly-installed VM (the VM must have booted
through the wizard at least once):

```bash
./restore.sh \
    --host anglerfish-ops@<new-service-ip> \
    --in   ./backups/anglerfish-2026-05-22.tar.gz.gpg \
    --gpg
```

The script stops the bridge + dashboard, untars the payload, fixes
permissions, and restarts the services.

---

## 6. Day-2 operations

| Task                          | Command                                                                  |
|-------------------------------|--------------------------------------------------------------------------|
| Restart the bridge            | `systemctl restart anglerfish-bridge.service`                            |
| Tail bridge logs              | `journalctl -u anglerfish-bridge.service -f`                             |
| Rotate the credentials key    | `anglerfish credentials rotate-key --new-key $(openssl rand -base64 32)` |
| Force a fresh geo download    | `systemctl start anglerfish-geo-update.service`                          |
| Re-run wizard (preserves DBs) | `anglerfish-wizard --reconfigure`                                        |
| View masked configuration     | `anglerfish config show`                                                 |
| Inspect audit log             | `cat /var/log/anglerfish/audit.jsonl \| jq`                              |

All these commands run inside the VM and live in the venv at
`/opt/anglerfish/venv/bin/`; symlinks under `/usr/local/bin/` keep
them on the operator's PATH.

---

## 7. Tearing down

```bash
qm stop 9001
qm destroy 9001
```

`vzdump` snapshots and `pve-backup` jobs survive `qm destroy`; the
deploy script does not touch them.

---

## 8. QEMU smoke before deploying

If you'd rather smoke-test the ISO on a workstation before pushing
it to Proxmox, [`iso/smoke.sh`](../iso/smoke.sh) boots it under
QEMU/KVM with bait + service NICs already wired:

```bash
./iso/smoke.sh ./build/anglerfish-ai-0.1.0.iso --memory 4G
```

Host port 2222 → guest 2222 (lure); host port 8420 → guest 8420
(dashboard). `Ctrl-A x` to terminate.

The smoke harness uses a persistent `iso/smoke/anglerfish.qcow2`
so reboots pick up the wizard's answers; delete it for a clean run.
