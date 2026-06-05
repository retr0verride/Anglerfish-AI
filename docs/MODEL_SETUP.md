# Local LLM setup

Anglerfish runs entirely on local LLMs via [Ollama](https://ollama.com),
no cloud dependencies. This is the model-stack reference: the three-tier
model picks, the hardware sizing, the Ollama workload tuning, the model
pulls, and the SHA256 hashes captured for the Stage 1 model-integrity
check.

The model stack runs on the **Model VM**, the GPU host. The honeypot VM
has no GPU and calls the Model VM over the service network. The canonical
deploy guide is [`proxmox.md`](proxmox.md); it builds both VMs end to end.
This guide is the detail behind its Model VM steps. Where the deploy guide
already covers a step, this guide points at it instead of repeating it.

Read [`proxmox.md`](proxmox.md) first if you have not. It owns the VM
build, the GPU passthrough, and the wiring. This guide owns the model
choices and the integrity pin.

See [`PRODUCT.md`](PRODUCT.md) §"Design principles" for the local-only
rationale (resilience against upstream LLM compromise).

---

## The three-tier model stack

| Tier | Purpose | When it runs | Recommended pick |
|------|---------|--------------|------------------|
| **Fast** | Per-command shell responses | Every attacker turn (hot path) | `qwen3:14b` |
| **Deep** | Intent extraction, session summaries | Once per session end (Stage 5+) | `phi-4` |
| **Embed** | Behavioural clustering | Per session (Stage 6+) | `nomic-embed-text` |

The Stage 1 defense layer only needs the **fast tier** to be wired up.
Deep and embed tiers come online with their respective stages but you
can pull them now to avoid re-doing the setup later.

See [`PRODUCT.md`](PRODUCT.md) for why these three roles and not a
single "do everything" model.

---

## Hardware sizing

The model picks above assume a single mid-range NVIDIA GPU on the Model
VM (12GB VRAM class. RTX 3060, 4070, etc.). Size the Model VM's GPU and
RAM from this table. Adjust as needed:

| GPU class | Fast model | Deep model | Embed model |
|-----------|-----------|-----------|-------------|
| **CPU only** (no GPU) | `phi-3:3.8b` (slow but works) | reuse fast model | `nomic-embed-text` |
| **8GB VRAM** (RTX 3050) | `qwen3:14b` (Q4) | `phi-3.5:3.8b` | `nomic-embed-text` |
| **12GB VRAM** (RTX 3060) - **recommended** | `qwen3:14b` (Q4_K_M) | `phi-4:14b` (Q4_K_M) | `nomic-embed-text` |
| **16GB VRAM** (RTX 4080) | `qwen3:14b` (Q5) | `phi-4:14b` (Q5) | `mxbai-embed-large` |
| **24GB+ VRAM** (RTX 3090/4090) | `qwen3:14b` | `qwen2.5:32b` | `mxbai-embed-large` |

The rest of this guide assumes the **12GB VRAM (recommended)** row.

---

## 1. Build the Model VM, pass through the GPU, install Ollama

These steps live in the deploy guide. Do them there, then come back here
for the tuning, the model pulls, and the hash capture:

* [`proxmox.md`](proxmox.md) **Step 2** enables GPU passthrough on the
  Proxmox host (IOMMU, bind the card to `vfio-pci`).
* [`proxmox.md`](proxmox.md) **Step 3** builds the Model VM and attaches
  the GPU.
* [`proxmox.md`](proxmox.md) **Step 4** installs the NVIDIA driver,
  confirms `nvidia-smi` sees the card, and installs Ollama.

When you finish Step 4, the Model VM has Ollama running and bound to its
service address (`OLLAMA_HOST=<model-ip>:11434`). The rest of this guide
runs on that VM: SSH in (`ssh <user>@<model-ip>`) and tune, pull, and
capture hashes.

The honeypot VM never runs Ollama and never touches the GPU. It only
reaches the Model VM over the service network.

> A loopback Ollama (`OLLAMA_HOST=127.0.0.1:11434`, model and bridge on
> one box) is fine for local dev or a single-machine test. It is not the
> deployed topology. The rest of this guide and [`proxmox.md`](proxmox.md)
> assume the split: GPU and Ollama on the Model VM, honeypot separate.

---

## 2. Tune Ollama for the Anglerfish workload

[`proxmox.md`](proxmox.md) Step 4 already sets these in the Model VM's
systemd drop-in, alongside the `OLLAMA_HOST` binding. This section is the
rationale. Use it to verify the drop-in or to tune a fresh install.

Anglerfish wants Ollama to:

1. Serve multiple attacker requests in parallel
2. Keep the hot tier in VRAM permanently
3. Swap models efficiently when the deep tier is called
4. Use VRAM-efficient features (flash attention, quantized KV cache)

Open the systemd drop-in on the Model VM:

```bash
sudo systemctl edit ollama.service
```

The full drop-in binds Ollama to the service address and applies the
tuning. Replace `<model-ip>` with the Model VM's service-network address:

```ini
[Service]
Environment="OLLAMA_HOST=<model-ip>:11434"
Environment="OLLAMA_NUM_PARALLEL=2"
Environment="OLLAMA_FLASH_ATTENTION=1"
Environment="OLLAMA_KV_CACHE_TYPE=q8_0"
Environment="OLLAMA_MAX_LOADED_MODELS=2"
Environment="OLLAMA_KEEP_ALIVE=-1"
```

Bind to the service address, never `0.0.0.0`. The Model VM firewall (set
in [`proxmox.md`](proxmox.md) Step 4) still limits port 11434 to the
honeypot, but binding narrow is the first line.

Reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ollama.service
```

The settings are now active. Each variable explained:

| Variable | Why |
|----------|-----|
| `OLLAMA_NUM_PARALLEL=2` | Fast tier serves 2 concurrent attacker requests. More = better throughput, more VRAM per request. |
| `OLLAMA_FLASH_ATTENTION=1` | ~15% VRAM savings, ~10% faster on Ampere+. |
| `OLLAMA_KV_CACHE_TYPE=q8_0` | Quantize attention cache to 8-bit. More VRAM headroom for context. |
| `OLLAMA_MAX_LOADED_MODELS=2` | Embedding model + one big model can coexist. Bigger model evicts the other when needed. |
| `OLLAMA_KEEP_ALIVE=-1` | Don't auto-unload on idle. Anglerfish manages eviction via per-call `keep_alive` later. |

---

## 3. Pull the three models

Run these on the Model VM. Total download is ~13GB; takes 5-20 minutes
depending on your internet.

```bash
# Fast tier - ~4.4GB
ollama pull qwen3:14b

# Deep tier - ~8.5GB
ollama pull phi-4

# Embedding tier - ~280MB
ollama pull nomic-embed-text
```

Verify all three are present:

```bash
ollama list
# NAME                                 ID            SIZE
# qwen3:14b            ...           4.4 GB
# phi-4:latest                         ...           8.5 GB
# nomic-embed-text:latest              ...           274 MB
```

---

## 4. Smoke-test each model

Run these on the Model VM. The `ollama run` calls use the local CLI. The
embeddings curl hits the HTTP API, so it uses the bound service address
(`<model-ip>`), not loopback.

```bash
# Fast tier - should respond in 1-2s
ollama run qwen3:14b "explain ls -la output"

# Deep tier - should respond in 10-30s
ollama run phi-4 "summarize: an SSH attacker tried 47 common passwords against root, then ran wget to download a script. what are they probably doing?"

# Embedding tier - returns a vector
curl -s http://<model-ip>:11434/api/embeddings \
    -d '{"model": "nomic-embed-text", "prompt": "ls -la /etc"}' \
    | head -c 200
```

If all three return sensible output, the models are functional.

Watch GPU memory while these run:

```bash
watch -n 1 nvidia-smi
```

You should see the model processes loading into VRAM, hitting ~5-10GB
used, and freeing on exit (except where `keep_alive=-1` keeps them
warm).

---

## 5. Capture the layer-blob hashes for the integrity check

The Stage 1 model-integrity check ([`design/STAGE_1_llm_defense.md`](design/STAGE_1_llm_defense.md))
pins against the *layer/blob* digest, not the human-readable tag. This
defeats silent tag re-pointing attacks. Capture the hashes now so the
bridge can verify them at startup.

Run this on the Model VM (the manifests live next to the models). The
official systemd installer stores them under the `ollama` user's home;
a user install stores them under yours. Pick the root that exists:

```bash
# Install jq if not present
sudo apt install -y jq

# Manifest root. Official systemd installer (used by proxmox.md):
MANIFEST_ROOT=/usr/share/ollama/.ollama/models/manifests/registry.ollama.ai/library
# User-installed Ollama instead:
#   MANIFEST_ROOT=~/.ollama/models/manifests/registry.ollama.ai/library

FAST_HASH=$(sudo jq -r '.layers[] | select(.mediaType == "application/vnd.ollama.image.model") | .digest' \
    "$MANIFEST_ROOT/qwen3/14b")
DEEP_HASH=$(sudo jq -r '.layers[] | select(.mediaType == "application/vnd.ollama.image.model") | .digest' \
    "$MANIFEST_ROOT/phi-4/latest")
EMBED_HASH=$(sudo jq -r '.layers[] | select(.mediaType == "application/vnd.ollama.image.model") | .digest' \
    "$MANIFEST_ROOT/nomic-embed-text/latest")

echo "Fast:  $FAST_HASH"
echo "Deep:  $DEEP_HASH"
echo "Embed: $EMBED_HASH"
```

Each prints `sha256:abc123...`. Save the fast and deep hashes. They go
into the next step on the honeypot. Stage 1 pins only the fast and deep
roles, so the embed hash is informational for now.

The honeypot pins these hashes but reads its own local manifest copy to
do it, so a remote manifest only helps if you sync it. The next step and
[`proxmox.md`](proxmox.md) Step 8 "Model-integrity pinning" cover the
sync-or-skip choice.

---

## 6. Wire the models into Anglerfish (on the honeypot)

This step runs on the **honeypot VM**, not the Model VM. The first-boot
wizard ([`proxmox.md`](proxmox.md) Step 6) already wrote the endpoint and
the trusted-remote IP. Edit the env file to add the per-role models and
the integrity hashes you captured in §5.

```bash
sudo nano /etc/anglerfish/anglerfish.env
```

Set or update these lines. Replace `<model-ip>` with the Model VM's
service-network address:

```bash
# Point the bridge at the Model VM. Both must be set in split mode: the
# base_url host must equal trusted_remote_host, and it must be an IP
# literal (hostnames are rejected because DNS could change under us).
ANGLERFISH_OLLAMA__BASE_URL=http://<model-ip>:11434/
ANGLERFISH_OLLAMA__TRUSTED_REMOTE_HOST=<model-ip>

# Per-role models (fast + deep tiers). The pre-Stage-5 single-key
# aliases ANGLERFISH_OLLAMA__MODEL / ANGLERFISH_DEFENSE__MODEL_EXPECTED_HASH
# still work as deprecated shims, but use the explicit keys below.
ANGLERFISH_OLLAMA__FAST_MODEL=qwen3:14b
ANGLERFISH_OLLAMA__DEEP_MODEL=phi-4

# Stage 1 defense - pin each model's layer hash (from step 5).
# OPTIONAL in split mode: see the manifest note below before setting these.
ANGLERFISH_DEFENSE__FAST_MODEL_EXPECTED_HASH=sha256:<paste fast hash from step 5>
ANGLERFISH_DEFENSE__DEEP_MODEL_EXPECTED_HASH=sha256:<paste deep hash from step 5>

# REQUIRED when any *_MODEL_EXPECTED_HASH is set: where to find the
# manifest ON THE HONEYPOT. The bridge reads its LOCAL filesystem, so in
# split mode this is a copy synced from the Model VM (see note below).
# The bridge cross-validates these together; setting a hash without the
# manifest dir fails at startup with a clear error.
ANGLERFISH_DEFENSE__OLLAMA_MANIFEST_DIR=/etc/anglerfish/ollama-manifests

# Stage 1 defense layer tuning (optional - defaults are sensible)
ANGLERFISH_DEFENSE__OUTPUT_FILTER_ENABLED=true
ANGLERFISH_DEFENSE__INJECTION_FILTER_ENABLED=true
ANGLERFISH_DEFENSE__INJECTION_THRESHOLD=0.7
```

### The hash pin needs the manifest on the honeypot

The integrity check reads Ollama's manifest from the bridge's **local**
filesystem ([`src/anglerfish/bridge/defense.py:638-650`](../src/anglerfish/bridge/defense.py#L638-L650)).
In split mode the manifests live on the Model VM, so the honeypot has no
local copy by default. You have two options:

1. **Skip the pin.** Leave both
   `ANGLERFISH_DEFENSE__FAST_MODEL_EXPECTED_HASH` and
   `ANGLERFISH_DEFENSE__DEEP_MODEL_EXPECTED_HASH` (and
   `ANGLERFISH_DEFENSE__OLLAMA_MANIFEST_DIR`) unset. The bridge logs
   `bridge.model_integrity_skipped` and starts. The honeypot does not
   manage the model anyway.
2. **Keep the pin.** Sync the Model VM's manifest tree to the honeypot
   (rsync over the service link, read-only) and point
   `ANGLERFISH_DEFENSE__OLLAMA_MANIFEST_DIR` at the local copy. Re-sync on
   every `ollama pull`.

[`proxmox.md`](proxmox.md) Step 8 "Model-integrity pinning" has the rsync
command and the full reasoning. Pick one before you restart the bridge.

Restart the bridge to pick up the new config:

```bash
sudo systemctl restart anglerfish-bridge.service
```

Verify on the honeypot:

```bash
sudo journalctl -u anglerfish-bridge.service --since '1 min ago' --no-pager
sudo tail -5 /var/log/anglerfish/audit.jsonl | jq
```

What you should see depends on the choice above:

* **Pin kept:** `bridge.model_integrity_verified` for each role.
* **Pin skipped:** `bridge.model_integrity_skipped`. This is a valid
  state in split mode, not an error.

---

## 7. End-to-end smoke test

From a throwaway host on the bait NIC:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 testuser@<bait-ip>
# Try a few commands; the LLM should respond plausibly
```

On the honeypot, watch the bridge process the commands:

```bash
sudo journalctl -u anglerfish-bridge.service -f
```

You should see Ollama HTTP calls to the Model VM, response timings, and
(if you trigger a defense pattern with something like `ignore previous
instructions`) a `bridge.defense_fired` audit-log entry.

[`proxmox.md`](proxmox.md) Step 7 has the full chain verification,
including the dashboard health check.

---

## When you update a model

Whenever you `ollama pull` a new version of a tracked model, the layer
digest changes. If you kept the integrity pin, the check catches the
mismatch and the bridge refuses to start. That is working as designed.

The pull happens on the Model VM. The env update happens on the honeypot.
To roll an update intentionally with the pin kept:

```bash
# 1. On the Model VM: update the model
ollama pull qwen3:14b

# 2. On the Model VM: capture the new hash (adjust MANIFEST_ROOT per step 5)
sudo jq -r '.layers[] | select(.mediaType == "application/vnd.ollama.image.model") | .digest' \
    /usr/share/ollama/.ollama/models/manifests/registry.ollama.ai/library/qwen3/14b

# 3. If you sync the manifest tree (pin kept), re-sync it to the honeypot
#    now so its local copy matches. See proxmox.md Step 8.

# 4. On the honeypot: update the env file
sudo nano /etc/anglerfish/anglerfish.env
# Change ANGLERFISH_DEFENSE__FAST_MODEL_EXPECTED_HASH to the new value

# 5. On the honeypot: restart the bridge
sudo systemctl restart anglerfish-bridge.service

# 6. Verify the new hash was accepted
sudo tail -3 /var/log/anglerfish/audit.jsonl | jq
# Look for: bridge.model_integrity_verified
```

If you skipped the pin, you only do steps 1 and 2 (and the model just
updates). The integrity check is the visibility tax: every pinned model
update is intentional and audited.

---

## Troubleshooting

All of these except the env-file ones are on the **Model VM**. The
`anglerfish.env` and bridge entries are on the **honeypot**.

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `ollama: command not found` (Model VM) | Ollama not installed | Run [`proxmox.md`](proxmox.md) Step 4 |
| `nvidia-smi: command not found` (Model VM) | NVIDIA driver not installed | `sudo apt install nvidia-driver firmware-misc-nonfree && sudo reboot` |
| `nvidia-smi` works but Ollama is slow (>10s/token) | Ollama falling back to CPU | Check `journalctl -u ollama.service` for CUDA errors; usually a driver / CUDA-runtime version mismatch |
| `Out of memory` on `ollama run phi-4` | Fast model still loaded | Verify `OLLAMA_MAX_LOADED_MODELS=2`; if still failing, restart Ollama to clear state |
| Honeypot bridge fails to start: `base_url host ... does not match trusted_remote_host` | `BASE_URL` IP and `TRUSTED_REMOTE_HOST` disagree | Make both the same Model VM IP literal; no hostnames |
| Bridge logs `bridge.model_integrity` mismatch after `ollama pull` | Expected with the pin kept; model updated, hash changed | Recapture the hash and update the env var per "When you update a model"; re-sync the manifest |
| Bridge logs `bridge.model_integrity_skipped` | A `*_MODEL_EXPECTED_HASH` is unset | Valid in split mode (see §6 option 1). To pin: sync the manifest, set the hash + `OLLAMA_MANIFEST_DIR`, restart the bridge |
| Bridge start fails: `*_model_expected_hash is set but ... ollama_manifest_dir is not` | Hash set without the manifest dir | Set `ANGLERFISH_DEFENSE__OLLAMA_MANIFEST_DIR` to the synced manifest path on the honeypot, or unset the hash |
| `OLLAMA_FLASH_ATTENTION=1` makes inference slower or crashes | Flash attention incompatible with your quant type or driver version | Set to `0`, restart Ollama |
| Disk filling fast under the Ollama `models/blobs` dir | `keep_alive=-1` + multiple pulls of similar models | Run `ollama list` and `ollama rm <unused>` to clean up |

---

## Why these models, and not others

See [`PRODUCT.md`](PRODUCT.md) §"Why these specifically" for the full
reasoning. Short version:

* **Qwen3:14b over Deepseek-Coder** - Apache-2.0 licensed, distributed
  via Hugging Face, 14B params fits in 12GB VRAM at Q4. **Deepseek
  family deliberately avoided in production defaults**: third-party
  security reviews have flagged CCP-aligned content moderation that
  surfaces in shell honeypot contexts (LLM occasionally refuses or
  re-frames responses in ways that don't match a real Linux shell,
  breaking the deception). Qwen3 is independent of those concerns.
  The known markdown-drift quirk is *exactly* what the Stage 1
  `markdown_formatting` detector targets.
* **Phi-4 over Qwen2.5:32B** - 14B parameters that punch like 30B for
  summarization, and fits in 12GB VRAM where 32B doesn't.
* **Nomic-Embed over MiniLM** - Better semantic representation, fast
  enough that we can re-embed sessions cheaply when the model is
  swapped.

**Operator override is one env var per tier.** Nothing about Stage 1's
defense layer is model-specific; if you have an internal preference (an
in-house fine-tune, a different upstream you trust) just set
`ANGLERFISH_OLLAMA__FAST_MODEL` (and/or `__DEEP_MODEL`) and capture the
new hash per §5.

If a future model meaningfully beats one of these on the relevant axis
(shell knowledge, summarization quality, embedding cluster purity),
swapping is one env var change + a hash recapture. Local-LLM is the
constraint; specific model choice is replaceable.
