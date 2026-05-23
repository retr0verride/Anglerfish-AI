# Local LLM setup

Anglerfish runs entirely on local LLMs via [Ollama](https://ollama.com) —
no cloud dependencies. This guide walks you from a fresh Anglerfish VM
to a working three-tier model stack, with the SHA256 hashes captured
for the Stage 1 model-integrity check.

See [`PRODUCT.md`](PRODUCT.md) §"Design principles" for the local-only
rationale (resilience against upstream LLM compromise).

---

## The three-tier model stack

| Tier | Purpose | When it runs | Recommended pick |
|------|---------|--------------|------------------|
| **Fast** | Per-command shell responses | Every attacker turn (hot path) | `qwen2.5-coder:7b-instruct` |
| **Deep** | Intent extraction, session summaries | Once per session end (Stage 5+) | `phi-4` |
| **Embed** | Behavioural clustering | Per session (Stage 6+) | `nomic-embed-text` |

The Stage 1 defense layer only needs the **fast tier** to be wired up.
Deep and embed tiers come online with their respective stages but you
can pull them now to avoid re-doing the setup later.

See [`PRODUCT.md`](PRODUCT.md) for why these three roles and not a
single "do everything" model.

---

## Hardware sizing

The model picks above assume a single mid-range NVIDIA GPU (12GB VRAM
class — RTX 3060, 4070, etc.). Adjust as needed:

| GPU class | Fast model | Deep model | Embed model |
|-----------|-----------|-----------|-------------|
| **CPU only** (no GPU) | `phi-3:3.8b` (slow but works) | reuse fast model | `nomic-embed-text` |
| **8GB VRAM** (RTX 3050) | `qwen2.5-coder:7b-instruct` (Q4) | `phi-3.5:3.8b` | `nomic-embed-text` |
| **12GB VRAM** (RTX 3060) — **recommended** | `qwen2.5-coder:7b-instruct` (Q4_K_M) | `phi-4:14b` (Q4_K_M) | `nomic-embed-text` |
| **16GB VRAM** (RTX 4080) | `qwen2.5-coder:7b-instruct` (Q5) | `phi-4:14b` (Q5) | `mxbai-embed-large` |
| **24GB+ VRAM** (RTX 3090/4090) | `qwen2.5-coder:7b-instruct` | `qwen2.5:32b` | `mxbai-embed-large` |

The rest of this guide assumes the **12GB VRAM (recommended)** row.

---

## 1. Get the GPU to the Anglerfish VM

On Proxmox, the GPU can only be passed through to one VM at a time.
See [`proxmox.md`](proxmox.md) §"GPU passthrough" for the full
walkthrough; the short version:

```bash
# On the Proxmox host
qm stop <anglerfish-vmid>
qm set <anglerfish-vmid> --hostpci0 01:00,pcie=1,x-vga=1
qm start <anglerfish-vmid>
```

Then SSH into the Anglerfish VM over the service NIC:

```bash
ssh anglerfish-ops@<service-ip>
```

Install the NVIDIA driver and verify:

```bash
sudo apt install -y nvidia-driver firmware-misc-nonfree
sudo reboot

# After reboot
nvidia-smi
# Should show: GeForce RTX 3060, 12288MiB Memory-Usage
```

If `nvidia-smi` works inside the guest, GPU passthrough is good.

---

## 2. Install Ollama

Two paths depending on how the ISO was built:

### 2a. Already installed (build-time opt-in)

If the ISO was built with `ANGLERFISH_INSTALL_OLLAMA=1` (see
[`INSTALL.md`](INSTALL.md) §prerequisites), Ollama is already present.
Verify:

```bash
systemctl status ollama.service
# Should be: active (running)
ollama --version
```

Skip to [step 3](#3-tune-ollama-for-the-anglerfish-workload).

### 2b. Install at runtime (slim ISO)

If the ISO was built without the Ollama hook (the default — smaller
image), install now:

```bash
# This is Ollama's official installer — runs as root, installs the
# systemd unit, starts the service. No interactive prompts.
curl -fsSL https://ollama.com/install.sh | sh
```

Verify:

```bash
systemctl status ollama.service
ollama --version
```

---

## 3. Tune Ollama for the Anglerfish workload

Anglerfish wants Ollama to:

1. Serve multiple attacker requests in parallel
2. Keep the hot tier in VRAM permanently
3. Swap models efficiently when the deep tier is called
4. Use VRAM-efficient features (flash attention, quantized KV cache)

Add a systemd drop-in:

```bash
sudo systemctl edit ollama.service
```

Paste this into the editor that opens:

```ini
[Service]
Environment="OLLAMA_NUM_PARALLEL=2"
Environment="OLLAMA_FLASH_ATTENTION=1"
Environment="OLLAMA_KV_CACHE_TYPE=q8_0"
Environment="OLLAMA_MAX_LOADED_MODELS=2"
Environment="OLLAMA_KEEP_ALIVE=-1"
```

Reload + restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ollama.service
```

The new settings are now active. Each variable explained:

| Variable | Why |
|----------|-----|
| `OLLAMA_NUM_PARALLEL=2` | Fast tier serves 2 concurrent attacker requests. More = better throughput, more VRAM per request. |
| `OLLAMA_FLASH_ATTENTION=1` | ~15% VRAM savings, ~10% faster on Ampere+. |
| `OLLAMA_KV_CACHE_TYPE=q8_0` | Quantize attention cache to 8-bit. More VRAM headroom for context. |
| `OLLAMA_MAX_LOADED_MODELS=2` | Embedding model + one big model can coexist. Bigger model evicts the other when needed. |
| `OLLAMA_KEEP_ALIVE=-1` | Don't auto-unload on idle. Anglerfish manages eviction via per-call `keep_alive` later. |

---

## 4. Pull the three models

Total download is ~13GB; takes 5-20 minutes depending on your internet.

```bash
# Fast tier — ~4.4GB
ollama pull qwen2.5-coder:7b-instruct

# Deep tier — ~8.5GB
ollama pull phi-4

# Embedding tier — ~280MB
ollama pull nomic-embed-text
```

Verify all three are present:

```bash
ollama list
# NAME                                 ID            SIZE
# qwen2.5-coder:7b-instruct            ...           4.4 GB
# phi-4:latest                         ...           8.5 GB
# nomic-embed-text:latest              ...           274 MB
```

---

## 5. Smoke-test each model

```bash
# Fast tier — should respond in 1-2s
ollama run qwen2.5-coder:7b-instruct "explain ls -la output"

# Deep tier — should respond in 10-30s
ollama run phi-4 "summarize: an SSH attacker tried 47 common passwords against root, then ran wget to download a script. what are they probably doing?"

# Embedding tier — returns a vector
curl -s http://localhost:11434/api/embeddings \
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

## 6. Capture the layer-blob hashes for the integrity check

The Stage 1 model-integrity check ([`design/STAGE_1_llm_defense.md`](design/STAGE_1_llm_defense.md))
pins against the *layer/blob* digest, not the human-readable tag — this
defeats silent tag re-pointing attacks. Capture the hashes now so the
bridge can verify them at every startup.

```bash
# Install jq if not present
sudo apt install -y jq

# Capture each hash
MANIFEST_ROOT=~/.ollama/models/manifests/registry.ollama.ai/library

FAST_HASH=$(jq -r '.layers[] | select(.mediaType == "application/vnd.ollama.image.model") | .digest' \
    "$MANIFEST_ROOT/qwen2.5-coder/7b-instruct")
DEEP_HASH=$(jq -r '.layers[] | select(.mediaType == "application/vnd.ollama.image.model") | .digest' \
    "$MANIFEST_ROOT/phi-4/latest")
EMBED_HASH=$(jq -r '.layers[] | select(.mediaType == "application/vnd.ollama.image.model") | .digest' \
    "$MANIFEST_ROOT/nomic-embed-text/latest")

echo "Fast:  $FAST_HASH"
echo "Deep:  $DEEP_HASH"
echo "Embed: $EMBED_HASH"
```

Each prints `sha256:abc123...`. Save these — they go into the next step.

---

## 7. Wire the models into Anglerfish

Edit `/etc/anglerfish/anglerfish.env`:

```bash
sudo nano /etc/anglerfish/anglerfish.env
```

Set or update these lines:

```bash
# Loopback Ollama — co-located with the bridge, no trusted_remote_host needed
ANGLERFISH_OLLAMA__BASE_URL=http://127.0.0.1:11434/

# Fast-tier model (the only one Stage 1 needs; Stage 3 adds the multi-model layer)
ANGLERFISH_OLLAMA__MODEL=qwen2.5-coder:7b-instruct

# Stage 1 defense — pin the fast model's layer hash
ANGLERFISH_DEFENSE__MODEL_EXPECTED_HASH=sha256:<paste fast hash from step 6>

# REQUIRED when MODEL_EXPECTED_HASH is set: where to find the manifest.
# Common values:
#   /usr/share/ollama/.ollama/models/manifests  (Linux, official systemd installer)
#   ~/.ollama/models/manifests                  (user-installed Ollama)
# The bridge cross-field-validates these two together; setting one without
# the other fails at startup with a clear error.
ANGLERFISH_DEFENSE__OLLAMA_MANIFEST_DIR=/usr/share/ollama/.ollama/models/manifests

# Stage 1 defense layer tuning (optional — defaults are sensible)
ANGLERFISH_DEFENSE__OUTPUT_FILTER_ENABLED=true
ANGLERFISH_DEFENSE__INJECTION_FILTER_ENABLED=true
ANGLERFISH_DEFENSE__INJECTION_THRESHOLD=0.7
```

Restart the bridge to pick up the new config:

```bash
sudo systemctl restart anglerfish-bridge.service
```

Verify:

```bash
sudo journalctl -u anglerfish-bridge.service --since '1 min ago' --no-pager
# Should NOT see: "model integrity skipped" warning
# Should see: "bridge.model_integrity_verified" in the audit log
sudo tail -5 /var/log/anglerfish/audit.jsonl | jq
```

---

## 8. End-to-end smoke test

From a throwaway host on the bait NIC:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 testuser@<bait-ip>
# Try a few commands; the LLM should respond plausibly
```

Inside the Anglerfish VM, watch the bridge process the commands:

```bash
sudo journalctl -u anglerfish-bridge.service -f
```

You should see Ollama HTTP calls, response timings, and (if you trigger
a defense pattern with something like `ignore previous instructions`) a
`bridge.defense_fired` audit-log entry.

---

## When you update a model

Whenever you `ollama pull` a new version of a tracked model, the layer
digest changes — the integrity check will catch it as a mismatch and
the bridge will refuse to start. That's working as designed.

To roll an update intentionally:

```bash
# 1. Update the model
ollama pull qwen2.5-coder:7b-instruct

# 2. Capture the new hash
jq -r '.layers[] | select(.mediaType == "application/vnd.ollama.image.model") | .digest' \
    ~/.ollama/models/manifests/registry.ollama.ai/library/qwen2.5-coder/7b-instruct

# 3. Update the env file
sudo nano /etc/anglerfish/anglerfish.env
# Change ANGLERFISH_DEFENSE__MODEL_EXPECTED_HASH to the new value

# 4. Restart the bridge
sudo systemctl restart anglerfish-bridge.service

# 5. Verify the new hash was accepted
sudo tail -3 /var/log/anglerfish/audit.jsonl | jq
# Look for: bridge.model_integrity_verified
```

This three-step process is the visibility tax for the integrity check.
Every model update is intentional and audited.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `ollama: command not found` | Slim ISO, Ollama not installed | Run step 2b |
| `nvidia-smi: command not found` | NVIDIA driver not installed | `sudo apt install nvidia-driver firmware-misc-nonfree && sudo reboot` |
| `nvidia-smi` works but Ollama is slow (>10s/token) | Ollama falling back to CPU | Check `journalctl -u ollama.service` for CUDA errors; usually a driver / CUDA-runtime version mismatch |
| `Out of memory` on `ollama run phi-4` | Fast model still loaded | Verify `OLLAMA_MAX_LOADED_MODELS=2`; if still failing, restart Ollama to clear state |
| Bridge logs `model integrity check failed` after `ollama pull` | Expected — model updated, hash mismatch | Update `ANGLERFISH_DEFENSE__MODEL_EXPECTED_HASH` per "When you update a model" |
| Bridge logs `model integrity skipped` warning | `ANGLERFISH_DEFENSE__MODEL_EXPECTED_HASH` unset | Capture the hash (step 6), set the env var, restart the bridge |
| `OLLAMA_FLASH_ATTENTION=1` makes inference slower or crashes | Flash attention incompatible with your quant type or driver version | Set to `0`, restart Ollama |
| Disk filling fast under `~/.ollama/models/blobs` | `keep_alive=-1` + multiple pulls of similar models | Run `ollama list` and `ollama rm <unused>` to clean up |

---

## Why these models, and not others

See [`PRODUCT.md`](PRODUCT.md) §"Why these specifically" for the full
reasoning. Short version:

* **Qwen2.5-Coder over Deepseek-Coder** — surpassed it in late 2024 on
  shell/code generation; Apache 2.0; actively maintained. The known
  markdown-drift quirk is *exactly* what the Stage 1 `markdown_formatting`
  detector targets.
* **Phi-4 over Qwen2.5:32B** — 14B parameters that punch like 30B for
  summarization, and fits in 12GB VRAM where 32B doesn't.
* **Nomic-Embed over MiniLM** — Better semantic representation, fast
  enough that we can re-embed sessions cheaply when the model is
  swapped.

If a future model meaningfully beats one of these on the relevant axis
(shell knowledge, summarization quality, embedding cluster purity),
swapping is one env var change + a hash recapture. Local-LLM is the
constraint; specific model choice is replaceable.
