# Strict-lab Proxmox setup

This is the **closed-lab** variant of the Proxmox deployment guide. The
production [`proxmox.md`](proxmox.md) puts Anglerfish on a real attacker
network; this one puts it in a hermetic sandbox where attackers can
only reach the honeypot from inside your own host.

Read [`proxmox.md`](proxmox.md) first. It is the canonical step-by-step
deploy: two bridges, GPU passthrough, the Model VM, Ollama, the honeypot
VM, the first-boot wizard, and verification. This lab guide does not
repeat those steps. It covers only the lab-specific differences: the
air-gapped bait bridge, host-side PCAP capture, the snapshot/reset
workflow, and PCAP replay. Everything else, including the split-VM
topology, you take from `proxmox.md`.

The topology is the same as production. The honeypot VM has no GPU and
calls a separate Model VM running Ollama. The lab difference is scale,
not shape: a lab Model VM can run a small model, and the bait bridge is
air-gapped instead of internet-exposed. The honeypot still reaches
Ollama over the service network, never over loopback.

Use the lab for:

* **Training yourself** - operate a honeypot end-to-end without the
  legal/operational risk of exposing it to the real internet.
* **Replaying captured PCAPs** against the honeypot to study one
  attacker session in depth (you control the replay timing, you can
  pause and inspect, you can repeat).
* **Developing detection rules** - write a Suricata/Zeek rule, replay
  the PCAP, see if it fires.

When to graduate: once you've got operator reps and you have a
disclosure + incident-response plan, switch to [`proxmox.md`](proxmox.md)
for real exposure. The lab does not generate threat-intel for the
community, it's a private training environment.

---

## What "strict" means here

1. **Air-gapped bait bridge.** The bait NIC inside the honeypot is on
   `vmbr-lab`, a Linux bridge with `bridge-ports none`, no physical
   uplink. Nothing from outside the Proxmox host can reach the honeypot.
   Attacker traffic comes from another VM on the same host (a Kali, a
   replay-tool VM, etc.).
2. **Continuous PCAP capture** on the bait bridge, host-side, rotating
   hourly with a 7-day retention. Every byte the attacker VM sends is
   archived to `/var/log/anglerfish-lab/pcap/` for after-the-fact
   analysis in Wireshark, Suricata, or Zeek.
3. **Snapshot-and-reset workflow.** Take a clean snapshot of the
   honeypot VM before each study, study one attacker, roll back. Each
   study starts from byte-identical state, credentials DB empty, audit
   log fresh, no contamination from the previous session.

---

## 1. Host preparation

### 1.1 The air-gapped bait bridge

Append [`proxmox/lab/host-bridge.conf`](../proxmox/lab/host-bridge.conf)
to `/etc/network/interfaces` on the Proxmox host, then:

```bash
ifreload -a
ip -br link show vmbr-lab
# vmbr-lab          UP             <BROADCAST,MULTICAST,UP,LOWER_UP>
```

The bridge exists but has no uplink. Anything attached to it can only
reach other VMs on the same bridge, there's no route to the rest of
the network.

You still need `vmbr-service` (the operator-facing bridge from the
production guide); the dashboard and SSH ops live there.

### 1.2 PCAP capture systemd unit

Install [`proxmox/lab/anglerfish-lab-pcap.service`](../proxmox/lab/anglerfish-lab-pcap.service):

```bash
apt install tcpdump                     # if not present
useradd --system --no-create-home --shell /usr/sbin/nologin tcpdump || true
install -d -m 0750 -o tcpdump -g tcpdump /var/log/anglerfish-lab/pcap

cp proxmox/lab/anglerfish-lab-pcap.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now anglerfish-lab-pcap.service

# Verify it's writing PCAPs.
ls -lh /var/log/anglerfish-lab/pcap/
```

The unit captures full-packet on `vmbr-lab`, rotates the PCAP file
every hour (`-G 3600`), keeps 168 files (`-W 168` = 7 days), and drops
privileges to the `tcpdump` user once the raw socket is open.

To inspect a PCAP later:

```bash
# All traffic from a specific hour
wireshark /var/log/anglerfish-lab/pcap/cap-2026-05-23-14*.pcap

# Just SSH negotiation for one source IP
tshark -r cap-2026-05-23-14*.pcap -Y 'ip.src == 10.20.30.40 && tcp.port == 22'

# Run a Suricata ruleset across all captures
suricata -r /var/log/anglerfish-lab/pcap/cap-*.pcap -l /tmp/sur-out
```

---

## 2. Build the Model VM and deploy the honeypot

Build the Model VM and stand up Ollama per [`proxmox.md`](proxmox.md)
steps 3 and 4. The only lab change is the model: pull a smaller one from
the [`MODEL_SETUP.md`](MODEL_SETUP.md) hardware table (for example
`phi-3.5:3.8b`) instead of the production stack, and size the Model VM's
RAM and VRAM to it. Put the Model VM on `vmbr-service`, same as
production. The honeypot reaches it over that bridge.

Deploy the honeypot VM with [`proxmox/deploy.sh`](../proxmox/deploy.sh)
as in [`proxmox.md`](proxmox.md) step 5. The deploy script reads the VM
parameters, including the bait bridge, from
[`proxmox/anglerfish.json`](../proxmox/anglerfish.json) (the `--template`
flag points it at a different file). It has no `--bait-bridge` flag. For
the lab, copy `anglerfish.json` and set `network.bait_bridge` to
`vmbr-lab` (the air-gapped bridge from §1.1), then pass your copy:

```bash
sudo ./deploy.sh \
    --iso ./anglerfish-ai-0.1.0.iso \
    --vmid 9000 \
    --name anglerfish-lab \
    --template ./anglerfish-lab.json
```

The first-boot wizard runs as in [`proxmox.md`](proxmox.md) step 6.
Point the Ollama endpoint and trusted remote IP at the lab Model VM:

* **Ollama endpoint URL:** `http://<model-ip>:11434/` (the lab Model VM
  on `vmbr-service`).
* **Trusted remote Ollama IP:** `<model-ip>` (must match the endpoint
  host).
* **Ollama model tag:** the smaller model you pulled, for example
  `phi-3.5:3.8b`.

The endpoint host must be an IP literal, and it must not be loopback.
The wizard rejects a hostname, and the split topology means the honeypot
never runs Ollama itself.

---

## 3. Take a clean snapshot

After the wizard finishes and the honeypot is running normally, capture
the baseline:

```bash
sudo ./proxmox/lab/snapshot.sh 9000
# [lab] taking snapshot 'clean' on VM 9000
# [lab] done. roll back with: sudo ./reset.sh 9000 clean
```

`snapshot.sh` deletes any existing snapshot of that name first, then
takes a fresh one, so re-running it always reflects current state. The
VM disk must be on snapshot-capable storage (LVM-thin, ZFS, or qcow2);
raw on directory storage does not support `qm snapshot`.

This is the state every future attacker session starts from: empty
credentials DB, empty audit log past the wizard's bootstrap entries,
empty threat history, default geo cache. Re-snapshot whenever you
intentionally change the baseline (e.g. after a software upgrade).

---

## 4. Run an attacker session

Either:

* Stand up a second VM on `vmbr-lab` with attack tooling (Kali, Metasploit,
  hydra, etc.) and point it at the honeypot's bait IP.
* Replay a captured PCAP against the honeypot using `tcpreplay`:
  ```bash
  tcpreplay -i vmbr-lab --pps 50 ./attacker-sample.pcap
  ```

Watch the dashboard at `http://<service-ip>:8420/` in real time (plain
HTTP, no TLS). The audit log records operator actions; the credentials
DB collects what the attacker tried; the threat engine scores the
session.

When you're done analyzing, grab any data you want to keep:

```bash
# Inside the honeypot
ssh anglerfish-ops@<service-ip>
sudo journalctl -u anglerfish-bridge.service > /tmp/bridge-log.txt
sudo cp /var/lib/anglerfish/credentials.db /tmp/creds-session-1.db
sudo cp /var/log/anglerfish/audit.jsonl /tmp/audit-session-1.jsonl
exit
# Pull them to the operator host
scp anglerfish-ops@<service-ip>:/tmp/{bridge-log.txt,creds-session-1.db,audit-session-1.jsonl} ./session-1/
```

---

## 5. Reset to clean

```bash
sudo ./proxmox/lab/reset.sh 9000
# [lab] roll VM 9000 back to 'clean'? This DISCARDS all changes. [y/N] y
# [lab] stopping VM 9000
# [lab] rolling back VM 9000 to 'clean'
# [lab] starting VM 9000
```

The script refuses to proceed without an explicit `y` because rollback
destroys everything since the snapshot, including captured credentials,
audit log, and threat history. Save anything you want first (see the end
of §4). Once the VM comes back up, you're ready for the next session.
The Model VM stays up across resets; only the honeypot rolls back.

---

## 6. Replay a real attacker against your lab

If you have a PCAP of a real SSH brute-force or honeypot session
(maybe from a previous internet-exposed honeypot, or from a public
dataset like the SANS DShield captures), you can replay it:

```bash
# 1. Make sure the honeypot is at clean state
sudo ./proxmox/lab/reset.sh 9000

# 2. Find the bait IP (from the wizard's output, or qm config)
BAIT_IP=10.10.10.42

# 3. Rewrite the PCAP so the destination matches your honeypot
tcprewrite \
    --infile=./real-attacker.pcap \
    --outfile=./replay.pcap \
    --dstipmap=0.0.0.0/0:$BAIT_IP

# 4. Replay onto vmbr-lab. The honeypot sees a synthetic attacker.
sudo tcpreplay -i vmbr-lab --pps 20 ./replay.pcap

# 5. Compare what the honeypot recorded against what's in the PCAP.
```

This is the highest-signal exercise the lab offers. You learn:

* What the attacker tried (from the PCAP).
* What the honeypot's LLM responded with (from the dashboard).
* Whether the threat engine caught the right techniques (from
  `/api/threats`).
* What credentials were captured vs. tried (compare to the PCAP).

Iterate: tune the threat ruleset, tune the LLM prompt, re-replay, see
what changed.

---

## 7. Graduating to real exposure

The lab is the right place to learn the operator workflow, but it
doesn't generate intelligence the community can use. When you're ready:

1. Read [`SECURITY.md`](../SECURITY.md) and the
   [legal notice](../README.md#-legal-and-ethical-use) carefully. Real
   exposure means real consequences.
2. Switch from `vmbr-lab` to `vmbr-bait` (with an actual uplink) per
   [`proxmox.md`](proxmox.md).
3. Set up the abuse-reporting pipeline, captured credentials and IPs
   should flow to AbuseIPDB, your registrar's abuse contact, and (if you
   participate) MISP or SANS DShield.
4. Configure the alert webhook (`ANGLERFISH_THREAT__ALERT_WEBHOOK_URL`)
   to page you on high-severity events. The webhook URL must be HTTPS
   and on a public IP, see [`API_REFERENCE.md`](API_REFERENCE.md).
5. Keep the lab around, when you tune a detection rule, validate it
   in the lab before pushing it to the exposed honeypot.

---

## Quick reference

| Task                                 | Command                                          |
| ------------------------------------ | ------------------------------------------------ |
| Apply the lab bridge config          | `ifreload -a`                                    |
| Tail PCAP filenames                  | `ls -lt /var/log/anglerfish-lab/pcap/ \| head`   |
| Deploy lab VM                        | `sudo ./proxmox/deploy.sh --template ./anglerfish-lab.json ...` |
| Take baseline snapshot               | `sudo ./proxmox/lab/snapshot.sh <vmid>`          |
| Roll back between sessions           | `sudo ./proxmox/lab/reset.sh <vmid>`             |
| Replay a PCAP                        | `sudo tcpreplay -i vmbr-lab --pps 20 file.pcap`  |
| Stop PCAP capture                    | `systemctl stop anglerfish-lab-pcap.service`     |
