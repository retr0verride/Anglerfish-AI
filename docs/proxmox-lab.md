# Strict-lab Proxmox setup

This is the **closed-lab** variant of the Proxmox deployment guide. The
production [`proxmox.md`](proxmox.md) puts Anglerfish on a real attacker
network; this one puts it in a hermetic sandbox where attackers can
only reach the honeypot from inside your own host. Use it for:

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

## 2. Deploy the honeypot VM in lab mode

The existing [`proxmox/deploy.sh`](../proxmox/deploy.sh) works for the
lab too, just override the bait bridge:

```bash
sudo ./deploy.sh \
    --iso ./anglerfish-ai-0.1.0.iso \
    --vmid 9100 \
    --name anglerfish-lab \
    --bait-bridge vmbr-lab    # the air-gapped one, not vmbr-bait
```

(If `--bait-bridge` isn't in your `deploy.sh` yet, edit
[`proxmox/anglerfish.json`](../proxmox/anglerfish.json) and set
`network.bait_bridge` to `vmbr-lab` before running the deploy.)

The first-boot wizard runs as normal. When it asks for the Ollama
endpoint, you can:

* Run Ollama on the Proxmox host (`http://<host-service-ip>:11434/`)
  and reach it over `vmbr-service`. Most practical.
* Run Ollama inside the honeypot VM (`http://127.0.0.1:11434/`). Wastes
  RAM in a lab, both Ollama and the lure compete for the VM's memory.

---

## 3. Take a clean snapshot

After the wizard finishes and the honeypot is running normally, capture
the baseline:

```bash
sudo ./proxmox/lab/snapshot.sh 9100
# [lab] taking snapshot 'clean' on VM 9100
# [lab] done. roll back with: sudo ./reset.sh 9100 clean
```

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

Watch the dashboard at `https://<service-ip>:8420/` in real time.
The audit log records operator actions; the credentials DB collects
what the attacker tried; the threat engine scores the session.

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
sudo ./proxmox/lab/reset.sh 9100
# [lab] roll VM 9100 back to 'clean'? This DISCARDS all changes. [y/N] y
# [lab] stopping VM 9100
# [lab] rolling back VM 9100 to 'clean'
# [lab] starting VM 9100
```

The script refuses to proceed without an explicit `y` because rollback
destroys everything since the snapshot. Once it comes back up, you're
ready for the next session.

---

## 6. Replay a real attacker against your lab

If you have a PCAP of a real SSH brute-force or honeypot session
(maybe from a previous internet-exposed honeypot, or from a public
dataset like the SANS DShield captures), you can replay it:

```bash
# 1. Make sure the honeypot is at clean state
sudo ./proxmox/lab/reset.sh 9100

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
| Deploy lab VM                        | `sudo ./proxmox/deploy.sh --bait-bridge vmbr-lab ...` |
| Take baseline snapshot               | `sudo ./proxmox/lab/snapshot.sh <vmid>`          |
| Roll back between sessions           | `sudo ./proxmox/lab/reset.sh <vmid>`             |
| Replay a PCAP                        | `sudo tcpreplay -i vmbr-lab --pps 20 file.pcap`  |
| Stop PCAP capture                    | `systemctl stop anglerfish-lab-pcap.service`     |
