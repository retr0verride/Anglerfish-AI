# Incident response playbook

When something happens that isn't in [`RUNBOOK.md`](RUNBOOK.md), work
through this. The runbook is for known failure modes with known fixes;
this is for the situations where you don't yet know what broke.

The single most important rule: **preserve evidence before you change
state**. A snapshot you took 30 seconds before the compromise is worth
more than three hours of poking at a live system.

---

## Roles

* **First responder** - whoever sees the alert first. Their job:
  contain, snapshot, escalate. Not their job: fix.
* **IC (Incident Commander)** - decides whether to take the honeypot
  offline. For a one-person operation, that's you.
* **Scribe** - keeps the timeline. Even for solo response, open a
  text file and timestamp every action. Future-you will thank present-you.

---

## Severity classes

| Severity | Trigger                                                                       | Response time |
| -------- | ----------------------------------------------------------------------------- | ------------- |
| **SEV-1** | Suspected pivot / lateral movement / data exfil from the honeypot to elsewhere | Immediate     |
| **SEV-2** | Operator credential / API key compromise; audit log gap; persistence detected  | < 30 minutes  |
| **SEV-3** | Service crash loop, disk fill, missing alerts                                 | < 2 hours     |
| **SEV-4** | Cosmetic - dashboard slow, geo lookups failing, etc.                          | Next business day |

When in doubt, classify up. Downgrading mid-incident is fine.

---

## Universal first steps (do these for every SEV-1/SEV-2)

```bash
# 1. SNAPSHOT THE VM. Before anything else. This is forensic gold.
sudo qm snapshot <vmid> "incident-$(date +%Y%m%d-%H%M%S)" \
    --description "Pre-IR snapshot, $(whoami)"

# 2. Note the time + alert that triggered you. Open a scribe log:
mkdir -p ~/incidents/$(date +%Y%m%d)
cd ~/incidents/$(date +%Y%m%d)
nano timeline.md
# First line: "T0: <UTC time>  Alert: <what fired>"

# 3. Capture current state without modifying it.
sudo journalctl --since '30 min ago' -o json > journal.json
sudo cp /var/log/anglerfish/audit.jsonl audit.jsonl
sudo cp /var/lib/anglerfish/credentials.db creds.db
sudo nft list ruleset > nftables.snapshot
sudo ss -tunap > sockets.snapshot
sudo ps auxf > ps.snapshot
```

Now you can investigate without destroying evidence.

---

## Scenarios

### S1 - Suspected pivot / lateral movement (SEV-1)

**Symptoms.** Unexpected outbound connection from the honeypot VM. The
bridge or dashboard logs an OSError opening a socket. A network IDS in
front of the host fires on egress from the bait subnet.

**Immediate.**
```bash
# Take the bait NIC offline RIGHT NOW. The honeypot stays up so you
# can investigate, but the attacker is disconnected.
sudo ip link set <bait-iface> down

# Confirm no other outbound is happening.
sudo ss -tunap state established '! ( dst 127.0.0.0/8 or dst <service-net>/24 )'
# Want: empty.
```

**Investigate.**
```bash
# 1. What sessions were active at the time?
sudo sqlite3 /var/lib/anglerfish/credentials.db \
    'SELECT source_ip, MAX(last_seen), COUNT(*) FROM attempts GROUP BY source_ip ORDER BY 2 DESC LIMIT 10;'

# 2. What commands did the live sessions just run?
curl -fsS -u "admin:$ADMIN_PASS" 'http://127.0.0.1:8420/api/commands?limit=200' \
    | jq '.[] | select(.source != "ai") | {timestamp, command}'

# 3. Did the LLM respond with anything that looks like a real-shell
#    side-effect? (It shouldn't - the bridge is supposed to be pure
#    LLM-text, but a regression could break that invariant.)
sudo journalctl -u anglerfish-bridge.service --since '1 hour ago' \
    | grep -iE 'exec|subprocess|system|popen|fork'
```

**Recovery.**
1. If you confirmed lateral movement: **the honeypot is burned**.
   `qm destroy` the VM. Deploy a fresh one. Don't reuse the
   credentials DB, assume the encryption key is also compromised.
2. If you confirmed nothing escaped: bring the bait NIC back up after
   you've audited the most recent code changes. Verify nftables rules
   are still loaded.

**Post-incident.**
* If escape was confirmed: file a CVE-style disclosure with whoever
  controls the upstream component that allowed it (asyncssh, Ollama,
  the bridge's prompt sanitizer, etc.). The community needs to know.
* Update [`THREAT_MODEL.md`](THREAT_MODEL.md) - the threat you didn't
  mitigate is now a known limitation worth documenting.

---

### S2 - Operator credential breach (SEV-2)

**Symptoms.** Dashboard login from an unfamiliar IP. `audit.jsonl`
shows a `dashboard.login_success` from a source you don't recognize.
Your off-host alerting fires on session-creation outside operator
hours.

**Immediate.**
```bash
# 1. Rotate the dashboard session secret - invalidates ALL active sessions.
NEW_SECRET=$(openssl rand -base64 48)
sudo sed -i "s|^ANGLERFISH_DASHBOARD__SESSION_SECRET=.*|ANGLERFISH_DASHBOARD__SESSION_SECRET=$NEW_SECRET|" \
    /etc/anglerfish/anglerfish.env

# 2. Rotate the bcrypt password hash.
NEW_PW=$(openssl rand -base64 24)
NEW_HASH=$(/opt/anglerfish/venv/bin/python -c "import bcrypt; print(bcrypt.hashpw(b'$NEW_PW', bcrypt.gensalt()).decode())")
sudo sed -i "s|^ANGLERFISH_DASHBOARD__ADMIN_PASSWORD_HASH=.*|ANGLERFISH_DASHBOARD__ADMIN_PASSWORD_HASH=$NEW_HASH|" \
    /etc/anglerfish/anglerfish.env
echo "New password: $NEW_PW" > ~/incidents/$(date +%Y%m%d)/new-password.txt
chmod 0600 ~/incidents/$(date +%Y%m%d)/new-password.txt

# 3. Restart the dashboard to load the new secrets.
sudo systemctl restart anglerfish-dashboard.service
```

**Investigate.**
```bash
# Which session IDs are tied to the suspicious login?
sudo grep '"event_type":"dashboard.login_success"' /var/log/anglerfish/audit.jsonl \
    | jq 'select(.ip != "<your-known-ip>")'

# Did the breached session export credentials?
sudo journalctl -u anglerfish-dashboard.service --since '24 hours ago' \
    | grep -iE 'GET /api/credentials'

# Did the bridge bearer token leak with the dashboard creds?
grep ANGLERFISH_BRIDGE__SHARED_SECRET /etc/anglerfish/anglerfish.env
# If yes, rotate it too.
```

**Recovery.** Assume everything the dashboard had access to is leaked:
captured credentials, threat assessments, session history. Treat any
credentials in your DB as burned, they're public knowledge now.

**Post-incident.**
* Add the source IP to your nftables drop list permanently.
* If your dashboard was internet-reachable (it shouldn't be), put it
  behind a VPN or reverse proxy with mTLS.
* Tighten the per-IP login rate limit in `dashboard/rate_limit.py` if
  the breach used a brute force.

---

### S3 - Audit log gap (SEV-2)

**Symptoms.** `audit.jsonl` has a time gap (e.g. no entries between
14:00 and 16:00 yesterday). `lsattr` shows the +a attribute is missing.
File size is smaller than your last backup.

The Splunk-forwarder cross-check that this scenario used to rely on
no longer applies; the forwarder package was removed in the 2026-05
Cowrie removal. Pre-incident off-host shipping (rsync, syslog drain,
object-store push) is now the operator's responsibility.

**Immediate.**
```bash
# Confirm the gap.
sudo jq -r '.ts' /var/log/anglerfish/audit.jsonl | sort -u | head -50
sudo jq -r '.ts' /var/log/anglerfish/audit.jsonl | sort -u | tail -50

# Compare to your last off-host backup.
diff <(jq -r '.ts' ~/backups/audit-yesterday.jsonl) \
     <(jq -r '.ts' /var/log/anglerfish/audit.jsonl) | head

# Re-apply the append-only attribute.
sudo chattr +a /var/log/anglerfish/audit.jsonl
sudo lsattr /var/log/anglerfish/audit.jsonl
```

**Investigate.**
Someone with root access either truncated the file, removed +a, or
deleted entries. Possibilities:

1. **Your off-host copy has the gap window intact.** Whatever
   pipeline you ship `audit.jsonl` to (rsync target, S3, syslog
   drain) is the canary. If the off-host copy has the missing
   entries, someone modified the local file only.
2. **Off-host also has a gap.** Either the off-host shipping was
   stalled at the time, or both were tampered.
3. **Filesystem corruption.** `dmesg | grep -i 'ext4\|btrfs\|xfs'`
   for filesystem errors. Run `fsck` from a recovery shell if
   you see any.

**Recovery.**
1. Restore `audit.jsonl` from your last good backup.
2. Re-apply `chattr +a`.
3. If the off-host copy has the missing entries, replay them into
   a separate `audit-recovered.jsonl` and document the source.
4. If neither side has them, mark the time window as "evidence
   missing, see incident log YYYYMMDD" and treat any decisions made
   from that window as untrusted.

**Post-incident.** This is exactly why audit logs need to be off-host.
If the primary off-host pipeline also failed, you need a second
sink, a different collector, an S3 bucket with object-lock, or a
printer. Yes, a printer.

---

### S4 - Disk filling fast (SEV-3)

**Symptoms.** `journalctl: No space left on device`. Dashboard returns
500. SQLite write errors in the bridge logs.

**Immediate.**
```bash
df -h /var
sudo du -sh /var/lib/anglerfish/* /var/log/anglerfish/* /var/log/journal 2>/dev/null \
    | sort -hr | head -10
```

The biggest disk fillers, in order of likelihood:

1. **SessionStore SQLite growing without bound.** Stage 4 grows
   unboundedly by design (no GC).
   ```bash
   ls -lh /var/lib/anglerfish/sessions.db
   # Snapshot it off-host, then VACUUM in place:
   sudo cp /var/lib/anglerfish/sessions.db ~/incidents/$(date +%Y%m%d)/sessions.db
   sudo sqlite3 /var/lib/anglerfish/sessions.db 'VACUUM;'
   ```
2. **Credentials DB growing past the cap.** Should be bounded by
   `ANGLERFISH_CREDENTIALS__MAX_UNIQUE_PER_SOURCE_IP` (default 1000).
   If the DB is huge despite the cap, the cap got disabled or rolled
   back. Check `anglerfish config show | grep max_unique`.
3. **systemd journal not rotating.** Check `journalctl --disk-usage`.
   Set `SystemMaxUse=1G` in `/etc/systemd/journald.conf` and run
   `journalctl --rotate && journalctl --vacuum-size=1G`.
4. **Lab PCAP rotation broken.** If you're running the strict-lab
   `anglerfish-lab-pcap.service`, check `ls /var/log/anglerfish-lab/pcap/`
   - should have ≤168 files. If more, tcpdump is stuck - restart it.

**Recovery.** Reclaim space, restart the affected services, verify
they recover. Set a disk-usage monitor that alerts at 80%, not 100%.

---

### S5 - Bridge crash loop (SEV-3)

**Symptoms.** `systemctl status anglerfish-bridge.service` shows
`activating (auto-restart)` cycling repeatedly. The lure returns
fallback responses for every command.

**Immediate.**
```bash
# Stop the auto-restart so you can read what's actually wrong.
sudo systemctl stop anglerfish-bridge.service
sudo journalctl -u anglerfish-bridge.service -n 200 --no-pager
```

Common causes:

* **Ollama unreachable at startup.** Bridge config validates the
  endpoint at startup but doesn't health-check it. Restart Ollama
  first, then the bridge:
  ```bash
  sudo systemctl restart ollama && sleep 5 && sudo systemctl start anglerfish-bridge
  ```
* **Env file corruption.** A bad edit removed or renamed a required
  secret. `pydantic` errors out at startup. Validate:
  ```bash
  sudo -u anglerfish /opt/anglerfish/venv/bin/anglerfish config show
  ```
* **Port in use.** Something else grabbed 8421:
  ```bash
  sudo ss -tlnp | grep :8421
  ```
* **OOM-killer.** Check `dmesg | grep -i oom`. The bridge is small;
  if it's getting OOM-killed something else on the box is bloated.

**Recovery.** Fix the root cause, `systemctl start` once manually,
confirm it stays up for 60s, then re-enable auto-restart.

---

### S6 - Captured credentials used against you (SEV-2)

**Symptoms.** Your security monitoring (separate from Anglerfish)
detects login attempts to your real systems using a username +
password combo that's in the honeypot's credentials DB. An attacker
is reusing harvested creds.

**Immediate.**
This usually means the attacker doesn't realize the honeypot was a
honeypot and is treating the harvested creds as gold. Three things
happen in parallel:

```bash
# 1. Confirm the cred came from the honeypot.
sudo sqlite3 /var/lib/anglerfish/credentials.db \
    "SELECT source_ip, first_seen, last_seen FROM attempts WHERE username_fp = ? AND password_fp = ?" \
    -cmd ".load /opt/anglerfish/venv/lib/.../crypto.so"
# (Easier: query through the dashboard API with the username filter,
# which decrypts server-side.)

# 2. Rotate the matching real-systems credential immediately.

# 3. Add the source IPs that tried that cred against the honeypot to
#    your real-systems block list.
```

**Investigate.** Why does the attacker have a credential that matches
something real? Likely one of:

* The username/password was a default or weak combination that
  happens to be in use on a real system. Audit your real systems
  for the same weakness.
* An operator copy-pasted a real credential into the honeypot during
  testing. That's a serious operator hygiene issue.
* You're being targeted - the attacker is correlating honeypot
  captures with your real infrastructure. Treat as SEV-1.

**Post-incident.** Document the cred + username pair and the IP that
used it across both sides. This is high-value threat intel, share it
upstream (AbuseIPDB, your ISAC, etc.) with the IP and the fact that
the actor reuses honeypot-harvested creds.

---

### S7 - Upstream CVE (Ollama, asyncssh, FastAPI, etc.) (SEV-1 to SEV-3)

**Symptoms.** A CVE drops for a component you use, with a working
proof-of-concept that targets your version.

**Immediate.**
```bash
# Figure out what versions you're actually running.
dpkg -l | grep -iE 'ollama'
/opt/anglerfish/venv/bin/pip list | grep -iE 'asyncssh|fastapi|uvicorn|pydantic|httpx'

# If the CVE is in a network-reachable component, take the bait NIC
# down until you can patch.
sudo ip link set <bait-iface> down
```

**Recovery.** Update the affected component. Test in the strict-lab
([`proxmox-lab.md`](proxmox-lab.md)) before rolling to production.
Bring the bait NIC back up only after you can demonstrate the PoC
fails against the patched version.

**Post-incident.**
* If the CVE was in a dependency we pin: bump the pin in
  `pyproject.toml` and ship a patch release.
* If the CVE was in our code: file a security advisory per
  [`SECURITY.md`](../SECURITY.md), then ship the fix.

---

## When to take the honeypot offline (no second-guessing)

Take it offline if any of these are true:

* Confirmed lateral movement / pivot from the honeypot to elsewhere.
* Confirmed operator credential breach AND the dashboard was reachable
  beyond the service network.
* Audit log was tampered AND the off-host copy also has the gap.
* You can't explain what's happening within 30 minutes of starting IR.

"Offline" means `qm stop`, not just `ip link set down`. A stopped VM
can be cloned for forensics without changing further state.

---

## Recovery: bringing a honeypot back up after an incident

1. Read this playbook end-to-end.
2. Read your incident timeline. What changed in the environment?
3. Deploy a fresh VM ([`INSTALL.md`](INSTALL.md)). Do not reuse the
   compromised VM's data, assume keys and DBs are tainted.
4. Run [`PRE_DEPLOY_CHECKLIST.md`](PRE_DEPLOY_CHECKLIST.md) top to
   bottom, no skipping.
5. Restore credentials and audit log from the *pre-incident* backup,
   not from anything post-incident.
6. Bring the bait NIC up. Watch the first hour live.

---

## After every incident, regardless of severity

Update three things, these are the only artifacts the next IR will
trust:

1. Your incident timeline. Final write-up: what happened, what worked,
   what didn't, what you'd do differently. Store with the snapshot,
   journal, and audit captures.
2. [`PRE_DEPLOY_CHECKLIST.md`](PRE_DEPLOY_CHECKLIST.md). If the
   incident exposed a check that wasn't in the list, add it.
3. This file. If you ran into a scenario that isn't documented above,
   add it. The first responder of the next incident will be either you
   in six months (who has forgotten the details) or a teammate (who
   never knew them).

---

## What you don't have to do

* **You don't have to notify users of stolen credentials in your DB.**
  Those credentials weren't real (an attacker tried them against a
  fake shell). Don't email people "your password might be compromised"
  based on honeypot data, you'd be making things worse with no signal.
* **You don't have to take down the LLM if it said something weird.**
  The LLM is sandboxed: its output is text, returned to the attacker,
  and never executed. A weird response is interesting but not an
  incident. Log it, investigate at leisure.
* **You don't have to file a CVE for every wobble.** A bridge crash
  loop is an SEV-3 ops issue, not a security incident, unless the
  cause turns out to be exploitable.

When in doubt, page someone. The cost of a false alarm is one
person's hour; the cost of a missed incident is everything.
