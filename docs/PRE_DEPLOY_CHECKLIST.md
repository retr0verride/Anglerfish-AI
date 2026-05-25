# Pre-deploy checklist

Work this top to bottom before exposing Anglerfish to attacker traffic.
Each step is a single command you can run and verify. Skipping items is
fine for a closed lab; **don't skip them for real-internet exposure**.

If you're doing the strict-lab variant, see
[`proxmox-lab.md`](proxmox-lab.md) instead, most of these checks still
apply but the network ones loosen up.

Legend: `[ ]` open, `[x]` done.

---

## 1. Authorization

- `[ ]` **You own the bait IP or have written authorization to operate
  a honeypot on it.** Operating a honeypot on a third-party network
  may constitute unauthorized access or wiretapping in your jurisdiction.
- `[ ]` **The IP block has an abuse contact set.** When the honeypot
  starts collecting creds, you'll want abuse reports for those source
  IPs to flow somewhere useful. `whois <your-bait-ip>` should show a
  monitored email address.
- `[ ]` **Your hosting provider allows honeypots.** Some VPS providers
  forbid them in their AUP. Check before you turn it on.
- `[ ]` **You have a disclosure + IR plan.** What do you do when an
  attacker tries to break out? Who do you call? Have it written down
  before you need it.

---

## 2. Required secrets

The bridge and dashboard refuse to start without these. The wizard
generates them; verify they exist and look right.

```bash
# All four must be present and non-empty.
grep -E '^ANGLERFISH_(DASHBOARD__SESSION_SECRET|CREDENTIALS__ENCRYPTION_KEY|BRIDGE__SHARED_SECRET|DASHBOARD__ADMIN_PASSWORD_HASH)' \
    /etc/anglerfish/anglerfish.env \
    | sed 's/=.*/=<set>/'
```

- `[ ]` `ANGLERFISH_DASHBOARD__SESSION_SECRET` - ≥32 chars, base64.
- `[ ]` `ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY` - base64, decodes to 32 bytes.
- `[ ]` `ANGLERFISH_BRIDGE__SHARED_SECRET` - the lure sends this in
  `Authorization: Bearer <secret>` on every bridge call.
- `[ ]` `ANGLERFISH_DASHBOARD__ADMIN_PASSWORD_HASH` - bcrypt hash. If
  this is empty the dashboard runs in **open mode**. That's only safe
  in a closed lab. Set it.

```bash
# Verify the env file itself isn't world-readable.
stat -c '%a %U:%G %n' /etc/anglerfish/anglerfish.env
# Want: 640 root:anglerfish /etc/anglerfish/anglerfish.env
```

- `[ ]` Env file mode is `0640`, group `anglerfish`.

---

## 3. Network isolation

This is the hardest line of defense, get it right or don't deploy.

### 3.1 Two-NIC physical separation

- `[ ]` Bait NIC is a **different physical port** from the management
  NIC. Not a VLAN on the same port; different copper/fibre.
- `[ ]` Bait NIC's bridge (`vmbr-bait` on Proxmox) is **not** the
  Proxmox management bridge.

```bash
# On the Proxmox host:
ip -br link show vmbr-bait vmbr-service
# Both should be UP. vmbr-bait should NOT share a port with vmbr0.
```

### 3.2 nftables rules loaded

Inside the honeypot VM:

```bash
sudo nft list ruleset | head -40
sudo systemctl is-active anglerfish-firewall.service
# active
```

- `[ ]` Ruleset shows the `anglerfish_*` chains.
- `[ ]` `anglerfish-firewall.service` is `active`.

### 3.3 Egress lock-down

```bash
# These MUST all be blocked from inside the VM:
timeout 3 curl -sS https://1.1.1.1/        ; echo "exit=$?"   # want non-zero
timeout 3 curl -sS https://github.com/      ; echo "exit=$?"  # want non-zero
timeout 3 nc -zv 8.8.8.8 443                ; echo "exit=$?"  # want non-zero

# These MUST work (the service-NIC allowlist):
timeout 3 curl -sS http://127.0.0.1:11434/  ; echo "exit=$?"  # Ollama, want 0
```

- `[ ]` All outbound to the open internet is **dropped** from inside
  the honeypot.
- `[ ]` Ollama is reachable (loopback or trusted IP).

### 3.4 No DNS leaks from the bait side

```bash
# Inside the VM, on the BAIT interface:
sudo tcpdump -i <bait-iface> -n udp port 53 -c 5 &
sleep 5
sudo kill %1
```

- `[ ]` No DNS traffic on the bait interface for 5+ seconds. If you see
  any, something on the bait side is doing DNS lookups, investigate.

---

## 4. Endpoint validation

The config validator catches these at startup, but verify the live
behavior matches your intent.

```bash
sudo -u anglerfish ANGLERFISH_LOG_LEVEL=INFO \
    /opt/anglerfish/venv/bin/anglerfish config show \
    | grep -E '(base_url|alert_webhook|trusted_remote|hec_url)'
```

- `[ ]` `ollama.base_url` is loopback or matches `trusted_remote_host`.
- `[ ]` `threat.alert_webhook_url` (if set) is `https://` and points to
  a public hostname or public IP, **not** RFC1918 / loopback /
  link-local. The validator will refuse to start otherwise.

---

## 5. Filesystem & permissions

```bash
# Data directory
stat -c '%a %U:%G %n' /var/lib/anglerfish
# Want: 750 anglerfish:anglerfish

# Credentials DB
stat -c '%a %U:%G %n' /var/lib/anglerfish/credentials.db 2>/dev/null
# Want: 600 anglerfish:anglerfish (created on first credential write)

# Audit log
stat -c '%a %U:%G %n' /var/log/anglerfish/audit.jsonl
# Want: 640 anglerfish:anglerfish

# Append-only attribute (ext2/3/4, btrfs, xfs)
sudo lsattr /var/log/anglerfish/audit.jsonl
# Want: -----a-------------- /var/log/anglerfish/audit.jsonl
```

- `[ ]` `/var/lib/anglerfish` is `0750 anglerfish:anglerfish`.
- `[ ]` `credentials.db` (if it exists yet) is `0600 anglerfish:anglerfish`.
- `[ ]` `audit.jsonl` has the `a` attribute. If `lsattr` shows no `a`,
  you're either on a filesystem that doesn't support it (zfs, nfs, etc.)
  or the firstboot ExecStartPost didn't run. Try
  `sudo chattr +a /var/log/anglerfish/audit.jsonl` manually.

---

## 6. Systemd state

```bash
systemctl --no-pager status \
    anglerfish-firewall.service \
    anglerfish-bridge.service \
    anglerfish-dashboard.service \
    anglerfish-firstboot.service \
    ollama.service 2>&1 | grep -E 'Loaded|Active' | head -40
```

- `[ ]` `anglerfish-firewall.service` - active or `oneshot` exited 0.
  This MUST be `Before=` the bridge and dashboard. Verify:
  ```bash
  systemctl list-dependencies --before anglerfish-firewall.service
  ```
- `[ ]` `anglerfish-bridge.service` - `active (running)`.
- `[ ]` `anglerfish-dashboard.service` - `active (running)`.
- `[ ]` Lure listener (`anglerfish lure serve`) is running. There is
  no first-class systemd unit yet (TODO-3); operators run it
  manually or via a hand-rolled unit.
- `[ ]` `ollama.service` - `active (running)` (or running on a trusted
  remote host you can reach).
- `[ ]` No service in `failed` state:
  ```bash
  systemctl --failed --no-legend | head
  ```

---

## 7. Health endpoints

```bash
# Inside the VM:
curl -fsS http://127.0.0.1:8421/api/health    # bridge - want {"status":"ok",...}
curl -fsS http://127.0.0.1:8420/api/health    # dashboard - same

# Bridge with bearer token:
SECRET=$(grep ANGLERFISH_BRIDGE__SHARED_SECRET /etc/anglerfish/anglerfish.env | cut -d= -f2)
curl -fsS -H "Authorization: Bearer $SECRET" \
    http://127.0.0.1:8421/api/v1/sessions
# Want: []  (or current sessions)

# Lure: confirm the SSH listener is up on the bait NIC only.
ss -lntp | grep -E ':2222 |:22 '
# Want: a single LISTEN line on the bait-NIC IP, not 0.0.0.0.

# Lure: validate-config without binding (idempotent, safe on a live host).
anglerfish lure validate-config
# Want: "lure config OK - listener would bind to <bait-ip>:<port>"
```

- `[ ]` Bridge `/api/health` returns 200.
- `[ ]` Dashboard `/api/health` returns 200.
- `[ ]` Bridge accepts your bearer token.
- `[ ]` Lure listener is bound to the bait-NIC IP, not `0.0.0.0`.
- `[ ]` `anglerfish lure validate-config` exits 0.
- `[ ]` Lure host keys exist at `ANGLERFISH_LURE__HOST_KEY_DIR`
  with mode `0600` (key files) and `0700` (directory). Generated
  fresh per install; never copied from another host.

---

## 8. Smoke test - drive a fake attacker

End-to-end test: hit the lure from a throwaway IP, verify the LLM
responded, verify the audit + credentials + threat pipelines fired.

```bash
# From outside the VM, on a throwaway client:
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 testuser@<bait-ip>
# Try a few commands then disconnect.

# Inside the VM:
# 1. Check the audit log captured something.
sudo tail -5 /var/log/anglerfish/audit.jsonl | jq

# 2. Check the credential made it into the DB (encrypted).
sudo sqlite3 /var/lib/anglerfish/credentials.db \
    'SELECT COUNT(*), MAX(last_seen) FROM attempts;'

# 3. Hit the dashboard for the live view.
curl -fsS -u "admin:$ADMIN_PASS" http://127.0.0.1:8420/api/sessions \
    | jq '.[] | {source_ip, last_activity_at, num_turns: (.turns|length)}'

# 4. Check the threat engine scored it.
curl -fsS -u "admin:$ADMIN_PASS" http://127.0.0.1:8420/api/threats \
    | jq '.[] | {session_id, score, persistence_attempted}'
```

- `[ ]` Audit log has a recent entry.
- `[ ]` Credentials DB has at least one row.
- `[ ]` Dashboard shows the session.
- `[ ]` Threat engine scored it (even if low).

---

## 9. Off-host shipping

The honeypot itself can be compromised, your most important records
have to live somewhere else.

```bash
# SessionStore on disk.
ls -lh /var/lib/anglerfish/sessions.db
```

- `[ ]` A backup job pulls `/var/lib/anglerfish/sessions.db`,
  `/var/lib/anglerfish/credentials.db`, and
  `/var/log/anglerfish/audit.jsonl` off the VM regularly. Without it
  you lose history on every rollback / VM destroy.

---

## 10. Alerting

```bash
# Verify the webhook URL is reachable and accepting POSTs.
WEBHOOK=$(grep ANGLERFISH_THREAT__ALERT_WEBHOOK_URL /etc/anglerfish/anglerfish.env | cut -d= -f2)
[ -n "$WEBHOOK" ] && curl -fsS -X POST -H 'Content-Type: application/json' \
    -d '{"text":"anglerfish pre-deploy smoke test"}' "$WEBHOOK"
```

- `[ ]` Webhook URL is set (or you have explicitly chosen no alerting).
- `[ ]` Test POST returned 200 / your service's success code.
- `[ ]` The test message arrived where you expected it.

---

## 11. Backups configured

- `[ ]` `pve-backup` / `vzdump` job scheduled for full-VM snapshots
  (Proxmox).
- `[ ]` `proxmox/backup.sh` wired into cron or a systemd timer for
  state-only backups (credentials.db, sessions.db, audit.jsonl).
- `[ ]` Verified `proxmox/restore.sh` works against a recent backup
  on a throwaway VM. (Untested backups are not backups.)

---

## 12. Final review

- `[ ]` Read [`THREAT_MODEL.md`](THREAT_MODEL.md) once more. Make sure
  the threats it doesn't mitigate are ones you accept.
- `[ ]` Read [`SECURITY.md`](../SECURITY.md). You're now in scope for
  its disclosure policy.
- `[ ]` Tag your `.env` file with the commit SHA you deployed from:
  ```bash
  echo "# Deployed from $(git -C /opt/anglerfish/src rev-parse HEAD)" \
      | sudo tee -a /etc/anglerfish/anglerfish.env
  ```
- `[ ]` Note in your operations log: deployed `<git sha>` to
  `<vmid>/<hostname>` at `<timestamp>`, smoke-tested with `<test method>`.

---

## What to do after deployment

Day 1: watch the dashboard for the first few hours. Real attacker traffic
arrives fast on a fresh public IP.

Week 1: check the credentials DB grows, the threat assessments accumulate,
the audit log has no unexplained gaps. Confirm the SessionStore has new
rows.

Month 1: rotate the credentials encryption key
([`RUNBOOK.md`](RUNBOOK.md) §credentials), run a fresh `vzdump` backup,
verify the restore. Update the Tor exit list cache:
```bash
sudo systemctl start anglerfish-geo-update.service
```

If the dashboard's `persistence_attempt_count` ever goes up: **investigate
immediately**. Persistence attempts mean the attacker thinks they have a
foothold; either the LLM was very convincing, or something's broken on
your side.
