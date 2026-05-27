# Anglerfish AI - Operator Runbook

Day-2 procedures. Each task is a short heading + the commands; if a
step needs explanation it lives below the block, never inside it.

All commands assume:

* You're logged in to the honeypot VM as the operator user
  (`ssh anglerfish-ops@<service-ip>`).
* `sudo` is available where needed.
* The package lives in `/opt/anglerfish/venv/`. Symlinks under
  `/usr/local/bin/` keep `anglerfish`/`anglerfish-wizard` on PATH.

> When in doubt, run `anglerfish config show` - it prints the live
> configuration with secrets masked, which is enough to confirm what
> the bridge and dashboard are actually using.

---

## Services and what they do

| Unit                              | Purpose                                                   |
|-----------------------------------|-----------------------------------------------------------|
| `anglerfish-firewall.service`     | Applies the nftables ruleset at boot.                     |
| `anglerfish-firstboot.service`    | Runs the wizard on first boot (and never again).          |
| `anglerfish-bridge.service`       | The LLM bridge HTTP API + orchestrator.                   |
| `anglerfish-lure.service`         | Native asyncssh SSH honeypot bound to the bait NIC.       |
| `anglerfish-dashboard.service`    | FastAPI dashboard + WebSocket stream.                     |
| `anglerfish-geo-update.service`   | One-shot MaxMind GeoLite2 fetch.                          |
| `anglerfish-geo-update.timer`     | Weekly trigger for the geo-update service.                |

`systemctl status <unit>` and `journalctl -u <unit> -f` are your
two main observation tools.

---

## Credentials

### Rotate the credentials database encryption key

```bash
sudo systemctl stop anglerfish-bridge.service anglerfish-dashboard.service

NEW_KEY=$(openssl rand -base64 32)
sudo /opt/anglerfish/venv/bin/anglerfish credentials rotate-key \
    --new-key "${NEW_KEY}" --yes

# Update the env file with the new key
sudo sed -i \
    "s|^ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY=.*|ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY=${NEW_KEY}|" \
    /etc/anglerfish/anglerfish.env

sudo systemctl start anglerfish-bridge.service anglerfish-dashboard.service
```

The old database is preserved at `<path>.bak` next to the new one.
Keep that backup until you've verified at least one fresh credential
record decrypts with the new key. The rotation tool refuses to run
if a previous rotation left a `.new` or `.bak` file in place, clean
those up first if so.

### Query captured credentials

```bash
# Top 10 most-attempted usernames in the last 24 h:
curl -s -u admin:<pw> http://localhost:8420/api/credentials/stats | jq

# All records for a single source IP:
curl -s -u admin:<pw> \
    "http://localhost:8420/api/credentials?source_ip=203.0.113.7&limit=50" | jq
```

The records are decrypted server-side before returning to the
dashboard; nothing exposes the AES key.

---

## Threat engine

### Replay a stored session

Sessions live in the SQLite store at `/var/lib/anglerfish/sessions.db`.
To pull one record by session UUID:

```bash
sqlite3 /var/lib/anglerfish/sessions.db \
    "SELECT * FROM sessions WHERE session_id = '9e9f4b2a-...';"
```

To replay the LLM-driven exchanges in order:

```bash
sqlite3 /var/lib/anglerfish/sessions.db \
    "SELECT timestamp, command, response FROM turns
     WHERE session_id = '9e9f4b2a-...'
     ORDER BY sequence_n;"
```

### Inspect the audit log

The audit log is separate from session capture, it records
operator-facing events (login success/failure, key rotation, geo
updates, wizard runs):

```bash
sudo tail -F /var/log/anglerfish/audit.jsonl | jq
```

Audit records never include attacker-supplied content; if you need
to forensicate an attack, the session log is the right surface.

### Suppress a noisy alert

The threat-alert webhook fires when a session's score exceeds
`ANGLERFISH_THREAT__ALERT_THRESHOLD` (default `70`). To raise the
bar temporarily:

```bash
sudo sed -i 's|^ANGLERFISH_THREAT__ALERT_THRESHOLD=.*|ANGLERFISH_THREAT__ALERT_THRESHOLD=90|' \
    /etc/anglerfish/anglerfish.env
sudo systemctl restart anglerfish-bridge.service
```

The alerter is idempotent on a session, a single session won't fire
twice even if its score keeps climbing.

---

## Geo

### Force a fresh GeoLite2 download

```bash
sudo systemctl start anglerfish-geo-update.service
journalctl -u anglerfish-geo-update.service --since '5 minutes ago'
```

The timer ([systemd/anglerfish-geo-update.timer](../systemd/anglerfish-geo-update.timer))
re-fires every Wednesday at 03:30 + 30 min random delay. To change
the cadence, override the timer:

```bash
sudo systemctl edit anglerfish-geo-update.timer
# Set [Timer] OnCalendar=...
sudo systemctl daemon-reload
sudo systemctl restart anglerfish-geo-update.timer
```

### Skip geo on a single VM

Comment out the MaxMind licence key in `anglerfish.env`:

```bash
sudo sed -i 's|^ANGLERFISH_GEO__MAXMIND_LICENSE_KEY=|# ANGLERFISH_GEO__MAXMIND_LICENSE_KEY=|' \
    /etc/anglerfish/anglerfish.env
sudo systemctl restart anglerfish-bridge.service anglerfish-dashboard.service
```

The geo-update unit becomes a no-op; existing `.mmdb` files on disk
are still consulted.

---

## Dashboard

### Reset the admin password

The wizard's `--reconfigure` flow prompts for a new password and
re-hashes it:

```bash
sudo anglerfish-wizard --reconfigure
# Walk through; at the dashboard password prompt, enter the new one.
sudo systemctl restart anglerfish-dashboard.service
```

If you only want to change the password without touching the rest
of the configuration, generate a hash with the embedded helper:

```bash
sudo /opt/anglerfish/venv/bin/python -c \
    "from anglerfish.dashboard.auth import hash_password; \
     import getpass; print(hash_password(getpass.getpass('new password: ')))"
```

Paste the resulting `$2b$...` string into
`ANGLERFISH_DASHBOARD__ADMIN_PASSWORD_HASH=` in
`/etc/anglerfish/anglerfish.env` and restart the dashboard.

### Force-logout all sessions

Session cookies are signed with `ANGLERFISH_DASHBOARD__SESSION_SECRET`.
Rotate it to invalidate every issued cookie:

```bash
NEW_SESSION_SECRET=$(openssl rand -hex 32)
sudo sed -i \
    "s|^ANGLERFISH_DASHBOARD__SESSION_SECRET=.*|ANGLERFISH_DASHBOARD__SESSION_SECRET=${NEW_SESSION_SECRET}|" \
    /etc/anglerfish/anglerfish.env
sudo systemctl restart anglerfish-dashboard.service
```

Active WebSocket subscribers are dropped with close code 4401 and
must re-login.

### Investigate a login failure

```bash
sudo tail -F /var/log/anglerfish/audit.jsonl |
    jq 'select(.event_type | test("dashboard.login"))'
```

`login_rate_limited` events indicate the per-IP token bucket fired;
`Retry-After` in the response header tells the operator when to
back off. The bucket allowance is 5 attempts then ~1 every 12 s;
successful login resets the bucket immediately.

---

## Disk and log management

### Audit log rotation

`/var/log/anglerfish/audit.jsonl` is append-only and the bridge
never rotates it. Use `logrotate`:

```text
# /etc/logrotate.d/anglerfish
/var/log/anglerfish/audit.jsonl {
    weekly
    rotate 12
    compress
    delaycompress
    notifempty
    missingok
    create 0640 anglerfish anglerfish
    copytruncate
}
```

`copytruncate` matters, the AuditLog reopens the file on every
write, but a regular rename mid-rotation would leave a window where
records vanish.

### Session store growth

The SessionStore SQLite file at `/var/lib/anglerfish/sessions.db`
grows unboundedly by design (operators usually want the full
attacker corpus). A `sessions purge --older-than 90d` command will
land if disk pressure forces the issue; until then, snapshot the
file and `VACUUM` periodically.

### Free disk space in a crunch

Stop captures (so attackers see a stuck shell, not a crash):

```bash
sudo systemctl stop anglerfish-bridge.service
# Stop the lure listener too (if it's running under a hand-rolled unit).
sudo zstd -19 --rm /var/lib/anglerfish/sessions.db
sudo systemctl start anglerfish-bridge.service
```

The credentials DB is small (a few MB per ten-thousand attempts);
don't truncate it.

---

## Recovery scenarios

### Ollama unreachable

The bridge degrades to a static fallback (`anglerfish.bridge.fallback`)
that returns plausible-looking shell errors. Attackers see no LLM
output but the honeypot stays up. Symptoms in `journalctl -u
anglerfish-bridge.service`:

```text
ollama.client_error url=http://...:11434/api/chat ...
```

Recovery:

```bash
# 1. Reach the LLM box yourself
curl -s http://<ollama-host>:11434/api/version

# 2. If unreachable, check the firewall rule lets you through
sudo nft list ruleset | grep ollama

# 3. Restart the bridge after the LLM comes back; not strictly
#    required (the bridge retries) but resets the per-session
#    history window and fallback counters.
sudo systemctl restart anglerfish-bridge.service
```

### Full disk

Look at the JSONL and credentials DB sizes first:

```bash
du -sh /var/lib/anglerfish/* /var/log/anglerfish/* /tmp
```

99% of full-disk incidents are session-log growth. Use the JSONL
rotation procedure above. The credentials DB is small enough to be
ignored.

### Boot failure: wizard didn't write the env

If `anglerfish-bridge.service` keeps failing with "no env file"
after a reboot, the wizard was interrupted. Re-run it manually:

```bash
sudo anglerfish-wizard --env /etc/anglerfish/anglerfish.env
```

Once the env file is in place the bridge picks up.

### Recover from a corrupted credentials DB

The encrypted SQLite file is just a file. Restore the most recent
`vzdump` snapshot or the `proxmox/backup.sh` tarball; the encryption
key in `anglerfish.env` is what makes the restored DB decrypt.

If you've already rotated the key since the backup was taken,
restore both the DB and the corresponding pre-rotation key (you
kept it, right?), then rotate forward.

---

## Maintenance

### Upgrade Anglerfish AI itself

Built into the venv; replace it cleanly:

```bash
sudo systemctl stop anglerfish-bridge.service anglerfish-dashboard.service
sudo /opt/anglerfish/venv/bin/pip install --upgrade anglerfish-ai
sudo systemctl start anglerfish-bridge.service anglerfish-dashboard.service
```

Schema and config defaults are intentionally backward-compatible
within a minor version. Always read the release notes first; a major
bump can require a wizard `--reconfigure` to pick up new fields.

### Import historical JSONL into the session store

The Stage 4 session store backs `/var/lib/anglerfish/sessions.db`.
Operators upgrading from a pre-Stage-4 release that wrote sessions
as JSONL into `/var/lib/anglerfish/sessions.jsonl` (the historical
fallback path) can replay that file into the store one-time:

```bash
sudo systemctl stop anglerfish-bridge.service anglerfish-dashboard.service

sudo /opt/anglerfish/venv/bin/python -c "
import asyncio
from pathlib import Path
from anglerfish.config.settings import load_settings
from anglerfish.sessions import SessionStore, import_jsonl_into_store

async def main():
    settings = load_settings()
    async with SessionStore(settings.sessions) as store:
        n = await import_jsonl_into_store(
            Path('/var/lib/anglerfish/sessions.jsonl'),
            store,
        )
        print(f'imported {n} sessions')

asyncio.run(main())
"

sudo systemctl start anglerfish-bridge.service anglerfish-dashboard.service
```

The import is idempotent on `session_id` (re-running it overwrites
the same rows) but each Cowrie session-id is mapped to a fresh
UUID, so re-running against the same JSONL file produces a second
set of imported sessions. Move or compress the JSONL after a
successful run to avoid that.

Malformed lines (truncated mid-write, non-JSON) are logged and
skipped; a partial corpus is better than refusing to import.

### Decommission

```bash
sudo systemctl stop \
    anglerfish-bridge.service \
    anglerfish-dashboard.service \
    anglerfish-firewall.service
sudo shred -u /etc/anglerfish/anglerfish.env
sudo shred -u /var/lib/anglerfish/credentials.db*
sudo shred -u /var/lib/anglerfish/sessions.db*
```

Then `qm destroy <vmid>` on the Proxmox host. Audit logs are not
shredded by this procedure, handle them per your retention policy.
