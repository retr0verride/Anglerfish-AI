# systemd units

These unit files run the Anglerfish components as long-lived services
on the honeypot host. Each unit is locked down with systemd's
sandboxing primitives (`ProtectSystem=strict`, `NoNewPrivileges`,
`SystemCallFilter`, restricted capability bounding sets, etc.). The
bridge and dashboard read configuration exclusively from
`/etc/anglerfish/anglerfish.env`, written by the first-boot wizard.

| Unit                              | Type     | Purpose                                                  |
| --------------------------------- | -------- | -------------------------------------------------------- |
| `anglerfish-firewall.service`     | oneshot  | Apply nftables rules locking down the service NIC        |
| `anglerfish-firstboot.service`    | oneshot  | Run the wizard before any other service comes up         |
| `anglerfish-bridge.service`       | long     | Bridge HTTP API (loopback) consumed by the native lure   |
| `anglerfish-dashboard.service`    | long     | FastAPI/WebSocket operator UI                            |

The native SSH lure currently runs via `anglerfish lure serve`
invoked by the operator (or under a hand-rolled systemd unit). A
first-class `anglerfish-lure.service` shipping in this tree is
TODO-3 (`docs/TODO.md`); the Cowrie removal in 2026-05 surfaced
the gap by deleting the only auto-enabled bait-NIC unit.

## Install

The ISO build (see [`../iso/`](../iso/)) copies these into
`/etc/systemd/system/` and enables them. For a manual deployment:

```bash
sudo cp systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now anglerfish-firewall.service
sudo systemctl enable --now anglerfish-firstboot.service
sudo systemctl enable anglerfish-bridge.service anglerfish-dashboard.service
sudo systemctl start anglerfish-bridge.service anglerfish-dashboard.service
```

## Required system state

* `anglerfish` UNIX user/group (the ISO build creates this).
* `/var/lib/anglerfish/` writable by `anglerfish`.
* `/etc/anglerfish/nftables/anglerfish.nft` present (the wizard
  renders this).
* The `anglerfish-ai` Python package installed system-wide so
  `/usr/local/bin/anglerfish` and `/usr/local/bin/anglerfish-wizard`
  exist.
