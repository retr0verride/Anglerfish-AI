# Cowrie deployment artefacts

This directory contains the configuration files that the ISO build (or
a manual install) deposits on the honeypot host. None of it is
imported by the Anglerfish Python package — these are deployment
artefacts only.

| File                       | Destination on host                                       |
| -------------------------- | --------------------------------------------------------- |
| `cowrie.cfg.template`      | `/opt/cowrie/etc/cowrie.cfg` (after `envsubst`)           |
| `output_anglerfish.py`     | `/opt/cowrie/src/cowrie/output/anglerfish.py`             |
| `nftables/anglerfish.nft`  | `/etc/anglerfish/nftables/anglerfish.nft` (after envsubst) |

## How the integration works

```
                 attacker
                    |
                  SSH/Telnet  (bait NIC)
                    v
                 +--------+
                 | Cowrie |
                 +---+----+
                     | unknown commands  (HTTP, loopback)
                     v
                +----+----+
                | bridge  |  Anglerfish HTTP API
                +----+----+    (anglerfish bridge serve)
                     |
                     v
               +-----+-----+
               | AI bridge | -> Ollama  (loopback or trusted IP)
               +-----+-----+
                     |
                     v
              +------+-------+
              | forwarder    | -> Splunk HEC  (or JSONL fallback)
              +------+-------+
                     |
                     v
              +------+-------+
              | dashboard    |  (operator UI, service NIC)
              +--------------+
```

The output-plugin path (`output_anglerfish.py`) lets Cowrie ship every
event it sees to the forwarder. A follow-up commit will introduce the
**command-handler** path: a Cowrie shell-component hook that calls
`POST /api/v1/session/{id}/command` on the bridge for commands not
handled by Cowrie's built-in implementations. That hook lives outside
the Python package because it requires patching Cowrie internals.

## Manual install (development)

```bash
cd /opt/cowrie
git checkout v2.5.0    # tested baseline
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install -r requirements.txt
pip install /path/to/anglerfish-ai

# Drop in the plugin.
cp /path/to/anglerfish-ai/cowrie/output_anglerfish.py \
   src/cowrie/output/anglerfish.py

# Render the config from the wizard-generated env file.
set -a; source /etc/anglerfish/anglerfish.env; set +a
envsubst < /path/to/anglerfish-ai/cowrie/cowrie.cfg.template \
    > etc/cowrie.cfg

bin/cowrie start
```
