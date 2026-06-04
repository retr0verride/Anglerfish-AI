#!/usr/bin/env python3
"""Drive the Anglerfish first-boot wizard over QMP for the appliance smoke.

The live ISO autostarts ``anglerfish-firstboot.service`` on tty1 with the
interactive wizard. Under ``-display none`` we cannot type at tty1
directly, so this drives it through the QMP ``send-key`` channel:

  1. Press ENTER at the isolinux boot menu (default entry).
  2. Wait for the wizard to render on tty1.
  3. Replay the answer sequence. Every prompt has a default, so the
     sequence is ``y`` (accept the terms, whose default is *no*) followed
     by blank lines (accept each default) -- except the Ollama model tag,
     where we type a TINY model so model-pull does not stall the boot
     fetching a multi-GB default. Loopback Ollama endpoint => no trusted-IP
     prompt; declining honeytokens / counter-deception => no follow-ups, so
     the sequence lines up 1:1 with the prompts.
  4. Screendump before and after so the run can be eyeballed.

The lure (:2222) and dashboard (:8420) reachability checks happen in the
bash orchestrator after this returns; by then the services have come up.

Usage:
  qmp_wizard_smoke.py <qmp.sock> <out_dir> [menu_wait] [boot_wait] [svc_wait]
"""

from __future__ import annotations

import json
import socket
import sys
import time
from typing import IO, Any

# Answer for each wizard prompt, in order. "" means "just press ENTER"
# (accept the default). The one non-default is the Ollama model tag.
SEQUENCE = [
    "y",  # terms: default is NO, so we must type y to accept
    "",  # VM hostname            -> anglerfish-honeypot
    "",  # bait interface         -> first NIC
    "",  # service interface      -> second NIC
    "",  # bait DHCP?             -> yes
    "",  # service DHCP?          -> yes
    "",  # operator UNIX username -> anglerfish-ops
    "",  # operator SSH pubkey    -> blank (skip)
    "",  # dashboard admin user   -> admin
    "",  # dashboard admin pass   -> blank (open mode, isolated NIC)
    "",  # Ollama endpoint URL    -> http://127.0.0.1:11434/ (loopback)
    "tinyllama",  # Ollama model tag -> tiny, so model-pull is quick
    "",  # fake hostname          -> srv-prod-01
    "",  # fake username          -> root
    "",  # threat alert webhook   -> blank (skip)
    "",  # MaxMind licence key    -> blank (skip)
    "",  # honeytokens enable?    -> no
    "",  # counter-deception?     -> no
]


def _rpc(f: IO[str], obj: dict[str, Any]) -> str:
    f.write(json.dumps(obj) + "\n")
    f.flush()
    # Drain async events (NIC_RX_FILTER_CHANGED etc.) so we return the
    # actual command response, not an event that happened to interleave.
    while True:
        line = f.readline()
        if not line:
            return ""
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if "event" in msg:
            continue
        return line.strip()


# Non-alphanumeric characters we type (boot-line edit) -> qcodes. Shift is
# a separate qcode sent as a chord with the base key.
_PUNCT_QCODE = {
    " ": ["spc"],
    ",": ["comma"],
    "=": ["equal"],
    ".": ["dot"],
    "-": ["minus"],
    "/": ["slash"],
    ":": ["shift", "semicolon"],
}


def _qcodes_for(ch: str) -> list[str]:
    if ch in _PUNCT_QCODE:
        return _PUNCT_QCODE[ch]
    if ch.isupper():
        return ["shift", ch.lower()]
    return [ch]  # a-z or 0-9: qcode is the character itself


def _chord(f: IO[str], qcodes: list[str]) -> None:
    keys = [{"type": "qcode", "data": q} for q in qcodes]
    _rpc(f, {"execute": "send-key", "arguments": {"keys": keys}})


def _key(f: IO[str], qcode: str) -> None:
    _chord(f, [qcode])


def _type_line(f: IO[str], text: str, *, char_delay: float = 0.12, line_delay: float = 0.6) -> None:
    for ch in text:
        _chord(f, _qcodes_for(ch))
        time.sleep(char_delay)
    _key(f, "ret")
    time.sleep(line_delay)


def _dump(f: IO[str], path: str) -> None:
    print("screendump", path, _rpc(f, {"execute": "screendump", "arguments": {"filename": path}}))


def main() -> int:
    sock_path = sys.argv[1]
    out_dir = sys.argv[2].rstrip("/")
    menu_wait = float(sys.argv[3]) if len(sys.argv) > 3 else 12.0
    boot_wait = float(sys.argv[4]) if len(sys.argv) > 4 else 120.0
    svc_wait = float(sys.argv[5]) if len(sys.argv) > 5 else 180.0
    # "skip-wizard": the image carries a pre-seeded /etc/anglerfish config so
    # firstboot is ConditionPathExists-skipped and services auto-start. No
    # interactive prompts to drive -- a deterministic steady-state boot.
    skip_wizard = len(sys.argv) > 6 and sys.argv[6] == "skip-wizard"

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    for _ in range(60):
        try:
            s.connect(sock_path)
            break
        except OSError:
            time.sleep(1)
    else:
        print("could not connect to QMP", file=sys.stderr)
        return 1

    f = s.makefile("rw")
    f.readline()  # greeting
    _rpc(f, {"execute": "qmp_capabilities"})

    # Boot menu -> default entry.
    time.sleep(menu_wait)
    _key(f, "ret")
    print("sent boot-menu ENTER")

    # Wait for the wizard to render, capture the terms screen.
    time.sleep(boot_wait)
    _dump(f, f"{out_dir}/smoke-1-prewizard.ppm")

    if not skip_wizard:
        # Replay answers. The tty line discipline buffers anything sent before
        # a given prompt reads it, so modest per-line pacing is enough.
        for i, line in enumerate(SEQUENCE):
            _type_line(f, line)
            if i == 11:  # right after the model tag
                _dump(f, f"{out_dir}/smoke-2-aftermodel.ppm")
        print("wizard sequence sent")
    else:
        print("skip-wizard: pre-seeded config, waiting for services")

    # Let firstboot finish, services start, model-pull grab tinyllama.
    time.sleep(svc_wait)
    _dump(f, f"{out_dir}/smoke-3-postboot.ppm")
    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
