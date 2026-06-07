#!/usr/bin/env python3
"""Drive the Anglerfish first-boot wizard over the serial console for the smoke.

The live ISO autostarts ``anglerfish-firstboot.service`` on ``/dev/console``,
which takes its input from the serial line (``console=ttyS0`` on the kernel
cmdline). So the wizard is driven as plain text over the serial socket, not by
replaying VGA keystrokes:

  1. QMP ``send-key`` ENTER at the isolinux boot menu. The bootloader reads the
     VGA keyboard, not serial, so this stays on QMP.
  2. Wait for the wizard to render, then replay the answer sequence by writing
     each line to the serial socket. A background reader tees the serial stream
     to ``<out>/smoke-serial.log`` for the record.
  3. Screendump the VGA console (which mirrors the serial wizard via
     ``console=tty0``) before and after, so the run can still be eyeballed.

The wizard runs ``--provision`` on the appliance, so the sequence ends with the
operator's SSH key (fed in so the bash orchestrator can prove the account works
over SSH) and the console fallback password.

Usage:
  qmp_wizard_smoke.py <qmp.sock> <serial.sock> <out_dir> \
      [menu_wait] [boot_wait] [svc_wait] [pubkey_path] [skip-wizard]
"""

from __future__ import annotations

import json
import socket
import sys
import threading
import time
from pathlib import Path
from typing import IO, Any

# Console fallback value fed to the wizard's --provision prompt. The bash
# orchestrator does not use it (sshd is key-only); it just exercises chpasswd.
_CONSOLE_FALLBACK = "smoke-rescue-pw"


def _build_sequence(pubkey: str) -> list[str]:
    """Answer for each wizard prompt, in order. "" means accept the default."""
    return [
        "y",  # terms: default is NO, so we must type y to accept
        "",  # VM hostname            -> anglerfish-honeypot
        "",  # bait interface         -> first NIC
        "",  # service interface      -> second NIC
        "",  # bait DHCP?             -> yes
        "",  # service DHCP?          -> yes
        "",  # operator UNIX username -> anglerfish-ops
        pubkey,  # operator SSH pubkey -> the smoke's generated key
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
        _CONSOLE_FALLBACK,  # --provision console fallback value
    ]


# Index of the model-tag line; screendump right after it (matches the old run).
_MODEL_LINE_INDEX = 11


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


def _key(f: IO[str], qcode: str) -> None:
    _rpc(f, {"execute": "send-key", "arguments": {"keys": [{"type": "qcode", "data": qcode}]}})


def _dump(f: IO[str], path: str) -> None:
    print("screendump", path, _rpc(f, {"execute": "screendump", "arguments": {"filename": path}}))


def _connect(path: str) -> socket.socket:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    for _ in range(60):
        try:
            s.connect(path)
            return s
        except OSError:
            time.sleep(1)
    print(f"could not connect to {path}", file=sys.stderr)
    raise SystemExit(1)


def _tee_serial(sock: socket.socket, log_path: str) -> None:
    """Append everything the guest writes on serial to a log (best-effort)."""
    with open(log_path, "ab", buffering=0) as log:
        while True:
            try:
                chunk = sock.recv(4096)
            except OSError:
                return
            if not chunk:
                return
            log.write(chunk)


def _send_line(sock: socket.socket, text: str, *, line_delay: float = 0.8) -> None:
    """Write one answer line to the serial console and pace for the next prompt."""
    sock.sendall(text.encode() + b"\n")
    time.sleep(line_delay)


def main() -> int:
    qmp_path = sys.argv[1]
    serial_path = sys.argv[2]
    out_dir = sys.argv[3].rstrip("/")
    menu_wait = float(sys.argv[4]) if len(sys.argv) > 4 else 12.0
    boot_wait = float(sys.argv[5]) if len(sys.argv) > 5 else 120.0
    svc_wait = float(sys.argv[6]) if len(sys.argv) > 6 else 180.0
    pubkey_path = sys.argv[7] if len(sys.argv) > 7 and sys.argv[7] else ""
    # "skip-wizard": the image carries a pre-seeded /etc/anglerfish config so
    # firstboot is ConditionPathExists-skipped and services auto-start. No
    # interactive prompts to drive -- a deterministic steady-state boot.
    skip_wizard = len(sys.argv) > 8 and sys.argv[8] == "skip-wizard"

    qmp_sock = _connect(qmp_path)
    f = qmp_sock.makefile("rw")
    f.readline()  # greeting
    _rpc(f, {"execute": "qmp_capabilities"})

    # Serial channel for wizard input; tee its output to the log.
    serial_sock = _connect(serial_path)
    threading.Thread(
        target=_tee_serial,
        args=(serial_sock, f"{out_dir}/smoke-serial.log"),
        daemon=True,
    ).start()

    # Boot menu -> default entry (VGA keyboard, so QMP).
    time.sleep(menu_wait)
    _key(f, "ret")
    print("sent boot-menu ENTER")

    # Wait for the wizard to render, capture the terms screen.
    time.sleep(boot_wait)
    _dump(f, f"{out_dir}/smoke-1-prewizard.ppm")

    if not skip_wizard:
        pubkey = Path(pubkey_path).read_text().strip() if pubkey_path else ""
        for i, line in enumerate(_build_sequence(pubkey)):
            _send_line(serial_sock, line)
            if i == _MODEL_LINE_INDEX:
                _dump(f, f"{out_dir}/smoke-2-aftermodel.ppm")
        print("wizard sequence sent over serial")
    else:
        print("skip-wizard: pre-seeded config, waiting for services")

    # Let firstboot finish, services start, model-pull grab tinyllama.
    time.sleep(svc_wait)
    _dump(f, f"{out_dir}/smoke-3-postboot.ppm")
    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
