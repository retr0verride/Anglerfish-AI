#!/usr/bin/env python3
"""Drive a QEMU live boot: send ENTER at the boot menu, then screendump.

Usage: qmp_boot_capture.py <socket> <out.ppm> <menu_wait_s> <boot_wait_s>
Used by the per-service-user boot test: the live ISO's isolinux menu waits
for input under -display none, so press ENTER to select the default entry,
then capture once the system has come up.
"""

import json
import socket
import sys
import time


def main() -> int:
    sock_path, out = sys.argv[1], sys.argv[2]
    menu_wait = float(sys.argv[3]) if len(sys.argv) > 3 else 10.0
    boot_wait = float(sys.argv[4]) if len(sys.argv) > 4 else 75.0
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
    f.write(json.dumps({"execute": "qmp_capabilities"}) + "\n")
    f.flush()
    f.readline()
    # Let the boot menu render, then press ENTER for the default entry.
    time.sleep(menu_wait)
    f.write(
        json.dumps(
            {"execute": "send-key", "arguments": {"keys": [{"type": "qcode", "data": "ret"}]}}
        )
        + "\n"
    )
    f.flush()
    print("sent ENTER:", f.readline().strip())
    # Wait for the live system to come up, then capture.
    time.sleep(boot_wait)
    f.write(json.dumps({"execute": "screendump", "arguments": {"filename": out}}) + "\n")
    f.flush()
    print("screendump:", f.readline().strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
