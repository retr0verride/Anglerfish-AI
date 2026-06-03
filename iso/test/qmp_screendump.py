#!/usr/bin/env python3
"""Connect to a QEMU QMP unix socket, capture the guest screen to PPM.

Usage: qmp_screendump.py <socket> <out.ppm>
Used by the install-to-disk boot test to observe whether the installed
disk reaches userspace, without modifying the guest image.
"""

import json
import socket
import sys
import time


def main() -> int:
    sock_path, out = sys.argv[1], sys.argv[2]
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
    f.write(json.dumps({"execute": "screendump", "arguments": {"filename": out}}) + "\n")
    f.flush()
    print(f.readline().strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
