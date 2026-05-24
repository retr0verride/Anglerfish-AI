"""SSH server identification banner (RFC 4253 section 4.2).

A real shell-honeypot's banner is what scanners read first. The default
mirrors a recent Debian stable so the lure blends with the long tail of
internet-facing Debian SSH boxes. Configurable so operators can drift
the value when upstream releases move and the static banner becomes a
fingerprint.
"""

from __future__ import annotations

__all__ = ["debian_banner"]


def debian_banner(
    *,
    openssh_version: str = "9.2p1",
    debian_version: str = "2+deb12u3",
) -> str:
    """Return an ``SSH-2.0-OpenSSH_X Debian-Y`` identification string."""
    if not openssh_version:
        raise ValueError("openssh_version cannot be empty")
    if not debian_version:
        raise ValueError("debian_version cannot be empty")
    return f"SSH-2.0-OpenSSH_{openssh_version} Debian-{debian_version}"
