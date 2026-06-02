"""Session fingerprinting: SSH banner parsing, JA3/HASSH hashes, Tor detection.

Public surface:

* :class:`Fingerprinter` — orchestrator that produces a
  :class:`anglerfish.models.fingerprint.SessionFingerprint` per session.
* :func:`parse_ssh_banner` — RFC 4253 banner parser.
* :class:`TorExitList` — async-safe IP-set wrapper around a
  refreshable exit-node list file.
* :func:`compute_hassh` — pure hash helper the lure calls when
  constructing SSH fingerprints.
* :func:`compute_ja3` — pure hash helper for TLS ClientHello
  fingerprints. A deliberate, currently-unwired extension point: SSH
  carries no TLS handshake, so the lure passes ``ja3=None``. Kept for
  a future TLS-bearing protocol surface.
"""

from __future__ import annotations

from anglerfish.fingerprint.hashes import (
    compute_hassh,
    compute_hassh_string,
    compute_ja3,
    compute_ja3_string,
)
from anglerfish.fingerprint.service import Fingerprinter
from anglerfish.fingerprint.ssh import parse_ssh_banner
from anglerfish.fingerprint.tor import TorExitList

__all__ = [
    "Fingerprinter",
    "TorExitList",
    "compute_hassh",
    "compute_hassh_string",
    "compute_ja3",
    "compute_ja3_string",
    "parse_ssh_banner",
]
