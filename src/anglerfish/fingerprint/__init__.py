"""Session fingerprinting: SSH banner parsing, JA3/HASSH hashes, Tor detection.

Public surface:

* :class:`Fingerprinter` — orchestrator that produces a
  :class:`anglerfish.models.fingerprint.SessionFingerprint` per session.
* :func:`parse_ssh_banner` — RFC 4253 banner parser.
* :class:`TorExitList` — async-safe IP-set wrapper around a
  refreshable exit-node list file.
* :func:`compute_ja3`, :func:`compute_hassh` — pure hash helpers the
  lure calls when constructing fingerprints.
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
