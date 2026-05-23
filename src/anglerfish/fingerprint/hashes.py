"""Network-protocol fingerprint hash helpers.

Two algorithms are supported:

* **JA3** (TLS) — MD5 of the canonical comma-separated string
  ``Version,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats``.
  Each list is dash-separated. Used when the honeypot exposes a TLS
  surface (HTTPS endpoint, etc.).
* **HASSH** (SSH) — MD5 of the canonical
  ``KexAlgorithms;Encryption;MACs;Compression`` string sent by the
  client during the SSH key exchange. The Cowrie integration extracts
  these four lists from the SSH KEXINIT packet and hands them here.

Both functions are pure and synchronous — they perform string
formatting plus a hashlib hash. They are kept in their own module so
that the network-extraction code (in the Cowrie integration) has a
narrow seam to call.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

__all__ = ["compute_hassh", "compute_hassh_string", "compute_ja3", "compute_ja3_string"]


def _join_ints(values: Sequence[int]) -> str:
    return "-".join(str(v) for v in values)


def compute_ja3_string(
    version: int,
    ciphers: Sequence[int],
    extensions: Sequence[int],
    elliptic_curves: Sequence[int],
    elliptic_curve_point_formats: Sequence[int],
) -> str:
    """Return the canonical JA3 input string (pre-hash)."""
    return ",".join(
        [
            str(version),
            _join_ints(ciphers),
            _join_ints(extensions),
            _join_ints(elliptic_curves),
            _join_ints(elliptic_curve_point_formats),
        ],
    )


def compute_ja3(
    version: int,
    ciphers: Sequence[int],
    extensions: Sequence[int],
    elliptic_curves: Sequence[int],
    elliptic_curve_point_formats: Sequence[int],
) -> str:
    """Return the lowercase hex MD5 of the JA3 canonical string."""
    canonical = compute_ja3_string(
        version,
        ciphers,
        extensions,
        elliptic_curves,
        elliptic_curve_point_formats,
    )
    return hashlib.md5(canonical.encode("ascii"), usedforsecurity=False).hexdigest()


def compute_hassh_string(
    kex_algorithms: Sequence[str],
    encryption_algorithms: Sequence[str],
    mac_algorithms: Sequence[str],
    compression_algorithms: Sequence[str],
) -> str:
    """Return the canonical HASSH input string (pre-hash)."""
    return ";".join(
        [
            ",".join(kex_algorithms),
            ",".join(encryption_algorithms),
            ",".join(mac_algorithms),
            ",".join(compression_algorithms),
        ],
    )


def compute_hassh(
    kex_algorithms: Sequence[str],
    encryption_algorithms: Sequence[str],
    mac_algorithms: Sequence[str],
    compression_algorithms: Sequence[str],
) -> str:
    """Return the lowercase hex MD5 of the HASSH canonical string."""
    canonical = compute_hassh_string(
        kex_algorithms,
        encryption_algorithms,
        mac_algorithms,
        compression_algorithms,
    )
    return hashlib.md5(canonical.encode("ascii"), usedforsecurity=False).hexdigest()
