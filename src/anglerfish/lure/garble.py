"""Byte-level corruption for counter-deception (Stage 12).

Pure functions. The lure's ``_cat`` handler calls :func:`garble` when an
engaged session reads a file in its
``counter_deception_garble_paths`` allowlist. The corruption is
deterministic per ``(session_id, path)`` so re-reads in the same session
yield identical output: serving different bytes on each ``cat`` would
tell the attacker the file is dynamic.

v1 garbles text-shaped files only (the lure fakefs's
``ReadResult.content`` is ``str``). Binary kinds (ELF / PE / tarball /
image) are v1.1+ and depend on a fakefs bytes-mode read path that does
not exist yet. See ``docs/design/STAGE_12_counter_deception.md``.

Three kinds:

* PEM private keys: the BEGIN/END armor lines survive; characters in
  the base64 body are flipped so ``openssl rsa -check`` / ``ssh -i``
  fail with a parse error on a file that still looks like a key.
* AWS credentials: the INI keys + the ``aws_access_key_id`` value
  survive (the AKIA prefix is what the Stage 11 callback receiver
  decodes); the ``aws_secret_access_key`` value is rewritten with junk
  so ``aws s3 ls`` fails with a signature mismatch, not an
  invalid-key error.
* default text: a leading prefix survives so ``head`` shows
  plausible content; characters deeper in the file are flipped so a
  full ``cat`` reveals corruption.
"""

from __future__ import annotations

import hashlib
import random
import re
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

__all__ = ["GarbleKind", "GarbleResult", "garble", "infer_kind"]


class GarbleKind(StrEnum):
    """Which corruption strategy :func:`garble` applied."""

    PEM = "pem"
    AWS = "aws"
    DEFAULT = "default"


@dataclass(frozen=True)
class GarbleResult:
    """Outcome of a :func:`garble` call.

    ``content`` is the corrupted text to serve. The char counts feed the
    ``lure.counter_deception_garble_served`` audit event.
    """

    content: str
    kind: GarbleKind
    original_chars: int
    garbled_chars: int


_PEM_KEY_NAMES = frozenset({"id_rsa", "id_ed25519", "id_ecdsa"})
_DEFAULT_PREFIX_KEEP = 4096
_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_SECRET_RE = re.compile(r"(aws_secret_access_key\s*=\s*)(\S+)")


def infer_kind(path: str, content: str) -> GarbleKind:
    """Classify ``path`` / ``content`` into a :class:`GarbleKind`."""
    name = path.rsplit("/", 1)[-1]
    if name in _PEM_KEY_NAMES or content.startswith("-----BEGIN"):
        return GarbleKind.PEM
    if "/.aws/" in path and name in {"credentials", "config"}:
        return GarbleKind.AWS
    return GarbleKind.DEFAULT


def garble(content: str, *, session_id: UUID, path: str) -> GarbleResult:
    """Corrupt ``content`` deterministically for ``(session_id, path)``.

    The seed is a SHA-256 of ``session_id:path`` so the corruption is
    reproducible across processes (testable) and identical for repeated
    reads of the same path in the same session.
    """
    kind = infer_kind(path, content)
    rng = random.Random(_seed(session_id, path))  # noqa: S311 - deterministic deception, not crypto
    if kind is GarbleKind.PEM:
        garbled = _garble_pem(content, rng)
    elif kind is GarbleKind.AWS:
        garbled = _garble_aws(content, rng)
    else:
        garbled = _garble_default(content, rng)
    return GarbleResult(
        content=garbled,
        kind=kind,
        original_chars=len(content),
        garbled_chars=len(garbled),
    )


def _seed(session_id: UUID, path: str) -> int:
    digest = hashlib.sha256(f"{session_id}:{path}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def _flip_b64(char: str, rng: random.Random) -> str:
    """Return a base64 character different from ``char``."""
    if char not in _B64_ALPHABET:
        return char
    replacement = rng.choice(_B64_ALPHABET)
    while replacement == char:
        replacement = rng.choice(_B64_ALPHABET)
    return replacement


def _flip_text(char: str, rng: random.Random) -> str:
    """Return a printable ASCII character different from ``char``.

    Newlines + tabs are preserved so the file's line structure (and a
    plausible ``wc -l``) survives; only visible content shifts.
    """
    if char in "\n\t\r":
        return char
    replacement = chr(rng.randint(33, 126))
    while replacement == char:
        replacement = chr(rng.randint(33, 126))
    return replacement


def _garble_pem(content: str, rng: random.Random) -> str:
    lines = content.split("\n")
    target = rng.randint(8, 16)
    mangled = 0
    out: list[str] = []
    for line in lines:
        if line.startswith("-----") or not line.strip():
            out.append(line)
            continue
        chars = list(line)
        positions = list(range(len(chars)))
        rng.shuffle(positions)
        for pos in positions:
            if mangled >= target:
                break
            chars[pos] = _flip_b64(chars[pos], rng)
            mangled += 1
        out.append("".join(chars))
    if mangled == 0:
        # No base64 body found (degenerate PEM); fall back to text garble.
        return _garble_default(content, rng)
    return "\n".join(out)


def _garble_aws(content: str, rng: random.Random) -> str:
    junk = "".join(rng.choice(_B64_ALPHABET) for _ in range(40))
    new, n = _SECRET_RE.subn(lambda m: m.group(1) + junk, content)
    if n == 0:
        # No secret-access-key line; fall back to text garble so the
        # operator-configured AWS path still gets corrupted.
        return _garble_default(content, rng)
    return new


def _garble_default(content: str, rng: random.Random) -> str:
    if not content:
        return content
    keep = min(_DEFAULT_PREFIX_KEEP, len(content) // 2)
    head = content[:keep]
    tail = list(content[keep:])
    # Only flip visible (non-whitespace) chars; flipping a newline is a
    # no-op (_flip_text preserves line structure) and could leave a short
    # file unchanged if every chosen slot landed on whitespace.
    flippable = [i for i, c in enumerate(tail) if c not in "\n\t\r"]
    if not flippable:
        # Tail is all whitespace (rare). Flip a visible char in the head
        # so the file still ends up corrupted; otherwise leave it (nothing
        # visible to change).
        head_chars = list(head)
        head_flippable = [i for i, c in enumerate(head_chars) if c not in "\n\t\r"]
        if not head_flippable:
            return content
        pos = rng.choice(head_flippable)
        head_chars[pos] = _flip_text(head_chars[pos], rng)
        return "".join(head_chars) + "".join(tail)
    target = max(1, len(flippable) // 10)
    rng.shuffle(flippable)
    for pos in flippable[:target]:
        tail[pos] = _flip_text(tail[pos], rng)
    return head + "".join(tail)
