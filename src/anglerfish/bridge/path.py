"""Shell-path normalisation shared by the bridge and the lure.

Lives in :mod:`anglerfish.bridge` rather than under either consumer
so import goes parent-to-child: the lure imports from the bridge,
not the other way around.
"""

from __future__ import annotations

__all__ = ["normalise_path"]


def normalise_path(path: str) -> str:
    """Collapse ``.`` and ``..`` segments into a clean absolute path.

    Mirrors ``cd`` semantics in a real shell. Always returns an
    absolute path; relative inputs are anchored at ``/``. Trailing
    slashes are dropped. Empty path resolves to ``/``.
    """
    if not path.startswith("/"):
        path = "/" + path
    parts: list[str] = []
    for piece in path.split("/"):
        if piece in ("", "."):
            continue
        if piece == "..":
            if parts:
                parts.pop()
            continue
        parts.append(piece)
    return "/" + "/".join(parts)
