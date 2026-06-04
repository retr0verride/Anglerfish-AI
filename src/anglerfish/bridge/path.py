"""Shell-path normalisation shared by the bridge and the lure.

Lives in :mod:`anglerfish.bridge` rather than under either consumer
so import goes parent-to-child: the lure imports from the bridge,
not the other way around.
"""

from __future__ import annotations

__all__ = ["normalise_path"]

# C0 control characters + DEL. A real shell path never contains them, and
# leaving them in lets an attacker-controlled `cd` target smuggle a newline
# into the session cwd, which the bridge interpolates verbatim into the LLM
# system prompt ("Working directory: {cwd}") -- a prompt-injection vector.
# normalise_path is the single chokepoint every cwd update flows through
# (bridge service + lure session/commands), so stripping here closes it.
_CONTROL_CHARS = dict.fromkeys([*range(0x20), 0x7F])


def normalise_path(path: str) -> str:
    """Collapse ``.`` and ``..`` segments into a clean absolute path.

    Mirrors ``cd`` semantics in a real shell. Always returns an
    absolute path; relative inputs are anchored at ``/``. Trailing
    slashes are dropped. Empty path resolves to ``/``. Control
    characters are stripped (a path cannot legitimately contain them).
    """
    path = path.translate(_CONTROL_CHARS)
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
