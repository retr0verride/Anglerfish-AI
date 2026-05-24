"""Scripted fallback responses the lure serves when the bridge is down.

Re-uses ``anglerfish.bridge.fallback`` for the heavy lifting so a
single canned-response table stays the source of truth. The thin
wrapper here exists so lure callers do not import directly from the
bridge package; if Stage 2C or later adds lure-only scripted responses
(for SSH subsystems the bridge does not see, for example), they grow
here without bleeding into the bridge.
"""

from __future__ import annotations

from anglerfish.bridge.fallback import fallback_response

__all__ = ["fallback_response", "fallback_with_default"]


def fallback_with_default(
    command: str,
    *,
    hostname: str,
    username: str,
    cwd: str,
) -> str:
    """Return a scripted response, defaulting to ``command not found``.

    ``fallback_response`` returns ``None`` when no canned answer fits;
    the lure wraps with the canonical bash error so attackers always
    see something on the wire. Keeps the lure's fallback path total
    and removes a ``None``-handling branch from every caller.
    """
    scripted = fallback_response(
        command,
        hostname=hostname,
        username=username,
        cwd=cwd,
    )
    if scripted is not None:
        return scripted
    head = command.strip().split(maxsplit=1)[0] if command.strip() else ""
    return f"bash: {head}: command not found" if head else ""
