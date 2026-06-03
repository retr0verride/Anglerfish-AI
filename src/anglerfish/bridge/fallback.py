"""Scripted shell responses for use when the LLM is unavailable.

These are not a comprehensive shell. They cover the small set of
commands an attacker types in the first few seconds of a session
(``whoami``, ``id``, ``uname``, etc.) so that a brief Ollama outage
does not immediately reveal the honeypot. Anything unmatched returns
:data:`None`, leaving the bridge to emit the generic
``bash: <command>: command not found`` instead.
"""

from __future__ import annotations

import shlex

from anglerfish import system_identity

__all__ = ["fallback_response"]


def _fmt_uname(flags: list[str], *, hostname: str) -> str:
    if not flags or flags == ["-s"]:
        return "Linux"
    if flags == ["-a"]:
        return system_identity.uname_a(hostname)
    if flags == ["-r"]:
        return system_identity.KERNEL_RELEASE
    if flags == ["-n"]:
        return hostname
    if flags == ["-m"]:
        return system_identity.MACHINE
    if flags == ["-o"]:
        return system_identity.OPERATING_SYSTEM
    return "Linux"


def fallback_response(
    command: str,
    *,
    hostname: str,
    username: str,
    cwd: str,
) -> str | None:
    """Return a plausible scripted response, or :data:`None` if no match."""
    stripped = command.strip()
    if not stripped:
        return ""

    try:
        tokens = shlex.split(stripped, posix=True)
    except ValueError:
        return None
    if not tokens:
        return ""

    head, *rest = tokens

    if head == "whoami":
        return username
    if head == "id":
        return system_identity.id_line(username)
    if head == "hostname":
        return hostname
    if head == "pwd":
        return cwd
    if head == "uname":
        return _fmt_uname(rest, hostname=hostname)
    if head == "echo":
        return " ".join(rest)
    if head == "uptime":
        return " 12:34:56 up 7 days,  3:14,  1 user,  load average: 0.04, 0.07, 0.03"
    if head in {"exit", "logout"}:
        return ""
    return None
