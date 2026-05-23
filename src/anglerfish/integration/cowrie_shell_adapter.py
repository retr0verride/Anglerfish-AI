"""Monkey-patch that routes Cowrie shell input through the Anglerfish bridge.

The patch replaces :meth:`cowrie.shell.honeypot.HoneyPotShell.lineReceived`
with one that:

1. Resolves the Cowrie-side session UUID + source IP + username from
   the shell's protocol attributes.
2. Asks :mod:`anglerfish.integration.cowrie_shell` to register the
   session with the bridge (idempotent — the output plugin usually
   pre-registers on ``cowrie.session.connect``).
3. Submits the attacker's input line to the bridge.
4. Writes the bridge's response to the attacker's terminal and prints
   the next prompt.
5. Falls through to Cowrie's original ``lineReceived`` if the bridge
   returned an empty response, refused, or is unreachable — Cowrie's
   built-in command registry still gives a plausible answer.

Why monkey-patch rather than ship a Cowrie subclass: Cowrie does not
expose a class-override hook for its shell, and shipping a forked
shell would require us to maintain that fork in lockstep with Cowrie.
A targeted method replacement keeps the surface area to a single
function pointer.

The Cowrie attributes we read (``shell.protocol.transport.session.sessionno``,
etc.) are stable across the Cowrie 2.x line. The reader functions
defensively fall back to safe defaults so the bridge call still goes
through if a future Cowrie release rearranges them.
"""

from __future__ import annotations

import logging
from typing import Any

from anglerfish.integration import cowrie_shell

__all__ = [
    "extract_session_metadata",
    "install",
    "is_installed",
    "uninstall_for_tests",
]


_logger = logging.getLogger(__name__)
_PATCH_INSTALLED = False
_ATTR_ORIGINAL = "_anglerfish_original_lineReceived"


def is_installed() -> bool:
    return _PATCH_INSTALLED


def install() -> None:
    """Install the line-handler patch on ``HoneyPotShell``.

    Idempotent. Logs and returns silently if Cowrie is not importable
    (e.g. when the Anglerfish package is being tested in isolation).
    """
    global _PATCH_INSTALLED
    if _PATCH_INSTALLED:
        return
    try:
        from cowrie.shell.honeypot import HoneyPotShell
    except ImportError as exc:
        _logger.warning(
            "cowrie not importable; shell patch deferred: %s",
            exc,
        )
        return

    setattr(HoneyPotShell, _ATTR_ORIGINAL, HoneyPotShell.lineReceived)
    HoneyPotShell.lineReceived = _patched_line_received
    _PATCH_INSTALLED = True
    _logger.info("anglerfish shell adapter installed")


def uninstall_for_tests() -> None:
    """Restore the original Cowrie shell method. Test helper only."""
    global _PATCH_INSTALLED
    if not _PATCH_INSTALLED:
        return
    try:
        from cowrie.shell.honeypot import HoneyPotShell
    except ImportError:
        _PATCH_INSTALLED = False
        return
    original = getattr(HoneyPotShell, _ATTR_ORIGINAL, None)
    if original is not None:
        HoneyPotShell.lineReceived = original
        delattr(HoneyPotShell, _ATTR_ORIGINAL)
    _PATCH_INSTALLED = False


def extract_session_metadata(shell: Any) -> tuple[str, str, str]:
    """Pull ``(cowrie_session_id, source_ip, username)`` from a shell instance.

    Defensive about Cowrie's attribute layout — each path is wrapped
    so a missing attribute falls through to a sensible default.
    """
    cowrie_sid = _safe_path(shell, "protocol", "transport", "session", "sessionno")
    if cowrie_sid is None:
        cowrie_sid = id(shell)

    source_ip = _safe_peer_host(shell)
    if source_ip is None:
        # Fallback placeholder for unknown peer — not a bind address.
        source_ip = "0.0.0.0"  # noqa: S104

    username_raw = _safe_path(shell, "protocol", "user", "username")
    if isinstance(username_raw, bytes):
        username = username_raw.decode("utf-8", errors="replace")
    elif isinstance(username_raw, str):
        username = username_raw
    else:
        username = "root"

    return str(cowrie_sid), str(source_ip), username


def _safe_path(obj: Any, *attrs: str) -> Any:
    cur = obj
    for a in attrs:
        cur = getattr(cur, a, None)
        if cur is None:
            return None
    return cur


def _safe_peer_host(shell: Any) -> str | None:
    """Walk ``shell.protocol.transport.transport.getPeer().host`` defensively."""
    transport = _safe_path(shell, "protocol", "transport", "transport")
    if transport is None:
        return None
    get_peer = getattr(transport, "getPeer", None)
    if get_peer is None:
        return None
    try:
        peer = get_peer()
    except (AttributeError, OSError) as exc:
        _logger.debug("getPeer() failed: %s", exc)
        return None
    host = getattr(peer, "host", None)
    return str(host) if host is not None else None


def _patched_line_received(self: Any, line: Any) -> Any:
    """Replacement for :meth:`HoneyPotShell.lineReceived`.

    See module docstring for the algorithm. This function is attached
    to ``HoneyPotShell`` as an unbound method, so ``self`` is the shell
    instance and ``line`` is the bytes-or-str attacker input.
    """
    line_str = line.decode("utf-8", errors="replace") if isinstance(line, bytes) else str(line)

    sid, source_ip, username = extract_session_metadata(self)

    try:
        cowrie_shell.get_or_open_session(sid, source_ip=source_ip, username=username)
    except cowrie_shell.BridgeClientError as exc:
        _logger.warning(
            "bridge open_session failed; falling back to Cowrie: %s",
            exc,
        )
        return _fall_back(self, line)

    response = cowrie_shell.submit_command(sid, line_str)
    if response == "":
        return _fall_back(self, line)

    if not _write_response(self, response):
        return _fall_back(self, line)

    _show_prompt(self)
    return None


def _fall_back(shell: Any, line: Any) -> Any:
    """Hand the line back to Cowrie's original ``lineReceived``."""
    original = getattr(shell, _ATTR_ORIGINAL, None)
    if original is None:
        _logger.error(
            "anglerfish shell adapter: no original lineReceived stored; dropping",
        )
        return None
    return original(line)


def _write_response(shell: Any, response: str) -> bool:
    terminal = _safe_path(shell, "protocol", "terminal")
    if terminal is None:
        return False
    write = getattr(terminal, "write", None)
    if write is None:
        return False
    try:
        write(response.encode("utf-8") + b"\r\n")
    except OSError as exc:
        _logger.warning("terminal.write failed: %s", exc)
        return False
    return True


def _show_prompt(shell: Any) -> None:
    show_prompt = getattr(shell, "showPrompt", None)
    if show_prompt is None:
        return
    try:
        show_prompt()
    except AttributeError as exc:
        _logger.debug("showPrompt failed: %s", exc)
