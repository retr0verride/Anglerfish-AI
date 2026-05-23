"""Synchronous bridge-client used by Cowrie's Twisted-based shell.

Cowrie runs on Twisted's reactor; its command-dispatch path is
synchronous and expects an immediate response to write back to the
attacker. We therefore use :class:`httpx.Client` (sync) here rather
than the async client the rest of Anglerfish uses.

Design notes:

* The client is a process-level singleton guarded by a re-entrant lock.
  Twisted may dispatch shell commands from its own thread or from a
  thread pool, so the lock protects the lazy-init path.
* Configuration is read from environment variables at first use, not
  at import time, so the Cowrie systemd unit's ``EnvironmentFile``
  takes effect.
* The session map translates Cowrie's per-connection session UUID
  string into the bridge's UUID. The mapping is in-memory; Cowrie and
  the bridge are co-located on the same host so a crash on either side
  legitimately ends the session.
* Every call is wrapped in a coarse try/except. Failures degrade to
  empty-string responses so the Cowrie shell can fall back to its
  built-in command registry without crashing the connection.

The Cowrie patch in ``cowrie/patches/0001-anglerfish-shell.patch``
inserts calls to :func:`submit_command` at the top of
:meth:`cowrie.shell.honeypot.HoneyPotShell.runCommand`. The output
plugin in :mod:`anglerfish.integration.cowrie` manages session
lifecycle by listening for ``cowrie.session.connect`` and
``cowrie.session.closed`` events.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Final
from uuid import UUID

import httpx

__all__ = [
    "BridgeClientError",
    "close_session",
    "get_or_open_session",
    "open_session",
    "reset_client_for_tests",
    "submit_command",
]


_logger = logging.getLogger(__name__)

_PROTOCOL_HEADER: Final[str] = "X-Anglerfish-Protocol"
_PROTOCOL_VERSION: Final[str] = "1"
_DEFAULT_URL: Final[str] = "http://127.0.0.1:8421"
_DEFAULT_TIMEOUT_S: Final[float] = 30.0


class BridgeClientError(RuntimeError):
    """Raised when the bridge HTTP API returns an unrecoverable error."""


def _read_env() -> tuple[str, str, float]:
    return (
        os.environ.get("ANGLERFISH_BRIDGE_URL", _DEFAULT_URL),
        os.environ.get("ANGLERFISH_BRIDGE__SHARED_SECRET", ""),
        float(os.environ.get("ANGLERFISH_BRIDGE_TIMEOUT_S", str(_DEFAULT_TIMEOUT_S))),
    )


_client_lock = threading.RLock()
_client: httpx.Client | None = None

_session_lock = threading.RLock()
_session_map: dict[str, UUID] = {}


def _get_client() -> httpx.Client:
    global _client
    with _client_lock:
        if _client is None:
            base_url, secret, timeout = _read_env()
            headers = {
                _PROTOCOL_HEADER: _PROTOCOL_VERSION,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "anglerfish-cowrie-shell/0.1.0",
            }
            if secret:
                headers["Authorization"] = f"Bearer {secret}"
            _client = httpx.Client(
                base_url=base_url,
                timeout=timeout,
                headers=headers,
            )
        return _client


def reset_client_for_tests() -> None:
    """Drop the cached client and the session map. Test helper only."""
    global _client
    with _client_lock:
        if _client is not None:
            _client.close()
        _client = None
    with _session_lock:
        _session_map.clear()


def open_session(cowrie_session_id: str, *, source_ip: str, username: str) -> UUID:
    """Register a Cowrie session with the bridge.

    Idempotent in ``cowrie_session_id`` — calling again returns the
    bridge UUID assigned to the first call. Raises
    :class:`BridgeClientError` on any network or HTTP failure.
    """
    with _session_lock:
        existing = _session_map.get(cowrie_session_id)
        if existing is not None:
            return existing

    client = _get_client()
    try:
        r = client.post(
            "/api/v1/session",
            json={"source_ip": source_ip, "username": username},
        )
        r.raise_for_status()
    except httpx.HTTPError as exc:
        raise BridgeClientError(
            f"bridge open_session failed: {type(exc).__name__}: {exc}",
        ) from exc

    body = r.json()
    if "session_id" not in body:
        raise BridgeClientError(
            f"bridge open_session: missing session_id in response: {body!r}",
        )
    sid = UUID(body["session_id"])
    with _session_lock:
        _session_map[cowrie_session_id] = sid
    return sid


def get_or_open_session(
    cowrie_session_id: str,
    *,
    source_ip: str,
    username: str,
) -> UUID:
    """Convenience: return the bridge UUID, registering if absent.

    Useful from the Cowrie shell patch when an event-plugin race
    means the session wasn't registered yet via
    ``cowrie.session.connect``.
    """
    with _session_lock:
        existing = _session_map.get(cowrie_session_id)
    if existing is not None:
        return existing
    return open_session(cowrie_session_id, source_ip=source_ip, username=username)


def submit_command(cowrie_session_id: str, command: str) -> str:
    """Submit one command to the bridge. Returns the response text.

    Failure modes return the empty string and log a warning; callers
    should treat that as "the bridge has nothing to say, fall back to
    Cowrie's built-in handling for this command".
    """
    with _session_lock:
        sid = _session_map.get(cowrie_session_id)
    if sid is None:
        _logger.debug(
            "cowrie_shell.submit_command: session %s not registered",
            cowrie_session_id,
        )
        return ""

    client = _get_client()
    try:
        r = client.post(
            f"/api/v1/session/{sid}/command",
            json={"command": command},
        )
    except httpx.HTTPError as exc:
        _logger.warning(
            "cowrie_shell.submit_command: network failure: %s: %s",
            type(exc).__name__,
            exc,
        )
        return ""

    if r.status_code == 404:
        _logger.info(
            "cowrie_shell.submit_command: bridge dropped session %s; forgetting",
            cowrie_session_id,
        )
        with _session_lock:
            _session_map.pop(cowrie_session_id, None)
        return ""
    if r.status_code >= 500:
        _logger.warning(
            "cowrie_shell.submit_command: bridge 5xx (%s)",
            r.status_code,
        )
        return ""
    if r.status_code >= 400:
        _logger.warning(
            "cowrie_shell.submit_command: bridge 4xx (%s): %s",
            r.status_code,
            r.text[:200],
        )
        return ""

    try:
        body = r.json()
    except ValueError as exc:
        _logger.warning(
            "cowrie_shell.submit_command: malformed bridge response: %s",
            exc,
        )
        return ""
    text = body.get("text", "")
    return text if isinstance(text, str) else ""


def close_session(cowrie_session_id: str) -> None:
    """End a Cowrie session. Best-effort — never raises."""
    with _session_lock:
        sid = _session_map.pop(cowrie_session_id, None)
    if sid is None:
        return
    try:
        client = _get_client()
        client.delete(f"/api/v1/session/{sid}")
    except httpx.HTTPError as exc:
        _logger.warning(
            "cowrie_shell.close_session: %s: %s",
            type(exc).__name__,
            exc,
        )
