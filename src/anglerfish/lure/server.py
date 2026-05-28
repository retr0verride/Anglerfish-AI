"""asyncssh-based SSH server that fronts the bridge.

The server splits into three concerns:

* :class:`_PerIPLimiter` tracks per-source-IP concurrent connection
  counts and a sliding-window of recent connections so we can reject
  abusive clients before they cost a session slot.
* :class:`_LureSSHServer` is the asyncssh ``SSHServer`` subclass
  invoked per connection. It handles the SSH-protocol callbacks
  (auth, fingerprinting, refusing SFTP / port-forwarding / TUN /
  TAP), records credentials, and stitches per-connection state onto
  the ``SSHServerConnection`` object so the shell-loop process
  handler can recover it.
* :class:`LureServer` is the lifecycle wrapper the runner module
  drives: it owns the asyncssh acceptor, applies the bait-NIC
  validation at start, exposes ``start`` / ``stop`` / async-context
  semantics, and tracks the dep graph (CredentialStore,
  Fingerprinter, BridgeClient, NativeCommands, AuditLog).

The per-connection state lives on each ``SSHServerConnection`` via
the attribute ``conn._anglerfish_state``. The leading underscore is
the convention asyncssh users follow: the connection object is
yours per-session, attribute soup is fine, the namespace will not
collide with asyncssh internals.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import hashlib
import ipaddress
import logging
import socket
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Self
from uuid import UUID

import asyncssh

from anglerfish.fingerprint.hashes import compute_hassh
from anglerfish.lure.bridge_client import BridgeClient, BridgeUnavailableError
from anglerfish.lure.commands import NativeCommands
from anglerfish.lure.fakefs import system_prompt_summary
from anglerfish.lure.fallback import fallback_with_default
from anglerfish.lure.session import LureSessionContext

if TYPE_CHECKING:
    from anglerfish.audit import AuditLog
    from anglerfish.credentials.storage import CredentialStore
    from anglerfish.fingerprint.service import Fingerprinter
    from anglerfish.lure.config import LureConfig

__all__ = [
    "BaitNicError",
    "LureServer",
    "validate_bait_nic",
]


_logger = logging.getLogger(__name__)

_RATE_WINDOW_SECONDS = 60.0


class BaitNicError(RuntimeError):
    """Raised when the configured listen_host is not bindable on the host.

    The lure refuses to start in this state. The most common cause
    is a misconfigured ``ANGLERFISH_LURE__LISTEN_HOST`` that points
    at an IP not assigned to any interface, or the unspecified
    address ``0.0.0.0`` / ``::`` (which is rejected so a missing
    config does not silently bind to every interface).
    """


def validate_bait_nic(listen_host: str) -> None:
    """Refuse to proceed unless ``listen_host`` is a real local IP.

    Free function so the CLI's ``lure validate-config`` subcommand
    can run the same check the runtime does without instantiating
    the whole LureServer dep graph.

    Raises :class:`BaitNicError` on failure. Returns ``None`` on
    success.
    """
    try:
        addr = ipaddress.ip_address(listen_host)
    except ValueError as exc:
        raise BaitNicError(
            f"lure.listen_host {listen_host!r} is not a valid IP literal",
        ) from exc

    if addr.is_unspecified:
        raise BaitNicError(
            "lure.listen_host is the unspecified address "
            f"({listen_host}). Set ANGLERFISH_LURE__LISTEN_HOST to the "
            "bait NIC's IP so the lure does not bind every interface "
            "by accident.",
        )

    # Test-bind. The OS only lets you bind to addresses that are
    # actually assigned to a local interface (loopback included).
    # We do not keep the socket; freeing it before asyncssh binds
    # is acceptable because the real bind happens immediately under
    # the same routing rules.
    family = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        try:
            sock.bind((listen_host, 0))
        except OSError as exc:
            if exc.errno in (errno.EADDRNOTAVAIL, errno.EADDRINUSE):
                raise BaitNicError(
                    f"lure.listen_host {listen_host!r} is not assigned "
                    "to any local interface (test bind returned "
                    f"{exc.errno}/{exc.strerror!r}).",
                ) from exc
            # Other OSError (permission, etc.) - surface as a specific
            # bait-NIC error so operators see the cause at startup.
            raise BaitNicError(
                f"lure.listen_host {listen_host!r} bait-NIC check "
                f"failed: {exc.errno}/{exc.strerror!r}",
            ) from exc
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Per-IP limiter
# ---------------------------------------------------------------------------


class _PerIPLimiter:
    """Track concurrent connection count + sliding-window rpm per source IP.

    Two checks per incoming connection:

    * `concurrent[ip]` must be below `max_concurrent` BEFORE we
      increment.
    * `recent[ip]` (a deque of timestamps in the last 60s) must be
      below `max_rpm` BEFORE we record the new timestamp.

    Both checks are cheap (dict + deque) and called from the asyncio
    thread so no locking is required.
    """

    def __init__(self, *, max_concurrent: int, max_rpm: int) -> None:
        self._max_concurrent = max_concurrent
        self._max_rpm = max_rpm
        self._concurrent: dict[str, int] = {}
        self._recent: dict[str, deque[float]] = {}

    def admit(self, source_ip: str, *, now: float | None = None) -> tuple[bool, str]:
        """Decide whether to accept a new connection from ``source_ip``.

        Returns ``(allowed, reason)``. ``reason`` is empty on accept
        and one of ``"per_ip_concurrent"`` / ``"per_ip_rpm"`` on
        reject so the caller can audit the kind of throttle that
        fired.
        """
        if self._concurrent.get(source_ip, 0) >= self._max_concurrent:
            return False, "per_ip_concurrent"

        ts = now if now is not None else time.monotonic()
        recent = self._recent.setdefault(source_ip, deque())
        cutoff = ts - _RATE_WINDOW_SECONDS
        while recent and recent[0] < cutoff:
            recent.popleft()
        if len(recent) >= self._max_rpm:
            return False, "per_ip_rpm"

        # Commit: bump concurrent + record timestamp. The release
        # path lives in :meth:`release` and runs on disconnect.
        self._concurrent[source_ip] = self._concurrent.get(source_ip, 0) + 1
        recent.append(ts)
        return True, ""

    def release(self, source_ip: str) -> None:
        """Decrement the concurrent counter on disconnect."""
        current = self._concurrent.get(source_ip, 0)
        if current <= 1:
            self._concurrent.pop(source_ip, None)
        else:
            self._concurrent[source_ip] = current - 1

    def concurrent_for(self, source_ip: str) -> int:
        return self._concurrent.get(source_ip, 0)


# ---------------------------------------------------------------------------
# Per-connection state
# ---------------------------------------------------------------------------


@dataclass
class _ConnectionState:
    """Per-connection scratch space the shell loop reads back."""

    source_ip: str
    username: str = ""
    bridge_uuid: UUID | None = None
    lure_session: LureSessionContext | None = None
    open_audited: bool = False
    fingerprint_audited: bool = False
    started_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    # Track whether per-IP slot was acquired so connection_lost can
    # release exactly once even when the connection fails early.
    rate_slot_held: bool = False


# ---------------------------------------------------------------------------
# asyncssh SSHServer subclass
# ---------------------------------------------------------------------------


class _LureSSHServer(asyncssh.SSHServer):
    """Per-connection asyncssh SSHServer for the lure.

    asyncssh constructs one of these per attacker connection. Long-
    lived dependencies (CredentialStore, Fingerprinter, BridgeClient,
    NativeCommands, AuditLog, LureConfig, the rate limiter) come in
    through the constructor.
    """

    def __init__(self, container: LureServer) -> None:
        self._container = container
        self._conn: asyncssh.SSHServerConnection | None = None
        self._state: _ConnectionState | None = None

    # -- lifecycle --------------------------------------------------------

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername")
        source_ip = peer[0] if isinstance(peer, tuple) and peer else "unknown"
        state = _ConnectionState(source_ip=source_ip)
        self._state = state
        self._conn = conn
        # Attach for the process_handler shell loop to read back.
        conn._anglerfish_state = state  # type: ignore[attr-defined]  # noqa: SLF001

        allowed, reason = self._container.limiter.admit(source_ip)
        if not allowed:
            self._container.audit.record(
                "lure.rate_limited",
                source_ip=source_ip,
                kind=reason,
                concurrent=self._container.limiter.concurrent_for(source_ip),
            )
            # Closing the transport from connection_made aborts the
            # SSH handshake before any auth attempt is processed; the
            # attacker sees a TCP-level disconnect, which is the
            # closest equivalent to nftables-side packet drop.
            conn.close()
            return
        state.rate_slot_held = True
        # Fingerprint extraction lives in begin_auth(), not here:
        # connection_made fires before key exchange completes so the
        # kex extras (client_kex_algs etc.) are not yet populated.

    def connection_lost(self, exc: Exception | None) -> None:
        state = self._state
        if state is None:
            return
        if state.rate_slot_held:
            self._container.limiter.release(state.source_ip)
        duration_s = (datetime.now(tz=UTC) - state.started_at).total_seconds()
        # session_id is included only when the shell loop reached the
        # point of constructing the lure_session; connections that died
        # earlier (auth-stage disconnect, rate-limited) get a close
        # record without a session_id and the Stage 4.2 tailer ignores
        # them (no SessionStore row was ever opened).
        close_extras: dict[str, Any] = {}
        if state.lure_session is not None:
            close_extras["session_id"] = str(state.lure_session.session_id)
        self._container.audit.record(
            "lure.session_closed",
            source_ip=state.source_ip,
            username=state.username,
            duration_seconds=duration_s,
            command_count=state.lure_session.command_count() if state.lure_session else 0,
            error=type(exc).__name__ if exc else None,
            **close_extras,
        )
        if state.bridge_uuid is not None:
            self._container.spawn_background(
                self._container.bridge_client.close_session(state.bridge_uuid),
            )

    # -- auth -------------------------------------------------------------

    def begin_auth(self, username: str) -> bool:
        # First post-kex hook: asyncssh has the kex algorithms and the
        # client banner available now. Capture the fingerprint here so
        # connect-and-immediately-auth attackers still get logged.
        state = self._state
        if state is not None:
            state.username = username[:64] or "root"
            conn = self._conn
            if conn is not None:
                self._capture_fingerprint(conn, state.source_ip)
        # Returning True tells asyncssh "auth required". We accept any
        # password but must signal we want the client to send one.
        return True

    def _capture_fingerprint(
        self,
        conn: asyncssh.SSHServerConnection,
        source_ip: str,
    ) -> None:
        """Read kex extras + record HASSH. Idempotent per connection.

        Called from begin_auth (first post-kex hook). asyncssh's
        ``get_extra_info`` returns ``None`` when the field is not
        populated yet; the empty-fallback keeps the call total.
        """
        state = self._state
        if state is None or state.fingerprint_audited:
            return
        client_version = conn.get_extra_info("client_version")
        kex_algs = conn.get_extra_info("client_kex_algs") or []
        enc_algs = conn.get_extra_info("client_encryption_algs_cs") or []
        mac_algs = conn.get_extra_info("client_mac_algs_cs") or []
        comp_algs = conn.get_extra_info("client_compression_algs_cs") or []
        hassh = compute_hassh(kex_algs, enc_algs, mac_algs, comp_algs)
        self._container.audit.record(
            "lure.fingerprint_observed",
            source_ip=source_ip,
            client_version=client_version,
            hassh=hassh,
        )
        self._container.spawn_background(
            self._container.record_fingerprint(
                source_ip=source_ip,
                client_version=client_version,
                hassh=hassh,
            ),
        )
        state.fingerprint_audited = True

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        # Advertise pubkey so clients offer it; we log the fingerprint
        # then reject. The attempt itself is intel.
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        state = self._state
        source_ip = state.source_ip if state else "unknown"
        # Record asynchronously so a slow store doesn't extend the
        # SSH handshake. asyncssh awaits this coroutine so we get
        # backpressure for free.
        try:
            await self._container.credential_store.record_attempt(
                source_ip=source_ip,
                username=username,
                password=password,
                session_id=self._container.placeholder_session_id(),
                timestamp=datetime.now(tz=UTC),
            )
        except Exception as exc:  # noqa: BLE001 - never crash auth on store failure
            _logger.warning(
                "lure: credential store record failed (%s): %s",
                type(exc).__name__,
                exc,
            )
        self._container.audit.record(
            "lure.login_attempt",
            source_ip=source_ip,
            username=username,
            password_hash_prefix=_password_hash_prefix(password),
        )
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        state = self._state
        source_ip = state.source_ip if state else "unknown"
        fingerprint = key.get_fingerprint() if hasattr(key, "get_fingerprint") else "unknown"
        self._container.audit.record(
            "lure.login_attempt",
            source_ip=source_ip,
            username=username,
            auth_method="publickey",
            key_fingerprint=fingerprint,
        )
        # Refuse so the client falls back to password auth, which we
        # do accept and which is where credential capture happens.
        return False

    # -- subsystem refusals (intel via audit, no service) ----------------

    def session_requested(self) -> bool:
        # Shell channel is the only thing we serve. session_requested
        # returning True lets the framework call the process_handler
        # registered with asyncssh.listen.
        return True

    def connection_requested(
        self,
        dest_host: str,
        dest_port: int,
        orig_host: str,
        orig_port: int,
    ) -> bool:
        self._audit_refusal("direct-tcpip", dest_host=dest_host, dest_port=dest_port)
        del orig_host, orig_port
        return False

    def server_requested(self, listen_host: str, listen_port: int) -> bool:
        self._audit_refusal("tcpip-forward", listen_host=listen_host, listen_port=listen_port)
        return False

    def unix_connection_requested(self, dest_path: str) -> bool:
        self._audit_refusal("direct-streamlocal", dest_path=dest_path)
        return False

    def unix_server_requested(self, listen_path: str) -> bool:
        self._audit_refusal("streamlocal-forward", listen_path=listen_path)
        return False

    def tun_requested(self, unit: int | None) -> bool:
        self._audit_refusal("tun", unit=unit)
        return False

    def tap_requested(self, unit: int | None) -> bool:
        self._audit_refusal("tap", unit=unit)
        return False

    def _audit_refusal(self, kind: str, **fields: Any) -> None:
        state = self._state
        self._container.audit.record(
            "lure.subsystem_refused",
            kind=kind,
            source_ip=state.source_ip if state else "unknown",
            **fields,
        )


def _password_hash_prefix(password: str) -> str:
    """First 8 hex chars of sha256(password) - dedup, never plaintext."""
    return hashlib.sha256(password.encode("utf-8", errors="replace")).hexdigest()[:8]


# ---------------------------------------------------------------------------
# Process handler (shell loop)
# ---------------------------------------------------------------------------


async def _process_handler(
    container: LureServer,
    process: asyncssh.SSHServerProcess[str],
) -> None:
    """One attacker shell session.

    Pulled out as a free function and bound to ``container`` via the
    factory in :meth:`LureServer.start`. asyncssh invokes this once
    per session_requested True after auth succeeds.
    """
    conn = process.channel.get_connection()
    state: _ConnectionState | None = getattr(conn, "_anglerfish_state", None)
    if state is None:
        # Should not happen - connection_made always sets it - but
        # close cleanly rather than throw inside asyncssh's frame.
        process.exit(1)
        return

    # Open the bridge session BEFORE prompting the attacker. If the
    # bridge is unreachable, we still serve the session via native
    # dispatch + scripted fallback (the design wants captures
    # whether or not the LLM side is up).
    bridge_uuid: UUID | None = None
    bridge_hostname: str | None = None
    bridge_cwd: str | None = None
    persona_name: str | None = None
    persona_overlay: dict[str, str] = {}
    garble_paths: frozenset[str] = frozenset()
    try:
        result = await container.bridge_client.open_session(
            source_ip=state.source_ip,
            username=state.username,
        )
        bridge_uuid = result.session_id
        bridge_hostname = result.fake_hostname
        bridge_cwd = result.fake_cwd
        persona_name = result.persona_name
        persona_overlay = result.persona_overlay
        garble_paths = frozenset(result.counter_deception_garble_paths)
        state.bridge_uuid = bridge_uuid
    except BridgeUnavailableError as exc:
        container.audit.record(
            "lure.bridge_unavailable",
            source_ip=state.source_ip,
            reason="open_session_failed",
            error_type=type(exc).__name__,
        )

    # Stage 9: when the bridge returned a persona-driven identity,
    # use it; otherwise fall back to the lure's static config hostname
    # and the legacy /home/<user> derivation. This keeps the bridge-
    # unreachable path identical to the pre-Stage-9 behaviour.
    hostname = bridge_hostname if bridge_hostname is not None else container.config.hostname
    cwd = (
        bridge_cwd
        if bridge_cwd is not None
        else (f"/home/{state.username}" if state.username != "root" else "/root")
    )
    lure_session = LureSessionContext(
        bridge_uuid if bridge_uuid is not None else container.placeholder_session_id(),
        source_ip=state.source_ip,
        username=state.username,
        hostname=hostname,
        cwd=cwd,
        history_window=container.config.history_window,
        persona_name=persona_name,
        persona_overlay=persona_overlay,
        counter_deception_garble_paths=garble_paths,
    )
    state.lure_session = lure_session
    if not state.open_audited:
        container.audit.record(
            "lure.session_opened",
            source_ip=state.source_ip,
            username=state.username,
            client_version=conn.get_extra_info("client_version"),
            session_id=str(lure_session.session_id),
        )
        state.open_audited = True

    # Subsystem requests (sftp, etc.) we did not register get nothing
    # back; close the channel after auditing.
    if process.subsystem:
        container.audit.record(
            "lure.subsystem_refused",
            kind=f"subsystem:{process.subsystem}",
            source_ip=state.source_ip,
        )
        with contextlib.suppress(Exception):
            process.exit(1)
        return

    # Exec mode: client sent one command with `conn.run("...")` or
    # `ssh user@host "cmd"`. Run it once, write the response, exit.
    if process.command:
        await _handle_one_command(
            container,
            lure_session,
            process.command,
            process.stdout.write,
        )
        with contextlib.suppress(Exception):
            process.exit(0)
        return

    # Interactive shell mode: read lines from stdin and dispatch.
    process.stdout.write(_render_prompt(lure_session))

    try:
        async for raw_line in process.stdin:
            line = raw_line.rstrip("\r\n")
            if not line.strip():
                process.stdout.write(_render_prompt(lure_session))
                continue
            close_after = await _handle_one_command(
                container,
                lure_session,
                line,
                process.stdout.write,
            )
            if close_after:
                break
            process.stdout.write(_render_prompt(lure_session))
    except asyncssh.BreakReceived:
        pass
    except asyncssh.ConnectionLost:
        pass
    finally:
        with contextlib.suppress(Exception):
            process.exit(0)


def _render_prompt(session: LureSessionContext) -> str:
    """``user@host:cwd$ `` (or ``#`` for root)."""
    sigil = "#" if session.username == "root" else "$"
    return f"{session.username}@{session.hostname}:{session.cwd}{sigil} "


async def _handle_one_command(
    container: LureServer,
    session: LureSessionContext,
    line: str,
    write: Callable[[str], None],
) -> bool:
    """Dispatch one command, write output via ``write``, return ``close_after``.

    Owns the output side of the lure shell: native commands write the
    full response in one call; bridge commands either stream chunks
    (when ``config.bridge_stream_enabled`` and the bridge supports
    protocol v3) or write the full buffered response in one call.
    """
    # Lure-side cap. The design intentionally caps closer to the
    # attacker than the bridge's max_input_chars.
    sanitised = line[: container.config.max_command_chars]
    sanitised = _strip_c0(sanitised)

    native = await container.commands.dispatch(session, sanitised)
    if native.handled:
        session.record(sanitised, response_source="native")
        container.audit.record(
            "lure.command_native",
            source_ip=session.source_ip,
            command=sanitised[:200],
            session_id=str(session.session_id),
        )
        # Stage 12: the cat handler corrupted a counter-deception
        # allowlisted file for this session. Record it so the operator
        # sees which bait files the attacker actually exfiltrated.
        if native.garble is not None:
            container.audit.record(
                "lure.counter_deception_garble_served",
                source_ip=session.source_ip,
                session_id=str(session.session_id),
                path=native.garble.path,
                kind=native.garble.kind,
                original_chars=native.garble.original_chars,
                garbled_chars=native.garble.garbled_chars,
            )
        if native.text:
            write(native.text)
        return native.close_after

    # Bridge route.
    if container.config.bridge_stream_enabled:
        await _handle_bridge_stream(container, session, sanitised, write)
    else:
        await _handle_bridge_buffered(container, session, sanitised, write)
    return False


async def _handle_bridge_stream(
    container: LureServer,
    session: LureSessionContext,
    sanitised: str,
    write: Callable[[str], None],
) -> None:
    """Stream the bridge response chunk-by-chunk to the attacker terminal."""
    bridge_uuid = session.session_id
    start = time.monotonic()
    wrote_any = False
    try:
        async for chunk in container.bridge_client.command_stream(
            bridge_uuid,
            sanitised,
            fs_context=system_prompt_summary(session),
        ):
            if chunk.delta:
                write(chunk.delta)
                wrote_any = True
        latency_ms = (time.monotonic() - start) * 1000.0
    except BridgeUnavailableError as exc:
        # Mid-stream failure: emit the lure-side fallback only if we
        # have not already written any AI text (would otherwise duck
        # in mid-sentence with a "command not found"). If we did
        # write something, just stop - the partial reply looks like
        # a hung command, the lure's existing fallback path doesn't
        # apply.
        latency_ms = (time.monotonic() - start) * 1000.0
        _audit_bridge_failure(container, session, sanitised, exc)
        if not wrote_any:
            _write_fallback(container, session, sanitised, write)
            return
        # Ensure newline so the next prompt sits cleanly.
        write("\n")
        return

    container.commands.record_bridge_latency(latency_ms)
    session.record(sanitised, response_source="bridge")
    container.audit.record(
        "lure.command_bridge",
        source_ip=session.source_ip,
        command=sanitised[:200],
        latency_ms=latency_ms,
        session_id=str(session.session_id),
    )
    # Bridge chunks don't include a trailing newline; add one so the
    # next prompt sits on its own line.
    if wrote_any:
        write("\n")


async def _handle_bridge_buffered(
    container: LureServer,
    session: LureSessionContext,
    sanitised: str,
    write: Callable[[str], None],
) -> None:
    """Submit the command and write the full buffered response (v2 path)."""
    bridge_uuid = session.session_id
    start = time.monotonic()
    try:
        response = await container.bridge_client.submit_command(
            bridge_uuid,
            sanitised,
            fs_context=system_prompt_summary(session),
        )
        latency_ms = (time.monotonic() - start) * 1000.0
        container.commands.record_bridge_latency(latency_ms)
        session.record(sanitised, response_source="bridge")
        container.audit.record(
            "lure.command_bridge",
            source_ip=session.source_ip,
            command=sanitised[:200],
            latency_ms=latency_ms,
            session_id=str(session.session_id),
        )
        if response and not response.endswith("\n"):
            response = response + "\n"
        if response:
            write(response)
    except BridgeUnavailableError as exc:
        _audit_bridge_failure(container, session, sanitised, exc)
        _write_fallback(container, session, sanitised, write)


def _audit_bridge_failure(
    container: LureServer,
    session: LureSessionContext,
    sanitised: str,
    exc: BridgeUnavailableError,
) -> None:
    """Audit a bridge failure (shared between streaming and buffered paths)."""
    container.audit.record(
        "lure.bridge_unavailable",
        source_ip=session.source_ip,
        reason="submit_command_failed",
        error_type=type(exc).__name__,
        session_id=str(session.session_id),
    )
    container.audit.record(
        "lure.fallback_served",
        source_ip=session.source_ip,
        command=sanitised[:200],
        reason=type(exc).__name__,
        session_id=str(session.session_id),
    )


def _write_fallback(
    container: LureServer,
    session: LureSessionContext,
    sanitised: str,
    write: Callable[[str], None],
) -> None:
    """Render the scripted fallback for ``sanitised`` and write it."""
    del container  # unused but kept for symmetry with the other helpers
    scripted = fallback_with_default(
        sanitised,
        hostname=session.hostname,
        username=session.username,
        cwd=session.cwd,
    )
    session.record(sanitised, response_source="fallback")
    if scripted and not scripted.endswith("\n"):
        scripted = scripted + "\n"
    if scripted:
        write(scripted)


def _strip_c0(text: str) -> str:
    """Drop C0 control bytes (except tab and newline) before sending up."""
    allowed = {"\t", "\n"}
    return "".join(c for c in text if c in allowed or (ord(c) >= 0x20 and c != "\x7f"))


# ---------------------------------------------------------------------------
# Top-level LureServer
# ---------------------------------------------------------------------------


# Type alias for the dep bundle. Kept ad-hoc because Stage 2A's
# components are independently constructable.
ProcessHandler = Callable[[asyncssh.SSHServerProcess[str]], Awaitable[None]]


class LureServer:
    """Lifecycle wrapper around the asyncssh listener and the dep graph.

    Construct once at boot. Call :meth:`start` to bind and accept
    traffic; :meth:`stop` for graceful drain. The async context
    manager protocol does the same with auto-cleanup.

    Per-connection state lives on each ``SSHServerConnection`` (see
    :class:`_LureSSHServer.connection_made`); the container owns
    everything else.
    """

    def __init__(
        self,
        config: LureConfig,
        *,
        credential_store: CredentialStore,
        fingerprinter: Fingerprinter,
        bridge_client: BridgeClient,
        audit_log: AuditLog,
        host_keys: list[bytes],
        commands: NativeCommands | None = None,
    ) -> None:
        self._config = config
        self._credential_store = credential_store
        self._fingerprinter = fingerprinter
        self._bridge_client = bridge_client
        self._audit = audit_log
        self._host_keys_pem = host_keys
        self._commands = commands if commands is not None else NativeCommands(config)
        self._limiter = _PerIPLimiter(
            max_concurrent=config.per_ip_max_concurrent_connections,
            max_rpm=config.per_ip_max_connections_per_minute,
        )
        self._acceptor: asyncssh.SSHAcceptor | None = None
        self._background: set[asyncio.Task[Any]] = set()
        # UUID re-used for bridge-less placeholder sessions. Kept
        # frozen so collisions are obvious in audit logs.
        self._placeholder_session_id = UUID("00000000-0000-0000-0000-000000000000")

    # -- public read-only accessors used by the SSHServer instances ------

    @property
    def config(self) -> LureConfig:
        return self._config

    @property
    def audit(self) -> AuditLog:
        return self._audit

    @property
    def credential_store(self) -> CredentialStore:
        return self._credential_store

    @property
    def bridge_client(self) -> BridgeClient:
        return self._bridge_client

    @property
    def commands(self) -> NativeCommands:
        return self._commands

    @property
    def limiter(self) -> _PerIPLimiter:
        return self._limiter

    def placeholder_session_id(self) -> UUID:
        return self._placeholder_session_id

    # -- lifecycle --------------------------------------------------------

    async def start(self) -> None:
        """Bind the listener after validating bait-NIC presence."""
        listen_host = str(self._config.listen_host)
        validate_bait_nic(listen_host)

        # Load host keys into asyncssh's required format. The bytes
        # come from disk via lure.keys.load_host_keys.
        try:
            ssh_keys = [asyncssh.import_private_key(pem) for pem in self._host_keys_pem]
        except (asyncssh.KeyImportError, ValueError) as exc:
            raise BaitNicError(
                f"host-key import failed: {type(exc).__name__}: {exc}",
            ) from exc

        # Construct the per-connection server with the container ref.
        container = self

        def server_factory() -> _LureSSHServer:
            return _LureSSHServer(container)

        async def process_factory(process: asyncssh.SSHServerProcess[str]) -> None:
            await _process_handler(container, process)

        # asyncssh's server_version accepts only RFC 4253's
        # `softwareversion` token, which forbids spaces. The
        # OpenSSH version is the only part that fits; the Debian
        # suffix that the Stage 2 design contemplated was dropped
        # (closed TODO-4) because asyncssh has no separate
        # `comments` parameter and bypassing its banner generation
        # would be a fragile monkey-patch.
        options_kwargs: dict[str, Any] = {
            "server_host_keys": ssh_keys,
            "server_version": f"OpenSSH_{self._config.banner_openssh_version}",
            "process_factory": process_factory,
            "allow_scp": False,
            "x11_forwarding": False,
            "agent_forwarding": False,
        }
        if self._config.keepalive_interval_s > 0:
            options_kwargs["keepalive_interval"] = self._config.keepalive_interval_s
            options_kwargs["keepalive_count_max"] = self._config.keepalive_count_max

        try:
            self._acceptor = await asyncssh.listen(
                listen_host,
                self._config.listen_port,
                server_factory=server_factory,
                **options_kwargs,
            )
        except OSError as exc:
            raise BaitNicError(
                f"failed to bind {listen_host}:{self._config.listen_port}: "
                f"{type(exc).__name__}: {exc}",
            ) from exc

        actual_port = self._acceptor.get_port()
        self._audit.record(
            "lure.server_started",
            listen_host=listen_host,
            listen_port=actual_port,
        )
        _logger.info(
            "lure listening on %s:%s",
            listen_host,
            actual_port,
        )

    def get_port(self) -> int:
        """Bound port. Useful for tests that bind to port 0."""
        if self._acceptor is None:
            raise RuntimeError("LureServer.start() has not been awaited yet")
        return self._acceptor.get_port()

    async def stop(self, *, drain_timeout_s: float = 30.0) -> None:
        """Close the listener and wait for in-flight sessions to drain."""
        started = time.monotonic()
        graceful = True
        if self._acceptor is not None:
            self._acceptor.close()
            try:
                await asyncio.wait_for(
                    self._acceptor.wait_closed(),
                    timeout=drain_timeout_s,
                )
            except TimeoutError:
                graceful = False
            self._acceptor = None
        # Drain background tasks (fire-and-forget audit / record calls).
        if self._background:
            await asyncio.wait(self._background, timeout=drain_timeout_s)
        self._audit.record(
            "lure.server_stopped",
            graceful=graceful,
            drain_seconds=time.monotonic() - started,
        )

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.stop()

    # -- helpers used from the per-connection callbacks ------------------

    def spawn_background(self, coro: Awaitable[Any]) -> None:
        """Run a coroutine without awaiting it.

        For audit-side-effects (credential record, fingerprint
        compose, bridge close) that must not block the SSH protocol
        handlers. Tasks are tracked so :meth:`stop` can wait on them.
        """
        task = asyncio.ensure_future(coro)
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    async def record_fingerprint(
        self,
        *,
        source_ip: str,
        client_version: str | None,
        hassh: str | None,
    ) -> None:
        """Compose a SessionFingerprint via the Stage 2A typed API."""
        try:
            await self._fingerprinter.fingerprint(
                source_ip=source_ip,
                ssh_banner=client_version,
                hassh=hassh,
                ja3=None,  # SSH-only listener; JA3 is TLS
            )
        except Exception as exc:  # noqa: BLE001 - intel-side, never crash session
            _logger.warning(
                "lure: fingerprint compose failed (%s): %s",
                type(exc).__name__,
                exc,
            )

    # bait-NIC validation lives in the free function above; LureServer
    # calls it from start() and the CLI's `lure validate-config`
    # subcommand calls it directly.
