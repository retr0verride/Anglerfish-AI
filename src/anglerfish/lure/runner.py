"""Top-level coroutine that wires the lure dep graph and runs the server.

`run_lure` is the entry point both `python -m anglerfish.lure` and the
CLI `anglerfish lure serve` subcommand call. It owns the lifecycle of
the dependencies the design separates (CredentialStore, Fingerprinter,
BridgeClient) and the LureServer itself, plus the signal handlers
that translate SIGTERM/SIGINT into a graceful shutdown.

The signal-driven shutdown path uses an `asyncio.Event` rather than
direct signal-handler `LureServer.stop()` calls. That keeps the
shutdown work inside the asyncio loop where the rest of the code
lives and avoids the "what loop am I on" reentrancy that bare
loop.add_signal_handler closures invite.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import socket
import struct
from typing import TYPE_CHECKING

from anglerfish.audit import AuditLog
from anglerfish.credentials.storage import CredentialStore
from anglerfish.fingerprint.service import Fingerprinter
from anglerfish.lure.bridge_client import BridgeClient
from anglerfish.lure.keys import ensure_host_keys, load_host_keys
from anglerfish.lure.server import BaitNicError, LureServer

try:
    import fcntl
except ImportError:  # non-POSIX (e.g. Windows): interface resolution is a no-op
    fcntl = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from anglerfish.config.settings import AnglerfishSettings
    from anglerfish.lure.config import LureConfig

__all__ = ["BaitNicError", "run_lure"]


_logger = logging.getLogger(__name__)

_SIOCGIFADDR = 0x8915  # Linux ioctl: fetch an interface's IPv4 address


def _resolve_interface_ipv4(ifname: str) -> str | None:
    """Return the IPv4 currently assigned to ``ifname``, or ``None``.

    Linux-only (``SIOCGIFADDR`` ioctl). Returns ``None`` on a non-POSIX
    host or when the interface has no IPv4 yet (e.g. DHCP has not
    completed). The lure calls this at every start, so a DHCP lease -- or
    a renewal that changed the address -- is picked up on the next
    (re)start rather than frozen at wizard time.
    """
    if fcntl is None or not ifname:
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", ifname[:15].encode("ascii", "ignore"))
        raw = fcntl.ioctl(sock.fileno(), _SIOCGIFADDR, packed)
    except OSError:
        return None
    finally:
        sock.close()
    return socket.inet_ntoa(raw[20:24])


def _effective_lure_config(settings: AnglerfishSettings) -> LureConfig:
    """Resolve the lure's bind address, handling a DHCP bait NIC.

    The wizard leaves ``lure.listen_host`` unset for a DHCP bait NIC
    (the IP is unknown at config time), so it defaults to the
    unspecified address, which the lure refuses to bind. When a bait
    interface is configured, bind that interface's current IPv4 instead.
    A static bait NIC already carries an explicit ``listen_host`` and is
    returned unchanged. If resolution fails (no IPv4 yet), the config is
    left unchanged so ``validate_bait_nic`` rejects it and systemd's
    ``Restart=on-failure`` retries once DHCP has assigned an address.
    """
    lure = settings.lure
    if not lure.listen_host.is_unspecified or not settings.bait_interface:
        return lure
    resolved = _resolve_interface_ipv4(settings.bait_interface)
    if resolved is None:
        _logger.warning(
            "lure: bait interface %s has no IPv4 yet; bind will fail and "
            "retry until DHCP assigns one.",
            settings.bait_interface,
        )
        return lure
    _logger.info(
        "lure: binding bait interface %s current IPv4 %s",
        settings.bait_interface,
        resolved,
    )
    return lure.model_copy(update={"listen_host": resolved})


# Signals to install handlers for. SIGTERM is systemd's stop signal;
# SIGINT is Ctrl-C in interactive runs. Both translate to "drain and
# exit cleanly." Windows does not deliver SIGTERM the same way and
# `loop.add_signal_handler` is POSIX-only, so the runner skips signal
# wiring on nt and relies on KeyboardInterrupt for interactive use.
_GRACEFUL_SIGNALS: tuple[signal.Signals, ...] = (
    (signal.SIGTERM, signal.SIGINT) if os.name != "nt" else ()
)


async def run_lure(settings: AnglerfishSettings) -> None:
    """Boot the lure, serve traffic, and shut down on signal.

    The function returns cleanly when shutdown completes. Any
    bait-NIC validation failure raises :class:`BaitNicError` from
    ``LureServer.start``; the caller (the CLI wrapper) is expected
    to convert that into a non-zero exit status.
    """
    if not settings.lure.enabled:
        _logger.warning(
            "lure: ANGLERFISH_LURE__ENABLED=false; exiting without binding",
        )
        return

    # Host keys: generate if missing, load + permission-check.
    ensure_host_keys(settings.lure.host_key_dir)
    rsa_pem, ed25519_pem = load_host_keys(settings.lure.host_key_dir)

    # Single AuditLog instance is shared across the bridge, the lure,
    # and the rest of Anglerfish. Path comes from settings.audit so
    # the writer and the Stage 4.2 dashboard tailer agree on it.
    audit_log = AuditLog(settings.audit.log_path)

    # CredentialStore must be opened before we hand it to LureServer
    # (the lure's validate_password awaits record_attempt on every
    # auth attempt). Use the existing async-context-manager.
    cred_store = CredentialStore(settings.credentials)
    await cred_store.open()

    fingerprinter = Fingerprinter(settings)

    bridge_secret_obj = settings.bridge.shared_secret
    bridge_secret = bridge_secret_obj.get_secret_value() if bridge_secret_obj is not None else None
    bridge_client = BridgeClient(
        base_url=settings.lure.bridge_base_url,
        shared_secret=bridge_secret,
        request_timeout_s=settings.lure.bridge_request_timeout_s,
        connect_timeout_s=settings.lure.bridge_connect_timeout_s,
    )

    # Resolve a DHCP bait NIC's current IP before binding (no-op for a
    # static listen_host or when no bait interface is configured).
    lure_config = _effective_lure_config(settings)

    server = LureServer(
        lure_config,
        credential_store=cred_store,
        fingerprinter=fingerprinter,
        bridge_client=bridge_client,
        audit_log=audit_log,
        host_keys=[rsa_pem, ed25519_pem],
    )

    shutdown = asyncio.Event()
    _install_signal_handlers(shutdown)

    try:
        await server.start()
        _logger.info(
            "lure: serving on %s:%s; SIGTERM or SIGINT for graceful drain",
            lure_config.listen_host,
            server.get_port(),
        )
        await shutdown.wait()
    finally:
        await server.stop()
        await bridge_client.aclose()
        await cred_store.aclose()
        await fingerprinter.aclose()


def _install_signal_handlers(shutdown: asyncio.Event) -> None:
    """Translate SIGTERM/SIGINT into ``shutdown.set()`` on the running loop."""
    if not _GRACEFUL_SIGNALS:
        return
    loop = asyncio.get_running_loop()
    for sig in _GRACEFUL_SIGNALS:
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, shutdown.set)
