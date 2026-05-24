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
from typing import TYPE_CHECKING

from anglerfish.audit import AuditLog
from anglerfish.credentials.storage import CredentialStore
from anglerfish.fingerprint.service import Fingerprinter
from anglerfish.lure.bridge_client import BridgeClient
from anglerfish.lure.keys import ensure_host_keys, load_host_keys
from anglerfish.lure.server import BaitNicError, LureServer

if TYPE_CHECKING:
    from anglerfish.config.settings import AnglerfishSettings

__all__ = ["run_lure"]


_logger = logging.getLogger(__name__)

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
    # and the rest of Anglerfish. Constructed at module-default path
    # so audit events land in the same JSONL the rest of the stack
    # writes to.
    audit_log = AuditLog()

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

    server = LureServer(
        settings.lure,
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
            settings.lure.listen_host,
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


# Re-export the dep-failure exception so CLI / __main__ wrappers do not
# have to import from anglerfish.lure.server directly.
__all__ += ["BaitNicError"]
