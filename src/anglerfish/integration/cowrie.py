"""Cowrie output plugin that ships every Cowrie event to the Anglerfish bridge.

Three responsibilities:

* **Event forwarding.** Every Cowrie event is wrapped in a
  :class:`ForwarderEvent` and submitted to the
  :class:`anglerfish.forwarder.Forwarder` (Splunk HEC with JSONL
  fallback).
* **Shell adapter installation.** On plugin start, the
  :mod:`anglerfish.integration.cowrie_shell_adapter` monkey-patch is
  installed on ``HoneyPotShell.lineReceived``. The patch routes
  attacker input through the bridge HTTP API and writes the
  LLM-driven response back to the terminal.
* **Session lifecycle.** ``cowrie.session.connect`` events register
  the session with the bridge; ``cowrie.session.closed`` events
  release the bridge-side state.

Configure Cowrie's ``output_plugins`` list to include
``anglerfish.integration.cowrie`` and ensure ``anglerfish-ai`` is
importable from the Python interpreter Cowrie runs under.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from anglerfish.config.settings import AnglerfishSettings, load_settings
from anglerfish.forwarder import Forwarder, ForwarderEvent
from anglerfish.integration import cowrie_shell, cowrie_shell_adapter

__all__ = ["AnglerfishOutput", "build_plugin"]


class AnglerfishOutput:
    """Bridge between Cowrie's event stream and Anglerfish."""

    def __init__(
        self,
        *,
        settings: AnglerfishSettings | None = None,
        forwarder: Forwarder | None = None,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        self._settings = settings if settings is not None else load_settings()
        self._forwarder = forwarder if forwarder is not None else Forwarder(self._settings)
        self._loop = loop
        self._logger = logging.getLogger(__name__)

    @property
    def forwarder(self) -> Forwarder:
        return self._forwarder

    def start(self) -> None:
        """Cowrie calls this when the plugin loads — install the shell adapter."""
        cowrie_shell_adapter.install()

    def handle_event(self, event: Mapping[str, Any]) -> None:
        """Dispatch by ``eventid`` — session lifecycle alongside universal forwarding."""
        eventid = event.get("eventid")
        if eventid == "cowrie.session.connect":
            self._on_session_connect(event)
        elif eventid == "cowrie.session.closed":
            self._on_session_closed(event)

    def _on_session_connect(self, event: Mapping[str, Any]) -> None:
        sid = event.get("session")
        if not isinstance(sid, str) or not sid:
            return
        src_ip = event.get("src_ip", "0.0.0.0")  # noqa: S104 - placeholder, not a bind
        if not isinstance(src_ip, str):
            src_ip = "0.0.0.0"  # noqa: S104 - placeholder, not a bind
        username_raw = event.get("username", "root")
        if isinstance(username_raw, bytes):
            username = username_raw.decode("utf-8", errors="replace")
        elif isinstance(username_raw, str):
            username = username_raw
        else:
            username = "root"
        if not username:
            username = "root"
        try:
            cowrie_shell.open_session(sid, source_ip=src_ip, username=username)
        except cowrie_shell.BridgeClientError as exc:
            self._logger.warning(
                "bridge.open_session failed for cowrie session %s: %s",
                sid,
                exc,
            )

    def _on_session_closed(self, event: Mapping[str, Any]) -> None:
        sid = event.get("session")
        if isinstance(sid, str) and sid:
            cowrie_shell.close_session(sid)

    def submit(
        self,
        event: Mapping[str, Any],
    ) -> asyncio.Task[None] | concurrent.futures.Future[None] | None:
        """Schedule a forwarder submission for ``event``.

        Returns:
            * an :class:`asyncio.Task` if a loop is running in the
              current thread (tests),
            * a :class:`concurrent.futures.Future` if the operator
              passed an explicit ``loop`` (production, Twisted),
            * :data:`None` when no loop is available anywhere and the
              call was executed synchronously via :func:`asyncio.run`.
        """
        payload: dict[str, Any] = dict(event)
        ts = payload.pop("timestamp", None)
        when: datetime | None = None
        if isinstance(ts, str):
            try:
                when = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                when = None
        if when is None:
            when = datetime.now(tz=UTC)
        envelope = ForwarderEvent(
            event=payload,
            sourcetype="cowrie:event",
            time=when,
        )

        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None

        if running is not None:
            return running.create_task(self._dispatch(envelope))
        if self._loop is not None:
            return asyncio.run_coroutine_threadsafe(
                self._dispatch(envelope),
                self._loop,
            )
        asyncio.run(self._dispatch(envelope))
        return None

    async def _dispatch(self, envelope: ForwarderEvent) -> None:
        """Forward an envelope and discard the routing outcome."""
        await self._forwarder.submit(envelope)

    def shutdown(self) -> None:
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is not None:
            running.create_task(self._forwarder.aclose())
            return
        if self._loop is not None:
            asyncio.run_coroutine_threadsafe(self._forwarder.aclose(), self._loop)
            return
        asyncio.run(self._forwarder.aclose())


def build_plugin() -> type:  # pragma: no cover - imported from Cowrie at runtime
    """Return a Cowrie-compatible output plugin class.

    The import of ``cowrie.core.output`` is deferred so that the
    Anglerfish package can be imported and tested without Cowrie
    installed.
    """
    from cowrie.core.output import Output

    class _Plugin(Output):  # type: ignore[misc, no-any-unimported]
        def __init__(self) -> None:
            super().__init__()
            self._impl = AnglerfishOutput()

        def start(self) -> None:
            self._impl.start()

        def stop(self) -> None:
            self._impl.shutdown()

        def write(self, event: Mapping[str, Any]) -> None:
            self._impl.handle_event(event)
            self._impl.submit(event)

    _Plugin.__name__ = "Output"
    return _Plugin
