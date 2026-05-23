"""High-level AI bridge service.

:class:`AIBridgeService` is the orchestrator that Cowrie's command
handler talks to. Given a session and a command, it returns the
response to print to the attacker's terminal. It wires together:

* :mod:`anglerfish.bridge.sanitize` (input cap + control-char strip)
* the deterministic ``cd`` shortcut so cwd never depends on the LLM
* :mod:`anglerfish.bridge.rate_limit` (global + per-session caps)
* :mod:`anglerfish.bridge.prompts` (prompt construction)
* :mod:`anglerfish.bridge.client` (Ollama HTTP call)
* :mod:`anglerfish.bridge.fallback` (scripted responses on failure)
* :mod:`anglerfish.bridge.session` (per-attacker state recording)

The service catches every bridge-level error and degrades to a
fallback response so that Cowrie always gets a non-empty result and
the attacker is never shown an exception.
"""

from __future__ import annotations

import logging
import shlex
import time
from collections.abc import Callable
from typing import Self

from anglerfish.bridge.client import OllamaClient
from anglerfish.bridge.errors import (
    BridgeError,
    GlobalQueueTimeoutError,
    OllamaResponseError,
    OllamaUnavailableError,
    SessionRateLimitedError,
)
from anglerfish.bridge.fallback import fallback_response
from anglerfish.bridge.prompts import build_messages
from anglerfish.bridge.rate_limit import BridgeRateLimiter
from anglerfish.bridge.sanitize import cap_output, sanitize_command
from anglerfish.bridge.session import SessionContext
from anglerfish.config.settings import AnglerfishSettings
from anglerfish.models.session import BridgeResponse, ResponseSource

__all__ = ["AIBridgeService"]


class AIBridgeService:
    """Cowrie-facing orchestrator.

    Construct once at startup; share across all sessions.
    """

    def __init__(
        self,
        settings: AnglerfishSettings,
        *,
        client: OllamaClient,
        limiter: BridgeRateLimiter | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        logger: logging.Logger | None = None,
    ) -> None:
        self._settings = settings
        self._client = client
        self._limiter = limiter if limiter is not None else BridgeRateLimiter(settings.rate_limit)
        self._monotonic = monotonic
        self._logger = logger if logger is not None else logging.getLogger(__name__)

    @property
    def settings(self) -> AnglerfishSettings:
        return self._settings

    @property
    def client(self) -> OllamaClient:
        return self._client

    @property
    def limiter(self) -> BridgeRateLimiter:
        return self._limiter

    async def handle_command(
        self,
        session: SessionContext,
        command: str,
    ) -> BridgeResponse:
        """Return the shell response to display for ``command``.

        Always returns a :class:`BridgeResponse` — never raises.
        Bridge-level failures degrade to scripted fallback content;
        when fallbacks are disabled in configuration, the response text
        is empty and ``source`` is :attr:`ResponseSource.REJECTED`.
        """
        sanitised = sanitize_command(
            command,
            max_chars=self._settings.bridge.max_input_chars,
        )

        # Empty command — bash just shows the next prompt.
        if not sanitised.strip():
            session.record(
                sanitised,
                "",
                source=ResponseSource.AI,
                latency_ms=0.0,
            )
            return BridgeResponse(text="", source=ResponseSource.AI, latency_ms=0.0)

        # `cd` is handled deterministically so cwd never depends on the LLM.
        if self._handle_cd(session, sanitised):
            session.record(
                sanitised,
                "",
                source=ResponseSource.AI,
                latency_ms=0.0,
            )
            return BridgeResponse(text="", source=ResponseSource.AI, latency_ms=0.0)

        start = self._monotonic()
        text: str
        source: ResponseSource
        try:
            async with self._limiter.slot(session.session_id):
                messages = build_messages(
                    sanitised,
                    config=self._settings.bridge,
                    cwd=session.cwd,
                    history=session.history(),
                )
                raw = await self._client.chat(messages)
                text = cap_output(
                    raw,
                    max_chars=self._settings.ollama.max_response_chars,
                )
                source = ResponseSource.AI
        except (
            OllamaUnavailableError,
            OllamaResponseError,
            SessionRateLimitedError,
            GlobalQueueTimeoutError,
        ) as exc:
            text, source = self._fallback(session, sanitised, reason=exc)

        latency_ms = (self._monotonic() - start) * 1000.0
        session.record(sanitised, text, source=source, latency_ms=latency_ms)
        return BridgeResponse(text=text, source=source, latency_ms=latency_ms)

    def _fallback(
        self,
        session: SessionContext,
        command: str,
        *,
        reason: BridgeError,
    ) -> tuple[str, ResponseSource]:
        self._logger.warning(
            "bridge.fallback session=%s reason=%s message=%s",
            session.session_id,
            type(reason).__name__,
            reason,
        )
        if not self._settings.bridge.enable_fallback:
            return ("", ResponseSource.REJECTED)
        scripted = fallback_response(
            command,
            hostname=session.fake_hostname,
            username=session.fake_username,
            cwd=session.cwd,
        )
        if scripted is None:
            head = self._first_token(command)
            scripted = f"bash: {head}: command not found" if head else ""
        return (scripted, ResponseSource.FALLBACK)

    def _handle_cd(self, session: SessionContext, command: str) -> bool:
        stripped = command.strip()
        if not stripped:
            return False
        try:
            tokens = shlex.split(stripped, posix=True)
        except ValueError:
            return False
        if not tokens or tokens[0] != "cd":
            return False

        if len(tokens) == 1 or tokens[1] == "~":
            target = (
                f"/home/{session.fake_username}" if session.fake_username != "root" else "/root"
            )
        elif tokens[1].startswith("/"):
            target = tokens[1]
        else:
            base = session.cwd.rstrip("/") or "/"
            target = f"{base}/{tokens[1]}"
        session.update_cwd(self._normalise_path(target))
        return True

    @staticmethod
    def _normalise_path(path: str) -> str:
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

    @staticmethod
    def _first_token(command: str) -> str:
        stripped = command.strip()
        if not stripped:
            return ""
        try:
            tokens = shlex.split(stripped, posix=True)
        except ValueError:
            return stripped.split()[0]
        return tokens[0] if tokens else ""

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
