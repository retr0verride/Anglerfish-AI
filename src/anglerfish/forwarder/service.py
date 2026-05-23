"""Forwarder orchestrator.

The :class:`Forwarder` is the single submission interface used by other
Anglerfish subsystems. It tries the Splunk HEC endpoint first when
configured; on transport-level failures it degrades to the local JSONL
sink so that captured intelligence is not lost. Both backends are
optional dependencies of the forwarder — when Splunk is disabled the
forwarder simply writes every event to JSONL.

The orchestrator returns a :class:`ForwardOutcome` for every call so
callers (and the dashboard) can render an honest "where did this go?"
status without parsing log lines.
"""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import Any, Self

from anglerfish.config.settings import AnglerfishSettings
from anglerfish.forwarder.errors import (
    HECResponseError,
    HECUnavailableError,
    JsonlWriteError,
)
from anglerfish.forwarder.event import ForwarderEvent
from anglerfish.forwarder.hec import SplunkHECClient
from anglerfish.forwarder.jsonl import JsonlSink

__all__ = ["ForwardOutcome", "Forwarder"]


class ForwardOutcome(StrEnum):
    """Where the forwarder placed a submitted event."""

    HEC = "hec"
    JSONL = "jsonl"
    DROPPED = "dropped"


class Forwarder:
    """Orchestrates HEC submission with JSONL fallback."""

    def __init__(
        self,
        settings: AnglerfishSettings,
        *,
        hec_client: SplunkHECClient | None = None,
        jsonl_sink: JsonlSink | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._settings = settings
        self._logger = logger if logger is not None else logging.getLogger(__name__)
        self._jsonl_sink = (
            jsonl_sink if jsonl_sink is not None else JsonlSink(settings.splunk.fallback_path)
        )
        if hec_client is not None:
            self._hec_client: SplunkHECClient | None = hec_client
        elif settings.splunk.enabled:
            self._hec_client = SplunkHECClient(settings.splunk)
        else:
            self._hec_client = None

    @property
    def settings(self) -> AnglerfishSettings:
        return self._settings

    @property
    def hec_client(self) -> SplunkHECClient | None:
        return self._hec_client

    @property
    def jsonl_sink(self) -> JsonlSink:
        return self._jsonl_sink

    async def submit(self, event: ForwarderEvent) -> ForwardOutcome:
        if self._hec_client is not None:
            try:
                await self._hec_client.submit(event)
            except (HECUnavailableError, HECResponseError) as exc:
                self._logger.warning(
                    "forwarder.hec_failed kind=%s message=%s",
                    type(exc).__name__,
                    exc,
                )
            else:
                return ForwardOutcome.HEC

        record = self._serialise(event)
        try:
            await self._jsonl_sink.write(record)
        except JsonlWriteError as exc:
            self._logger.error(
                "forwarder.jsonl_failed message=%s payload_keys=%s",
                exc,
                sorted(event.event),
            )
            return ForwardOutcome.DROPPED
        return ForwardOutcome.JSONL

    @staticmethod
    def _serialise(event: ForwarderEvent) -> dict[str, Any]:
        return {
            "event": event.event,
            "sourcetype": event.sourcetype,
            "index": event.index,
            "time": event.time.isoformat() if event.time is not None else None,
        }

    async def aclose(self) -> None:
        if self._hec_client is not None:
            await self._hec_client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
