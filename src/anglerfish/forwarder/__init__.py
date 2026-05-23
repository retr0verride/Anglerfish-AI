"""Splunk HEC forwarder with a JSONL on-disk fallback.

Public surface:

* :class:`Forwarder` — orchestrator. Wraps the optional HEC client and
  the always-available JSONL sink, returns a :class:`ForwardOutcome`
  for every submission.
* :class:`SplunkHECClient` — async HTTP client for the HEC ``event``
  endpoint.
* :class:`JsonlSink` — append-only JSONL writer with size-based
  rotation.
* :class:`ForwarderEvent` — the event envelope shared by both
  backends.
* :func:`event_from_session_snapshot` — helper that wraps a
  :class:`anglerfish.models.session.SessionSnapshot` for forwarding.
"""

from __future__ import annotations

from anglerfish.forwarder.errors import (
    ForwarderError,
    HECResponseError,
    HECUnavailableError,
    JsonlWriteError,
)
from anglerfish.forwarder.event import ForwarderEvent
from anglerfish.forwarder.factories import event_from_session_snapshot
from anglerfish.forwarder.hec import SplunkHECClient
from anglerfish.forwarder.jsonl import JsonlSink
from anglerfish.forwarder.service import Forwarder, ForwardOutcome

__all__ = [
    "ForwardOutcome",
    "Forwarder",
    "ForwarderError",
    "ForwarderEvent",
    "HECResponseError",
    "HECUnavailableError",
    "JsonlSink",
    "JsonlWriteError",
    "SplunkHECClient",
    "event_from_session_snapshot",
]
