"""Exception hierarchy for the forwarder."""

from __future__ import annotations

__all__ = [
    "ForwarderError",
    "HECResponseError",
    "HECUnavailableError",
    "JsonlWriteError",
]


class ForwarderError(Exception):
    """Base class for all forwarder errors."""


class HECUnavailableError(ForwarderError):
    """Network failure or 5xx response from the Splunk HEC endpoint."""


class HECResponseError(ForwarderError):
    """4xx response or structurally invalid response from Splunk HEC."""


class JsonlWriteError(ForwarderError):
    """Local JSONL fallback file could not be written."""
