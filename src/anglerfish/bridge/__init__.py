"""Anglerfish AI bridge — the LLM middleware that drives the fake shell.

Public surface:

- :class:`AIBridgeService` — orchestrates sanitisation, prompting,
  rate-limiting, the LLM call, fallback selection, and session
  recording.
- :class:`LLMClient` — typed async chat client; new code imports it
  from :mod:`anglerfish.llm` directly. ``OllamaClient`` survives
  here as a one-release-cycle deprecation alias.
- :class:`SessionContext` — per-attacker shell state (cwd, history).
- :class:`BridgeRateLimiter` — combined global concurrency cap and
  per-session token bucket.
- :func:`create_bridge_app` — FastAPI app factory exposing the
  bridge service over HTTP for the lure to consume.

Errors raised by the bridge are exported from
:mod:`anglerfish.bridge.errors`.
"""

from __future__ import annotations

from anglerfish.bridge.errors import (
    BridgeError,
    GlobalQueueTimeoutError,
    OllamaResponseError,
    OllamaUnavailableError,
    SessionRateLimitedError,
)
from anglerfish.bridge.fallback import fallback_response
from anglerfish.bridge.prompts import build_messages, build_system_prompt
from anglerfish.bridge.rate_limit import BridgeRateLimiter, TokenBucket
from anglerfish.bridge.sanitize import cap_output, sanitize_command
from anglerfish.bridge.server import (
    CommandRequest,
    CommandResponse,
    SessionStartRequest,
    SessionStartResponse,
    create_bridge_app,
)
from anglerfish.bridge.service import AIBridgeService
from anglerfish.bridge.session import SessionContext

# anglerfish.llm.client imports from anglerfish.bridge.errors, so
# pulling LLMClient through the anglerfish.bridge.client deprecation
# shim would re-enter this package init mid-load. Source from the
# new home directly.
from anglerfish.llm import ChatMessage, LLMClient

# Stage 5 deprecation alias — remove with anglerfish.bridge.client
# in the next release.
OllamaClient = LLMClient

__all__ = [
    "AIBridgeService",
    "BridgeError",
    "BridgeRateLimiter",
    "ChatMessage",
    "CommandRequest",
    "CommandResponse",
    "GlobalQueueTimeoutError",
    "LLMClient",
    "OllamaClient",
    "OllamaResponseError",
    "OllamaUnavailableError",
    "SessionContext",
    "SessionRateLimitedError",
    "SessionStartRequest",
    "SessionStartResponse",
    "TokenBucket",
    "build_messages",
    "build_system_prompt",
    "cap_output",
    "create_bridge_app",
    "fallback_response",
    "sanitize_command",
]
