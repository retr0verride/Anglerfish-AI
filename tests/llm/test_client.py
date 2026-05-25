"""Tests for :class:`anglerfish.llm.LLMClient` (Stage 5 foundation slice).

These cover the new surface that bridge.client doesn't: role
selection (fast vs deep) and the ``ChatResult.usage`` parsing of
Ollama's ``prompt_eval_count`` / ``eval_count`` fields. Error
mapping + transport-creation paths are exercised by the
inherited ``tests/bridge/test_client.py`` suite through the
deprecation alias.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest
from pydantic import HttpUrl

from anglerfish.config.models import OllamaConfig
from anglerfish.llm import ChatMessage, LLMClient, LLMRole

_Handler = Callable[[httpx.Request], httpx.Response]


def _mock_client(transport: httpx.MockTransport) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:11434")


def _ok_handler(seen: list[dict[str, object]]) -> _Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.read()))
        return httpx.Response(
            200,
            json={
                "message": {"role": "assistant", "content": "ok"},
                "prompt_eval_count": 42,
                "eval_count": 7,
                "done": True,
            },
        )

    return handler


# ---------------------------------------------------------------------------
# Role selection
# ---------------------------------------------------------------------------


async def test_chat_defaults_to_fast_role() -> None:
    seen: list[dict[str, object]] = []
    client = LLMClient(
        OllamaConfig(fast_model="fast-test:7b", deep_model="deep-test:14b"),
        http_client=_mock_client(httpx.MockTransport(_ok_handler(seen))),
    )
    try:
        await client.chat([ChatMessage(role="user", content="hi")])
    finally:
        await client.aclose()
    assert seen[0]["model"] == "fast-test:7b"


async def test_chat_with_deep_role_picks_deep_model() -> None:
    seen: list[dict[str, object]] = []
    client = LLMClient(
        OllamaConfig(fast_model="fast-test:7b", deep_model="deep-test:14b"),
        http_client=_mock_client(httpx.MockTransport(_ok_handler(seen))),
    )
    try:
        await client.chat(
            [ChatMessage(role="user", content="hi")],
            role=LLMRole.DEEP,
        )
    finally:
        await client.aclose()
    assert seen[0]["model"] == "deep-test:14b"


def test_model_for_unknown_role_raises() -> None:
    """Regression coverage for the fail-loud invariant in model_for().

    LLMRole defines FAST + DEEP today, so the raise is unreachable
    in normal production use. This test exists to catch the
    refactor that silently returns an empty string (or None) when a
    new role is added to the enum without updating model_for(). The
    Stage 8 EMBED addition is the first realistic trigger; until
    then this is a regression guard, not a behavioural assertion.
    """
    from enum import StrEnum

    class _PhantomRole(StrEnum):
        UNKNOWN = "unknown"

    client = LLMClient(OllamaConfig())
    with pytest.raises(ValueError, match="unknown role"):
        client.model_for(_PhantomRole.UNKNOWN)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# ChatResult / TokenUsage
# ---------------------------------------------------------------------------


async def test_chat_returns_result_with_content_and_usage() -> None:
    seen: list[dict[str, object]] = []
    client = LLMClient(
        OllamaConfig(),
        http_client=_mock_client(httpx.MockTransport(_ok_handler(seen))),
    )
    try:
        result = await client.chat([ChatMessage(role="user", content="hi")])
    finally:
        await client.aclose()
    assert result.content == "ok"
    assert result.usage.prompt_tokens == 42
    assert result.usage.completion_tokens == 7


async def test_chat_tolerates_missing_usage_fields() -> None:
    """Some Ollama backends omit prompt_eval_count / eval_count for
    very short prompts; the client must default both to 0 rather than
    raise on missing keys."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"message": {"role": "assistant", "content": "ok"}, "done": True},
        )

    client = LLMClient(
        OllamaConfig(),
        http_client=_mock_client(httpx.MockTransport(handler)),
    )
    try:
        result = await client.chat([ChatMessage(role="user", content="hi")])
    finally:
        await client.aclose()
    assert result.usage.prompt_tokens == 0
    assert result.usage.completion_tokens == 0


async def test_chat_tolerates_non_integer_usage_fields() -> None:
    """If Ollama returns a string/null/negative for usage counts the
    client coerces to 0 rather than propagating the type."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message": {"role": "assistant", "content": "ok"},
                "prompt_eval_count": "not-an-int",
                "eval_count": -5,
                "done": True,
            },
        )

    client = LLMClient(
        OllamaConfig(),
        http_client=_mock_client(httpx.MockTransport(handler)),
    )
    try:
        result = await client.chat([ChatMessage(role="user", content="hi")])
    finally:
        await client.aclose()
    assert result.usage.prompt_tokens == 0
    assert result.usage.completion_tokens == 0


# ---------------------------------------------------------------------------
# Smoke: deprecation alias still works
# ---------------------------------------------------------------------------


def test_bridge_client_alias_resolves_to_llmclient() -> None:
    """The Stage 5 design ships a one-release-cycle deprecation
    alias at anglerfish.bridge.client.OllamaClient. Verify it
    actually points at the new LLMClient class."""
    from anglerfish.bridge.client import OllamaClient as _AliasedClient

    assert _AliasedClient is LLMClient


def test_chat_result_is_frozen() -> None:
    from pydantic import ValidationError

    from anglerfish.llm import ChatResult

    r = ChatResult(content="hi")
    with pytest.raises(ValidationError):
        r.content = "other"  # type: ignore[misc]


def test_config_with_trusted_remote_host_passes_through_to_client() -> None:
    """The host-validation logic on OllamaConfig is unchanged in
    Stage 5; just confirm a non-loopback config remains constructable
    via the trusted_remote_host escape hatch and that the client takes
    it without modification."""
    cfg = OllamaConfig(
        base_url=HttpUrl("http://10.0.0.5:11434/"),
        trusted_remote_host="10.0.0.5",  # type: ignore[arg-type]
    )
    client = LLMClient(cfg)
    assert client.config.fast_model == "qwen3:14b"
