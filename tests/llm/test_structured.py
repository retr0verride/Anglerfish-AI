"""Tests for :meth:`anglerfish.llm.LLMClient.structured_chat` (Stage 5 slice 6)."""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest
from pydantic import BaseModel, Field

from anglerfish.config.models import OllamaConfig
from anglerfish.llm import (
    BudgetExhaustedError,
    ChatMessage,
    LLMClient,
    LLMRole,
    StructuredOutputError,
    TokenBudget,
)

_Handler = Callable[[httpx.Request], httpx.Response]


class _Sample(BaseModel):
    """Pydantic schema the LLM is asked to fill."""

    intent: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)


def _make_client(handler: _Handler) -> LLMClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:11434")
    return LLMClient(
        OllamaConfig(fast_model="fast:7b", deep_model="deep:14b"),
        http_client=http,
    )


def _scripted_responses(payloads: list[str], usage_tokens: int = 10) -> _Handler:
    """Return a handler that emits ``payloads`` in order, one per call."""
    seen_requests: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.read())
        seen_requests.append(body)
        idx = len(seen_requests) - 1
        if idx >= len(payloads):
            return httpx.Response(500)
        return httpx.Response(
            200,
            json={
                "message": {"role": "assistant", "content": payloads[idx]},
                "prompt_eval_count": usage_tokens,
                "eval_count": 0,
                "done": True,
            },
        )

    handler.seen = seen_requests  # type: ignore[attr-defined]
    return handler


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_structured_chat_first_attempt_success() -> None:
    handler = _scripted_responses(['{"intent": "discover", "confidence": 0.9}'])
    client = _make_client(handler)
    try:
        result = await client.structured_chat(
            [ChatMessage(role="user", content="summarise")],
            _Sample,
        )
    finally:
        await client.aclose()

    assert isinstance(result, _Sample)
    assert result.intent == "discover"
    assert result.confidence == pytest.approx(0.9)


async def test_structured_chat_defaults_to_deep_role() -> None:
    handler = _scripted_responses(['{"intent": "x", "confidence": 0.1}'])
    client = _make_client(handler)
    try:
        await client.structured_chat(
            [ChatMessage(role="user", content="summarise")],
            _Sample,
        )
    finally:
        await client.aclose()
    seen = handler.seen  # type: ignore[attr-defined]
    assert seen[0]["model"] == "deep:14b"
    assert seen[0]["format"] == "json"


async def test_structured_chat_role_override_uses_fast_model() -> None:
    handler = _scripted_responses(['{"intent": "x", "confidence": 0.1}'])
    client = _make_client(handler)
    try:
        await client.structured_chat(
            [ChatMessage(role="user", content="x")],
            _Sample,
            role=LLMRole.FAST,
        )
    finally:
        await client.aclose()
    seen = handler.seen  # type: ignore[attr-defined]
    assert seen[0]["model"] == "fast:7b"


# ---------------------------------------------------------------------------
# Retry + recovery
# ---------------------------------------------------------------------------


async def test_structured_chat_retries_on_invalid_json() -> None:
    handler = _scripted_responses(
        [
            "this is not json at all",
            '{"intent": "scan", "confidence": 0.5}',
        ],
    )
    client = _make_client(handler)
    try:
        result = await client.structured_chat(
            [ChatMessage(role="user", content="x")],
            _Sample,
            max_retries=2,
        )
    finally:
        await client.aclose()
    assert result.intent == "scan"
    seen = handler.seen  # type: ignore[attr-defined]
    assert len(seen) == 2
    # The retry includes a correction message.
    second_request_msgs = seen[1]["messages"]
    assert any(
        "could not be parsed" in m["content"]
        for m in second_request_msgs  # type: ignore[union-attr]
    )


async def test_structured_chat_retries_on_validation_error() -> None:
    """First response is valid JSON but fails the schema; second succeeds."""
    handler = _scripted_responses(
        [
            '{"intent": "", "confidence": 2.5}',  # both fields invalid
            '{"intent": "recon", "confidence": 0.7}',
        ],
    )
    client = _make_client(handler)
    try:
        result = await client.structured_chat(
            [ChatMessage(role="user", content="x")],
            _Sample,
            max_retries=1,
        )
    finally:
        await client.aclose()
    assert result.intent == "recon"
    seen = handler.seen  # type: ignore[attr-defined]
    assert len(seen) == 2
    # The second request includes the offending assistant message in
    # context so the model can self-correct.
    msgs = seen[1]["messages"]
    assert any(m["role"] == "assistant" for m in msgs)  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


async def test_structured_chat_exhausted_retries_raises() -> None:
    handler = _scripted_responses(
        [
            "not json",
            "still not json",
            "nope",
        ],
    )
    client = _make_client(handler)
    try:
        with pytest.raises(StructuredOutputError, match="after 3 attempt"):
            await client.structured_chat(
                [ChatMessage(role="user", content="x")],
                _Sample,
                max_retries=2,
            )
    finally:
        await client.aclose()


async def test_structured_chat_zero_retries_raises_after_first_fail() -> None:
    handler = _scripted_responses(["not json"])
    client = _make_client(handler)
    try:
        with pytest.raises(StructuredOutputError, match="after 1 attempt"):
            await client.structured_chat(
                [ChatMessage(role="user", content="x")],
                _Sample,
                max_retries=0,
            )
    finally:
        await client.aclose()


async def test_structured_chat_negative_max_retries_rejected() -> None:
    client = _make_client(_scripted_responses([]))
    try:
        with pytest.raises(ValueError, match="max_retries must be >= 0"):
            await client.structured_chat(
                [ChatMessage(role="user", content="x")],
                _Sample,
                max_retries=-1,
            )
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Budget integration
# ---------------------------------------------------------------------------


async def test_structured_chat_consumes_budget_per_attempt() -> None:
    handler = _scripted_responses(
        ["not json", '{"intent": "x", "confidence": 0.5}'],
        usage_tokens=10,
    )
    client = _make_client(handler)
    budget = TokenBudget(deep_token_cap=100)
    try:
        await client.structured_chat(
            [ChatMessage(role="user", content="x")],
            _Sample,
            budget=budget,
            max_retries=1,
        )
    finally:
        await client.aclose()
    assert budget.consumed_deep == 20  # 10 per attempt, 2 attempts


async def test_structured_chat_budget_exhausted_before_first_attempt() -> None:
    handler = _scripted_responses(['{"intent": "x", "confidence": 0.5}'])
    client = _make_client(handler)
    budget = TokenBudget(deep_token_cap=0)
    try:
        with pytest.raises(BudgetExhaustedError):
            await client.structured_chat(
                [ChatMessage(role="user", content="x")],
                _Sample,
                budget=budget,
            )
    finally:
        await client.aclose()
    assert handler.seen == []  # type: ignore[attr-defined]


async def test_structured_chat_schema_injected_into_system_message() -> None:
    handler = _scripted_responses(['{"intent": "x", "confidence": 0.5}'])
    client = _make_client(handler)
    try:
        await client.structured_chat(
            [ChatMessage(role="user", content="hi")],
            _Sample,
        )
    finally:
        await client.aclose()
    seen = handler.seen  # type: ignore[attr-defined]
    msgs = seen[0]["messages"]
    # Last message is the schema-bearing system instruction.
    assert msgs[-1]["role"] == "system"  # type: ignore[index]
    assert "JSON object" in msgs[-1]["content"]  # type: ignore[index]
    assert "confidence" in msgs[-1]["content"]  # type: ignore[index]
