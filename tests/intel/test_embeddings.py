"""Tests for :class:`anglerfish.intel.EmbeddingGenerator` (Stage 8 slice 2)."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest

from anglerfish.config.models import OllamaConfig
from anglerfish.intel import EmbeddingGenerator
from anglerfish.intel.embeddings import (
    _DEFAULT_MAX_COMMAND_CHARS,
    _DEFAULT_MIN_COMMANDS,
    _join_commands,
)
from anglerfish.llm import BudgetExhaustedError, LLMClient
from anglerfish.llm.errors import OllamaResponseError, OllamaUnavailableError
from anglerfish.models import CommandTurn, ResponseSource, SessionSnapshot

_Handler = Callable[[httpx.Request], httpx.Response]


def _make_client(handler: _Handler) -> LLMClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:11434")
    return LLMClient(
        OllamaConfig(
            fast_model="fast:7b",
            deep_model="deep:14b",
            embed_model="embed-test",
        ),
        http_client=http,
    )


def _vector_handler(vector: list[float]) -> _Handler:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"embedding": vector})

    return handler


def _snapshot(*, n_commands: int) -> SessionSnapshot:
    now = datetime(2026, 5, 26, 12, 0, tzinfo=UTC)
    turns = tuple(
        CommandTurn(
            command=f"cmd-{i}",
            response=f"output-{i}",
            source=ResponseSource.AI,
            timestamp=now,
            latency_ms=1.0,
        )
        for i in range(n_commands)
    )
    return SessionSnapshot(
        session_id=uuid4(),
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=now,
        last_activity_at=now,
        turns=turns,
    )


# Vector of the minimum schema-allowed dimension (64) for round-trip tests.
_VECTOR_64 = [0.01 * i for i in range(64)]


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


async def test_constructor_rejects_negative_min_commands() -> None:
    client = _make_client(_vector_handler(_VECTOR_64))
    try:
        with pytest.raises(ValueError, match="min_commands"):
            EmbeddingGenerator(client, min_commands=-1)
    finally:
        await client.aclose()


async def test_constructor_rejects_negative_budget() -> None:
    client = _make_client(_vector_handler(_VECTOR_64))
    try:
        with pytest.raises(ValueError, match="budget_cap_tokens"):
            EmbeddingGenerator(client, budget_cap_tokens=-1)
    finally:
        await client.aclose()


async def test_constructor_rejects_zero_max_command_chars() -> None:
    client = _make_client(_vector_handler(_VECTOR_64))
    try:
        with pytest.raises(ValueError, match="max_command_chars"):
            EmbeddingGenerator(client, max_command_chars=0)
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Below-min-commands short-circuit
# ---------------------------------------------------------------------------


async def test_below_min_commands_returns_none_without_calling_ollama() -> None:
    calls = 0

    def handler(_r: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    client = _make_client(handler)
    gen = EmbeddingGenerator(client, min_commands=3)
    try:
        result = await gen.generate(_snapshot(n_commands=2))
    finally:
        await client.aclose()
    assert result is None
    assert calls == 0


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_happy_path_returns_populated_embedding() -> None:
    client = _make_client(_vector_handler(_VECTOR_64))
    gen = EmbeddingGenerator(client)
    snapshot = _snapshot(n_commands=5)
    try:
        embedding = await gen.generate(snapshot)
    finally:
        await client.aclose()
    assert embedding is not None
    assert embedding.session_id == snapshot.session_id
    assert embedding.vector == tuple(_VECTOR_64)
    assert embedding.dimension == 64
    assert embedding.model == "embed-test"
    assert embedding.generated_at.tzinfo is not None


async def test_embed_input_is_joined_commands_only() -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.read()))
        return httpx.Response(200, json={"embedding": _VECTOR_64})

    client = _make_client(handler)
    gen = EmbeddingGenerator(client)
    try:
        await gen.generate(_snapshot(n_commands=3))
    finally:
        await client.aclose()
    body = seen[0]
    assert body["model"] == "embed-test"
    input_text = body["input"]
    assert isinstance(input_text, str)
    assert "cmd-0" in input_text
    assert "cmd-2" in input_text
    # Bridge responses MUST NOT be included.
    assert "output-0" not in input_text
    assert "output-2" not in input_text


async def test_max_command_chars_truncates_oldest_first() -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.read()))
        return httpx.Response(200, json={"embedding": _VECTOR_64})

    client = _make_client(handler)
    # 10 commands each ~6 chars: "cmd-N\n" = 6 chars; total 60. Cap
    # at 30 chars keeps the most-recent 5 commands.
    gen = EmbeddingGenerator(client, max_command_chars=30)
    try:
        await gen.generate(_snapshot(n_commands=10))
    finally:
        await client.aclose()
    text = seen[0]["input"]
    assert isinstance(text, str)
    assert "cmd-9" in text
    assert "cmd-5" in text
    assert "cmd-0" not in text  # oldest dropped


async def test_clock_injection_sets_generated_at() -> None:
    fixed = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
    client = _make_client(_vector_handler(_VECTOR_64))
    gen = EmbeddingGenerator(client, clock=lambda: fixed)
    try:
        embedding = await gen.generate(_snapshot(n_commands=3))
    finally:
        await client.aclose()
    assert embedding is not None
    assert embedding.generated_at == fixed


# ---------------------------------------------------------------------------
# Budget integration
# ---------------------------------------------------------------------------


async def test_zero_budget_raises_budget_exhausted() -> None:
    client = _make_client(_vector_handler(_VECTOR_64))
    gen = EmbeddingGenerator(client, budget_cap_tokens=0)
    try:
        with pytest.raises(BudgetExhaustedError):
            await gen.generate(_snapshot(n_commands=3))
    finally:
        await client.aclose()


async def test_each_call_gets_fresh_budget() -> None:
    """Two back-to-back generate() calls each get a fresh embed budget."""
    client = _make_client(_vector_handler(_VECTOR_64))
    # Tight cap; each call consumes well under it but if budgets leaked
    # across calls the second would BudgetExhaust.
    gen = EmbeddingGenerator(client, budget_cap_tokens=500)
    try:
        _ = await gen.generate(_snapshot(n_commands=3))
        _ = await gen.generate(_snapshot(n_commands=3))
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Failure propagation
# ---------------------------------------------------------------------------


async def test_ollama_unavailable_propagates() -> None:
    client = _make_client(lambda _r: httpx.Response(503, text="overloaded"))
    gen = EmbeddingGenerator(client)
    try:
        with pytest.raises(OllamaUnavailableError):
            await gen.generate(_snapshot(n_commands=3))
    finally:
        await client.aclose()


async def test_ollama_response_error_propagates() -> None:
    client = _make_client(lambda _r: httpx.Response(404, text="not found"))
    gen = EmbeddingGenerator(client)
    try:
        with pytest.raises(OllamaResponseError):
            await gen.generate(_snapshot(n_commands=3))
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_join_commands_drops_oldest_when_over_cap() -> None:
    snapshot = _snapshot(n_commands=4)
    # Each turn renders as "cmd-N\n" = 6 chars; cap 18 keeps the last
    # three (cmd-1, cmd-2, cmd-3).
    text = _join_commands(snapshot.turns, cap=18)
    assert "cmd-1" in text
    assert "cmd-3" in text
    assert "cmd-0" not in text


def test_join_commands_keeps_all_when_under_cap() -> None:
    snapshot = _snapshot(n_commands=3)
    text = _join_commands(snapshot.turns, cap=10_000)
    assert text == "cmd-0\ncmd-1\ncmd-2\n"


def test_join_commands_empty_string_for_zero_cap() -> None:
    snapshot = _snapshot(n_commands=3)
    assert _join_commands(snapshot.turns, cap=0) == ""


def test_module_constants_have_sane_defaults() -> None:
    assert _DEFAULT_MIN_COMMANDS == 3
    assert _DEFAULT_MAX_COMMAND_CHARS == 4096


# ---------------------------------------------------------------------------
# SessionEmbedding model invariants
# ---------------------------------------------------------------------------


def test_session_embedding_rejects_dimension_mismatch() -> None:
    from anglerfish.models import SessionEmbedding

    with pytest.raises(ValueError, match="does not match"):
        SessionEmbedding(
            session_id=uuid4(),
            vector=tuple(_VECTOR_64),
            dimension=128,  # lies about the vector
            model="embed-test",
            generated_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
        )


def test_session_embedding_too_short_vector_rejected() -> None:
    from anglerfish.models import SessionEmbedding

    with pytest.raises(ValueError):
        SessionEmbedding(
            session_id=uuid4(),
            vector=(0.1, 0.2),  # below 64
            dimension=2,
            model="embed-test",
            generated_at=datetime(2026, 5, 26, 12, 0, tzinfo=UTC),
        )
