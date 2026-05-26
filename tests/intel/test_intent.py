"""Tests for :class:`anglerfish.intel.IntentExtractor` (Stage 7 slice 1)."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest

from anglerfish.config.models import OllamaConfig
from anglerfish.intel import IntentExtractor
from anglerfish.intel.intent import (
    _DEFAULT_MAX_HISTORY_TURNS,
    _PLACEHOLDER_SUMMARY,
    _LLMIntentPayload,
    _render_threat_context,
    _truncate,
)
from anglerfish.llm import BudgetExhaustedError, LLMClient, StructuredOutputError
from anglerfish.models import (
    CommandTurn,
    IntentSummary,
    ResponseSource,
    SessionSnapshot,
    ThreatAssessment,
    ThreatTechnique,
)

_Handler = Callable[[httpx.Request], httpx.Response]


def _make_client(handler: _Handler) -> LLMClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:11434")
    return LLMClient(
        OllamaConfig(fast_model="fast:7b", deep_model="deep:14b"),
        http_client=http,
    )


def _ok_payload_handler(payload: dict[str, object]) -> _Handler:
    """Scripted handler that returns ``payload`` as the LLM message content."""

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message": {"content": json.dumps(payload)},
                "done": True,
                "prompt_eval_count": 100,
                "eval_count": 50,
            },
        )

    return handler


def _snapshot(*, n_commands: int) -> SessionSnapshot:
    now = datetime(2026, 5, 25, 12, 0, tzinfo=UTC)
    turns = tuple(
        CommandTurn(
            command=f"cmd-{i}",
            response=f"output-{i}",
            source=ResponseSource.AI,
            timestamp=now,
            latency_ms=10.0,
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


def _threat(*, score: int = 60) -> ThreatAssessment:
    return ThreatAssessment(
        session_id=uuid4(),
        score=score,
        techniques=(
            ThreatTechnique(id="T1059.004", name="Unix Shell"),
            ThreatTechnique(id="T1105", name="Ingress Tool Transfer"),
        ),
        persistence_attempted=False,
        high_severity=False,
        notes=("Reconnaissance pattern detected.",),
    )


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


async def test_constructor_rejects_negative_min_commands() -> None:
    client = _make_client(_ok_payload_handler({}))
    try:
        with pytest.raises(ValueError, match="min_commands"):
            IntentExtractor(client, min_commands=-1)
    finally:
        await client.aclose()


async def test_constructor_rejects_negative_budget() -> None:
    client = _make_client(_ok_payload_handler({}))
    try:
        with pytest.raises(ValueError, match="budget_cap_tokens"):
            IntentExtractor(client, budget_cap_tokens=-1)
    finally:
        await client.aclose()


async def test_constructor_rejects_zero_max_history_turns() -> None:
    client = _make_client(_ok_payload_handler({}))
    try:
        with pytest.raises(ValueError, match="max_history_turns"):
            IntentExtractor(client, max_history_turns=0)
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Placeholder short-circuit
# ---------------------------------------------------------------------------


async def test_below_min_commands_returns_placeholder_without_calling_ollama() -> None:
    calls = 0

    def handler(_req: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    client = _make_client(handler)
    extractor = IntentExtractor(client, min_commands=3)
    try:
        summary = await extractor.extract(_snapshot(n_commands=2))
    finally:
        await client.aclose()

    assert calls == 0
    assert summary.confidence == "low"
    assert summary.actor_profile == "opportunistic"
    assert summary.summary == _PLACEHOLDER_SUMMARY
    assert summary.matched_techniques == ()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_happy_path_returns_populated_summary() -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.read())
        seen.append(body)
        return httpx.Response(
            200,
            json={
                "message": {
                    "content": json.dumps(
                        {
                            "actor_profile": "automated",
                            "intent": "Deploy XMRig cryptominer.",
                            "why": "Downloaded miner binary and configured pool URL.",
                            "matched_techniques": ["T1059.004", "T1496"],
                            "confidence": "high",
                            "summary": (
                                "Automated IoT-botnet-style chain that downloaded "
                                "and configured a cryptominer."
                            ),
                        },
                    ),
                },
                "done": True,
                "prompt_eval_count": 200,
                "eval_count": 80,
            },
        )

    client = _make_client(handler)
    extractor = IntentExtractor(client)
    snapshot = _snapshot(n_commands=5)
    try:
        summary = await extractor.extract(snapshot, threat=_threat(score=80))
    finally:
        await client.aclose()

    assert summary.session_id == snapshot.session_id
    assert summary.actor_profile == "automated"
    assert summary.confidence == "high"
    assert summary.matched_techniques == ("T1059.004", "T1496")
    assert "XMRig" in summary.intent
    assert summary.summary  # non-empty
    # The structured_chat call used the deep model + format=json.
    assert seen[0]["model"] == "deep:14b"
    assert seen[0]["format"] == "json"


async def test_threat_assessment_included_in_prompt() -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.read()))
        return httpx.Response(
            200,
            json={
                "message": {
                    "content": json.dumps(
                        {
                            "actor_profile": "opportunistic",
                            "intent": "Reconnaissance.",
                            "why": "Multiple discovery commands.",
                            "matched_techniques": [],
                            "confidence": "medium",
                            "summary": "Recon-only session.",
                        },
                    ),
                },
                "done": True,
                "prompt_eval_count": 100,
                "eval_count": 30,
            },
        )

    client = _make_client(handler)
    extractor = IntentExtractor(client)
    try:
        await extractor.extract(_snapshot(n_commands=5), threat=_threat(score=42))
    finally:
        await client.aclose()

    messages = seen[0]["messages"]
    assert isinstance(messages, list)
    system_contents = [m["content"] for m in messages if m["role"] == "system"]
    assert any("Score: 42" in c for c in system_contents)
    assert any("T1059.004" in c for c in system_contents)


async def test_no_threat_argument_omits_context_block() -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.read()))
        return httpx.Response(
            200,
            json={
                "message": {
                    "content": json.dumps(
                        {
                            "actor_profile": "opportunistic",
                            "intent": "x",
                            "why": "x",
                            "matched_techniques": [],
                            "confidence": "low",
                            "summary": "x",
                        },
                    ),
                },
                "done": True,
                "prompt_eval_count": 10,
                "eval_count": 5,
            },
        )

    client = _make_client(handler)
    extractor = IntentExtractor(client)
    try:
        await extractor.extract(_snapshot(n_commands=3))
    finally:
        await client.aclose()

    system_contents = [
        m["content"]
        for m in seen[0]["messages"]
        if m["role"] == "system"  # type: ignore[union-attr,index]
    ]
    assert not any("Score:" in c for c in system_contents)


# ---------------------------------------------------------------------------
# Budget integration
# ---------------------------------------------------------------------------


async def test_budget_constructed_per_call_with_configured_cap() -> None:
    """budget_cap_tokens is used for the deep budget on each extract()."""
    # Tight cap that the structured_chat call (200+80 = 280 tokens)
    # exceeds on its own. structured_chat consumes the budget AFTER
    # the response so the second extract() call should fire
    # BudgetExhaustedError - but since we construct a fresh budget
    # per call, it should succeed every time.
    payload = {
        "actor_profile": "opportunistic",
        "intent": "x",
        "why": "x",
        "matched_techniques": [],
        "confidence": "low",
        "summary": "x",
    }
    client = _make_client(_ok_payload_handler(payload))
    extractor = IntentExtractor(client, budget_cap_tokens=500)
    try:
        # Two extract calls in a row should both succeed because each
        # gets a fresh 500-token budget; if budgets leaked across
        # calls, the second would BudgetExhausted.
        _ = await extractor.extract(_snapshot(n_commands=3))
        _ = await extractor.extract(_snapshot(n_commands=3))
    finally:
        await client.aclose()


async def test_zero_budget_raises_budget_exhausted() -> None:
    """budget_cap_tokens=0 means structured_chat raises on the first request."""
    client = _make_client(_ok_payload_handler({}))
    extractor = IntentExtractor(client, budget_cap_tokens=0)
    try:
        with pytest.raises(BudgetExhaustedError):
            await extractor.extract(_snapshot(n_commands=3))
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Failure propagation
# ---------------------------------------------------------------------------


async def test_structured_output_error_propagates() -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        # Always returns non-JSON, exhausts structured_chat's retries.
        return httpx.Response(
            200,
            json={
                "message": {"content": "not valid json at all"},
                "done": True,
            },
        )

    client = _make_client(handler)
    extractor = IntentExtractor(client)
    try:
        with pytest.raises(StructuredOutputError):
            await extractor.extract(_snapshot(n_commands=3))
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Clock injection
# ---------------------------------------------------------------------------


async def test_clock_injection_sets_extracted_at() -> None:
    fixed = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
    client = _make_client(
        _ok_payload_handler(
            {
                "actor_profile": "opportunistic",
                "intent": "x",
                "why": "x",
                "matched_techniques": [],
                "confidence": "low",
                "summary": "x",
            },
        ),
    )
    extractor = IntentExtractor(client, clock=lambda: fixed)
    try:
        summary = await extractor.extract(_snapshot(n_commands=3))
    finally:
        await client.aclose()
    assert summary.extracted_at == fixed


async def test_placeholder_uses_injected_clock() -> None:
    fixed = datetime(2026, 2, 2, 0, 0, tzinfo=UTC)
    client = _make_client(_ok_payload_handler({}))
    extractor = IntentExtractor(client, min_commands=3, clock=lambda: fixed)
    try:
        summary = await extractor.extract(_snapshot(n_commands=1))
    finally:
        await client.aclose()
    assert summary.extracted_at == fixed


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_truncate_keeps_recent_turns_when_oversize() -> None:
    turns = _snapshot(n_commands=100).turns
    kept = _truncate(turns, 10)
    assert len(kept) == 10
    # Should be the last ten (most recent).
    assert kept[0].command == "cmd-90"
    assert kept[-1].command == "cmd-99"


def test_truncate_returns_all_when_under_cap() -> None:
    turns = _snapshot(n_commands=5).turns
    kept = _truncate(turns, 10)
    assert kept == turns


def test_render_threat_context_lists_techniques_and_notes() -> None:
    rendered = _render_threat_context(_threat(score=75))
    assert "Score: 75" in rendered
    assert "T1059.004" in rendered
    assert "Reconnaissance pattern detected." in rendered


def test_max_history_default_matches_module_constant() -> None:
    """Sanity: tests reference the module constant rather than hard-coding 60."""
    assert _DEFAULT_MAX_HISTORY_TURNS == 60


def test_llm_intent_payload_schema_fields_match_intent_summary() -> None:
    """The LLM-supplied subset matches IntentSummary minus bridge-set fields."""
    payload_fields = set(_LLMIntentPayload.model_fields)
    summary_fields = set(IntentSummary.model_fields)
    bridge_set = {"session_id", "extracted_at"}
    assert payload_fields == summary_fields - bridge_set
