"""Stage 13 slice 13.5: NarratorService unit tests."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest

from anglerfish.audit import AuditLog
from anglerfish.bridge.defense import OutputFilter
from anglerfish.config.models import DefenseConfig, NarratorConfig
from anglerfish.dashboard.narrator import NarratorService
from anglerfish.dashboard.state import DashboardEventKind, DashboardState
from anglerfish.llm import ChatMessage, ChatResult, LLMClient, LLMRole, TokenBudget, TokenUsage
from anglerfish.llm.errors import OllamaUnavailableError
from anglerfish.models import CommandTurn, ResponseSource, SessionSnapshot

_AT = datetime(2026, 5, 29, 12, 0, tzinfo=UTC)


class _FakeClient:
    """Records chat calls and returns a canned result (or raises)."""

    def __init__(
        self, *, content: str = "Attacker is sweeping cron.", error: Exception | None = None
    ) -> None:
        self.calls: list[tuple[Sequence[ChatMessage], LLMRole]] = []
        self._content = content
        self._error = error

    async def chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        role: LLMRole = LLMRole.FAST,
        budget: TokenBudget | None = None,  # noqa: ARG002 - matches LLMClient.chat
    ) -> ChatResult:
        self.calls.append((messages, role))
        if self._error is not None:
            raise self._error
        return ChatResult(
            content=self._content,
            usage=TokenUsage(prompt_tokens=5, completion_tokens=7),
        )

    def model_for(self, role: LLMRole) -> str:
        return "qwen3:14b" if role is LLMRole.FAST else "phi-4"


def _service(
    state: DashboardState,
    audit: AuditLog,
    client: _FakeClient,
    *,
    enabled: bool = True,
    config: NarratorConfig | None = None,
) -> NarratorService:
    return NarratorService(
        state=state,
        client=cast("LLMClient", client),
        output_filter=OutputFilter(DefenseConfig()),
        audit=audit,
        config=config or NarratorConfig(),
        is_enabled=lambda: enabled,
        now=lambda: _AT,
    )


async def _seed_session(state: DashboardState, *, turns: int = 1) -> SessionSnapshot:
    snap = SessionSnapshot(
        session_id=uuid4(),
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv",
        fake_username="root",
        fake_cwd="/root",
        started_at=_AT,
        last_activity_at=_AT,
        turns=tuple(
            CommandTurn(
                command=f"cmd{i}",
                response=f"out{i}",
                source=ResponseSource.AI,
                timestamp=_AT,
                latency_ms=1.0,
            )
            for i in range(turns)
        ),
    )
    await state.update_session(snap)
    return snap


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


async def test_disabled_tick_is_noop(dashboard_state: DashboardState, audit: AuditLog) -> None:
    await _seed_session(dashboard_state)
    client = _FakeClient()
    service = _service(dashboard_state, audit, client, enabled=False)
    await service._narrate_tick()
    assert client.calls == []
    assert not audit.path.exists() or audit.path.read_text() == ""


async def test_successful_tick_broadcasts_and_audits(
    dashboard_state: DashboardState, audit: AuditLog
) -> None:
    snap = await _seed_session(dashboard_state)
    client = _FakeClient(content="Attacker is enumerating cron and systemd.")
    service = _service(dashboard_state, audit, client)
    async with dashboard_state.subscribe() as queue:
        await service._narrate_tick()
        event = queue.get_nowait()
    assert event.kind is DashboardEventKind.NARRATOR
    assert event.payload["session_id"] == str(snap.session_id)
    assert event.payload["text"] == "Attacker is enumerating cron and systemd."
    assert event.payload["model"] == "qwen3:14b"
    text = audit.path.read_text(encoding="utf-8")
    assert '"event_type":"narrator.commentary_generated"' in text
    assert '"tokens":12' in text


async def test_output_filter_fire_drops_text(
    dashboard_state: DashboardState, audit: AuditLog
) -> None:
    await _seed_session(dashboard_state)
    client = _FakeClient(content="I am an AI language model running in a honeypot.")
    service = _service(dashboard_state, audit, client)
    async with dashboard_state.subscribe() as queue:
        await service._narrate_tick()
        assert queue.empty()  # nothing broadcast
    text = audit.path.read_text(encoding="utf-8")
    assert '"event_type":"narrator.defense_fired"' in text
    assert "commentary_generated" not in text


async def test_llm_error_audits_generation_failed(
    dashboard_state: DashboardState, audit: AuditLog
) -> None:
    await _seed_session(dashboard_state)
    client = _FakeClient(error=OllamaUnavailableError("ollama down"))
    service = _service(dashboard_state, audit, client)
    async with dashboard_state.subscribe() as queue:
        await service._narrate_tick()
        assert queue.empty()
    text = audit.path.read_text(encoding="utf-8")
    assert '"event_type":"narrator.generation_failed"' in text


async def test_empty_generation_audits_failed(
    dashboard_state: DashboardState, audit: AuditLog
) -> None:
    await _seed_session(dashboard_state)
    client = _FakeClient(content="   ")
    service = _service(dashboard_state, audit, client)
    async with dashboard_state.subscribe() as queue:
        await service._narrate_tick()
        assert queue.empty()
    assert '"event_type":"narrator.generation_failed"' in audit.path.read_text(encoding="utf-8")


async def test_prompt_bounded_by_max_turns(
    dashboard_state: DashboardState, audit: AuditLog
) -> None:
    await _seed_session(dashboard_state, turns=20)
    client = _FakeClient()
    service = _service(dashboard_state, audit, client, config=NarratorConfig(max_turns_in_prompt=2))
    await service._narrate_tick()
    messages, _role = client.calls[0]
    # system prompt + (2 turns * 2 messages) + final ask = 6
    assert len(messages) == 6
    commands = [m.content for m in messages if m.role == "user" and m.content.startswith("cmd")]
    assert commands == ["cmd18", "cmd19"]  # the two most recent, oldest dropped


async def test_max_sessions_per_tick_bounds_calls(
    dashboard_state: DashboardState, audit: AuditLog
) -> None:
    for _ in range(3):
        await _seed_session(dashboard_state)
    client = _FakeClient()
    service = _service(
        dashboard_state, audit, client, config=NarratorConfig(max_sessions_per_tick=2)
    )
    await service._narrate_tick()
    assert len(client.calls) == 2


async def test_fast_role_used_by_default(dashboard_state: DashboardState, audit: AuditLog) -> None:
    await _seed_session(dashboard_state)
    client = _FakeClient()
    service = _service(dashboard_state, audit, client)
    await service._narrate_tick()
    _messages, role = client.calls[0]
    assert role is LLMRole.FAST


async def test_deep_role_when_configured(dashboard_state: DashboardState, audit: AuditLog) -> None:
    await _seed_session(dashboard_state)
    client = _FakeClient()
    service = _service(dashboard_state, audit, client, config=NarratorConfig(model_role="deep"))
    await service._narrate_tick()
    _messages, role = client.calls[0]
    assert role is LLMRole.DEEP


async def test_intent_summary_included_in_prompt(
    dashboard_state: DashboardState, audit: AuditLog
) -> None:
    from anglerfish.models.intent import IntentSummary

    snap = await _seed_session(dashboard_state)
    await dashboard_state.upsert_intent(
        IntentSummary(
            session_id=snap.session_id,
            actor_profile="opportunistic",
            intent="cryptojacking",
            why="deployed a miner",
            matched_techniques=("T1496",),
            confidence="high",
            summary="UNIQUEINTENTBLURB",
            extracted_at=_AT,
        ),
    )
    client = _FakeClient()
    service = _service(dashboard_state, audit, client)
    await service._narrate_tick()
    messages, _role = client.calls[0]
    assert any("UNIQUEINTENTBLURB" in m.content for m in messages)


async def test_background_loop_runs_then_stops(
    dashboard_state: DashboardState, audit: AuditLog
) -> None:
    import asyncio

    await _seed_session(dashboard_state)
    client = _FakeClient()
    service = _service(dashboard_state, audit, client)
    await service.start()
    try:
        # The first tick runs before the inter-tick sleep; poll until it lands.
        for _ in range(100):
            if client.calls:
                break
            await asyncio.sleep(0.01)
    finally:
        await service.stop()
    assert client.calls  # the loop executed a tick
    await service.stop()  # idempotent second stop is a no-op
