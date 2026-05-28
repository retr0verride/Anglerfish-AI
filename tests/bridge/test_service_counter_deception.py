"""Stage 12 slice 12.2: bridge-side counter-deception integration.

Covers the engagement hook (engage_counter_deception via
record_threat_assessment), the per-command prompt amendment
(amend_prompt_for_session), the per-session state lifecycle, and the
cross-session garble-paths lookup the HTTP server uses at session-open.
Lure-side garbling lands in slice 12.3.
"""

from __future__ import annotations

from uuid import uuid4

import httpx
from pydantic import SecretStr

from anglerfish.bridge.client import OllamaClient
from anglerfish.bridge.service import AIBridgeService
from anglerfish.bridge.strategies.counter_deception import (
    ModeAwareCounterDeceptionStrategy,
)
from anglerfish.config import AnglerfishSettings
from anglerfish.config.models import (
    CounterDeceptionConfig,
    CounterDeceptionMode,
    CredentialsConfig,
    DashboardConfig,
    OllamaConfig,
)
from anglerfish.llm.client import ChatMessage
from anglerfish.models.threat import ThreatAssessment


class _MockAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    def record(self, event_type: str, **fields: object) -> None:
        self.events.append((event_type, fields))


def _mock_client() -> OllamaClient:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message": {"content": "ok\n"},
                "done": True,
                "prompt_eval_count": 1,
                "eval_count": 1,
            },
        )

    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(base_url="http://127.0.0.1:11434", transport=transport)
    return OllamaClient(OllamaConfig(), http_client=http)


def _settings(
    *,
    session_secret: str,
    encryption_key_b64: str,
    cd_enabled: bool = True,
    cd_mode: CounterDeceptionMode = CounterDeceptionMode.BOTH,
    cd_threshold: int = 70,
) -> AnglerfishSettings:
    return AnglerfishSettings(
        dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
        counter_deception=CounterDeceptionConfig(
            enabled=cd_enabled,
            mode=cd_mode,
            engagement_threshold=cd_threshold,
            garble_paths=("/root/.ssh/id_rsa", "/root/.aws/credentials"),
            timebomb_cold_to_mild=6,
            timebomb_mild_to_severe=16,
        ),
    )


def _service(
    settings: AnglerfishSettings,
    *,
    audit: _MockAudit | None = None,
    with_strategy: bool = True,
) -> AIBridgeService:
    strategy = (
        ModeAwareCounterDeceptionStrategy(settings.counter_deception) if with_strategy else None
    )
    return AIBridgeService(
        settings,
        client=_mock_client(),
        audit_log=audit,  # type: ignore[arg-type]
        counter_deception_strategy=strategy,
    )


def _threat(score: int) -> ThreatAssessment:
    return ThreatAssessment(
        session_id=uuid4(),
        score=score,
        high_severity=score >= 70,
    )


def _messages() -> list[ChatMessage]:
    return [
        ChatMessage(role="system", content="You are a Linux shell."),
        ChatMessage(role="user", content="ps aux"),
    ]


# ---------------------------------------------------------------------------
# Engagement hook
# ---------------------------------------------------------------------------


async def test_engages_above_threshold(session_secret: str, encryption_key_b64: str) -> None:
    audit = _MockAudit()
    settings = _settings(session_secret=session_secret, encryption_key_b64=encryption_key_b64)
    service = _service(settings, audit=audit)
    sid = uuid4()
    service.record_session_source_ip(sid, "203.0.113.7")
    try:
        service.record_threat_assessment(sid, _threat(75))
    finally:
        await service.aclose()
    assert sid in service._counter_deception_state
    engaged = [e for e in audit.events if e[0] == "bridge.counter_deception_engaged"]
    assert len(engaged) == 1
    _, fields = engaged[0]
    assert fields["mode"] == "both"
    assert fields["threat_score"] == 75
    assert fields["garble_paths_count"] == 2


async def test_does_not_engage_below_threshold(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    audit = _MockAudit()
    settings = _settings(session_secret=session_secret, encryption_key_b64=encryption_key_b64)
    service = _service(settings, audit=audit)
    sid = uuid4()
    service.record_session_source_ip(sid, "203.0.113.7")
    try:
        service.record_threat_assessment(sid, _threat(50))  # below 70
    finally:
        await service.aclose()
    assert sid not in service._counter_deception_state
    assert not any(e[0] == "bridge.counter_deception_engaged" for e in audit.events)


async def test_disabled_short_circuits_even_on_high_threat(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    audit = _MockAudit()
    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        cd_enabled=False,
    )
    service = _service(settings, audit=audit)
    sid = uuid4()
    service.record_session_source_ip(sid, "203.0.113.7")
    try:
        service.record_threat_assessment(sid, _threat(99))
    finally:
        await service.aclose()
    assert sid not in service._counter_deception_state
    assert not any(e[0] == "bridge.counter_deception_engaged" for e in audit.events)


async def test_engagement_is_deduped_per_session(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    """A repeatedly-firing threat scorer engages + audits once per session."""
    audit = _MockAudit()
    settings = _settings(session_secret=session_secret, encryption_key_b64=encryption_key_b64)
    service = _service(settings, audit=audit)
    sid = uuid4()
    service.record_session_source_ip(sid, "203.0.113.7")
    try:
        service.record_threat_assessment(sid, _threat(75))
        service.record_threat_assessment(sid, _threat(88))  # second crossing
        service.record_threat_assessment(sid, _threat(95))  # third crossing
    finally:
        await service.aclose()
    engaged = [e for e in audit.events if e[0] == "bridge.counter_deception_engaged"]
    assert len(engaged) == 1


async def test_end_session_budget_drops_state(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    settings = _settings(session_secret=session_secret, encryption_key_b64=encryption_key_b64)
    service = _service(settings)
    sid = uuid4()
    service.record_session_source_ip(sid, "203.0.113.7")
    try:
        service.record_threat_assessment(sid, _threat(75))
        assert sid in service._counter_deception_state
        service.end_session_budget(sid)
        assert sid not in service._counter_deception_state
        assert sid not in service._counter_deception_engaged_for
    finally:
        await service.aclose()


# ---------------------------------------------------------------------------
# Prompt amendment
# ---------------------------------------------------------------------------


async def test_amend_prompt_noop_when_not_engaged(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    settings = _settings(session_secret=session_secret, encryption_key_b64=encryption_key_b64)
    service = _service(settings)
    try:
        messages = _messages()
        result = service.amend_prompt_for_session(uuid4(), messages, command_count=20)
    finally:
        await service.aclose()
    assert [m.content for m in result] == [m.content for m in messages]


async def test_amend_prompt_mild_band_injects_and_audits(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    audit = _MockAudit()
    settings = _settings(session_secret=session_secret, encryption_key_b64=encryption_key_b64)
    service = _service(settings, audit=audit)
    sid = uuid4()
    service.record_session_source_ip(sid, "203.0.113.7")
    try:
        service.record_threat_assessment(sid, _threat(75))
        messages = _messages()
        result = service.amend_prompt_for_session(sid, messages, command_count=6)
    finally:
        await service.aclose()
    assert len(result) == len(messages) + 1
    assert "ONE small factual error" in result[-1].content
    applied = [e for e in audit.events if e[0] == "bridge.counter_deception_timebomb_applied"]
    assert len(applied) == 1
    assert applied[0][1]["intensity"] == "mild"
    assert applied[0][1]["command_count"] == 6


async def test_amend_prompt_severe_band_injects_and_audits(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    audit = _MockAudit()
    settings = _settings(session_secret=session_secret, encryption_key_b64=encryption_key_b64)
    service = _service(settings, audit=audit)
    sid = uuid4()
    service.record_session_source_ip(sid, "203.0.113.7")
    try:
        service.record_threat_assessment(sid, _threat(75))
        messages = _messages()
        result = service.amend_prompt_for_session(sid, messages, command_count=16)
    finally:
        await service.aclose()
    assert len(result) == len(messages) + 2
    assert "Two to three small factual errors" in result[-1].content
    applied = [e for e in audit.events if e[0] == "bridge.counter_deception_timebomb_applied"]
    assert len(applied) == 1
    assert applied[0][1]["intensity"] == "severe"


async def test_amend_prompt_cold_band_no_audit(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    audit = _MockAudit()
    settings = _settings(session_secret=session_secret, encryption_key_b64=encryption_key_b64)
    service = _service(settings, audit=audit)
    sid = uuid4()
    service.record_session_source_ip(sid, "203.0.113.7")
    try:
        service.record_threat_assessment(sid, _threat(75))
        messages = _messages()
        result = service.amend_prompt_for_session(sid, messages, command_count=0)
    finally:
        await service.aclose()
    assert [m.content for m in result] == [m.content for m in messages]
    assert not any(e[0] == "bridge.counter_deception_timebomb_applied" for e in audit.events)


async def test_garble_mode_skips_timebomb_amendment(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    """mode=GARBLE engages (stashes garble paths) but never amends the
    prompt, even deep into the session."""
    audit = _MockAudit()
    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        cd_mode=CounterDeceptionMode.GARBLE,
    )
    service = _service(settings, audit=audit)
    sid = uuid4()
    service.record_session_source_ip(sid, "203.0.113.7")
    try:
        service.record_threat_assessment(sid, _threat(75))
        messages = _messages()
        result = service.amend_prompt_for_session(sid, messages, command_count=99)
    finally:
        await service.aclose()
    assert [m.content for m in result] == [m.content for m in messages]
    assert not any(e[0] == "bridge.counter_deception_timebomb_applied" for e in audit.events)


# ---------------------------------------------------------------------------
# Cross-session garble-paths lookup (used by the HTTP server at session-open)
# ---------------------------------------------------------------------------


async def test_garble_paths_available_for_source_ip_after_engagement(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    settings = _settings(session_secret=session_secret, encryption_key_b64=encryption_key_b64)
    service = _service(settings)
    sid = uuid4()
    service.record_session_source_ip(sid, "203.0.113.7")
    try:
        # No engagement yet -> empty.
        assert service.get_garble_paths_for_source_ip("203.0.113.7") == ()
        service.record_threat_assessment(sid, _threat(75))
        # After engagement the IP carries the configured garble paths,
        # surviving end_session_budget (cross-session by design).
        service.end_session_budget(sid)
        assert service.get_garble_paths_for_source_ip("203.0.113.7") == (
            "/root/.ssh/id_rsa",
            "/root/.aws/credentials",
        )
    finally:
        await service.aclose()


async def test_no_strategy_wired_is_inert(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    """enabled=True in config but no strategy instance: engagement no-ops."""
    audit = _MockAudit()
    settings = _settings(session_secret=session_secret, encryption_key_b64=encryption_key_b64)
    service = _service(settings, audit=audit, with_strategy=False)
    sid = uuid4()
    service.record_session_source_ip(sid, "203.0.113.7")
    try:
        service.record_threat_assessment(sid, _threat(99))
    finally:
        await service.aclose()
    assert sid not in service._counter_deception_state
    assert not any(e[0] == "bridge.counter_deception_engaged" for e in audit.events)
