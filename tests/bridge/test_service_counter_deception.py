"""Stage 12 slice 12.2: bridge-side counter-deception integration.

Covers the engagement hook (engage_counter_deception via
record_threat_assessment), the per-command prompt amendment
(amend_prompt_for_session), the per-session state lifecycle, and the
cross-session garble-paths lookup the HTTP server uses at session-open.
Lure-side garbling lands in slice 12.3.
"""

from __future__ import annotations

from pathlib import Path
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


# ---------------------------------------------------------------------------
# Operator pins (slice 12.4)
# ---------------------------------------------------------------------------


async def test_apply_pin_force_engages_with_pinned_mode(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    """A garble/both pin force-engages regardless of threat + audits trigger=pin."""
    audit = _MockAudit()
    settings = _settings(session_secret=session_secret, encryption_key_b64=encryption_key_b64)
    service = _service(settings, audit=audit)
    sid = uuid4()
    try:
        service.apply_counter_deception_pin(sid, "203.0.113.7", CounterDeceptionMode.BOTH)
    finally:
        await service.aclose()
    assert sid in service._counter_deception_state
    engaged = [e for e in audit.events if e[0] == "bridge.counter_deception_engaged"]
    assert len(engaged) == 1
    assert engaged[0][1]["trigger"] == "pin"
    assert engaged[0][1]["threat_score"] is None
    # The pin gives the CURRENT session its garble paths immediately.
    assert service.get_garble_paths_for_source_ip("203.0.113.7") == (
        "/root/.ssh/id_rsa",
        "/root/.aws/credentials",
    )


async def test_apply_pin_off_whitelists_session(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    """An OFF pin marks the session engaged (so the threat path skips it) but
    stashes no state and audits nothing - a whitelist."""
    audit = _MockAudit()
    settings = _settings(session_secret=session_secret, encryption_key_b64=encryption_key_b64)
    service = _service(settings, audit=audit)
    sid = uuid4()
    service.record_session_source_ip(sid, "203.0.113.7")
    try:
        service.apply_counter_deception_pin(sid, "203.0.113.7", CounterDeceptionMode.OFF)
        # A subsequent high-threat assessment must NOT engage (whitelisted).
        service.record_threat_assessment(sid, _threat(99))
    finally:
        await service.aclose()
    assert sid not in service._counter_deception_state
    assert sid in service._counter_deception_engaged_for
    assert not any(e[0] == "bridge.counter_deception_engaged" for e in audit.events)


async def test_pin_takes_precedence_over_threat(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    """Once a pin engaged a session, a later threat crossing does not re-engage."""
    audit = _MockAudit()
    settings = _settings(session_secret=session_secret, encryption_key_b64=encryption_key_b64)
    service = _service(settings, audit=audit)
    sid = uuid4()
    service.record_session_source_ip(sid, "203.0.113.7")
    try:
        service.apply_counter_deception_pin(sid, "203.0.113.7", CounterDeceptionMode.TIMEBOMB)
        service.record_threat_assessment(sid, _threat(99))
    finally:
        await service.aclose()
    engaged = [e for e in audit.events if e[0] == "bridge.counter_deception_engaged"]
    assert len(engaged) == 1
    assert engaged[0][1]["trigger"] == "pin"
    assert engaged[0][1]["mode"] == "timebomb"


async def test_apply_pin_inert_without_strategy(
    session_secret: str,
    encryption_key_b64: str,
) -> None:
    service = _service(
        _settings(session_secret=session_secret, encryption_key_b64=encryption_key_b64),
        with_strategy=False,
    )
    sid = uuid4()
    try:
        service.apply_counter_deception_pin(sid, "203.0.113.7", CounterDeceptionMode.BOTH)
    finally:
        await service.aclose()
    assert sid not in service._counter_deception_state


async def test_load_pin_reads_via_reader(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    """load_counter_deception_pin reads the persisted pin via the store reader."""
    from anglerfish.config.models import SessionStoreConfig
    from anglerfish.sessions import SessionStore
    from anglerfish.sessions.reader import SessionStoreReader

    cfg = SessionStoreConfig(database_path=tmp_path / "sessions.db")
    writer = SessionStore(cfg)
    await writer.open()
    await writer.upsert_counter_deception_pin(
        source_ip="203.0.113.7",
        mode=CounterDeceptionMode.GARBLE,
        created_by="op",
    )
    await writer.aclose()

    reader = SessionStoreReader(cfg)
    await reader.open()
    settings = _settings(session_secret=session_secret, encryption_key_b64=encryption_key_b64)
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        counter_deception_strategy=ModeAwareCounterDeceptionStrategy(settings.counter_deception),
        session_store_reader=reader,
    )
    try:
        mode = await service.load_counter_deception_pin("203.0.113.7")
        assert mode is CounterDeceptionMode.GARBLE
        assert await service.load_counter_deception_pin("8.8.8.8") is None
    finally:
        await service.aclose()
        await reader.aclose()


async def test_load_pin_none_when_disabled(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> None:
    """load_counter_deception_pin returns None when CD is globally disabled,
    even if a pin row exists."""
    from anglerfish.config.models import SessionStoreConfig
    from anglerfish.sessions import SessionStore
    from anglerfish.sessions.reader import SessionStoreReader

    cfg = SessionStoreConfig(database_path=tmp_path / "sessions.db")
    writer = SessionStore(cfg)
    await writer.open()
    await writer.upsert_counter_deception_pin(
        source_ip="203.0.113.7",
        mode=CounterDeceptionMode.BOTH,
        created_by="op",
    )
    await writer.aclose()

    reader = SessionStoreReader(cfg)
    await reader.open()
    settings = _settings(
        session_secret=session_secret,
        encryption_key_b64=encryption_key_b64,
        cd_enabled=False,
    )
    service = AIBridgeService(
        settings,
        client=_mock_client(),
        counter_deception_strategy=ModeAwareCounterDeceptionStrategy(settings.counter_deception),
        session_store_reader=reader,
    )
    try:
        assert await service.load_counter_deception_pin("203.0.113.7") is None
    finally:
        await service.aclose()
        await reader.aclose()
