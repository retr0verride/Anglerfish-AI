"""Tests for :class:`anglerfish.threat.ThreatEngine`."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import httpx
from pydantic import HttpUrl

from anglerfish.config import AnglerfishSettings
from anglerfish.config.models import ThreatConfig
from anglerfish.models.session import CommandTurn, ResponseSource, SessionSnapshot
from anglerfish.threat import ThreatAlerter, ThreatEngine


def _snapshot(*commands: str) -> SessionSnapshot:
    ts = datetime(2026, 5, 22, tzinfo=UTC)
    turns = tuple(
        CommandTurn(
            command=c,
            response="",
            source=ResponseSource.AI,
            timestamp=ts,
            latency_ms=1.0,
        )
        for c in commands
    )
    return SessionSnapshot(
        session_id=uuid4(),
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=ts,
        last_activity_at=ts,
        turns=turns,
    )


def _settings_with_threat_webhook(
    base: AnglerfishSettings,
    *,
    webhook: HttpUrl | None,
    threshold: int = 70,
) -> AnglerfishSettings:
    return base.model_copy(
        update={"threat": ThreatConfig(alert_threshold=threshold, alert_webhook_url=webhook)},
    )


def test_engine_assess_is_pure(settings: AnglerfishSettings) -> None:
    engine = ThreatEngine(settings, alerter=ThreatAlerter(settings.threat))
    a = engine.assess(_snapshot("whoami", "ls"))
    b = engine.assess(_snapshot("whoami", "ls"))
    # Different snapshots, same commands → same score
    assert a.score == b.score


async def test_engine_process_calls_alerter_for_high_severity(
    settings: AnglerfishSettings,
) -> None:
    sent_payloads: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent_payloads.append(request.read())
        return httpx.Response(200)

    cfg_with_webhook = _settings_with_threat_webhook(
        settings,
        webhook=HttpUrl("https://hooks.example/x"),
    )
    alerter = ThreatAlerter(
        cfg_with_webhook.threat,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    engine = ThreatEngine(cfg_with_webhook, alerter=alerter)
    try:
        a = await engine.process(_snapshot("useradd -m attacker"))
    finally:
        await engine.aclose()
    assert a.persistence_attempted is True
    assert len(sent_payloads) == 1


async def test_engine_process_skips_alert_for_low_score(
    settings: AnglerfishSettings,
) -> None:
    called = False

    def handler(_r: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    cfg = _settings_with_threat_webhook(
        settings,
        webhook=HttpUrl("https://hooks.example/x"),
        threshold=99,
    )
    alerter = ThreatAlerter(
        cfg.threat,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    engine = ThreatEngine(cfg, alerter=alerter)
    try:
        await engine.process(_snapshot("ls"))
    finally:
        await engine.aclose()
    assert called is False


def test_engine_properties_expose_config(settings: AnglerfishSettings) -> None:
    alerter = ThreatAlerter(settings.threat)
    engine = ThreatEngine(settings, alerter=alerter)
    assert engine.settings is settings
    assert engine.alerter is alerter
    assert engine.rules  # default rule set populated


async def test_engine_async_context_manager(settings: AnglerfishSettings) -> None:
    async with ThreatEngine(settings) as engine:
        a = engine.assess(_snapshot("ls"))
    assert a.score >= 0
