"""Tests for :class:`anglerfish.threat.ThreatAlerter`."""

from __future__ import annotations

import json
from collections.abc import Callable
from uuid import uuid4

import httpx
from pydantic import HttpUrl

from anglerfish.config.models import ThreatConfig
from anglerfish.models.threat import ThreatAssessment, ThreatTechnique
from anglerfish.threat.alerter import ThreatAlerter


def _config(threshold: int = 70, *, webhook: bool = True) -> ThreatConfig:
    return ThreatConfig(
        alert_threshold=threshold,
        alert_webhook_url=HttpUrl("https://hooks.example/anglerfish") if webhook else None,
    )


def _assessment(
    *,
    score: int,
    persistence: bool = False,
    techniques: tuple[ThreatTechnique, ...] = (),
) -> ThreatAssessment:
    return ThreatAssessment(
        session_id=uuid4(),
        score=score,
        techniques=techniques,
        persistence_attempted=persistence,
        high_severity=score >= 70 or persistence,
        notes=(),
    )


def _alerter_with_handler(
    config: ThreatConfig,
    handler: Callable[[httpx.Request], httpx.Response],
) -> ThreatAlerter:
    transport = httpx.MockTransport(handler)
    return ThreatAlerter(config, http_client=httpx.AsyncClient(transport=transport))


def test_should_not_alert_without_webhook() -> None:
    alerter = ThreatAlerter(_config(webhook=False))
    assert alerter.should_alert(_assessment(score=99)) is False


def test_should_not_alert_below_threshold() -> None:
    alerter = ThreatAlerter(_config(threshold=70))
    assert alerter.should_alert(_assessment(score=50)) is False


def test_should_alert_above_threshold() -> None:
    alerter = ThreatAlerter(_config(threshold=70))
    assert alerter.should_alert(_assessment(score=80)) is True


def test_should_alert_on_persistence_regardless_of_score() -> None:
    alerter = ThreatAlerter(_config(threshold=99))
    assert alerter.should_alert(_assessment(score=10, persistence=True)) is True


async def test_maybe_alert_posts_payload() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.read()))
        return httpx.Response(200, text="OK")

    alerter = _alerter_with_handler(_config(), handler)
    assessment = _assessment(
        score=90,
        techniques=(
            ThreatTechnique(id="T1003", name="OS Credential Dumping"),
            ThreatTechnique(id="T1098", name="Account Manipulation"),
        ),
    )
    sent = await alerter.maybe_alert(assessment)
    await alerter.aclose()
    assert sent is True
    assert captured["score"] == 90
    techniques = captured["techniques"]
    assert isinstance(techniques, list)
    technique_ids = [t["id"] for t in techniques]
    assert "T1003" in technique_ids


async def test_maybe_alert_returns_false_on_network_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("nope", request=request)

    alerter = _alerter_with_handler(_config(), handler)
    sent = await alerter.maybe_alert(_assessment(score=90))
    await alerter.aclose()
    assert sent is False


async def test_maybe_alert_returns_false_on_4xx() -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    alerter = _alerter_with_handler(_config(), handler)
    sent = await alerter.maybe_alert(_assessment(score=90))
    await alerter.aclose()
    assert sent is False


async def test_maybe_alert_skipped_when_below_threshold() -> None:
    called = False

    def handler(_r: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    alerter = _alerter_with_handler(_config(threshold=70), handler)
    sent = await alerter.maybe_alert(_assessment(score=50))
    await alerter.aclose()
    assert sent is False
    assert called is False


async def test_maybe_alert_skipped_without_webhook() -> None:
    alerter = ThreatAlerter(_config(webhook=False))
    sent = await alerter.maybe_alert(_assessment(score=99))
    await alerter.aclose()
    assert sent is False


async def test_async_context_manager() -> None:
    async with ThreatAlerter(
        _config(),
        http_client=httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _r: httpx.Response(200)),
        ),
    ) as alerter:
        assert alerter.config.alert_threshold == 70


def test_alerter_owns_client_when_none_provided() -> None:
    alerter = ThreatAlerter(_config())
    assert alerter._client is not None
    # cleanup
    import asyncio

    asyncio.run(alerter.aclose())


def test_alerter_owns_no_client_when_webhook_unset() -> None:
    alerter = ThreatAlerter(_config(webhook=False))
    assert alerter._client is None
