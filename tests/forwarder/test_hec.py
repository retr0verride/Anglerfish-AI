"""Tests for :class:`anglerfish.forwarder.SplunkHECClient`."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC

import httpx
import pytest
from pydantic import HttpUrl, SecretStr

from anglerfish.config.models import SplunkConfig
from anglerfish.forwarder.errors import HECResponseError, HECUnavailableError
from anglerfish.forwarder.event import ForwarderEvent
from anglerfish.forwarder.hec import SplunkHECClient


def _enabled_config() -> SplunkConfig:
    return SplunkConfig(
        enabled=True,
        hec_url=HttpUrl("https://splunk.test:8088/services/collector/event"),
        hec_token=SecretStr("test-token"),
    )


def _client_with_handler(
    config: SplunkConfig,
    handler: Callable[[httpx.Request], httpx.Response],
) -> SplunkHECClient:
    transport = httpx.MockTransport(handler)
    headers: dict[str, str] = {}
    if config.hec_token is not None:
        headers["Authorization"] = f"Splunk {config.hec_token.get_secret_value()}"
    http = httpx.AsyncClient(transport=transport, headers=headers)
    return SplunkHECClient(config, http_client=http)


def test_constructor_rejects_disabled_config() -> None:
    with pytest.raises(ValueError):
        SplunkHECClient(SplunkConfig(enabled=False))


def test_constructor_rejects_missing_url_or_token() -> None:
    # Bypass model_validator by using construct (still hits our own check).
    cfg = SplunkConfig.model_construct(enabled=True, hec_url=None, hec_token=None)
    with pytest.raises(ValueError):
        SplunkHECClient(cfg)


async def test_submit_posts_to_configured_endpoint() -> None:
    seen_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_requests.append(request)
        return httpx.Response(200, json={"text": "Success", "code": 0})

    cfg = _enabled_config()
    client = _client_with_handler(cfg, handler)
    try:
        await client.submit(ForwarderEvent(event={"command": "whoami"}))
    finally:
        await client.aclose()
    assert len(seen_requests) == 1
    assert seen_requests[0].url == httpx.URL(
        "https://splunk.test:8088/services/collector/event",
    )
    body = json.loads(seen_requests[0].read())
    assert body["event"] == {"command": "whoami"}
    assert body["sourcetype"] == cfg.sourcetype
    assert body["index"] == cfg.index


async def test_submit_overrides_sourcetype_and_index() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.read()))
        return httpx.Response(200, json={"text": "Success", "code": 0})

    client = _client_with_handler(_enabled_config(), handler)
    try:
        await client.submit(
            ForwarderEvent(
                event={"x": 1},
                sourcetype="anglerfish:threat",
                index="threat-intel",
            ),
        )
    finally:
        await client.aclose()
    assert captured["sourcetype"] == "anglerfish:threat"
    assert captured["index"] == "threat-intel"


async def test_submit_5xx_is_unavailable() -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="overloaded")

    client = _client_with_handler(_enabled_config(), handler)
    with pytest.raises(HECUnavailableError):
        await client.submit(ForwarderEvent(event={"x": 1}))
    await client.aclose()


async def test_submit_4xx_is_response_error() -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    client = _client_with_handler(_enabled_config(), handler)
    with pytest.raises(HECResponseError):
        await client.submit(ForwarderEvent(event={"x": 1}))
    await client.aclose()


async def test_submit_network_error_is_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = _client_with_handler(_enabled_config(), handler)
    with pytest.raises(HECUnavailableError):
        await client.submit(ForwarderEvent(event={"x": 1}))
    await client.aclose()


async def test_submit_hec_application_error() -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"text": "Invalid token", "code": 4})

    client = _client_with_handler(_enabled_config(), handler)
    with pytest.raises(HECResponseError):
        await client.submit(ForwarderEvent(event={"x": 1}))
    await client.aclose()


async def test_submit_ignores_non_json_success_body() -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="OK")

    client = _client_with_handler(_enabled_config(), handler)
    # Should not raise — non-JSON 2xx body is accepted as success.
    await client.submit(ForwarderEvent(event={"x": 1}))
    await client.aclose()


async def test_submit_attaches_time_when_provided() -> None:
    from datetime import datetime

    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.read()))
        return httpx.Response(200, json={"text": "Success", "code": 0})

    client = _client_with_handler(_enabled_config(), handler)
    when = datetime(2026, 5, 22, 12, 34, 56, tzinfo=UTC)
    await client.submit(ForwarderEvent(event={"x": 1}, time=when))
    await client.aclose()
    assert captured["time"] == pytest.approx(when.timestamp())


async def test_client_creates_own_transport_when_none_provided() -> None:
    client = SplunkHECClient(_enabled_config())
    try:
        assert client.endpoint.endswith("/services/collector/event")
        assert client.config.enabled is True
    finally:
        await client.aclose()


async def test_async_context_manager() -> None:
    async with SplunkHECClient(
        _enabled_config(),
        http_client=httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _r: httpx.Response(200, json={"code": 0}),
            ),
        ),
    ) as client:
        await client.submit(ForwarderEvent(event={"x": 1}))
