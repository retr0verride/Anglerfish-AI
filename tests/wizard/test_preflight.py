"""Tests for :mod:`anglerfish.wizard.preflight`."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest

from anglerfish.wizard import preflight


@pytest.fixture
def install_mock_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[[Callable[[httpx.Request], httpx.Response]], list[httpx.Request]]:
    """Replace httpx.Client construction with a MockTransport-wrapping one."""

    def _install(handler: Callable[[httpx.Request], httpx.Response]) -> list[httpx.Request]:
        captured: list[httpx.Request] = []

        def _wrap(req: httpx.Request) -> httpx.Response:
            captured.append(req)
            return handler(req)

        original = httpx.Client

        def _spy(*args: Any, **kwargs: Any) -> httpx.Client:
            kwargs["transport"] = httpx.MockTransport(_wrap)
            return original(*args, **kwargs)

        monkeypatch.setattr("anglerfish.wizard.preflight.httpx.Client", _spy)
        return captured

    return _install


# ---------------------------------------------------------------------------
# check_ollama
# ---------------------------------------------------------------------------


def test_ollama_ok(install_mock_transport: Any) -> None:
    captured = install_mock_transport(
        lambda _r: httpx.Response(200, json={"version": "0.1.42"}),
    )
    result = preflight.check_ollama("http://127.0.0.1:11434/")
    assert result.success is True
    assert "0.1.42" in result.detail
    assert captured[0].url.path == "/api/version"


def test_ollama_non_200(install_mock_transport: Any) -> None:
    install_mock_transport(lambda _r: httpx.Response(500, text="boom"))
    result = preflight.check_ollama("http://127.0.0.1:11434/")
    assert result.success is False
    assert "500" in result.detail


def test_ollama_network_error(install_mock_transport: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("nope", request=request)

    install_mock_transport(handler)
    result = preflight.check_ollama("http://127.0.0.1:11434/")
    assert result.success is False
    assert "ConnectError" in result.detail


def test_ollama_malformed_json_still_returns_ok(install_mock_transport: Any) -> None:
    install_mock_transport(lambda _r: httpx.Response(200, text="not json"))
    result = preflight.check_ollama("http://127.0.0.1:11434/")
    assert result.success is True
    assert "unknown" in result.detail


# ---------------------------------------------------------------------------
# check_splunk_hec
# ---------------------------------------------------------------------------


def test_splunk_hec_health_ok(install_mock_transport: Any) -> None:
    captured = install_mock_transport(lambda _r: httpx.Response(200, json={"text": "OK"}))
    result = preflight.check_splunk_hec(
        "https://splunk.test:8088/services/collector/event",
    )
    assert result.success is True
    assert captured[0].url.path == "/services/collector/health/1.0"


def test_splunk_hec_unhealthy(install_mock_transport: Any) -> None:
    install_mock_transport(lambda _r: httpx.Response(503))
    result = preflight.check_splunk_hec(
        "https://splunk.test:8088/services/collector/event",
    )
    assert result.success is False
    assert "503" in result.detail


def test_splunk_hec_connect_error(install_mock_transport: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    install_mock_transport(handler)
    result = preflight.check_splunk_hec("https://splunk.test:8088/services/collector/event")
    assert result.success is False


# ---------------------------------------------------------------------------
# check_webhook
# ---------------------------------------------------------------------------


def test_webhook_ok(install_mock_transport: Any) -> None:
    install_mock_transport(lambda _r: httpx.Response(204))
    result = preflight.check_webhook("https://hooks.example/x")
    assert result.success is True


def test_webhook_405_treated_as_alive(install_mock_transport: Any) -> None:
    install_mock_transport(lambda _r: httpx.Response(405))
    result = preflight.check_webhook("https://hooks.example/x")
    assert result.success is True  # HEAD not allowed but server is up


def test_webhook_5xx_failure(install_mock_transport: Any) -> None:
    install_mock_transport(lambda _r: httpx.Response(503))
    result = preflight.check_webhook("https://hooks.example/x")
    assert result.success is False


def test_webhook_network_error(install_mock_transport: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("nope", request=request)

    install_mock_transport(handler)
    result = preflight.check_webhook("https://hooks.example/x")
    assert result.success is False


# ---------------------------------------------------------------------------
# CheckResult
# ---------------------------------------------------------------------------


def test_check_result_render_ok() -> None:
    cr = preflight.CheckResult(service="ollama", success=True, detail="version 1.0")
    assert "OK" in cr.render()


def test_check_result_render_fail() -> None:
    cr = preflight.CheckResult(service="ollama", success=False, detail="oops")
    assert "FAIL" in cr.render()


# ---------------------------------------------------------------------------
# PreflightChecker
# ---------------------------------------------------------------------------


def test_preflight_runs_only_configured_checks(install_mock_transport: Any) -> None:
    captured = install_mock_transport(
        lambda _r: httpx.Response(200, json={"version": "x"}),
    )
    results = preflight.PreflightChecker().run(
        ollama_url="http://127.0.0.1:11434/",
        splunk_hec_url=None,
        webhook_url=None,
    )
    assert len(results) == 1
    assert results[0].service == "ollama"
    assert len(captured) == 1


def test_preflight_runs_all_three(install_mock_transport: Any) -> None:
    install_mock_transport(lambda _r: httpx.Response(200, json={"version": "x"}))
    results = preflight.PreflightChecker().run(
        ollama_url="http://127.0.0.1:11434/",
        splunk_hec_url="https://splunk.test:8088/services/collector/event",
        webhook_url="https://hooks.example/x",
    )
    assert {r.service for r in results} == {"ollama", "splunk", "webhook"}


def test_preflight_rejects_non_positive_timeout() -> None:
    with pytest.raises(ValueError):
        preflight.PreflightChecker(timeout=0)


def test_preflight_timeout_property() -> None:
    assert preflight.PreflightChecker(timeout=2.5).timeout == 2.5
