"""Tests for :mod:`anglerfish.integration.cowrie_shell`.

The module is a thin sync wrapper around the bridge's HTTP API used
from Twisted-based Cowrie. We exercise it against an in-process
:class:`httpx.MockTransport` and never touch the network.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest

from anglerfish.integration import cowrie_shell


@pytest.fixture(autouse=True)
def _reset_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Wipe the module-level client and session map before/after each test."""
    cowrie_shell.reset_client_for_tests()
    # Clear env vars that could leak across tests
    for key in (
        "ANGLERFISH_BRIDGE_URL",
        "ANGLERFISH_BRIDGE__SHARED_SECRET",
        "ANGLERFISH_BRIDGE_TIMEOUT_S",
    ):
        monkeypatch.delenv(key, raising=False)
    yield
    cowrie_shell.reset_client_for_tests()


def _install_transport(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[httpx.Request], httpx.Response],
) -> list[httpx.Request]:
    """Patch httpx.Client to use a MockTransport and capture requests."""
    captured: list[httpx.Request] = []

    def _recording_handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return handler(request)

    original = httpx.Client

    def _spy(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs["transport"] = httpx.MockTransport(_recording_handler)
        return original(*args, **kwargs)

    monkeypatch.setattr("anglerfish.integration.cowrie_shell.httpx.Client", _spy)
    return captured


# ---------------------------------------------------------------------------
# open_session
# ---------------------------------------------------------------------------


def test_open_session_returns_bridge_uuid(monkeypatch: pytest.MonkeyPatch) -> None:
    bridge_sid = uuid4()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/session"
        return httpx.Response(
            200,
            json={
                "session_id": str(bridge_sid),
                "fake_hostname": "srv-prod-01",
                "fake_username": "root",
                "fake_cwd": "/root",
            },
        )

    captured = _install_transport(monkeypatch, handler)
    sid = cowrie_shell.open_session(
        "cowrie-abc",
        source_ip="203.0.113.7",
        username="root",
    )
    assert isinstance(sid, UUID)
    assert sid == bridge_sid
    assert len(captured) == 1
    assert captured[0].headers["X-Anglerfish-Protocol"] == "1"


def test_open_session_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    bridge_sid = uuid4()

    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"session_id": str(bridge_sid)})

    captured = _install_transport(monkeypatch, handler)
    a = cowrie_shell.open_session("dup", source_ip="1.1.1.1", username="root")
    b = cowrie_shell.open_session("dup", source_ip="1.1.1.1", username="root")
    assert a == b
    assert len(captured) == 1  # second call did not hit the bridge


def test_open_session_includes_bearer_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANGLERFISH_BRIDGE__SHARED_SECRET", "topsecret-token")

    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"session_id": str(uuid4())})

    captured = _install_transport(monkeypatch, handler)
    cowrie_shell.open_session("x", source_ip="1.1.1.1", username="root")
    assert captured[0].headers["Authorization"] == "Bearer topsecret-token"


def test_open_session_omits_bearer_when_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"session_id": str(uuid4())})

    captured = _install_transport(monkeypatch, handler)
    cowrie_shell.open_session("x", source_ip="1.1.1.1", username="root")
    assert "Authorization" not in captured[0].headers


def test_open_session_network_error_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("nope", request=request)

    _install_transport(monkeypatch, handler)
    with pytest.raises(cowrie_shell.BridgeClientError):
        cowrie_shell.open_session("y", source_ip="1.1.1.1", username="root")


def test_open_session_missing_session_id_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"fake_hostname": "x"})

    _install_transport(monkeypatch, handler)
    with pytest.raises(cowrie_shell.BridgeClientError):
        cowrie_shell.open_session("z", source_ip="1.1.1.1", username="root")


def test_open_session_http_error_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    _install_transport(monkeypatch, handler)
    with pytest.raises(cowrie_shell.BridgeClientError):
        cowrie_shell.open_session("w", source_ip="1.1.1.1", username="root")


# ---------------------------------------------------------------------------
# get_or_open_session
# ---------------------------------------------------------------------------


def test_get_or_open_returns_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    bridge_sid = uuid4()

    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"session_id": str(bridge_sid)})

    captured = _install_transport(monkeypatch, handler)
    a = cowrie_shell.get_or_open_session(
        "c1",
        source_ip="1.1.1.1",
        username="root",
    )
    b = cowrie_shell.get_or_open_session(
        "c1",
        source_ip="1.1.1.1",
        username="root",
    )
    assert a == b
    assert len(captured) == 1


# ---------------------------------------------------------------------------
# submit_command
# ---------------------------------------------------------------------------


def test_submit_command_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    bridge_sid = uuid4()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/session":
            return httpx.Response(200, json={"session_id": str(bridge_sid)})
        assert request.url.path == f"/api/v1/session/{bridge_sid}/command"
        return httpx.Response(
            200,
            json={
                "text": "drwxr-xr-x 2 root root 4096",
                "source": "ai",
                "latency_ms": 12.5,
                "cwd": "/root",
            },
        )

    _install_transport(monkeypatch, handler)
    cowrie_shell.open_session("c", source_ip="1.1.1.1", username="root")
    out = cowrie_shell.submit_command("c", "ls /etc")
    assert out == "drwxr-xr-x 2 root root 4096"


def test_submit_command_unknown_session_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"text": "should-not-arrive"})

    _install_transport(monkeypatch, handler)
    out = cowrie_shell.submit_command("never-opened", "whoami")
    assert out == ""


def test_submit_command_404_evicts_session(monkeypatch: pytest.MonkeyPatch) -> None:
    bridge_sid = uuid4()
    seen = {"open": 0, "cmd": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/session":
            seen["open"] += 1
            return httpx.Response(200, json={"session_id": str(bridge_sid)})
        seen["cmd"] += 1
        return httpx.Response(404)

    _install_transport(monkeypatch, handler)
    cowrie_shell.open_session("e", source_ip="1.1.1.1", username="root")
    out = cowrie_shell.submit_command("e", "ls")
    assert out == ""
    # Next submit should drop through without hitting the network
    out2 = cowrie_shell.submit_command("e", "id")
    assert out2 == ""
    assert seen["cmd"] == 1


def test_submit_command_5xx_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    bridge_sid = uuid4()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/session":
            return httpx.Response(200, json={"session_id": str(bridge_sid)})
        return httpx.Response(503)

    _install_transport(monkeypatch, handler)
    cowrie_shell.open_session("s", source_ip="1.1.1.1", username="root")
    assert cowrie_shell.submit_command("s", "whoami") == ""


def test_submit_command_4xx_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    bridge_sid = uuid4()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/session":
            return httpx.Response(200, json={"session_id": str(bridge_sid)})
        return httpx.Response(401, text="unauthenticated")

    _install_transport(monkeypatch, handler)
    cowrie_shell.open_session("a", source_ip="1.1.1.1", username="root")
    assert cowrie_shell.submit_command("a", "whoami") == ""


def test_submit_command_network_error_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge_sid = uuid4()
    seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/session":
            seen.append(0)
            return httpx.Response(200, json={"session_id": str(bridge_sid)})
        raise httpx.ConnectError("refused", request=request)

    _install_transport(monkeypatch, handler)
    cowrie_shell.open_session("n", source_ip="1.1.1.1", username="root")
    assert cowrie_shell.submit_command("n", "whoami") == ""


def test_submit_command_malformed_json_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge_sid = uuid4()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/session":
            return httpx.Response(200, json={"session_id": str(bridge_sid)})
        return httpx.Response(200, text="not json")

    _install_transport(monkeypatch, handler)
    cowrie_shell.open_session("j", source_ip="1.1.1.1", username="root")
    assert cowrie_shell.submit_command("j", "whoami") == ""


def test_submit_command_non_string_text_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge_sid = uuid4()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/session":
            return httpx.Response(200, json={"session_id": str(bridge_sid)})
        return httpx.Response(200, json={"text": 42})

    _install_transport(monkeypatch, handler)
    cowrie_shell.open_session("k", source_ip="1.1.1.1", username="root")
    assert cowrie_shell.submit_command("k", "whoami") == ""


# ---------------------------------------------------------------------------
# close_session
# ---------------------------------------------------------------------------


def test_close_session_deletes_and_evicts(monkeypatch: pytest.MonkeyPatch) -> None:
    bridge_sid = uuid4()
    deletes: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"session_id": str(bridge_sid)})
        if request.method == "DELETE":
            deletes.append(request)
            return httpx.Response(204)
        return httpx.Response(500)

    _install_transport(monkeypatch, handler)
    cowrie_shell.open_session("d", source_ip="1.1.1.1", username="root")
    cowrie_shell.close_session("d")
    assert len(deletes) == 1
    # second close is a no-op
    cowrie_shell.close_session("d")
    assert len(deletes) == 1


def test_close_session_unknown_is_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _install_transport(monkeypatch, lambda _r: httpx.Response(500))
    cowrie_shell.close_session("nope")
    assert captured == []


def test_close_session_network_error_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge_sid = uuid4()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"session_id": str(bridge_sid)})
        raise httpx.ConnectError("refused", request=request)

    _install_transport(monkeypatch, handler)
    cowrie_shell.open_session("err", source_ip="1.1.1.1", username="root")
    # Must not raise
    cowrie_shell.close_session("err")
