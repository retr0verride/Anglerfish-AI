"""Tests for :class:`anglerfish.lure.bridge_client.BridgeClient`."""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID, uuid4

import httpx
import pytest
from pydantic import HttpUrl

from anglerfish.lure.bridge_client import (
    PROTOCOL_VERSION_HEADER,
    BridgeClient,
    BridgeUnavailableError,
)

_TEST_SECRET = "test-secret"


def _client_with(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    secret: str | None = _TEST_SECRET,
) -> BridgeClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(
        base_url="http://127.0.0.1:8421",
        transport=transport,
    )
    return BridgeClient(
        base_url=HttpUrl("http://127.0.0.1:8421/"),
        shared_secret=secret,
        request_timeout_s=5.0,
        connect_timeout_s=1.0,
        http_client=http,
    )


# ---------------------------------------------------------------------------
# open_session
# ---------------------------------------------------------------------------


async def test_open_session_returns_uuid() -> None:
    expected = uuid4()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/session"
        assert request.headers[PROTOCOL_VERSION_HEADER] == "2"
        assert request.headers["Authorization"] == "Bearer test-secret"
        return httpx.Response(200, json={"session_id": str(expected)})

    client = _client_with(handler)
    try:
        sid = await client.open_session(source_ip="203.0.113.7", username="root")
    finally:
        await client.aclose()
    assert sid == expected


async def test_open_session_trims_oversize_username() -> None:
    captured: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        captured.append(json.loads(request.read()))
        return httpx.Response(200, json={"session_id": str(uuid4())})

    client = _client_with(handler)
    try:
        await client.open_session(source_ip="1.1.1.1", username="a" * 200)
    finally:
        await client.aclose()
    assert len(captured[0]["username"]) == 64


async def test_open_session_defaults_empty_username_to_root() -> None:
    captured: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        captured.append(json.loads(request.read()))
        return httpx.Response(200, json={"session_id": str(uuid4())})

    client = _client_with(handler)
    try:
        await client.open_session(source_ip="1.1.1.1", username="")
    finally:
        await client.aclose()
    assert captured[0]["username"] == "root"


async def test_open_session_rejects_empty_source_ip() -> None:
    client = _client_with(lambda _r: httpx.Response(200))
    try:
        with pytest.raises(ValueError, match="source_ip"):
            await client.open_session(source_ip="", username="root")
    finally:
        await client.aclose()


async def test_open_session_missing_session_id_raises() -> None:
    client = _client_with(lambda _r: httpx.Response(200, json={}))
    try:
        with pytest.raises(BridgeUnavailableError, match="session_id"):
            await client.open_session(source_ip="1.1.1.1", username="root")
    finally:
        await client.aclose()


async def test_open_session_non_uuid_raises() -> None:
    client = _client_with(
        lambda _r: httpx.Response(200, json={"session_id": "not-a-uuid"}),
    )
    try:
        with pytest.raises(BridgeUnavailableError, match="non-UUID"):
            await client.open_session(source_ip="1.1.1.1", username="root")
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# submit_command
# ---------------------------------------------------------------------------


async def test_submit_command_returns_text() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "/command" in request.url.path
        return httpx.Response(200, json={"text": "drwxr-xr-x"})

    client = _client_with(handler)
    try:
        out = await client.submit_command(uuid4(), "ls")
    finally:
        await client.aclose()
    assert out == "drwxr-xr-x"


async def test_submit_command_sends_fs_context_when_present() -> None:
    captured: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        captured.append(json.loads(request.read()))
        return httpx.Response(200, json={"text": "ok"})

    client = _client_with(handler)
    try:
        await client.submit_command(
            uuid4(),
            "ls",
            fs_context="/etc/passwd: known",
        )
    finally:
        await client.aclose()
    assert captured[0]["fs_context"] == "/etc/passwd: known"


async def test_submit_command_omits_fs_context_when_none() -> None:
    captured: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        captured.append(json.loads(request.read()))
        return httpx.Response(200, json={"text": "ok"})

    client = _client_with(handler)
    try:
        await client.submit_command(uuid4(), "ls")
    finally:
        await client.aclose()
    assert "fs_context" not in captured[0]


async def test_submit_command_non_string_text_raises() -> None:
    client = _client_with(lambda _r: httpx.Response(200, json={"text": 42}))
    try:
        with pytest.raises(BridgeUnavailableError, match="non-string"):
            await client.submit_command(uuid4(), "ls")
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# close_session
# ---------------------------------------------------------------------------


async def test_close_session_swallows_404() -> None:
    client = _client_with(lambda _r: httpx.Response(404))
    try:
        await client.close_session(uuid4())  # must not raise
    finally:
        await client.aclose()


async def test_close_session_propagates_5xx() -> None:
    client = _client_with(lambda _r: httpx.Response(503))
    try:
        with pytest.raises(BridgeUnavailableError):
            await client.close_session(uuid4())
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Error matrix on _post_json
# ---------------------------------------------------------------------------


async def test_5xx_raises_bridge_unavailable() -> None:
    client = _client_with(lambda _r: httpx.Response(503, text="overloaded"))
    try:
        with pytest.raises(BridgeUnavailableError, match="server error"):
            await client.open_session(source_ip="1.1.1.1", username="root")
    finally:
        await client.aclose()


async def test_4xx_raises_bridge_unavailable() -> None:
    client = _client_with(lambda _r: httpx.Response(400, text="bad"))
    try:
        with pytest.raises(BridgeUnavailableError, match="client error"):
            await client.open_session(source_ip="1.1.1.1", username="root")
    finally:
        await client.aclose()


async def test_401_raises_with_auth_hint() -> None:
    client = _client_with(lambda _r: httpx.Response(401))
    try:
        with pytest.raises(BridgeUnavailableError, match="ANGLERFISH_BRIDGE__SHARED_SECRET"):
            await client.open_session(source_ip="1.1.1.1", username="root")
    finally:
        await client.aclose()


async def test_426_raises_with_protocol_mismatch_hint() -> None:
    client = _client_with(lambda _r: httpx.Response(426, text="upgrade required"))
    try:
        with pytest.raises(BridgeUnavailableError, match="protocol mismatch"):
            await client.open_session(source_ip="1.1.1.1", username="root")
    finally:
        await client.aclose()


async def test_network_failure_raises_bridge_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = _client_with(handler)
    try:
        with pytest.raises(BridgeUnavailableError, match="network failure"):
            await client.open_session(source_ip="1.1.1.1", username="root")
    finally:
        await client.aclose()


async def test_malformed_json_raises_bridge_unavailable() -> None:
    client = _client_with(lambda _r: httpx.Response(200, text="not json"))
    try:
        with pytest.raises(BridgeUnavailableError, match="malformed JSON"):
            await client.open_session(source_ip="1.1.1.1", username="root")
    finally:
        await client.aclose()


async def test_non_object_json_raises_bridge_unavailable() -> None:
    client = _client_with(lambda _r: httpx.Response(200, json=[1, 2, 3]))
    try:
        with pytest.raises(BridgeUnavailableError, match="non-object"):
            await client.open_session(source_ip="1.1.1.1", username="root")
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Header + ownership
# ---------------------------------------------------------------------------


async def test_protocol_header_present_on_every_request() -> None:
    seen_versions: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        # httpx.Headers is case-insensitive; .get() returns the value
        # regardless of casing in the original send.
        seen_versions.append(request.headers.get(PROTOCOL_VERSION_HEADER))
        return httpx.Response(
            200,
            json={"session_id": str(uuid4()), "text": "x"},
        )

    client = _client_with(handler)
    try:
        sid = await client.open_session(source_ip="1.1.1.1", username="root")
        await client.submit_command(sid, "ls")
        await client.close_session(sid)
    finally:
        await client.aclose()
    assert seen_versions == ["2", "2", "2"]


async def test_authorization_header_set_when_secret_provided() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("Authorization", ""))
        return httpx.Response(200, json={"session_id": str(uuid4())})

    client = _client_with(handler, secret="hunter2")
    try:
        await client.open_session(source_ip="1.1.1.1", username="root")
    finally:
        await client.aclose()
    assert seen[0] == "Bearer hunter2"


async def test_authorization_header_omitted_when_no_secret() -> None:
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("Authorization"))
        return httpx.Response(200, json={"session_id": str(uuid4())})

    client = _client_with(handler, secret=None)
    try:
        await client.open_session(source_ip="1.1.1.1", username="root")
    finally:
        await client.aclose()
    assert seen[0] is None


async def test_owned_client_is_closed_in_aclose() -> None:
    closed: list[bool] = []

    class _Tracking(httpx.AsyncClient):
        async def aclose(self) -> None:
            closed.append(True)
            await super().aclose()

    # Owned path: no http_client passed, client builds its own. We can
    # not inject Tracking without breaking ownership; verify via the
    # injected-client path that aclose does NOT close injected clients.
    transport = httpx.MockTransport(lambda _r: httpx.Response(200))
    tracking = _Tracking(transport=transport, base_url="http://127.0.0.1:8421")
    client = BridgeClient(
        base_url=HttpUrl("http://127.0.0.1:8421/"),
        shared_secret=None,
        request_timeout_s=1.0,
        connect_timeout_s=0.5,
        http_client=tracking,
    )
    await client.aclose()
    assert closed == []  # injected: caller owns it
    await tracking.aclose()
    assert closed == [True]


async def test_async_context_manager_closes_on_exit() -> None:
    # Owned client - construct without http_client. aclose closes the
    # internal client; verify no crash on context exit.
    client = BridgeClient(
        base_url=HttpUrl("http://127.0.0.1:8421/"),
        shared_secret=None,
        request_timeout_s=1.0,
        connect_timeout_s=0.5,
    )
    async with client:
        pass


def test_protocol_version_constant_is_two() -> None:
    # Sanity: the client ships with the v2 protocol header.
    from anglerfish.lure import bridge_client

    assert bridge_client._LURE_PROTOCOL_VERSION == "2"


def test_uuid_returned_is_uuid_type() -> None:
    # Type check via mock: open_session must return UUID, not str.
    expected = uuid4()

    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"session_id": str(expected)})

    import anyio

    async def _run() -> UUID:
        client = _client_with(handler)
        try:
            return await client.open_session(source_ip="1.1.1.1", username="root")
        finally:
            await client.aclose()

    sid = anyio.run(_run)
    assert isinstance(sid, UUID)
