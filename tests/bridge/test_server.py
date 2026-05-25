"""Tests for the bridge HTTP server (FastAPI shim around AIBridgeService)."""

from __future__ import annotations

from collections.abc import Callable, Iterator

import httpx
import pytest
from fastapi.testclient import TestClient

from anglerfish.bridge import AIBridgeService, OllamaClient, create_bridge_app
from anglerfish.config import AnglerfishSettings
from anglerfish.config.models import OllamaConfig


def _mock_client(handler: Callable[[httpx.Request], httpx.Response]) -> OllamaClient:
    transport = httpx.MockTransport(handler)
    return OllamaClient(
        OllamaConfig(),
        http_client=httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:11434",
        ),
    )


@pytest.fixture
def client(settings: AnglerfishSettings) -> Iterator[TestClient]:
    ai_client = _mock_client(
        lambda _r: httpx.Response(200, json={"message": {"content": "drwxr-xr-x"}}),
    )
    service = AIBridgeService(settings, client=ai_client)
    app = create_bridge_app(service)
    with TestClient(app) as c:
        yield c


def test_health(client: TestClient) -> None:
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_session_lifecycle(client: TestClient) -> None:
    r = client.post(
        "/api/v1/session",
        json={"source_ip": "203.0.113.7", "username": "root"},
    )
    assert r.status_code == 200
    body = r.json()
    session_id = body["session_id"]
    assert body["fake_hostname"] == "srv-prod-01"

    # Send a command.
    cr = client.post(
        f"/api/v1/session/{session_id}/command",
        json={"command": "ls /etc"},
    )
    assert cr.status_code == 200
    assert cr.json()["text"] == "drwxr-xr-x"

    # List sessions includes ours.
    list_resp = client.get("/api/v1/sessions")
    assert list_resp.status_code == 200
    assert any(s["session_id"] == session_id for s in list_resp.json())

    # End it.
    dr = client.delete(f"/api/v1/session/{session_id}")
    assert dr.status_code == 204

    # After deletion, command lookup returns 404.
    cr2 = client.post(
        f"/api/v1/session/{session_id}/command",
        json={"command": "ls"},
    )
    assert cr2.status_code == 404


def test_cd_handled_locally_does_not_call_ai(settings: AnglerfishSettings) -> None:
    called = False

    def handler(_r: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(500)

    ai_client = _mock_client(handler)
    service = AIBridgeService(settings, client=ai_client)
    app = create_bridge_app(service)
    with TestClient(app) as c:
        start = c.post(
            "/api/v1/session",
            json={"source_ip": "1.1.1.1", "username": "root"},
        )
        sid = start.json()["session_id"]
        cmd = c.post(f"/api/v1/session/{sid}/command", json={"command": "cd /etc"})
        assert cmd.status_code == 200
        assert cmd.json()["cwd"] == "/etc"
    assert called is False


def test_command_on_unknown_session(client: TestClient) -> None:
    r = client.post(
        "/api/v1/session/00000000-0000-0000-0000-000000000000/command",
        json={"command": "ls"},
    )
    assert r.status_code == 404


def test_delete_unknown_session_is_silent(client: TestClient) -> None:
    r = client.delete("/api/v1/session/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 204


# ---------------------------------------------------------------------------
# Stage 2A: CommandRequest gained an optional fs_context field. The bridge
# accepts it without rejecting requests that omit it (Cowrie v1 path) and
# without rejecting requests that include it (lure v2 path).
# ---------------------------------------------------------------------------


def test_command_request_accepts_omitted_fs_context(client: TestClient) -> None:
    r = client.post("/api/v1/session", json={"source_ip": "1.1.1.1", "username": "root"})
    sid = r.json()["session_id"]
    # No fs_context - Cowrie shim shape, still valid.
    cr = client.post(f"/api/v1/session/{sid}/command", json={"command": "ls"})
    assert cr.status_code == 200


def test_command_request_accepts_fs_context(client: TestClient) -> None:
    r = client.post("/api/v1/session", json={"source_ip": "1.1.1.1", "username": "root"})
    sid = r.json()["session_id"]
    # With fs_context - lure shape.
    cr = client.post(
        f"/api/v1/session/{sid}/command",
        json={"command": "ls", "fs_context": "/etc/passwd: root, daemon"},
    )
    assert cr.status_code == 200


def test_command_request_rejects_oversize_fs_context(client: TestClient) -> None:
    r = client.post("/api/v1/session", json={"source_ip": "1.1.1.1", "username": "root"})
    sid = r.json()["session_id"]
    cr = client.post(
        f"/api/v1/session/{sid}/command",
        json={"command": "ls", "fs_context": "x" * 4097},
    )
    assert cr.status_code == 422


def test_command_request_rejects_unknown_field(client: TestClient) -> None:
    r = client.post("/api/v1/session", json={"source_ip": "1.1.1.1", "username": "root"})
    sid = r.json()["session_id"]
    # extra="forbid" on the model rejects fields neither protocol defines.
    cr = client.post(
        f"/api/v1/session/{sid}/command",
        json={"command": "ls", "bogus_field": "x"},
    )
    assert cr.status_code == 422


# ---------------------------------------------------------------------------
# Stage 5 slice 4b: ?stream=1 returns NDJSON; absent / 0 keeps v2 JSON body.
# ---------------------------------------------------------------------------


def _ndjson_streaming_handler(
    chunks: list[dict[str, object]],
) -> Callable[[httpx.Request], httpx.Response]:
    import json as _json

    body = "\n".join(_json.dumps(c) for c in chunks) + "\n"

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=body.encode("utf-8"),
            headers={"content-type": "application/x-ndjson"},
        )

    return handler


def test_command_stream_returns_ndjson(settings: AnglerfishSettings) -> None:
    handler = _ndjson_streaming_handler(
        [
            {"message": {"content": "hello "}, "done": False},
            {"message": {"content": "world"}, "done": False},
            {"done": True, "prompt_eval_count": 1, "eval_count": 2},
        ],
    )
    service = AIBridgeService(settings, client=_mock_client(handler))
    app = create_bridge_app(service)
    with TestClient(app) as c:
        sid = c.post(
            "/api/v1/session",
            json={"source_ip": "1.1.1.1", "username": "root"},
        ).json()["session_id"]
        with c.stream(
            "POST",
            f"/api/v1/session/{sid}/command?stream=1",
            json={"command": "echo hi"},
        ) as response:
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("application/x-ndjson")
            lines = [line for line in response.iter_lines() if line]

    import json as _json

    decoded = [_json.loads(line) for line in lines]
    deltas = [c["delta"] for c in decoded]
    assert "hello " in deltas
    assert "world" in deltas
    # Terminal chunk
    assert decoded[-1]["done"] is True
    assert decoded[-1]["latency_ms"] is not None
    assert decoded[-1]["cwd"] == "/root"


def test_command_stream_zero_returns_json_body(client: TestClient) -> None:
    sid = client.post(
        "/api/v1/session",
        json={"source_ip": "1.1.1.1", "username": "root"},
    ).json()["session_id"]
    # ?stream=0 (or absent) keeps the v2 JSON shape.
    r = client.post(
        f"/api/v1/session/{sid}/command?stream=0",
        json={"command": "ls"},
    )
    assert r.status_code == 200
    assert "delta" not in r.json()
    assert r.json()["text"] == "drwxr-xr-x"


def test_command_stream_cd_yields_terminal_chunk_only(settings: AnglerfishSettings) -> None:
    """cd is handled deterministically - streaming path yields one done chunk."""
    called = False

    def handler(_req: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(500)

    service = AIBridgeService(settings, client=_mock_client(handler))
    app = create_bridge_app(service)
    with TestClient(app) as c:
        sid = c.post(
            "/api/v1/session",
            json={"source_ip": "1.1.1.1", "username": "root"},
        ).json()["session_id"]
        with c.stream(
            "POST",
            f"/api/v1/session/{sid}/command?stream=1",
            json={"command": "cd /tmp"},
        ) as response:
            lines = [line for line in response.iter_lines() if line]
    import json as _json

    decoded = [_json.loads(line) for line in lines]
    assert len(decoded) == 1
    assert decoded[0]["done"] is True
    assert decoded[0]["cwd"] == "/tmp"
    assert called is False
