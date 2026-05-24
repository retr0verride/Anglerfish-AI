"""Integration tests for :class:`anglerfish.lure.server.LureServer`.

Real asyncssh client against the lure on an ephemeral loopback port,
with the bridge mocked via :class:`httpx.MockTransport` and the
CredentialStore + Fingerprinter constructed against ``tmp_path``.
"""

from __future__ import annotations

import asyncio
import base64
import os
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

import asyncssh
import httpx
import pytest
from pydantic import HttpUrl, SecretStr

from anglerfish.audit import AuditLog
from anglerfish.config.models import CredentialsConfig, FingerprintConfig
from anglerfish.credentials.storage import CredentialStore
from anglerfish.fingerprint.service import Fingerprinter
from anglerfish.fingerprint.tor import TorExitList
from anglerfish.lure.bridge_client import BridgeClient
from anglerfish.lure.config import LureConfig
from anglerfish.lure.keys import ensure_host_keys, load_host_keys
from anglerfish.lure.server import LureServer

# Skip integration tests on Windows. asyncssh.listen needs POSIX
# signal-handler plumbing that nt does not provide, and CI for this
# project runs on Linux exclusively.
pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="asyncssh server is POSIX-only in this codebase",
)


@pytest.fixture
def bridge_handler() -> Callable[[httpx.Request], httpx.Response]:
    """Default bridge: accept session open, echo a deterministic command response."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/session":
            return httpx.Response(200, json={"session_id": str(uuid4())})
        if request.url.path.endswith("/command"):
            return httpx.Response(200, json={"text": "bridge-response\n"})
        if request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(404)

    return handler


@pytest.fixture
def audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


def _make_credstore(tmp_path: Path) -> CredentialStore:
    key = base64.b64encode(b"\x07" * 32).decode("ascii")
    return CredentialStore(
        CredentialsConfig(
            database_path=tmp_path / "creds.db",
            encryption_key=SecretStr(key),
        ),
    )


def _make_fingerprinter(tmp_path: Path) -> Fingerprinter:
    # Build a settings-like object with just what Fingerprinter reads.
    class _S:
        fingerprint = FingerprintConfig(
            tor_exit_list_path=tmp_path / "tor.txt",
            tor_exit_refresh_interval_s=3600.0,
        )

    tor_path = tmp_path / "tor.txt"
    tor_path.write_text("", encoding="utf-8")
    return Fingerprinter(
        _S(),  # type: ignore[arg-type]
        tor_exit_list=TorExitList(tor_path, refresh_interval_s=3600.0),
    )


def _make_lure_config(host_key_dir: Path, **overrides: Any) -> LureConfig:
    base: dict[str, Any] = {
        "enabled": True,
        "listen_host": "127.0.0.1",
        "listen_port": 0,  # ephemeral
        "hostname": "test-host-01",
        "host_key_dir": host_key_dir,
        "max_command_chars": 1024,
        "history_window": 50,
        "per_ip_max_concurrent_connections": 3,
        "per_ip_max_connections_per_minute": 30,
        "bridge_base_url": HttpUrl("http://127.0.0.1:8421/"),
        "bridge_request_timeout_s": 5.0,
        "bridge_connect_timeout_s": 1.0,
        "timing_jitter_enabled": False,  # disable for deterministic tests
        "keepalive_interval_s": 0,  # disable keepalive in tests
    }
    base.update(overrides)
    return LureConfig(**base)


async def _make_lure(
    tmp_path: Path,
    audit_log: AuditLog,
    bridge_handler: Callable[[httpx.Request], httpx.Response],
    **config_overrides: Any,
) -> LureServer:
    config = _make_lure_config(tmp_path / "keys", **config_overrides)
    ensure_host_keys(config.host_key_dir)
    rsa_pem, ed_pem = load_host_keys(config.host_key_dir)

    cred_store = _make_credstore(tmp_path)
    await cred_store.open()
    fingerprinter = _make_fingerprinter(tmp_path)

    transport = httpx.MockTransport(bridge_handler)
    http = httpx.AsyncClient(base_url="http://127.0.0.1:8421/", transport=transport)
    bridge = BridgeClient(
        base_url=config.bridge_base_url,
        shared_secret=None,
        request_timeout_s=5.0,
        connect_timeout_s=1.0,
        http_client=http,
    )

    return LureServer(
        config,
        credential_store=cred_store,
        fingerprinter=fingerprinter,
        bridge_client=bridge,
        audit_log=audit_log,
        host_keys=[rsa_pem, ed_pem],
    )


@pytest.fixture
async def lure(
    tmp_path: Path,
    audit_log: AuditLog,
    bridge_handler: Callable[[httpx.Request], httpx.Response],
) -> AsyncIterator[LureServer]:
    server = await _make_lure(tmp_path, audit_log, bridge_handler)
    await server.start()
    try:
        yield server
    finally:
        await server.stop(drain_timeout_s=2.0)
        await server.bridge_client.aclose()
        await server.credential_store.aclose()


async def _client(port: int) -> asyncssh.SSHClientConnection:
    return await asyncio.wait_for(
        asyncssh.connect(
            "127.0.0.1",
            port=port,
            username="alice",
            password="hunter2",
            known_hosts=None,
            client_version="SSH-2.0-pytest_client",
        ),
        timeout=5.0,
    )


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------


async def test_server_starts_and_stops_cleanly(lure: LureServer) -> None:
    assert lure.get_port() > 0


async def test_server_audits_start_and_stop_events(
    tmp_path: Path,
    audit_log: AuditLog,
    bridge_handler: Callable[[httpx.Request], httpx.Response],
) -> None:
    server = await _make_lure(tmp_path, audit_log, bridge_handler)
    await server.start()
    await server.stop(drain_timeout_s=2.0)
    await server.bridge_client.aclose()
    await server.credential_store.aclose()

    events = audit_log.path.read_text(encoding="utf-8").splitlines()
    types = [e for e in events if "lure.server_started" in e or "lure.server_stopped" in e]
    assert any("lure.server_started" in e for e in types)
    assert any("lure.server_stopped" in e for e in types)


# ---------------------------------------------------------------------------
# Auth and credential capture
# ---------------------------------------------------------------------------


async def test_accepts_any_password_and_records_attempt(
    lure: LureServer,
    audit_log: AuditLog,
) -> None:
    conn = await _client(lure.get_port())
    try:
        # Just connecting confirms auth succeeded.
        assert conn.get_extra_info("username") == "alice"
    finally:
        conn.close()
        await conn.wait_closed()

    # Give the background CredentialStore write a moment to flush.
    await asyncio.sleep(0.1)

    records = await lure.credential_store.query(limit=10)
    assert len(records) == 1
    assert records[0].username == "alice"
    assert records[0].password == "hunter2"


async def test_audit_records_login_attempt(
    lure: LureServer,
    audit_log: AuditLog,
) -> None:
    conn = await _client(lure.get_port())
    try:
        pass
    finally:
        conn.close()
        await conn.wait_closed()
    await asyncio.sleep(0.1)

    events = audit_log.path.read_text(encoding="utf-8")
    assert "lure.login_attempt" in events
    # SHA-256 prefix of "hunter2" - never the plaintext.
    assert "hunter2" not in events


async def test_audit_records_fingerprint(
    lure: LureServer,
    audit_log: AuditLog,
) -> None:
    conn = await _client(lure.get_port())
    conn.close()
    await conn.wait_closed()
    await asyncio.sleep(0.1)

    events = audit_log.path.read_text(encoding="utf-8")
    assert "lure.fingerprint_observed" in events
    # AuditLog writes with tight JSON separators (no space after colon).
    # HASSH is an MD5 hex string: 32 lowercase hex chars.
    import re

    assert re.search(r'"hassh":"[0-9a-f]{32}"', events)


async def test_per_session_events_carry_session_id(
    tmp_path: Path,
    audit_log: AuditLog,
) -> None:
    """Stage 4.2 contract: every per-session lure event carries a
    UUID-shaped session_id matching the bridge session for that exec.

    Pre-Stage-4.2 the lure never emitted session_id, so the dashboard
    tailer had no way to correlate rows. Events that fire before the
    bridge session is allocated (rate_limited, fingerprint_observed,
    login_attempt) intentionally do NOT carry session_id and are out
    of scope.

    Test uses a single exec because the lure's connection-scoped
    open_audited flag means multi-exec on one TCP connection emits
    one session_opened but multiple bridge_uuids — a pre-existing
    audit-semantics inconsistency, not a Stage 4.2 regression.
    """
    import json as _json
    import re

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/session":
            return httpx.Response(200, json={"session_id": str(uuid4())})
        if request.url.path.endswith("/command"):
            return httpx.Response(200, json={"text": "ok\n"})
        return httpx.Response(404)

    server = await _make_lure(tmp_path, audit_log, handler)
    await server.start()
    try:
        async with asyncssh.connect(
            "127.0.0.1",
            port=server.get_port(),
            username="alice",
            password="x",
            known_hosts=None,
        ) as conn:
            await conn.run("apt-get install hax", timeout=3.0)
    finally:
        await server.stop(drain_timeout_s=2.0)
        await server.bridge_client.aclose()
        await server.credential_store.aclose()

    lines = [
        _json.loads(raw)
        for raw in audit_log.path.read_text(encoding="utf-8").splitlines()
        if raw.strip()
    ]
    by_type: dict[str, list[dict[str, Any]]] = {}
    for line in lines:
        by_type.setdefault(line.get("event_type", ""), []).append(line)

    uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    for kind in ("lure.session_opened", "lure.command_bridge", "lure.session_closed"):
        assert by_type.get(kind), f"missing {kind} events: {sorted(by_type)}"
        for event in by_type[kind]:
            sid = event.get("session_id")
            assert isinstance(sid, str), f"{kind} missing session_id: {event!r}"
            assert uuid_re.match(sid), f"{kind} malformed session_id: {event!r}"

    # Single exec: every per-session event shares one UUID.
    session_ids = {
        event["session_id"]
        for kind in ("lure.session_opened", "lure.command_bridge", "lure.session_closed")
        for event in by_type[kind]
    }
    assert len(session_ids) == 1, f"single exec produced multiple session_ids: {session_ids}"


# ---------------------------------------------------------------------------
# Shell loop: native vs bridge dispatch
# ---------------------------------------------------------------------------


async def test_native_command_handled_without_bridge_call(
    tmp_path: Path,
    audit_log: AuditLog,
) -> None:
    bridge_calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bridge_calls.append(request.url.path)
        if request.url.path == "/api/v1/session":
            return httpx.Response(200, json={"session_id": str(uuid4())})
        return httpx.Response(404)

    server = await _make_lure(tmp_path, audit_log, handler)
    await server.start()
    try:
        async with asyncssh.connect(
            "127.0.0.1",
            port=server.get_port(),
            username="alice",
            password="x",
            known_hosts=None,
        ) as conn:
            result = await conn.run("whoami", timeout=3.0)
        # whoami is native; bridge was opened (session) but never
        # got the command.
        assert "alice" in (result.stdout or "")
        command_calls = [p for p in bridge_calls if p.endswith("/command")]
        assert command_calls == []
    finally:
        await server.stop(drain_timeout_s=2.0)
        await server.bridge_client.aclose()
        await server.credential_store.aclose()


async def test_unknown_command_routes_to_bridge(
    tmp_path: Path,
    audit_log: AuditLog,
) -> None:
    seen: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        if request.url.path == "/api/v1/session":
            return httpx.Response(200, json={"session_id": str(uuid4())})
        if request.url.path.endswith("/command"):
            seen.append(json.loads(request.read()))
            return httpx.Response(200, json={"text": "BRIDGE-OUTPUT\n"})
        return httpx.Response(404)

    server = await _make_lure(tmp_path, audit_log, handler)
    await server.start()
    try:
        async with asyncssh.connect(
            "127.0.0.1",
            port=server.get_port(),
            username="alice",
            password="x",
            known_hosts=None,
        ) as conn:
            result = await conn.run("apt-get install hax", timeout=3.0)
        assert "BRIDGE-OUTPUT" in (result.stdout or "")
        assert len(seen) == 1
        assert seen[0]["command"] == "apt-get install hax"
        # fs_context rides protocol v2.
        assert "fs_context" in seen[0]
    finally:
        await server.stop(drain_timeout_s=2.0)
        await server.bridge_client.aclose()
        await server.credential_store.aclose()


async def test_falls_back_when_bridge_returns_5xx(
    tmp_path: Path,
    audit_log: AuditLog,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/session":
            return httpx.Response(200, json={"session_id": str(uuid4())})
        if request.url.path.endswith("/command"):
            return httpx.Response(503, text="overloaded")
        return httpx.Response(404)

    server = await _make_lure(tmp_path, audit_log, handler)
    await server.start()
    try:
        async with asyncssh.connect(
            "127.0.0.1",
            port=server.get_port(),
            username="alice",
            password="x",
            known_hosts=None,
        ) as conn:
            result = await conn.run("apt-get install hax", timeout=3.0)
        # Fallback for an unknown command is "command not found".
        assert "command not found" in (result.stdout or "")
    finally:
        await server.stop(drain_timeout_s=2.0)
        await server.bridge_client.aclose()
        await server.credential_store.aclose()


async def test_session_continues_when_bridge_open_fails(
    tmp_path: Path,
    audit_log: AuditLog,
) -> None:
    """Bridge-down on session open must not block the attacker session.

    The lure still wants the credential capture; the LLM-driven shell
    layer just falls back to scripted responses for the duration.
    """

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    server = await _make_lure(tmp_path, audit_log, handler)
    await server.start()
    try:
        async with asyncssh.connect(
            "127.0.0.1",
            port=server.get_port(),
            username="bob",
            password="y",
            known_hosts=None,
        ) as conn:
            # whoami still works (native; no bridge needed).
            r = await conn.run("whoami", timeout=3.0)
            assert "bob" in (r.stdout or "")
    finally:
        await server.stop(drain_timeout_s=2.0)
        await server.bridge_client.aclose()
        await server.credential_store.aclose()


# ---------------------------------------------------------------------------
# Per-IP rate limit
# ---------------------------------------------------------------------------


async def test_per_ip_concurrent_limit_enforced(
    tmp_path: Path,
    audit_log: AuditLog,
    bridge_handler: Callable[[httpx.Request], httpx.Response],
) -> None:
    server = await _make_lure(
        tmp_path,
        audit_log,
        bridge_handler,
        per_ip_max_concurrent_connections=2,
        per_ip_max_connections_per_minute=10,
    )
    await server.start()
    try:
        c1 = await _client(server.get_port())
        c2 = await _client(server.get_port())
        # Third connection from the same IP must be rejected. The
        # server closes the transport during connection_made, so
        # asyncssh.connect raises.
        with pytest.raises((asyncssh.Error, ConnectionResetError, OSError)):
            await asyncio.wait_for(_client(server.get_port()), timeout=3.0)
        c1.close()
        c2.close()
        await c1.wait_closed()
        await c2.wait_closed()
    finally:
        await server.stop(drain_timeout_s=2.0)
        await server.bridge_client.aclose()
        await server.credential_store.aclose()

    events = audit_log.path.read_text(encoding="utf-8")
    assert "lure.rate_limited" in events
    assert "per_ip_concurrent" in events


# ---------------------------------------------------------------------------
# Public-key auth is logged and refused
# ---------------------------------------------------------------------------


async def test_pubkey_attempt_logged_and_refused_then_password_accepted(
    tmp_path: Path,
    audit_log: AuditLog,
    bridge_handler: Callable[[httpx.Request], httpx.Response],
) -> None:
    server = await _make_lure(tmp_path, audit_log, bridge_handler)
    await server.start()
    try:
        # Generate a throwaway client key.
        client_key = asyncssh.generate_private_key("ssh-ed25519")
        client_key_path = tmp_path / "client_key"
        client_key.write_private_key(str(client_key_path))
        os.chmod(client_key_path, 0o600)

        # Offer the key (refused) plus password (accepted).
        async with asyncssh.connect(
            "127.0.0.1",
            port=server.get_port(),
            username="alice",
            client_keys=[str(client_key_path)],
            password="fallback-password",
            preferred_auth=["publickey", "password"],
            known_hosts=None,
        ) as conn:
            r = await conn.run("whoami", timeout=3.0)
            assert "alice" in (r.stdout or "")
    finally:
        await server.stop(drain_timeout_s=2.0)
        await server.bridge_client.aclose()
        await server.credential_store.aclose()

    events = audit_log.path.read_text(encoding="utf-8")
    # Pubkey attempt audit-logged.
    assert "publickey" in events


# ---------------------------------------------------------------------------
# Disabled mode
# ---------------------------------------------------------------------------


def test_disabled_lure_config_does_not_explode_at_construction(
    tmp_path: Path,
) -> None:
    cfg = _make_lure_config(tmp_path / "keys", enabled=False)
    assert cfg.enabled is False  # construction still works; runner skips start
