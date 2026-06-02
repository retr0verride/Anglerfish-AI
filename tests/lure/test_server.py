"""Integration tests for :class:`anglerfish.lure.server.LureServer`.

Real asyncssh client against the lure on an ephemeral loopback port,
with the bridge mocked via :class:`httpx.MockTransport` and the
CredentialStore + Fingerprinter constructed against ``tmp_path``.
"""

from __future__ import annotations

import asyncio
import base64
import os
import struct
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import asyncssh
import httpx
import pytest
from pydantic import HttpUrl, SecretStr

from anglerfish.audit import AuditLog
from anglerfish.config.models import CredentialsConfig, FingerprintConfig
from anglerfish.credentials.storage import CredentialStore
from anglerfish.fingerprint.hashes import compute_hassh
from anglerfish.fingerprint.service import Fingerprinter
from anglerfish.fingerprint.tor import TorExitList
from anglerfish.lure.bridge_client import BridgeClient
from anglerfish.lure.config import LureConfig
from anglerfish.lure.keys import ensure_host_keys, load_host_keys
from anglerfish.lure.server import (
    LureServer,
    _client_offered_algorithms,
    _ConnectionState,
    _LureSSHServer,
)

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
        # Default the existing tests to the v2 buffered path; the
        # streaming path has its own dedicated tests below that flip
        # this back on.
        "bridge_stream_enabled": False,
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


async def test_username_normalised_consistently_across_auth_records() -> None:
    # begin_auth trims username to 64 chars (default root); validate_password
    # must record the same normalised value, or one connection presents two
    # usernames across its credential-store and audit records.
    long_name = "x" * 100
    store_usernames: list[str] = []
    audit_usernames: list[str] = []

    async def _record_attempt(*, username: str, **_kw: object) -> None:
        store_usernames.append(username)

    def _audit_record(event_type: str, **fields: object) -> None:
        if event_type == "lure.login_attempt":
            audit_usernames.append(cast("str", fields["username"]))

    container = cast(
        "LureServer",
        SimpleNamespace(
            credential_store=SimpleNamespace(record_attempt=_record_attempt),
            audit=SimpleNamespace(record=_audit_record),
            placeholder_session_id=uuid4,
        ),
    )
    server = _LureSSHServer(container)
    server._state = _ConnectionState(source_ip="203.0.113.9")

    server.begin_auth(long_name)
    assert server._state.username == "x" * 64
    await server.validate_password(long_name, "pw")

    assert store_usernames == ["x" * 64]
    assert audit_usernames == ["x" * 64]


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


def _kexinit_payload(
    kex: list[str],
    hostkey: list[str],
    enc_cs: list[str],
    enc_sc: list[str],
    mac_cs: list[str],
    mac_sc: list[str],
    cmp_cs: list[str],
) -> bytes:
    """Build a minimal SSH_MSG_KEXINIT payload (type byte + cookie + lists)."""

    def _nl(items: list[str]) -> bytes:
        body = ",".join(items).encode("ascii")
        return struct.pack(">I", len(body)) + body

    return (
        bytes([0x14])
        + b"\x00" * 16
        + _nl(kex)
        + _nl(hostkey)
        + _nl(enc_cs)
        + _nl(enc_sc)
        + _nl(mac_cs)
        + _nl(mac_sc)
        + _nl(cmp_cs)
    )


def test_client_offered_algorithms_parses_kexinit() -> None:
    payload = _kexinit_payload(
        ["kex1", "kex2"],
        ["ssh-ed25519"],
        ["aes128", "aes256"],
        ["aes128"],
        ["hmac-sha2-256"],
        ["hmac-sha2-256"],
        ["none", "zlib"],
    )
    conn = cast("asyncssh.SSHServerConnection", type("C", (), {"_client_kexinit": payload})())
    kex, enc, mac, comp = _client_offered_algorithms(conn)
    assert kex == ["kex1", "kex2"]
    assert enc == ["aes128", "aes256"]  # client->server only
    assert mac == ["hmac-sha2-256"]
    assert comp == ["none", "zlib"]


def test_client_offered_algorithms_missing_attribute_returns_empty() -> None:
    conn = cast("asyncssh.SSHServerConnection", object())
    assert _client_offered_algorithms(conn) == ([], [], [], [])


def test_client_offered_algorithms_malformed_payload_degrades_to_empty() -> None:
    # A truncated payload (a future asyncssh change, or a corrupt buffer)
    # must degrade to no HASSH, not raise into the post-kex auth hook.
    conn = cast(
        "asyncssh.SSHServerConnection", type("C", (), {"_client_kexinit": b"\x14\x00\x00"})()
    )
    assert _client_offered_algorithms(conn) == ([], [], [], [])


async def test_distinct_clients_get_distinct_hassh(
    lure: LureServer,
    audit_log: AuditLog,
) -> None:
    """Two clients with different algorithm offers get different HASSH.

    Audit H3: asyncssh does not expose the offered algorithm lists via
    get_extra_info, so the lure previously hashed four empty lists into
    one constant for every attacker, defeating re-identification. With
    the offered lists recovered from the client KEXINIT, distinct offers
    must hash distinctly.
    """
    import re

    c1 = await asyncio.wait_for(
        asyncssh.connect(
            "127.0.0.1",
            port=lure.get_port(),
            username="alice",
            password="hunter2",
            known_hosts=None,
            kex_algs=["curve25519-sha256"],
        ),
        timeout=5.0,
    )
    c1.close()
    await c1.wait_closed()
    c2 = await asyncio.wait_for(
        asyncssh.connect(
            "127.0.0.1",
            port=lure.get_port(),
            username="alice",
            password="hunter2",
            known_hosts=None,
            kex_algs=["ecdh-sha2-nistp256"],
        ),
        timeout=5.0,
    )
    c2.close()
    await c2.wait_closed()
    await asyncio.sleep(0.15)

    hasshes = re.findall(r'"hassh":"([0-9a-f]{32})"', audit_log.path.read_text(encoding="utf-8"))
    assert len(hasshes) == 2
    # Distinct offers -> distinct fingerprints (not one constant).
    assert hasshes[0] != hasshes[1]
    # And neither is the all-empty-lists constant the bug produced.
    assert compute_hassh([], [], [], []) not in hasshes


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


async def test_streaming_path_writes_chunks_in_order(
    tmp_path: Path,
    audit_log: AuditLog,
) -> None:
    """With bridge_stream_enabled=True the lure consumes ?stream=1 NDJSON."""
    import json as _json

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/session":
            return httpx.Response(200, json={"session_id": str(uuid4())})
        if request.url.path.endswith("/command"):
            assert request.url.params.get("stream") == "1"
            ndjson = (
                _json.dumps({"delta": "hel", "source": "ai", "done": False})
                + "\n"
                + _json.dumps({"delta": "lo", "source": "ai", "done": False})
                + "\n"
                + _json.dumps(
                    {
                        "delta": "",
                        "source": "ai",
                        "done": True,
                        "latency_ms": 12.3,
                        "cwd": "/root",
                    },
                )
                + "\n"
            )
            return httpx.Response(
                200,
                content=ndjson.encode("utf-8"),
                headers={"content-type": "application/x-ndjson"},
            )
        return httpx.Response(404)

    server = await _make_lure(
        tmp_path,
        audit_log,
        handler,
        bridge_stream_enabled=True,
    )
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
        # Both deltas concatenated, with a trailing newline appended.
        stdout = result.stdout or ""
        assert isinstance(stdout, str)
        assert stdout.startswith("hello")
    finally:
        await server.stop(drain_timeout_s=2.0)
        await server.bridge_client.aclose()
        await server.credential_store.aclose()


async def test_streaming_path_falls_back_when_bridge_5xx_with_no_chunks(
    tmp_path: Path,
    audit_log: AuditLog,
) -> None:
    """Mid-stream 5xx before any chunks: lure writes its scripted fallback."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/session":
            return httpx.Response(200, json={"session_id": str(uuid4())})
        if request.url.path.endswith("/command"):
            return httpx.Response(503, content=b"")
        return httpx.Response(404)

    server = await _make_lure(
        tmp_path,
        audit_log,
        handler,
        bridge_stream_enabled=True,
    )
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
        # Lure-side fallback fires because nothing was streamed.
        out = result.stdout or ""
        assert "command not found" in out or out  # non-empty fallback
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
