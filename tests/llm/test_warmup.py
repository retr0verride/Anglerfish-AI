"""Tests for :class:`anglerfish.llm.WarmPool` (Stage 5 slice 3)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from anglerfish.audit import AuditLog
from anglerfish.config.models import OllamaConfig
from anglerfish.llm import LLMClient, LLMRole, WarmPool

_Handler = Callable[[httpx.Request], httpx.Response]


def _make_client(handler: _Handler) -> LLMClient:
    transport = httpx.MockTransport(handler)
    http_client = httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:11434")
    return LLMClient(
        OllamaConfig(fast_model="fast:7b", deep_model="deep:14b"),
        http_client=http_client,
    )


def _read_events(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


async def test_warm_once_calls_generate_with_keep_alive(tmp_path: Path) -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            {
                "url": request.url.path,
                "body": json.loads(request.read()),
            },
        )
        return httpx.Response(200, json={"done": True})

    client = _make_client(handler)
    audit = AuditLog(tmp_path / "audit.jsonl")
    pool = WarmPool(
        client=client,
        config=client.config,
        audit_log=audit,
        roles=(LLMRole.FAST,),
    )
    try:
        status = await pool.warm_once(LLMRole.FAST)
    finally:
        await client.aclose()

    assert status.last_error is None
    assert status.warmed_at is not None
    assert status.refresh_count == 1
    assert seen == [
        {
            "url": "/api/generate",
            "body": {
                "model": "fast:7b",
                "prompt": "",
                "stream": False,
                "keep_alive": -1,
            },
        },
    ]


async def test_warm_once_records_success_audit_event(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"done": True})

    client = _make_client(handler)
    audit = AuditLog(tmp_path / "audit.jsonl")
    pool = WarmPool(
        client=client,
        config=client.config,
        audit_log=audit,
        roles=(LLMRole.DEEP,),
    )
    try:
        await pool.warm_once(LLMRole.DEEP)
    finally:
        await client.aclose()

    events = _read_events(audit.path)
    assert len(events) == 1
    assert events[0]["event_type"] == "llm.warmup_succeeded"
    assert events[0]["role"] == "deep"
    assert events[0]["model"] == "deep:14b"
    assert events[0]["refresh_count"] == 1


async def test_warm_once_swallows_5xx_and_records_failure(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="loading")

    client = _make_client(handler)
    audit = AuditLog(tmp_path / "audit.jsonl")
    pool = WarmPool(
        client=client,
        config=client.config,
        audit_log=audit,
        roles=(LLMRole.FAST,),
    )
    try:
        status = await pool.warm_once(LLMRole.FAST)
    finally:
        await client.aclose()

    assert status.warmed_at is None
    assert status.last_error is not None
    assert "OllamaUnavailableError" in status.last_error
    events = _read_events(audit.path)
    assert events[0]["event_type"] == "llm.warmup_failed"
    assert events[0]["role"] == "fast"


async def test_warm_once_swallows_4xx_and_records_failure(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="model not found")

    client = _make_client(handler)
    audit = AuditLog(tmp_path / "audit.jsonl")
    pool = WarmPool(
        client=client,
        config=client.config,
        audit_log=audit,
        roles=(LLMRole.FAST,),
    )
    try:
        status = await pool.warm_once(LLMRole.FAST)
    finally:
        await client.aclose()

    assert status.last_error is not None
    assert "OllamaResponseError" in status.last_error
    events = _read_events(audit.path)
    assert events[0]["event_type"] == "llm.warmup_failed"


async def test_warm_once_swallows_transport_error(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    client = _make_client(handler)
    audit = AuditLog(tmp_path / "audit.jsonl")
    pool = WarmPool(
        client=client,
        config=client.config,
        audit_log=audit,
        roles=(LLMRole.FAST,),
    )
    try:
        status = await pool.warm_once(LLMRole.FAST)
    finally:
        await client.aclose()

    assert status.last_error is not None
    assert "OllamaUnavailableError" in status.last_error


async def test_start_runs_initial_warmup_for_every_role(tmp_path: Path) -> None:
    seen_models: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_models.append(json.loads(request.read())["model"])
        return httpx.Response(200, json={"done": True})

    client = _make_client(handler)
    audit = AuditLog(tmp_path / "audit.jsonl")
    # Use the FAST + DEEP defaults.
    pool = WarmPool(client=client, config=client.config, audit_log=audit)
    try:
        await pool.start()
        # Give each task a chance to do its initial warmup. The sleep call
        # after the first warm_once parks them on the long interval.
        for _ in range(50):
            if len(seen_models) >= 2:
                break
            await asyncio.sleep(0)
        await pool.stop()
    finally:
        await client.aclose()

    assert sorted(seen_models) == ["deep:14b", "fast:7b"]


async def test_start_then_stop_cancels_tasks(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"done": True})

    client = _make_client(handler)
    audit = AuditLog(tmp_path / "audit.jsonl")
    pool = WarmPool(
        client=client,
        config=client.config,
        audit_log=audit,
        roles=(LLMRole.FAST,),
    )
    try:
        await pool.start()
        await pool.stop()
        # Re-stop is a no-op
        await pool.stop()
    finally:
        await client.aclose()


async def test_double_start_raises(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"done": True})

    client = _make_client(handler)
    audit = AuditLog(tmp_path / "audit.jsonl")
    pool = WarmPool(
        client=client,
        config=client.config,
        audit_log=audit,
        roles=(LLMRole.FAST,),
    )
    try:
        await pool.start()
        with pytest.raises(RuntimeError, match="already started"):
            await pool.start()
        await pool.stop()
    finally:
        await client.aclose()


async def test_async_context_manager_starts_and_stops(tmp_path: Path) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.read())["model"])
        return httpx.Response(200, json={"done": True})

    client = _make_client(handler)
    audit = AuditLog(tmp_path / "audit.jsonl")
    pool = WarmPool(
        client=client,
        config=client.config,
        audit_log=audit,
        roles=(LLMRole.FAST,),
    )
    try:
        async with pool:
            for _ in range(50):
                if seen:
                    break
                await asyncio.sleep(0)
    finally:
        await client.aclose()
    assert seen == ["fast:7b"]
