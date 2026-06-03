"""First-boot Ollama model pull (TODO-14)."""

from __future__ import annotations

import json

import httpx
from pydantic import HttpUrl

from anglerfish.config.models import OllamaConfig
from anglerfish.model_pull import ModelPuller

_SUCCESS = b'{"status":"pulling"}\n{"status":"success"}\n'
_ERROR = b'{"error":"manifest not found"}\n'


def _config(**overrides: object) -> OllamaConfig:
    base: dict[str, object] = {
        "fast_model": "m-fast",
        "deep_model": "m-deep",
        "embed_model": "m-embed",
    }
    base.update(overrides)
    return OllamaConfig(**base)  # type: ignore[arg-type]


def _puller(
    config: OllamaConfig,
    *,
    present: set[str] | None = None,
    pull_body: dict[str, bytes] | None = None,
    unreachable: bool = False,
) -> tuple[ModelPuller, list[tuple[str, str]]]:
    calls: list[tuple[str, str]] = []
    present = present or set()
    pull_body = pull_body or {}

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if unreachable:
            raise httpx.ConnectError("refused", request=request)
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": n} for n in present]})
        if request.url.path == "/api/pull":
            model = json.loads(request.content)["model"]
            return httpx.Response(200, content=pull_body.get(model, _SUCCESS))
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    puller = ModelPuller(config, http_client=client, max_attempts=2, retry_backoff_s=0.0)
    return puller, calls


async def test_trusted_remote_is_skipped() -> None:
    config = _config(
        base_url=HttpUrl("http://10.0.0.5:11434/"),
        trusted_remote_host="10.0.0.5",
    )
    puller, calls = _puller(config)
    summary = await puller.ensure_models()
    assert summary.remote_skipped is True
    assert calls == []  # never touches the remote


async def test_unreachable_is_clean_noop() -> None:
    puller, _ = _puller(_config(), unreachable=True)
    summary = await puller.ensure_models()
    assert summary.unreachable is True
    assert summary.pulled == []


async def test_all_present_pulls_nothing() -> None:
    puller, calls = _puller(_config(), present={"m-fast", "m-deep", "m-embed"})
    summary = await puller.ensure_models()
    assert set(summary.already_present) == {"m-fast", "m-deep", "m-embed"}
    assert summary.pulled == []
    assert [c for c in calls if c[1] == "/api/pull"] == []


async def test_pulls_only_missing_models() -> None:
    puller, calls = _puller(_config(), present={"m-fast"})
    summary = await puller.ensure_models()
    assert summary.already_present == ["m-fast"]
    assert set(summary.pulled) == {"m-deep", "m-embed"}
    pulls = [c for c in calls if c[1] == "/api/pull"]
    assert len(pulls) == 2


async def test_tagless_name_matches_latest() -> None:
    # Configured "m-fast" with no tag is satisfied by "m-fast:latest".
    puller, _ = _puller(_config(), present={"m-fast:latest", "m-deep", "m-embed"})
    summary = await puller.ensure_models()
    assert "m-fast" in summary.already_present
    assert summary.pulled == []


async def test_pull_failure_is_retried_then_reported() -> None:
    puller, calls = _puller(
        _config(),
        present={"m-deep", "m-embed"},
        pull_body={"m-fast": _ERROR},
    )
    summary = await puller.ensure_models()
    assert summary.failed == ["m-fast"]
    # max_attempts=2 -> two pull attempts for the failing model.
    assert len([c for c in calls if c[1] == "/api/pull"]) == 2


async def test_duplicate_model_tags_pulled_once() -> None:
    puller, calls = _puller(
        _config(fast_model="same", deep_model="same", embed_model="same"),
    )
    summary = await puller.ensure_models()
    assert summary.pulled == ["same"]
    assert len([c for c in calls if c[1] == "/api/pull"]) == 1
