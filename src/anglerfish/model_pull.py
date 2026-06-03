"""First-boot Ollama model pull (TODO-14).

The ``--with-ollama`` ISO installs the Ollama runtime but pulls no model, so
the box boots with nothing to serve. :class:`ModelPuller` pulls the three
configured model tags (``fast_model`` / ``deep_model`` / ``embed_model``) via
the Ollama HTTP API on first boot, skipping any already present.

It only pulls when Ollama is local. When ``trusted_remote_host`` is set the
endpoint is a separate GPU host the operator manages, so we never pull onto
it; and if the local API is unreachable (Ollama not installed) the pull is a
clean no-op. Pulls are retried because the first one races the network coming
up; a model already present is never re-pulled (idempotent).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field

import httpx

from anglerfish.config.models import OllamaConfig

__all__ = ["ModelPuller", "PullSummary"]

_logger = logging.getLogger(__name__)


@dataclass
class PullSummary:
    """Outcome of an :meth:`ModelPuller.ensure_models` run."""

    pulled: list[str] = field(default_factory=list)
    already_present: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    remote_skipped: bool = False
    unreachable: bool = False


class ModelPuller:
    def __init__(
        self,
        config: OllamaConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
        max_attempts: int = 5,
        retry_backoff_s: float = 5.0,
    ) -> None:
        self._config = config
        self._max_attempts = max_attempts
        self._retry_backoff_s = retry_backoff_s
        self._owns_client = http_client is None
        # Pulls stream progress frequently, but a whole pull has no useful
        # overall deadline (multi-GB models on slow links); cap the gap
        # between progress chunks instead of the total.
        self._client = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=10.0, read=120.0, pool=None),
        )

    def _api(self, path: str) -> str:
        return f"{str(self._config.base_url).rstrip('/')}/{path.lstrip('/')}"

    def _configured_models(self) -> list[str]:
        seen: dict[str, None] = {}
        for tag in (
            self._config.fast_model,
            self._config.deep_model,
            self._config.embed_model,
        ):
            seen.setdefault(tag, None)
        return list(seen)

    @staticmethod
    def _is_present(model: str, present: set[str]) -> bool:
        if model in present:
            return True
        # A tagless config name defaults to ":latest" in Ollama.
        return ":" not in model and f"{model}:latest" in present

    async def _present_models(self) -> set[str] | None:
        """Model names Ollama already has, or None if it is unreachable."""
        try:
            resp = await self._client.get(self._api("api/tags"))
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            _logger.warning("model_pull: Ollama tags query failed: %s", exc)
            return None
        models = data.get("models", []) if isinstance(data, dict) else []
        return {m["name"] for m in models if isinstance(m, dict) and "name" in m}

    async def _pull_once(self, model: str) -> bool:
        """Stream one pull; return True on a success status, False otherwise."""
        try:
            async with self._client.stream(
                "POST",
                self._api("api/pull"),
                json={"model": model, "stream": True},
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        status = json.loads(line)
                    except ValueError:
                        continue
                    if status.get("error"):
                        _logger.warning("model_pull: %s: %s", model, status["error"])
                        return False
                    if status.get("status") == "success":
                        return True
            # Stream ended without an explicit error or success marker.
        except httpx.HTTPError as exc:
            _logger.warning("model_pull: pull of %s failed: %s", model, exc)
            return False
        return True

    async def _pull_with_retry(self, model: str) -> bool:
        for attempt in range(1, self._max_attempts + 1):
            if await self._pull_once(model):
                return True
            if attempt < self._max_attempts:
                _logger.info(
                    "model_pull: retry %d/%d for %s",
                    attempt,
                    self._max_attempts,
                    model,
                )
                await asyncio.sleep(self._retry_backoff_s)
        return False

    async def ensure_models(self) -> PullSummary:
        summary = PullSummary()
        if self._config.trusted_remote_host is not None:
            _logger.info(
                "model_pull: Ollama is a trusted remote (%s); operator-managed, skipping pull",
                self._config.trusted_remote_host,
            )
            summary.remote_skipped = True
            return summary

        present = await self._present_models()
        if present is None:
            summary.unreachable = True
            return summary

        for model in self._configured_models():
            if self._is_present(model, present):
                summary.already_present.append(model)
                continue
            _logger.info("model_pull: pulling %s ...", model)
            if await self._pull_with_retry(model):
                summary.pulled.append(model)
            else:
                summary.failed.append(model)
        return summary

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
