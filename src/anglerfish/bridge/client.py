"""Async HTTP client for the Ollama chat API.

The endpoint host has already been validated by :class:`OllamaConfig`;
this client trusts ``config.base_url``. The :class:`OllamaClient` is
designed to be reusable across many requests — construct it once at
service startup, close it at shutdown.

The HTTP transport is injectable for tests via the ``http_client``
constructor parameter, which accepts a pre-configured
:class:`httpx.AsyncClient` (for example, one bound to a ``respx`` mock
router).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal, Self

import httpx
from pydantic import BaseModel, ConfigDict

from anglerfish.bridge.errors import OllamaResponseError, OllamaUnavailableError
from anglerfish.config.models import OllamaConfig

__all__ = ["ChatMessage", "OllamaClient"]


_USER_AGENT = "anglerfish-ai/0.1.0"


class ChatMessage(BaseModel):
    """One message in the Ollama chat protocol."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    role: Literal["system", "user", "assistant"]
    content: str


class OllamaClient:
    """Typed async client around ``POST /api/chat``."""

    def __init__(
        self,
        config: OllamaConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._config = config
        if http_client is None:
            timeout = httpx.Timeout(
                config.request_timeout_s,
                connect=config.connect_timeout_s,
            )
            self._client = httpx.AsyncClient(
                base_url=str(config.base_url),
                timeout=timeout,
                headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
            )
            self._owns_client = True
        else:
            self._client = http_client
            self._owns_client = False

    @property
    def config(self) -> OllamaConfig:
        return self._config

    async def chat(self, messages: Sequence[ChatMessage]) -> str:
        """Send ``messages``, return the assistant content as a single string.

        Raises:
            OllamaUnavailableError: network failure or 5xx response.
            OllamaResponseError: 4xx response or malformed body.
        """
        payload: dict[str, Any] = {
            "model": self._config.model,
            "stream": False,
            "messages": [m.model_dump() for m in messages],
            "options": {
                "temperature": self._config.temperature,
                "top_p": self._config.top_p,
                "num_predict": self._config.max_response_tokens,
            },
        }
        try:
            response = await self._client.post("/api/chat", json=payload)
        except httpx.HTTPError as exc:
            raise OllamaUnavailableError(
                f"Ollama request failed: {type(exc).__name__}: {exc}",
            ) from exc

        if 500 <= response.status_code < 600:
            raise OllamaUnavailableError(
                f"Ollama returned server error {response.status_code}",
            )
        if response.status_code >= 400:
            body_preview = response.text[:200]
            raise OllamaResponseError(
                f"Ollama returned client error {response.status_code}: {body_preview!r}",
            )

        try:
            data: dict[str, Any] = response.json()
        except ValueError as exc:
            raise OllamaResponseError(
                f"Ollama response was not valid JSON: {exc}",
            ) from exc

        if not isinstance(data, dict):
            raise OllamaResponseError(
                f"Ollama response is not a JSON object: {type(data).__name__}",
            )
        message = data.get("message")
        if not isinstance(message, dict):
            raise OllamaResponseError(
                f"Ollama response missing 'message' object: keys={list(data)}",
            )
        content = message.get("content")
        if not isinstance(content, str):
            raise OllamaResponseError(
                "Ollama response 'message.content' is not a string",
            )
        return content

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
