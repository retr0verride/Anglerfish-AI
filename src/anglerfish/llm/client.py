"""Async LLM client - replaces :class:`anglerfish.bridge.client.OllamaClient`.

Single httpx connection shared across calls. Constructed once at
service startup, closed at shutdown via :meth:`aclose` or async
context manager. The HTTP transport is injectable for tests.

Surface differences from the original ``OllamaClient``:

* ``chat()`` now takes a ``role`` keyword (defaulting to
  :attr:`LLMRole.FAST`) and returns a :class:`ChatResult` with
  both content and Ollama-reported token usage. The previous
  method returned a bare string; call sites unwrap ``result.content``.
* The bound model tag is read per-call from
  :class:`OllamaConfig` via the resolved role, not from a
  single ``config.model`` field. Sampling parameters
  (temperature, top_p, num_predict) stay shared across roles in
  Stage 5; a later slice may split them per role.

Errors map identically to the original client:
:class:`OllamaUnavailableError` for network / 5xx failures,
:class:`OllamaResponseError` for 4xx and malformed bodies.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Sequence
from typing import Any, Literal, Self, TypeVar

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from anglerfish.config.models import OllamaConfig
from anglerfish.llm.budget import TokenBudget
from anglerfish.llm.errors import (
    OllamaResponseError,
    OllamaUnavailableError,
    StructuredOutputError,
)
from anglerfish.llm.roles import LLMRole

__all__ = ["ChatChunk", "ChatMessage", "ChatResult", "LLMClient", "TokenUsage"]

_T_Model = TypeVar("_T_Model", bound=BaseModel)


_USER_AGENT = "anglerfish-ai/0.1.0"


class ChatMessage(BaseModel):
    """One message in the Ollama chat protocol."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    role: Literal["system", "user", "assistant"]
    content: str


class TokenUsage(BaseModel):
    """Tokens consumed by one chat call.

    Parsed from Ollama's ``prompt_eval_count`` and ``eval_count``
    response fields. Both default to 0 when Ollama omits them
    (some local backends do, particularly for short prompts).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)


class ChatResult(BaseModel):
    """One chat call's full result: content + token usage."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    content: str
    usage: TokenUsage = Field(default_factory=TokenUsage)


class ChatChunk(BaseModel):
    """One streamed slice of a chat response.

    Yielded by :meth:`LLMClient.stream_chat`. ``delta`` is the
    incremental token text from Ollama's chat NDJSON. The terminal
    chunk has ``done=True``, a typically-empty ``delta``, and
    ``usage`` populated from Ollama's ``prompt_eval_count`` +
    ``eval_count`` fields.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    delta: str
    done: bool = False
    usage: TokenUsage | None = None


class LLMClient:
    """Typed async client around ``POST /api/chat``, role-aware."""

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

    def model_for(self, role: LLMRole) -> str:
        """Return the configured Ollama tag for ``role``."""
        if role is LLMRole.FAST:
            return self._config.fast_model
        if role is LLMRole.DEEP:
            return self._config.deep_model
        raise ValueError(f"unknown role: {role!r}")

    async def chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        role: LLMRole = LLMRole.FAST,
        budget: TokenBudget | None = None,
        response_format: str | None = None,
    ) -> ChatResult:
        """Send ``messages`` for ``role``, return content + token usage.

        When ``budget`` is supplied, the per-role remaining cap is
        checked *before* the call - an exhausted role raises
        :class:`BudgetExhaustedError` with no Ollama traffic. The
        actual ``prompt_eval_count + eval_count`` reported on the
        response is then added to ``budget.consumed_<role>``.

        Raises:
            BudgetExhaustedError: ``budget`` supplied and exhausted.
            OllamaUnavailableError: network failure or 5xx response.
            OllamaResponseError: 4xx response or malformed body.
        """
        if budget is not None:
            budget.check(role)
        payload: dict[str, Any] = {
            "model": self.model_for(role),
            "stream": False,
            "messages": [m.model_dump() for m in messages],
            "options": {
                "temperature": self._config.temperature,
                "top_p": self._config.top_p,
                "num_predict": self._config.max_response_tokens,
            },
        }
        if response_format is not None:
            payload["format"] = response_format
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
        usage = _parse_usage(data)
        if budget is not None:
            budget.consume(role, usage.prompt_tokens + usage.completion_tokens)
        return ChatResult(content=content, usage=usage)

    async def stream_chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        role: LLMRole = LLMRole.FAST,
        budget: TokenBudget | None = None,
    ) -> AsyncIterator[ChatChunk]:
        """Stream a chat response from Ollama as :class:`ChatChunk` objects.

        Issues ``POST /api/chat`` with ``stream=True``; iterates the
        NDJSON response, yielding one :class:`ChatChunk` per line. The
        terminal chunk carries ``done=True`` and a populated
        :class:`TokenUsage`.

        When ``budget`` is supplied, the per-role remaining cap is
        checked *before* the request is sent - an exhausted role
        raises :class:`BudgetExhaustedError` with no Ollama traffic
        and no chunks yielded. The terminal chunk's usage is added to
        ``budget.consumed_<role>`` after the stream completes
        successfully; partial-stream failures do not consume budget
        (Ollama would not have charged for it either).

        Raises:
            BudgetExhaustedError: ``budget`` supplied and exhausted.
            OllamaUnavailableError: network failure, 5xx response,
                or malformed chunk mid-stream.
            OllamaResponseError: 4xx response before the first chunk.
        """
        if budget is not None:
            budget.check(role)
        payload: dict[str, Any] = {
            "model": self.model_for(role),
            "stream": True,
            "messages": [m.model_dump() for m in messages],
            "options": {
                "temperature": self._config.temperature,
                "top_p": self._config.top_p,
                "num_predict": self._config.max_response_tokens,
            },
        }
        try:
            async with self._client.stream("POST", "/api/chat", json=payload) as response:
                if 500 <= response.status_code < 600:
                    raise OllamaUnavailableError(
                        f"Ollama stream returned server error {response.status_code}",
                    )
                if response.status_code >= 400:
                    body = await response.aread()
                    body_preview = body[:200].decode("utf-8", errors="replace")
                    raise OllamaResponseError(
                        f"Ollama stream returned client error {response.status_code}: "
                        f"{body_preview!r}",
                    )
                async for chunk in self._iter_stream_lines(response):
                    if chunk.done and chunk.usage is not None and budget is not None:
                        budget.consume(
                            role,
                            chunk.usage.prompt_tokens + chunk.usage.completion_tokens,
                        )
                    yield chunk
        except httpx.HTTPError as exc:
            raise OllamaUnavailableError(
                f"Ollama stream failed: {type(exc).__name__}: {exc}",
            ) from exc

    @staticmethod
    async def _iter_stream_lines(response: httpx.Response) -> AsyncIterator[ChatChunk]:
        """Parse Ollama's NDJSON stream into :class:`ChatChunk` objects."""
        async for raw_line in response.aiter_lines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except ValueError as exc:
                raise OllamaUnavailableError(
                    f"Ollama stream chunk was not valid JSON: {exc}",
                ) from exc
            if not isinstance(data, dict):
                raise OllamaUnavailableError(
                    f"Ollama stream chunk is not a JSON object: {type(data).__name__}",
                )
            message = data.get("message")
            delta = ""
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str):
                    delta = content
            done = bool(data.get("done", False))
            usage: TokenUsage | None = _parse_usage(data) if done else None
            yield ChatChunk(delta=delta, done=done, usage=usage)

    async def structured_chat(
        self,
        messages: Sequence[ChatMessage],
        schema: type[_T_Model],
        *,
        role: LLMRole = LLMRole.DEEP,
        budget: TokenBudget | None = None,
        max_retries: int = 2,
    ) -> _T_Model:
        """Call the LLM and parse the response as a ``schema`` instance.

        Issues a chat call with Ollama's ``format="json"`` hint and a
        trailing system message that pastes the requested JSON schema.
        On JSON-decode or :class:`ValidationError`, retries up to
        ``max_retries`` more times with a correction message that
        includes the validation failure. The supplied ``budget``
        covers every attempt - retries consume real Ollama tokens.

        Raises:
            BudgetExhaustedError: ``budget`` exhausted before any
                attempt (or before a retry).
            OllamaUnavailableError / OllamaResponseError: same shape
                as :meth:`chat`; transport / 4xx-5xx failures abort
                immediately without retry.
            StructuredOutputError: every attempt produced non-JSON
                or schema-incompatible JSON.
            ValueError: ``max_retries`` is negative.
        """
        if max_retries < 0:
            raise ValueError(f"max_retries must be >= 0, got {max_retries}")

        schema_json = json.dumps(schema.model_json_schema(), separators=(",", ":"))
        instruction = (
            "Respond with a single JSON object that conforms to this JSON "
            "schema. Output only the JSON object, with no surrounding text "
            f"or markdown. Schema: {schema_json}"
        )
        attempts: list[ChatMessage] = [
            *messages,
            ChatMessage(role="system", content=instruction),
        ]

        last_error: str | None = None
        for _ in range(max_retries + 1):
            if last_error is not None:
                attempts = [
                    *attempts,
                    ChatMessage(
                        role="user",
                        content=(
                            "The previous response could not be parsed: "
                            f"{last_error}. Return only valid JSON that "
                            "conforms to the schema."
                        ),
                    ),
                ]
            result = await self.chat(
                attempts,
                role=role,
                budget=budget,
                response_format="json",
            )
            try:
                data = json.loads(result.content)
            except json.JSONDecodeError as exc:
                last_error = f"invalid JSON: {exc.msg}"
                continue
            try:
                return schema.model_validate(data)
            except ValidationError as exc:
                last_error = f"schema validation failed: {exc.error_count()} error(s)"
                # Stash the assistant's actual JSON so the correction
                # message gives the model concrete context to fix.
                attempts = [
                    *attempts,
                    ChatMessage(role="assistant", content=result.content),
                ]

        raise StructuredOutputError(
            f"failed to produce schema-compliant JSON after "
            f"{max_retries + 1} attempt(s): {last_error}",
        )

    async def warm(self, role: LLMRole) -> None:
        """Pin the model for ``role`` in Ollama's memory.

        Issues a no-op ``POST /api/generate`` with ``prompt=""`` and
        ``keep_alive=-1`` so Ollama keeps the model resident until the
        next call. Used by :class:`anglerfish.llm.warmup.WarmPool` at
        startup and on a periodic refresh cycle. Raises the same error
        types as :meth:`chat`, but always with the ``/api/generate``
        endpoint name in the message so log entries are unambiguous.
        """
        payload: dict[str, Any] = {
            "model": self.model_for(role),
            "prompt": "",
            "stream": False,
            "keep_alive": -1,
        }
        try:
            response = await self._client.post("/api/generate", json=payload)
        except httpx.HTTPError as exc:
            raise OllamaUnavailableError(
                f"Ollama warm request failed: {type(exc).__name__}: {exc}",
            ) from exc

        if 500 <= response.status_code < 600:
            raise OllamaUnavailableError(
                f"Ollama warm returned server error {response.status_code}",
            )
        if response.status_code >= 400:
            body_preview = response.text[:200]
            raise OllamaResponseError(
                f"Ollama warm returned client error {response.status_code}: {body_preview!r}",
            )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()


def _parse_usage(data: dict[str, Any]) -> TokenUsage:
    """Pull ``prompt_eval_count`` + ``eval_count`` from Ollama's response.

    Both fields are optional in the Ollama protocol; missing or non-
    integer values default to 0. Used by Stage 5's token-budget
    machinery in a later slice; in slice 1 it's parsed and discarded
    by call sites that don't yet consult it.
    """
    return TokenUsage(
        prompt_tokens=_int_or_zero(data.get("prompt_eval_count")),
        completion_tokens=_int_or_zero(data.get("eval_count")),
    )


def _int_or_zero(value: Any) -> int:
    if isinstance(value, int) and value >= 0:
        return value
    return 0
