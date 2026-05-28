"""Async HTTP client the lure uses to reach the bridge.

The bridge is a separate process on the same VM, listening on
loopback. This client is the lure-side half of the boundary the
design doc preserves on purpose: privilege separation, crash
isolation, future-container-ability. See
``docs/design/STAGE_2_lure_subsystem.md`` "Process topology" for the
full reasoning.

Every method either returns a typed result or raises
:class:`BridgeUnavailableError`. Callers always have a single failure
mode to handle; the network shape stays hidden behind the abstraction.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, Self
from uuid import UUID

import httpx
from pydantic import HttpUrl

__all__ = [
    "PROTOCOL_VERSION_HEADER",
    "BridgeClient",
    "BridgeStreamChunk",
    "BridgeUnavailableError",
    "OpenSessionResult",
]


PROTOCOL_VERSION_HEADER = "X-Anglerfish-Protocol"
_LURE_PROTOCOL_VERSION = "3"
_DEFAULT_USERNAME_MAX_LEN = 64


@dataclass(frozen=True)
class OpenSessionResult:
    """Outcome of :meth:`BridgeClient.open_session`.

    Carries everything the lure needs to construct a
    :class:`LureSessionContext` without a second round-trip.
    ``fake_*`` come from the bridge's chosen persona (Stage 9) or
    its ``BridgeConfig.fake_*`` defaults when persona support is
    disabled. ``persona_name`` is the registry key the bridge
    picked (or ``None`` when persona is disabled);
    ``persona_overlay`` is the persona's ``fakefs_overlay`` dict
    (empty when persona is disabled or the persona has no
    overlay paths).
    """

    session_id: UUID
    fake_hostname: str
    fake_username: str
    fake_cwd: str
    persona_name: str | None
    persona_overlay: dict[str, str]
    # Stage 12: fakefs paths the lure should garble for this session.
    # Non-empty only when the bridge engaged counter-deception for this
    # source IP on a prior session. Empty tuple for the common case.
    counter_deception_garble_paths: tuple[str, ...]


@dataclass(frozen=True)
class BridgeStreamChunk:
    """One streamed chunk parsed from the bridge's ``?stream=1`` response.

    Mirrors the NDJSON shape the bridge emits: ``delta`` is the
    incremental text, ``source`` is ``"ai"`` / ``"fallback"`` /
    ``"rejected"``, ``done`` flags the terminal chunk, and
    ``latency_ms`` / ``cwd`` are populated only on the terminal chunk.
    """

    delta: str
    source: str
    done: bool
    latency_ms: float | None = None
    cwd: str | None = None


class BridgeUnavailableError(RuntimeError):
    """Raised on any failure to reach or parse a response from the bridge.

    Collapses network errors, HTTP 4xx (including 401 auth failure and
    426 protocol mismatch), HTTP 5xx, and malformed JSON into a single
    exception type. The lure responds to all of them the same way:
    fall back to scripted responses and keep the attacker session
    alive.
    """


class BridgeClient:
    """Async HTTP client wrapping the bridge's :mod:`bridge.server` API.

    Owns its underlying :class:`httpx.AsyncClient` by default. Tests
    inject their own so :class:`httpx.MockTransport` can drive
    deterministic responses. Owned clients close in :meth:`aclose`;
    injected ones are left to the caller.
    """

    def __init__(
        self,
        *,
        base_url: HttpUrl,
        shared_secret: str | None,
        request_timeout_s: float,
        connect_timeout_s: float,
        http_client: httpx.AsyncClient | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._logger = logger if logger is not None else logging.getLogger(__name__)
        self._owns_client = http_client is None
        headers = {
            PROTOCOL_VERSION_HEADER: _LURE_PROTOCOL_VERSION,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "anglerfish-lure/0.1.0",
        }
        if shared_secret:
            headers["Authorization"] = f"Bearer {shared_secret}"
        if http_client is None:
            timeout = httpx.Timeout(
                request_timeout_s,
                connect=connect_timeout_s,
            )
            self._http = httpx.AsyncClient(
                base_url=str(base_url),
                timeout=timeout,
                headers=headers,
            )
        else:
            self._http = http_client
            # Update headers in-place so injected clients also send the
            # right auth + protocol version without forcing tests to
            # set them up identically.
            self._http.headers.update(headers)

    async def open_session(
        self,
        *,
        source_ip: str,
        username: str,
    ) -> OpenSessionResult:
        """Register a new session with the bridge.

        Returns an :class:`OpenSessionResult` carrying the bridge's
        UUID, the persona-resolved fake_* fields, and (Stage 9) the
        persona name + fakefs_overlay so the lure can mirror them
        on its side. The bridge enforces ``username`` length <= 64
        via Pydantic; the lure trims here so attackers sending
        oversize usernames see the session open (and get captured
        by CredentialStore) rather than the bridge rejecting with
        422.
        """
        if not source_ip:
            raise ValueError("source_ip cannot be empty")
        if not username:
            username = "root"
        trimmed_username = username[:_DEFAULT_USERNAME_MAX_LEN]

        payload: dict[str, Any] = {
            "source_ip": source_ip,
            "username": trimmed_username,
        }
        body = await self._post_json("/api/v1/session", payload)
        sid_raw = body.get("session_id")
        if not isinstance(sid_raw, str) or not sid_raw:
            raise BridgeUnavailableError(
                f"bridge open_session response missing session_id: {body!r}",
            )
        try:
            session_id = UUID(sid_raw)
        except ValueError as exc:
            raise BridgeUnavailableError(
                f"bridge open_session returned non-UUID session_id: {sid_raw!r}",
            ) from exc
        fake_hostname = body.get("fake_hostname")
        fake_username = body.get("fake_username")
        fake_cwd = body.get("fake_cwd")
        if (
            not isinstance(fake_hostname, str)
            or not isinstance(fake_username, str)
            or not isinstance(fake_cwd, str)
        ):
            raise BridgeUnavailableError(
                f"bridge open_session missing fake_* fields: {body!r}",
            )
        persona_name_raw = body.get("persona_name")
        persona_name = persona_name_raw if isinstance(persona_name_raw, str) else None
        overlay_raw = body.get("persona_overlay", {})
        persona_overlay = _coerce_overlay(overlay_raw)
        garble_raw = body.get("counter_deception_garble_paths", [])
        counter_deception_garble_paths = _coerce_str_tuple(garble_raw)
        return OpenSessionResult(
            session_id=session_id,
            fake_hostname=fake_hostname,
            fake_username=fake_username,
            fake_cwd=fake_cwd,
            persona_name=persona_name,
            persona_overlay=persona_overlay,
            counter_deception_garble_paths=counter_deception_garble_paths,
        )

    async def submit_command(
        self,
        session_id: UUID,
        command: str,
        *,
        fs_context: str | None = None,
    ) -> str:
        """Submit one command and return the response text.

        ``fs_context`` rides through protocol v2 and is the lure's way
        of telling the bridge prompt builder which paths the lure
        already serves natively (so LLM-invented content stays
        consistent with the static fakefs).
        """
        payload: dict[str, Any] = {"command": command}
        if fs_context is not None:
            payload["fs_context"] = fs_context
        body = await self._post_json(
            f"/api/v1/session/{session_id}/command",
            payload,
        )
        text = body.get("text", "")
        if not isinstance(text, str):
            raise BridgeUnavailableError(
                f"bridge submit_command returned non-string text: {body!r}",
            )
        return text

    async def command_stream(
        self,
        session_id: UUID,
        command: str,
        *,
        fs_context: str | None = None,
    ) -> AsyncIterator[BridgeStreamChunk]:
        """Stream one command's response from the bridge as NDJSON chunks.

        Protocol v3 only. Yields one :class:`BridgeStreamChunk` per
        NDJSON line; the terminal chunk has ``done=True`` and may
        carry ``latency_ms`` + ``cwd``. Caller is responsible for
        writing each delta to the attacker terminal as it arrives.

        Any network failure, non-2xx response, or malformed chunk
        raises :class:`BridgeUnavailableError` so the lure's existing
        fallback path applies uniformly. Failures mid-stream leave
        any already-yielded chunks intact - the caller has already
        written them to the attacker.
        """
        payload: dict[str, Any] = {"command": command}
        if fs_context is not None:
            payload["fs_context"] = fs_context
        path = f"/api/v1/session/{session_id}/command"
        try:
            async with self._http.stream(
                "POST",
                path,
                params={"stream": "1"},
                json=payload,
            ) as response:
                await self._raise_for_stream_status(response, path)
                async for line in response.aiter_lines():
                    stripped = line.strip()
                    if not stripped:
                        continue
                    yield _parse_stream_chunk(stripped, path)
        except httpx.HTTPError as exc:
            raise BridgeUnavailableError(
                f"bridge {path} network failure: {type(exc).__name__}: {exc}",
            ) from exc

    async def _raise_for_stream_status(
        self,
        response: httpx.Response,
        path: str,
    ) -> None:
        """Translate the stream's HTTP status into BridgeUnavailableError."""
        if response.status_code == 426:
            self._logger.error(
                "bridge protocol mismatch at %s: server rejected protocol %s",
                path,
                _LURE_PROTOCOL_VERSION,
            )
            raise BridgeUnavailableError(
                f"bridge {path}: protocol mismatch (server returned 426)",
            )
        if response.status_code == 401:
            raise BridgeUnavailableError(
                f"bridge {path}: authentication rejected (401); "
                "check ANGLERFISH_BRIDGE__SHARED_SECRET",
            )
        if response.status_code >= 500:
            raise BridgeUnavailableError(
                f"bridge {path}: server error HTTP {response.status_code}",
            )
        if response.status_code >= 400:
            body = await response.aread()
            raise BridgeUnavailableError(
                f"bridge {path}: client error HTTP {response.status_code}: {body[:200]!r}",
            )

    async def close_session(self, session_id: UUID) -> None:
        """Release the bridge-side state for ``session_id``.

        Idempotent and silent on 404 (already-closed sessions). Other
        errors propagate as :class:`BridgeUnavailableError`. The lure
        treats a failed close as "bridge has lost the session anyway"
        and moves on.
        """
        try:
            response = await self._http.delete(f"/api/v1/session/{session_id}")
        except httpx.HTTPError as exc:
            raise BridgeUnavailableError(
                f"bridge close_session network failure: {type(exc).__name__}: {exc}",
            ) from exc
        if response.status_code == 404:
            return  # already gone, nothing to do
        if response.status_code >= 400:
            raise BridgeUnavailableError(
                f"bridge close_session returned HTTP {response.status_code}",
            )

    async def _post_json(
        self,
        path: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            response = await self._http.post(path, json=payload)
        except httpx.HTTPError as exc:
            raise BridgeUnavailableError(
                f"bridge {path} network failure: {type(exc).__name__}: {exc}",
            ) from exc

        if response.status_code == 426:
            self._logger.error(
                "bridge protocol mismatch at %s: server rejected protocol %s",
                path,
                _LURE_PROTOCOL_VERSION,
            )
            raise BridgeUnavailableError(
                f"bridge {path}: protocol mismatch (server returned 426)",
            )
        if response.status_code == 401:
            raise BridgeUnavailableError(
                f"bridge {path}: authentication rejected (401); "
                "check ANGLERFISH_BRIDGE__SHARED_SECRET",
            )
        if response.status_code >= 500:
            raise BridgeUnavailableError(
                f"bridge {path}: server error HTTP {response.status_code}",
            )
        if response.status_code >= 400:
            raise BridgeUnavailableError(
                f"bridge {path}: client error HTTP {response.status_code}: {response.text[:200]}",
            )

        try:
            body = response.json()
        except ValueError as exc:
            raise BridgeUnavailableError(
                f"bridge {path} returned malformed JSON: {exc}",
            ) from exc
        if not isinstance(body, dict):
            raise BridgeUnavailableError(
                f"bridge {path} returned non-object JSON: {type(body).__name__}",
            )
        return body

    async def aclose(self) -> None:
        """Close the underlying HTTP client iff this instance owns it."""
        if self._owns_client:
            await self._http.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()


def _coerce_overlay(raw: Any) -> dict[str, str]:
    """Coerce the persona_overlay field from open_session into a typed dict.

    Returns an empty dict for any non-mapping payload or for
    entries whose key/value is not a string. Tolerant by design:
    the lure never crashes on a bridge-side schema regression;
    a missing overlay just means the static fakefs base applies
    everywhere (the pre-Stage-9 behaviour).
    """
    if not isinstance(raw, dict):
        return {}
    return {k: v for k, v in raw.items() if isinstance(k, str) and isinstance(v, str)}


def _coerce_str_tuple(raw: Any) -> tuple[str, ...]:
    """Coerce a JSON array field into a tuple of strings.

    Tolerant by design (same posture as :func:`_coerce_overlay`): a
    non-list payload or non-string entries yield an empty tuple so a
    bridge-side schema regression never crashes the lure. Stage 12's
    counter_deception_garble_paths uses this.
    """
    if not isinstance(raw, list):
        return ()
    return tuple(item for item in raw if isinstance(item, str))


def _parse_stream_chunk(line: str, path: str) -> BridgeStreamChunk:
    """Validate and parse one NDJSON line into a :class:`BridgeStreamChunk`."""
    try:
        payload = json.loads(line)
    except ValueError as exc:
        raise BridgeUnavailableError(
            f"bridge {path} returned malformed chunk: {exc}",
        ) from exc
    if not isinstance(payload, dict):
        raise BridgeUnavailableError(
            f"bridge {path} chunk is not a JSON object: {type(payload).__name__}",
        )
    delta = payload.get("delta")
    source = payload.get("source")
    if not isinstance(delta, str) or not isinstance(source, str):
        raise BridgeUnavailableError(
            f"bridge {path} chunk missing delta/source: {payload!r}",
        )
    latency_raw = payload.get("latency_ms")
    latency_ms = float(latency_raw) if isinstance(latency_raw, (int, float)) else None
    cwd_raw = payload.get("cwd")
    cwd = cwd_raw if isinstance(cwd_raw, str) else None
    return BridgeStreamChunk(
        delta=delta,
        source=source,
        done=bool(payload.get("done", False)),
        latency_ms=latency_ms,
        cwd=cwd,
    )
