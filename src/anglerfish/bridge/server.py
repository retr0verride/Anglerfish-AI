"""HTTP transport in front of :class:`AIBridgeService`.

The lure runs as a separate process; the bridge must be reachable
from that process. Anglerfish exposes a small loopback-only HTTP API
that the lure's bridge client calls.

The API has three endpoints:

* ``POST /api/v1/session`` — register a session, return its UUID and
  the configured fake prompt.
* ``POST /api/v1/session/{id}/command`` — submit one command,
  receive the AI shell response.
* ``DELETE /api/v1/session/{id}`` — release session state when the
  attacker disconnects.

Sessions are kept in memory: this server is intended to be co-located
with the lure on the bait host and never has more than a few hundred
concurrent sessions. Captured state is persisted by the Stage 4
session store (populated by the dashboard's audit-log tailer) and
the credentials store, not by this server.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from anglerfish import __version__
from anglerfish.bridge.defense import ModelIntegrity
from anglerfish.bridge.service import AIBridgeService
from anglerfish.bridge.session import SessionContext
from anglerfish.llm.warmup import WarmPool

__all__ = [
    "PROTOCOL_VERSION",
    "SUPPORTED_PROTOCOLS",
    "BearerTokenMiddleware",
    "CommandRequest",
    "CommandResponse",
    "SessionStartRequest",
    "SessionStartResponse",
    "create_bridge_app",
]


# Bumped only on breaking changes to the bridge wire protocol.
PROTOCOL_VERSION = "3"

# Versions the server still accepts on incoming requests. Stage 2A
# bumped to "2" to add CommandRequest.fs_context. Stage 5 slice 4
# bumps to "3" to add the additive ``?stream=1`` flag on the command
# endpoint (NDJSON streaming response). v2 stays accepted for one
# release cycle so a rolled-back lure keeps working against a v3
# bridge. Protocol "1" was the Cowrie shim's version; both Cowrie
# and its v1 acceptance path were removed in 2026-05.
SUPPORTED_PROTOCOLS: frozenset[str] = frozenset({"2", "3"})

_PROTOCOL_HEADER = "X-Anglerfish-Protocol"
_AUTH_HEADER = "Authorization"
_OPEN_PATHS = frozenset({"/api/health"})


class BearerTokenMiddleware(BaseHTTPMiddleware):
    """Require ``Authorization: Bearer <secret>`` on every non-health route.

    When the configured ``shared_secret`` is ``None`` the middleware is
    permissive (development mode). In production the wizard always
    generates a secret, so this should be active.

    Also enforces the protocol-version header for clients that send it.
    An unrecognised version is a 426 Upgrade Required; the response
    lists every supported version so the client can pick one.
    """

    def __init__(self, app: ASGIApp, *, expected_secret: str | None) -> None:
        super().__init__(app)
        self._expected_secret = expected_secret

    async def dispatch(  # type: ignore[no-untyped-def]  # starlette's dispatch signature uses untyped Callable for call_next
        self,
        request: Request,
        call_next,
    ):
        if request.url.path in _OPEN_PATHS:
            return await call_next(request)

        client_protocol = request.headers.get(_PROTOCOL_HEADER)
        if client_protocol is not None and client_protocol not in SUPPORTED_PROTOCOLS:
            return JSONResponse(
                status_code=status.HTTP_426_UPGRADE_REQUIRED,
                content={
                    "detail": (
                        f"bridge protocol unsupported: client={client_protocol!r} "
                        f"supported={sorted(SUPPORTED_PROTOCOLS)!r}"
                    ),
                },
            )

        if self._expected_secret is not None:
            auth = request.headers.get(_AUTH_HEADER, "")
            expected = f"Bearer {self._expected_secret}"
            if not _constant_time_equals(auth, expected):
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "missing or invalid bearer token"},
                )
        return await call_next(request)


def _constant_time_equals(a: str, b: str) -> bool:
    """Length-aware constant-time string compare to resist timing oracles."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


async def _stream_command(
    service: AIBridgeService,
    ctx: SessionContext,
    command: str,
) -> AsyncIterator[bytes]:
    """Render :meth:`AIBridgeService.handle_command_stream` as NDJSON bytes.

    One JSON object per line. Terminal line (``done=true``) carries
    ``latency_ms`` and ``cwd`` so the lure can update its prompt without
    a separate request.
    """
    async for chunk in service.handle_command_stream(ctx, command):
        payload: dict[str, object] = {
            "delta": chunk.delta,
            "source": str(chunk.source),
            "done": chunk.done,
        }
        if chunk.done:
            payload["latency_ms"] = chunk.latency_ms
            payload["cwd"] = ctx.cwd
        yield (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")


class SessionStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_ip: str = Field(..., min_length=1, max_length=64)
    username: str = Field(default="root", min_length=1, max_length=64)


class SessionStartResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: UUID
    fake_hostname: str
    fake_username: str
    fake_cwd: str
    # Stage 9: present when the bridge selected a persona for this
    # session. The lure mirrors the persona on its side so its native
    # fakefs handler consults the overlay before the static base, and
    # so subsequent submit_command calls send the right fs_context.
    # Absent (None / empty) when settings.persona.enabled=False or
    # no selector is wired - the lure falls back to its
    # container.config.hostname pre-Stage-9 behaviour.
    persona_name: str | None = None
    persona_overlay: dict[str, str] = Field(default_factory=dict)


class CommandRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str = Field(..., max_length=32768)
    fs_context: str | None = Field(
        default=None,
        max_length=4096,
        description=(
            "Optional compact summary of the static filesystem layout "
            "the lure is presenting, passed in protocol v2. The bridge "
            "prompt builder uses it to keep LLM-invented file contents "
            "consistent with what the lure already serves natively. "
            "Omitting the field stays compatible by virtue of the default."
        ),
    )


class CommandResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str
    source: str
    latency_ms: float
    cwd: str


def create_bridge_app(
    service: AIBridgeService,
    *,
    integrity: ModelIntegrity | None = None,
    warm_pool: WarmPool | None = None,
) -> FastAPI:
    """Build the FastAPI app that exposes ``service`` over HTTP.

    ``integrity`` runs once during startup (lifespan enter) before any
    requests are accepted. When unset, the integrity check is skipped
    entirely — useful for tests and dev loops; production deployments
    should construct it from settings.defense and pass it here.

    ``warm_pool`` is an optional :class:`anglerfish.llm.WarmPool`; when
    supplied, its background tasks start in the lifespan and are
    cancelled in teardown. Production deployments construct it from the
    LLMClient that backs the AIBridgeService.

    A :class:`ModelIntegrityError` raised by ``integrity.verify()``
    propagates out of the lifespan, which uvicorn surfaces as a
    non-zero process exit. The bridge does not start in that state.
    """
    logger = logging.getLogger(__name__)
    settings = service.settings
    sessions: dict[UUID, SessionContext] = {}
    lock = asyncio.Lock()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        if integrity is not None:
            # Raises ModelIntegrityError on hash mismatch; uvicorn then
            # exits non-zero. Refuse-to-serve is the correct posture for
            # a backdoored/swapped model — see Stage 1 design doc.
            #
            # 10-second timeout protects startup from a stalled NFS
            # mount or other filesystem hang on the manifest read; the
            # work itself is a single small JSON parse so the budget is
            # generous. A TimeoutError surfaces as a bridge.model_
            # integrity_failed audit event via verify()'s own except
            # block and aborts startup with a clean operator message.
            try:
                await asyncio.wait_for(integrity.verify(), timeout=10.0)
            except TimeoutError as exc:
                logger.error(
                    "model integrity check timed out after 10s; "
                    "check that ollama_manifest_dir is reachable. "
                    "Path: %s",
                    integrity.manifest_root,
                )
                raise RuntimeError(
                    "model integrity check timed out — see logs",
                ) from exc
        if warm_pool is not None:
            await warm_pool.start()
        try:
            yield
        finally:
            if warm_pool is not None:
                await warm_pool.stop()
            await service.aclose()

    app = FastAPI(
        title="Anglerfish Bridge",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    secret = settings.bridge.shared_secret
    app.add_middleware(
        BearerTokenMiddleware,
        expected_secret=secret.get_secret_value() if secret is not None else None,
    )
    app.state.service = service
    app.state.sessions = sessions

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post("/api/v1/session", response_model=SessionStartResponse)
    async def start_session(req: SessionStartRequest) -> SessionStartResponse:
        # Stage 9: ask the service for a persona before constructing
        # the SessionContext. select_persona returns None when
        # persona support is disabled (settings.persona.enabled=False)
        # or no selector was wired; SessionContext then falls back to
        # the BridgeConfig.fake_* defaults via the persona=None path.
        selection = await service.select_persona(req.source_ip)
        if selection is not None:
            persona = selection.persona
            fake_hostname = persona.hostname
            fake_username = persona.username
            fake_cwd = persona.cwd
        else:
            persona = None
            fake_hostname = settings.bridge.fake_hostname
            fake_username = settings.bridge.fake_username
            fake_cwd = settings.bridge.fake_cwd
        # Stage 10: seed the new session's in-memory
        # persistence_events list from any prior cross-session
        # installs for this source IP. Returns an empty list when
        # engaged_persistence is disabled or no reader is wired.
        prior_events = await service.load_persistence_for_source_ip(req.source_ip)
        # Stage 11: load static-base + per-IP honeytokens for the
        # fakefs_overlay merge. Returns an empty list when
        # honeytokens.enabled=False or no reader is wired.
        honeytokens = await service.load_honeytokens_for_source_ip(req.source_ip)
        ctx = SessionContext(
            uuid4(),
            source_ip=req.source_ip,
            username=req.username,
            fake_hostname=fake_hostname,
            fake_username=fake_username,
            fake_cwd=fake_cwd,
            history_window=settings.bridge.history_window,
            persona=persona,
            persistence_events=prior_events,
        )
        async with lock:
            sessions[ctx.session_id] = ctx
        # Stage 11: record source_ip for the
        # record_threat_assessment honeytoken-placement hook to
        # look up.
        service.record_session_source_ip(ctx.session_id, req.source_ip)
        # Pre-deploy sweep TODO-8: seed the activity timestamp so
        # idle-eviction sees the session as live from its opening
        # moment (a session whose first command never lands still
        # gets pruned after the cutoff).
        service.record_session_activity(ctx.session_id)
        if selection is not None:
            service.record_persona_selected(
                session_id=ctx.session_id,
                source_ip=req.source_ip,
                result=selection,
            )
        logger.info(
            "bridge.session_started id=%s source_ip=%s persona=%s",
            ctx.session_id,
            req.source_ip,
            ctx.persona_name,
        )
        # Stage 11: merge honeytoken payloads into the persona's
        # existing fakefs_overlay. Honeytoken paths override any
        # persona-defined entry at the same path (operator-
        # surprising; documented in HONEYTOKENS.md). The lure's
        # native cat handler serves the merged overlay as the
        # file content the attacker exfiltrates.
        overlay: dict[str, str] = dict(persona.fakefs_overlay) if persona is not None else {}
        for token in honeytokens:
            overlay[token.placed_at] = token.payload
        return SessionStartResponse(
            session_id=ctx.session_id,
            fake_hostname=ctx.fake_hostname,
            fake_username=ctx.fake_username,
            fake_cwd=ctx.cwd,
            persona_name=persona.name if persona is not None else None,
            persona_overlay=overlay,
        )

    @app.post("/api/v1/session/{session_id}/command", response_model=None)
    async def handle_command(
        session_id: UUID,
        req: CommandRequest,
        stream: bool = False,
    ) -> CommandResponse | StreamingResponse:
        """Submit one command for the session.

        Set ``?stream=1`` (protocol v3) for an NDJSON streaming
        response: one JSON object per line with ``delta``, ``source``,
        and ``done``; the terminal ``done=true`` line also carries
        ``latency_ms`` and ``cwd``. Without the flag, returns a single
        :class:`CommandResponse` body (protocol v2 behaviour).
        """
        # Pre-deploy sweep TODO-8: sweep idle sessions before the
        # lookup. Eviction is amortised across every per-session
        # command request (no background task). Drop any evicted
        # SessionContext entries the service no longer tracks so
        # the server-side dict stays in lock-step with the service.
        evicted = service.evict_idle_sessions()
        if evicted:
            async with lock:
                for sid in evicted:
                    sessions.pop(sid, None)
        async with lock:
            ctx = sessions.get(session_id)
        if ctx is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        service.record_session_activity(session_id)
        # Stage 10: classify pre-LLM so the current command's prompt
        # build sees the new install in its persistence_events block.
        # Classifier errors are swallowed inside classify_command +
        # audited as bridge.persistence_classifier_error.
        await service.classify_command(req.command, session=ctx)
        if stream:
            return StreamingResponse(
                _stream_command(service, ctx, req.command),
                media_type="application/x-ndjson",
            )
        result = await service.handle_command(ctx, req.command)
        return CommandResponse(
            text=result.text,
            source=str(result.source),
            latency_ms=result.latency_ms,
            cwd=ctx.cwd,
        )

    @app.delete("/api/v1/session/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def end_session(session_id: UUID) -> None:
        async with lock:
            ctx = sessions.pop(session_id, None)
        # Stage 7 + 8: snapshot before per-session state drops + spawn
        # both the intent-extraction and embedding-generation tasks.
        # Both run fire-and-forget with their own wall-clock timeouts;
        # this endpoint returns 204 immediately regardless of either
        # outcome. Stage 7 intent goes through the deep tier; Stage 8
        # embedding goes through the embed tier - independent budgets.
        if ctx is not None:
            snapshot = ctx.snapshot()
            service.schedule_intent_extraction(snapshot)
            service.schedule_embedding_generation(snapshot)
        service.end_session_budget(session_id)
        logger.info("bridge.session_ended id=%s", session_id)

    @app.get("/api/v1/sessions")
    async def list_sessions(_request: Request) -> list[dict[str, str]]:
        async with lock:
            return [
                {
                    "session_id": str(sid),
                    "source_ip": ctx.source_ip,
                    "cwd": ctx.cwd,
                }
                for sid, ctx in sessions.items()
            ]

    return app
