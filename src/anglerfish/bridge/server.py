"""HTTP transport in front of :class:`AIBridgeService`.

Cowrie runs as a separate process; the bridge must be reachable from
that process. Rather than embedding the bridge in Cowrie's Python (an
intrusive patch), Anglerfish exposes a small loopback-only HTTP API
that Cowrie's output plugin and command handler call.

The API has three endpoints:

* ``POST /api/v1/session`` — register a session, return its UUID and
  the configured fake prompt.
* ``POST /api/v1/session/{id}/command`` — submit one command,
  receive the AI shell response.
* ``DELETE /api/v1/session/{id}`` — release session state when the
  attacker disconnects.

Sessions are kept in memory: this server is intended to be co-located
with Cowrie on the bait host and never has more than a few hundred
concurrent sessions. Captured state is persisted by the forwarder /
dashboard / credentials store, not by this server.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from anglerfish import __version__
from anglerfish.bridge.defense import ModelIntegrity
from anglerfish.bridge.service import AIBridgeService
from anglerfish.bridge.session import SessionContext

__all__ = [
    "PROTOCOL_VERSION",
    "BearerTokenMiddleware",
    "CommandRequest",
    "CommandResponse",
    "SessionStartRequest",
    "SessionStartResponse",
    "create_bridge_app",
]


# Bumped only on breaking changes to the bridge wire protocol.
PROTOCOL_VERSION = "1"

_PROTOCOL_HEADER = "X-Anglerfish-Protocol"
_AUTH_HEADER = "Authorization"
_OPEN_PATHS = frozenset({"/api/health"})


class BearerTokenMiddleware(BaseHTTPMiddleware):
    """Require ``Authorization: Bearer <secret>`` on every non-health route.

    When the configured ``shared_secret`` is ``None`` the middleware is
    permissive (development mode). In production the wizard always
    generates a secret, so this should be active.

    Also enforces the protocol-version header for clients that send it —
    a mismatch is a 426 Upgrade Required.
    """

    def __init__(self, app: ASGIApp, *, expected_secret: str | None) -> None:
        super().__init__(app)
        self._expected_secret = expected_secret

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        if request.url.path in _OPEN_PATHS:
            return await call_next(request)

        client_protocol = request.headers.get(_PROTOCOL_HEADER)
        if client_protocol is not None and client_protocol != PROTOCOL_VERSION:
            return JSONResponse(
                status_code=status.HTTP_426_UPGRADE_REQUIRED,
                content={
                    "detail": (
                        f"bridge protocol mismatch: client={client_protocol!r} "
                        f"server={PROTOCOL_VERSION!r}"
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
    import hmac

    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


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


class CommandRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str = Field(..., max_length=32768)


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
) -> FastAPI:
    """Build the FastAPI app that exposes ``service`` over HTTP.

    ``integrity`` runs once during startup (lifespan enter) before any
    requests are accepted. When unset, the integrity check is skipped
    entirely — useful for tests and dev loops; production deployments
    should construct it from settings.defense and pass it here.

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
            await integrity.verify()
        yield
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
        ctx = SessionContext(
            uuid4(),
            source_ip=req.source_ip,
            username=req.username,
            fake_hostname=settings.bridge.fake_hostname,
            fake_username=settings.bridge.fake_username,
            fake_cwd=settings.bridge.fake_cwd,
            history_window=settings.bridge.history_window,
        )
        async with lock:
            sessions[ctx.session_id] = ctx
        logger.info(
            "bridge.session_started id=%s source_ip=%s",
            ctx.session_id,
            req.source_ip,
        )
        return SessionStartResponse(
            session_id=ctx.session_id,
            fake_hostname=ctx.fake_hostname,
            fake_username=ctx.fake_username,
            fake_cwd=ctx.cwd,
        )

    @app.post("/api/v1/session/{session_id}/command", response_model=CommandResponse)
    async def handle_command(
        session_id: UUID,
        req: CommandRequest,
    ) -> CommandResponse:
        async with lock:
            ctx = sessions.get(session_id)
        if ctx is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
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
            sessions.pop(session_id, None)
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
