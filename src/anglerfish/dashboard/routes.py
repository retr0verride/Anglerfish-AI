"""REST routes for the dashboard.

Each route is a thin shim over :class:`DashboardState` plus the
optional :class:`CredentialStore`. The auth dependency
(:func:`anglerfish.dashboard.auth.require_auth`) is applied at router
level so every endpoint requires authentication — except
``/`` (renders the login-aware SPA), ``/api/health`` (used by load
balancers and service probes), and ``/api/login``/``/api/logout``
(wired separately by :func:`build_auth_router`).
"""

from __future__ import annotations

from typing import Any, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from anglerfish import __version__
from anglerfish.dashboard.auth import is_open_mode, require_auth
from anglerfish.dashboard.state import DashboardState
from anglerfish.models.credentials import CredentialRecord, CredentialStats
from anglerfish.models.session import SessionSnapshot
from anglerfish.models.threat import ThreatAssessment

__all__ = ["build_router"]


def _get_state(request: Request) -> DashboardState:
    state = getattr(request.app.state, "dashboard_state", None)
    if state is None:  # pragma: no cover - guarded at startup
        raise RuntimeError("DashboardState not attached to app.state")
    return cast("DashboardState", state)


def _get_credential_store(request: Request) -> Any | None:
    return getattr(request.app.state, "credential_store", None)


def build_router(*, templates: Jinja2Templates) -> APIRouter:
    """Return a router wired to the configured templates directory."""
    router = APIRouter()

    @router.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        config = request.app.state.settings.dashboard
        return cast(
            "HTMLResponse",
            templates.TemplateResponse(
                request,
                "index.html",
                {
                    "version": __version__,
                    "open_mode": is_open_mode(config),
                    "admin_username": config.admin_username,
                },
            ),
        )

    @router.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @router.get("/api/stats", dependencies=[Depends(require_auth)])
    async def stats(
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> dict[str, Any]:
        snap = await state.get_stats()
        return snap.model_dump(mode="json")

    @router.get("/api/sessions", dependencies=[Depends(require_auth)])
    async def list_sessions(
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> list[dict[str, Any]]:
        sessions: list[SessionSnapshot] = await state.get_active_sessions()
        return [s.model_dump(mode="json") for s in sessions]

    @router.get(
        "/api/sessions/{session_id}",
        dependencies=[Depends(require_auth)],
    )
    async def get_session(
        session_id: UUID,
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> dict[str, Any]:
        session = await state.get_session(session_id)
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        return session.model_dump(mode="json")

    @router.get("/api/commands", dependencies=[Depends(require_auth)])
    async def recent_commands(
        limit: int = Query(default=100, ge=1, le=1000),
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> list[dict[str, Any]]:
        return await state.get_recent_commands(limit=limit)

    @router.get("/api/threats", dependencies=[Depends(require_auth)])
    async def recent_threats(
        limit: int = Query(default=50, ge=1, le=500),
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> list[dict[str, Any]]:
        threats: list[ThreatAssessment] = await state.get_recent_threats(limit=limit)
        return [t.model_dump(mode="json") for t in threats]

    @router.get("/api/credentials", dependencies=[Depends(require_auth)])
    async def list_credentials(
        limit: int = Query(default=100, ge=1, le=1000),
        offset: int = Query(default=0, ge=0, le=100_000),
        source_ip: str | None = Query(default=None, max_length=64),
        store: Any | None = Depends(_get_credential_store),  # noqa: B008
    ) -> dict[str, Any]:
        if store is None:
            return {"records": [], "configured": False}
        records: list[CredentialRecord] = await store.query(
            limit=limit,
            offset=offset,
            source_ip=source_ip,
        )
        return {
            "records": [r.model_dump(mode="json") for r in records],
            "configured": True,
        }

    @router.get(
        "/api/credentials/stats",
        dependencies=[Depends(require_auth)],
    )
    async def credential_stats(
        store: Any | None = Depends(_get_credential_store),  # noqa: B008
    ) -> dict[str, Any]:
        if store is None:
            return {"configured": False}
        stats: CredentialStats = await store.stats()
        return {**stats.model_dump(mode="json"), "configured": True}

    return router
