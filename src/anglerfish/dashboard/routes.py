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

from typing import Any, Literal, cast
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field

from anglerfish import __version__
from anglerfish.audit import AuditLog
from anglerfish.dashboard.alerts import ALERT_KINDS, ALERT_STUBS, list_alerts
from anglerfish.dashboard.auth import is_open_mode, require_auth
from anglerfish.dashboard.csrf import require_csrf
from anglerfish.dashboard.export import (
    ExportRangeError,
    audit_export_payload,
    parse_range,
    session_csv_rows,
    session_export_payload,
)
from anglerfish.dashboard.health import (
    ollama_health,
    sessions_health,
)
from anglerfish.dashboard.overrides import RuntimeOverrides, WastingStrategy
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


def _get_overrides(request: Request) -> RuntimeOverrides:
    overrides = getattr(request.app.state, "runtime_overrides", None)
    if overrides is None:  # pragma: no cover - attached in create_app
        raise RuntimeError("runtime_overrides not attached to app.state")
    return cast("RuntimeOverrides", overrides)


def _get_audit(request: Request) -> AuditLog:
    audit = getattr(request.app.state, "audit", None)
    if audit is None:  # pragma: no cover - attached in create_app
        raise RuntimeError("audit log not attached to app.state")
    return cast("AuditLog", audit)


def _get_overrides_publisher(request: Request) -> Any:
    """Return the runtime-overrides publisher, or None if not attached.

    Older test fixtures construct create_app paths that omit the
    publisher; the routes degrade to in-process-only override updates
    in that case so existing tests continue to pass.
    """
    return getattr(request.app.state, "overrides_publisher", None)


# ---------------------------------------------------------------------------
# Stage 3 request bodies for the settings POSTs. Kept here rather than in
# overrides.py because they are HTTP-layer schemas (Pydantic + bounds);
# overrides.py is the in-process mutation API.
# ---------------------------------------------------------------------------


class _BridgeSettingsUpdate(BaseModel):
    """POST /api/settings/bridge request body. All fields optional."""

    model_config = ConfigDict(extra="forbid")

    max_concurrent_requests: int | None = Field(default=None, ge=1, le=128)
    requests_per_session_per_minute: int | None = Field(default=None, ge=1, le=600)
    wasting_strategy: WastingStrategy | None = None


class _FeatureFlagsUpdate(BaseModel):
    """POST /api/settings/features request body. All fields optional."""

    model_config = ConfigDict(extra="forbid")

    time_wasting: bool | None = None
    engaged_persistence: bool | None = None
    decoy_poisoning: bool | None = None
    counter_deception: bool | None = None


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

    # -----------------------------------------------------------------
    # Stage 3: settings control plane
    # -----------------------------------------------------------------

    @router.get("/api/settings", dependencies=[Depends(require_auth)])
    async def get_settings(
        overrides: RuntimeOverrides = Depends(_get_overrides),  # noqa: B008
    ) -> dict[str, Any]:
        return overrides.snapshot()

    @router.post(
        "/api/settings/bridge",
        dependencies=[Depends(require_auth), Depends(require_csrf)],
    )
    async def update_bridge_settings(
        request: Request,
        body: _BridgeSettingsUpdate = Body(...),  # noqa: B008
        overrides: RuntimeOverrides = Depends(_get_overrides),  # noqa: B008
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
        publisher: Any = Depends(_get_overrides_publisher),  # noqa: B008
    ) -> dict[str, Any]:
        diff = overrides.apply_bridge(
            max_concurrent_requests=body.max_concurrent_requests,
            requests_per_session_per_minute=body.requests_per_session_per_minute,
            wasting_strategy=body.wasting_strategy,
        )
        if diff:
            audit.record(
                "dashboard.settings_changed",
                section="bridge",
                diff={k: {"old": v[0], "new": v[1]} for k, v in diff.items()},
                actor=_actor(request),
            )
            if publisher is not None:
                publisher.publish(overrides)
        snapshot = overrides.snapshot()
        snapshot["changed_fields"] = sorted(diff.keys())
        return snapshot

    @router.post(
        "/api/settings/features",
        dependencies=[Depends(require_auth), Depends(require_csrf)],
    )
    async def update_feature_flags(
        request: Request,
        body: _FeatureFlagsUpdate = Body(...),  # noqa: B008
        overrides: RuntimeOverrides = Depends(_get_overrides),  # noqa: B008
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
        publisher: Any = Depends(_get_overrides_publisher),  # noqa: B008
    ) -> dict[str, Any]:
        diff = overrides.apply_features(
            time_wasting=body.time_wasting,
            engaged_persistence=body.engaged_persistence,
            decoy_poisoning=body.decoy_poisoning,
            counter_deception=body.counter_deception,
        )
        for flag, (old, new) in diff.items():
            audit.record(
                "dashboard.feature_toggled",
                flag=flag,
                old=old,
                new=new,
                actor=_actor(request),
            )
        if diff and publisher is not None:
            publisher.publish(overrides)
        snapshot = overrides.snapshot()
        snapshot["changed_fields"] = sorted(diff.keys())
        return snapshot

    # -----------------------------------------------------------------
    # Stage 3: system health
    # -----------------------------------------------------------------

    @router.get("/api/health/ollama", dependencies=[Depends(require_auth)])
    async def health_ollama(
        request: Request,
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> dict[str, Any]:
        return await ollama_health(request.app.state.settings, audit)

    @router.get("/api/health/sessions", dependencies=[Depends(require_auth)])
    async def health_sessions(
        request: Request,
        state: DashboardState = Depends(_get_state),  # noqa: B008
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> dict[str, Any]:
        return await sessions_health(request.app.state.settings, state, audit)

    # -----------------------------------------------------------------
    # Stage 3: alerts
    # -----------------------------------------------------------------

    @router.get("/api/alerts", dependencies=[Depends(require_auth)])
    async def get_alerts(
        request: Request,
        limit: int = Query(default=50, ge=1, le=200),
        cursor: str | None = Query(default=None, max_length=128),
        kind: str | None = Query(default=None, max_length=64),
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> dict[str, Any]:
        if kind is not None and kind not in ALERT_KINDS:
            # Unknown kind yields an empty page rather than 422 so
            # the SPA can chip-filter on a kind not yet observed.
            # Guarded here (not inside list_alerts) so unknown-kind
            # requests don't generate a dashboard.audit_read row.
            return {"items": [], "next_cursor": None, "stubs": ALERT_STUBS}
        audit.record(
            "dashboard.audit_read",
            cursor=cursor,
            kind=kind,
            limit=limit,
            actor=_actor(request),
        )
        return list_alerts(audit.path, limit=limit, cursor=cursor, kind=kind)

    # -----------------------------------------------------------------
    # Stage 3: export
    # -----------------------------------------------------------------

    @router.get("/api/export/sessions", dependencies=[Depends(require_auth)])
    async def export_sessions(
        request: Request,
        export_format: Literal["json", "csv"] = Query(default="json", alias="format"),
        from_: str | None = Query(default=None, alias="from"),
        to: str | None = Query(default=None),
        state: DashboardState = Depends(_get_state),  # noqa: B008
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> Any:
        try:
            start, end = parse_range(from_=from_, to_=to)
        except ExportRangeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        audit.record(
            "dashboard.export_served",
            kind="sessions",
            export_format=export_format,
            from_=start.isoformat(),
            to=end.isoformat(),
            actor=_actor(request),
        )
        if export_format == "csv":
            filename = f"sessions-{start.date()}-to-{end.date()}.csv"
            return StreamingResponse(
                session_csv_rows(state, start=start, end=end),
                media_type="text/csv; charset=utf-8",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                },
            )
        return await session_export_payload(state, start=start, end=end)

    @router.get("/api/export/audit", dependencies=[Depends(require_auth)])
    async def export_audit(
        request: Request,
        from_: str | None = Query(default=None, alias="from"),
        to: str | None = Query(default=None),
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> dict[str, Any]:
        try:
            start, end = parse_range(from_=from_, to_=to)
        except ExportRangeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        payload = audit_export_payload(audit.path, start=start, end=end)
        audit.record(
            "dashboard.export_served",
            kind="audit",
            export_format="json",
            from_=start.isoformat(),
            to=end.isoformat(),
            item_count=payload["count"],
            actor=_actor(request),
        )
        return payload

    return router


def _actor(request: Request) -> str:
    """Best-effort principal identifier for audit-event ``actor`` fields.

    The session cookie sets ``authenticated`` plus the admin username
    when login succeeds; Basic-auth requests carry the username in the
    Authorization header. In open mode (no admin password) we record
    ``"open_mode"`` so the audit trail still distinguishes runs.
    """
    session = request.session
    if session.get("authenticated") and session.get("username"):
        return str(session["username"])
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        return "basic_auth"
    return "open_mode"
