"""FastAPI application factory for the Anglerfish dashboard.

The factory pattern keeps construction explicit: the bridge or wizard
builds a :class:`DashboardState`, optionally a credential store, and
hands them to :func:`create_app` which wires them onto ``app.state``
together with the auth + session middleware.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from anglerfish import __version__
from anglerfish.audit import AuditLog
from anglerfish.config.settings import AnglerfishSettings
from anglerfish.dashboard.auth import build_auth_router
from anglerfish.dashboard.overrides import build_runtime_overrides
from anglerfish.dashboard.rate_limit import LoginRateLimiter
from anglerfish.dashboard.routes import build_router
from anglerfish.dashboard.state import DashboardState
from anglerfish.dashboard.websocket import build_websocket_router

__all__ = ["create_app", "default_static_dir", "default_templates_dir"]


def default_templates_dir() -> Path:
    return Path(__file__).parent / "templates"


def default_static_dir() -> Path:
    return Path(__file__).parent / "static"


def create_app(
    settings: AnglerfishSettings,
    *,
    state: DashboardState | None = None,
    credential_store: Any | None = None,
    audit: AuditLog | None = None,
    login_rate_limiter: LoginRateLimiter | None = None,
    templates_dir: Path | None = None,
    static_dir: Path | None = None,
) -> FastAPI:
    """Build a FastAPI app for the dashboard."""
    templates_path = templates_dir if templates_dir is not None else default_templates_dir()
    static_path = static_dir if static_dir is not None else default_static_dir()
    if not templates_path.is_dir():
        raise FileNotFoundError(f"templates directory not found: {templates_path}")

    state_instance = state if state is not None else DashboardState()
    audit_log = audit if audit is not None else AuditLog()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        if credential_store is not None:
            await credential_store.aclose()

    app = FastAPI(
        title="Anglerfish AI",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # Sign session cookies with the configured secret; SameSite=strict +
    # HttpOnly + a 24-hour max age. The cookie is the only auth surface
    # the dashboard exposes to browsers.
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.dashboard.session_secret.get_secret_value(),
        session_cookie="anglerfish_session",
        max_age=24 * 3600,
        same_site="strict",
        https_only=False,  # operator may run without TLS on internal nets
    )

    app.state.settings = settings
    app.state.dashboard_state = state_instance
    app.state.credential_store = credential_store
    app.state.audit = audit_log
    # Stage 3: in-process mutable overrides the settings endpoints
    # update. Reset on dashboard restart back to env-file values; see
    # docs/design/STAGE_3_dashboard_control_plane.md for the boundary.
    app.state.runtime_overrides = build_runtime_overrides(settings)

    templates = Jinja2Templates(directory=str(templates_path))
    app.include_router(
        build_auth_router(audit=audit_log, rate_limiter=login_rate_limiter),
    )
    app.include_router(build_router(templates=templates))
    app.include_router(build_websocket_router())

    if static_path.is_dir():
        app.mount(
            "/static",
            StaticFiles(directory=str(static_path)),
            name="static",
        )

    return app
