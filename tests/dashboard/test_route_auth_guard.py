"""Mythos L7: enforce that every dashboard data/state route carries
require_auth, so a future endpoint cannot silently ship unauthenticated."""

from __future__ import annotations

from fastapi.routing import APIRoute

from anglerfish.dashboard import create_app
from anglerfish.dashboard.auth import require_auth

# Intentionally open routes (documented in routes.py / build_auth_router).
# /api/csrf is part of the auth-bootstrap router; its token is session-bound
# and useless without auth (every protected endpoint also requires auth).
_OPEN_PATHS = {"/", "/api/health", "/api/login", "/api/logout", "/api/csrf"}


def test_every_data_route_requires_auth(settings) -> None:  # type: ignore[no-untyped-def]
    app = create_app(settings)
    missing: list[str] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if route.path in _OPEN_PATHS:
            continue
        deps = [d.dependency for d in route.dependencies]
        if require_auth not in deps:
            missing.append(f"{sorted(route.methods)} {route.path}")
    assert not missing, f"routes missing require_auth: {missing}"
