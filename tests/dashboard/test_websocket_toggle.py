"""dashboard.enable_websockets gates the websocket routes."""

from __future__ import annotations

from fastapi import FastAPI

from anglerfish.config import AnglerfishSettings
from anglerfish.dashboard import create_app


def _ws_route_count(app: FastAPI) -> int:
    return sum(1 for r in app.routes if str(getattr(r, "path", "")).startswith("/ws"))


def test_websocket_routes_present_by_default(settings: AnglerfishSettings) -> None:
    # enable_websockets defaults on.
    assert _ws_route_count(create_app(settings)) > 0


def test_websocket_routes_absent_when_disabled(settings: AnglerfishSettings) -> None:
    disabled = settings.model_copy(
        update={
            "dashboard": settings.dashboard.model_copy(update={"enable_websockets": False}),
        },
    )
    assert _ws_route_count(create_app(disabled)) == 0
