"""WebSocket endpoint that streams dashboard events to subscribers.

Three guards apply before a WebSocket upgrade succeeds:

1. **Origin check** — the ``Origin`` header must match one of the
   dashboard's allowed origins (the dashboard's own ``host:port`` by
   default, plus any extra origins in
   :attr:`DashboardConfig.allowed_origins`). Reject otherwise — this
   stops a malicious page in an operator's browser from subscribing
   to the live attacker-command stream.
2. **Authentication** — the operator must have an active session
   cookie. Open-mode dashboards (no password configured) skip this
   check, matching the REST behaviour.
3. **Session-state attachment** — :class:`DashboardState` must be on
   ``app.state``; we ensure that during :func:`create_app`.

A failed guard closes the socket with the appropriate 4xxx close
code rather than 1011 (which would imply server error).
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import AbstractContextManager, nullcontext, suppress
from typing import cast

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from anglerfish.dashboard.auth import is_open_mode
from anglerfish.dashboard.state import DashboardState

__all__ = ["build_websocket_router"]


_WS_CLOSE_POLICY_VIOLATION = 4401
_WS_CLOSE_BAD_ORIGIN = 4403


def _get_state_from_ws(websocket: WebSocket) -> DashboardState:
    state = getattr(websocket.app.state, "dashboard_state", None)
    if state is None:  # pragma: no cover - guarded at startup
        raise RuntimeError("DashboardState not attached to app.state")
    return cast("DashboardState", state)


def _allowed_origins(websocket: WebSocket) -> set[str]:
    config = websocket.app.state.settings.dashboard
    origins: set[str] = set(config.allowed_origins)
    # Always allow the dashboard's own URL(s).
    host_for_url = "localhost" if config.host == "0.0.0.0" else config.host  # noqa: S104  # nosec B104
    for scheme in ("http", "https"):
        origins.add(f"{scheme}://{host_for_url}:{config.port}")
        origins.add(f"{scheme}://{host_for_url}")
    return origins


def _check_origin(websocket: WebSocket) -> bool:
    origin = websocket.headers.get("origin")
    if origin is None:
        # Some legitimate non-browser clients (curl --include) omit Origin.
        # We deny them: WebSocket upgrade from a tool that ignores the
        # Origin convention is the same shape as an unauthenticated
        # browser request from an attacker page.
        return False
    return origin in _allowed_origins(websocket)


def _check_auth(websocket: WebSocket) -> bool:
    config = websocket.app.state.settings.dashboard
    if is_open_mode(config):
        return True
    # Starlette's SessionMiddleware populates websocket.session.
    session = websocket.session
    return session.get("authenticated") is True


def build_websocket_router(*, ping_interval_s: float = 25.0) -> APIRouter:
    router = APIRouter()
    logger = logging.getLogger(__name__)

    @router.websocket("/ws/events")
    async def events(websocket: WebSocket) -> None:
        if not _check_origin(websocket):
            await websocket.close(code=_WS_CLOSE_BAD_ORIGIN)
            logger.info(
                "dashboard.ws_rejected_origin origin=%s",
                websocket.headers.get("origin", "<missing>"),
            )
            return
        if not _check_auth(websocket):
            await websocket.close(code=_WS_CLOSE_POLICY_VIOLATION)
            logger.info("dashboard.ws_rejected_auth")
            return

        state = _get_state_from_ws(websocket)
        await websocket.accept()
        try:
            async with state.subscribe() as queue:
                while True:
                    try:
                        event = await asyncio.wait_for(
                            queue.get(),
                            timeout=ping_interval_s,
                        )
                    except TimeoutError:
                        try:
                            await websocket.send_json({"kind": "ping"})
                        except (WebSocketDisconnect, RuntimeError):
                            break
                        continue
                    try:
                        await websocket.send_json(event.model_dump(mode="json"))
                    except (WebSocketDisconnect, RuntimeError):
                        break
        except WebSocketDisconnect:
            logger.debug("dashboard.ws_disconnect")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - log and close cleanly
            logger.warning("dashboard.ws_error error=%s", exc)
            with _suppress_already_closed():
                await websocket.close(code=1011)

    return router


def _suppress_already_closed() -> AbstractContextManager[None]:
    # WebSocket close on an already-closed socket raises RuntimeError;
    # we don't care once we're in the error path.
    return cast("AbstractContextManager[None]", suppress(RuntimeError))


# Touch nullcontext so unused-import doesn't fire if a future version drops it.
_ = nullcontext
