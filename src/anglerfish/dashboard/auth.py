"""Dashboard authentication: bcrypt password + signed session cookie.

Two paths are accepted:

* **Session cookie** — set by a successful ``POST /api/login`` and
  consumed by every subsequent request. Issued via Starlette's
  :class:`SessionMiddleware`, which signs the cookie with the
  configured ``session_secret``. Cookie is ``SameSite=Strict`` and
  ``HttpOnly`` so a malicious page cannot read or replay it.
* **HTTP Basic** — for non-browser clients (``curl``, monitoring
  probes, the operator's own scripts). Decoded against the same
  bcrypt hash, so a brute-force attempt is rate-limited by bcrypt's
  cost factor.

Open mode: when :attr:`DashboardConfig.admin_password_hash` is
:data:`None`, the dependency falls through — useful for first-boot
before the wizard has run, but emits a warning header so operators
notice if production runs in this state.

Login flow is rate-limited per-IP via :class:`LoginRateLimiter`
(token bucket); failed attempts produce a 429 with ``Retry-After``.
"""

from __future__ import annotations

import base64
import binascii
import logging

import bcrypt
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from anglerfish.audit import AuditLog
from anglerfish.config.models import DashboardConfig
from anglerfish.dashboard.csrf import issue_token
from anglerfish.dashboard.rate_limit import LoginRateLimiter

__all__ = [
    "AUTH_HEADER_OPEN_MODE",
    "LoginRequest",
    "build_auth_router",
    "hash_password",
    "is_open_mode",
    "require_auth",
    "verify_password",
]


_logger = logging.getLogger(__name__)
AUTH_HEADER_OPEN_MODE = "X-Anglerfish-Auth-Mode"


class LoginRequest(BaseModel):
    """Body shape for ``POST /api/login``."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=1024)


def hash_password(password: str) -> str:
    """Return a bcrypt hash of ``password``. Used by the wizard."""
    if not password:
        raise ValueError("password cannot be empty")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time check of ``password`` against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("ascii"))
    except (ValueError, binascii.Error):
        return False


def is_open_mode(config: DashboardConfig) -> bool:
    """True when no password hash is configured (open / first-boot mode)."""
    return config.admin_password_hash is None


def _check_basic_auth(authorization_header: str, config: DashboardConfig) -> bool:
    if not authorization_header.lower().startswith("basic "):
        return False
    encoded = authorization_header.split(" ", 1)[1].strip()
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    if ":" not in decoded:
        return False
    username, password = decoded.split(":", 1)
    return _check_credentials(username, password, config)


def _check_credentials(username: str, password: str, config: DashboardConfig) -> bool:
    if config.admin_username != username:
        return False
    if config.admin_password_hash is None:
        # Open mode — never accept Basic auth in open mode (Basic auth is
        # a positive assertion of credentials; pretending to validate when
        # we can't would be misleading).
        return False
    return verify_password(password, config.admin_password_hash.get_secret_value())


def _settings_from(request: Request) -> DashboardConfig:
    settings = request.app.state.settings
    return settings.dashboard  # type: ignore[no-any-return]


def require_auth(request: Request) -> None:
    """FastAPI dependency: deny unless authenticated.

    In open mode (no password configured), this is a no-op — the
    operator is relying on nftables for isolation. A warning header
    is appended to the response by the middleware.
    """
    config = _settings_from(request)
    if is_open_mode(config):
        return
    if request.session.get("authenticated") is True:
        return
    auth_header = request.headers.get("authorization", "")
    if auth_header and _check_basic_auth(auth_header, config):
        return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="authentication required",
        headers={"WWW-Authenticate": "Basic realm=anglerfish"},
    )


def build_auth_router(
    *,
    audit: AuditLog,
    rate_limiter: LoginRateLimiter | None = None,
) -> APIRouter:
    """Return a router exposing ``POST /api/login``, ``POST /api/logout``,
    and ``GET /api/csrf``.

    ``rate_limiter`` defaults to a fresh :class:`LoginRateLimiter`;
    tests inject a clock-driven instance.
    """
    router = APIRouter()
    limiter = rate_limiter or LoginRateLimiter()

    @router.post("/api/login")
    async def login(req: LoginRequest, request: Request) -> dict[str, str]:
        config = _settings_from(request)
        if is_open_mode(config):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="dashboard is in open mode; configure a password first",
            )
        peer = _peer(request)
        decision = await limiter.consume(peer)
        if not decision.allowed:
            audit.record(
                "dashboard.login_rate_limited",
                username=req.username,
                source_ip=peer,
                retry_after_s=round(decision.retry_after_seconds, 3),
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="too many login attempts",
                headers={"Retry-After": str(max(1, int(decision.retry_after_seconds)))},
            )
        if _check_credentials(req.username, req.password, config):
            request.session["authenticated"] = True
            request.session["username"] = req.username
            issue_token(request)
            await limiter.reset(peer)
            audit.record(
                "dashboard.login_success",
                username=req.username,
                source_ip=peer,
            )
            return {"status": "ok"}
        audit.record(
            "dashboard.login_failure",
            username=req.username,
            source_ip=peer,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )

    @router.post("/api/logout")
    async def logout(request: Request) -> dict[str, str]:
        username = request.session.get("username", "")
        request.session.clear()
        audit.record(
            "dashboard.logout",
            username=username,
            source_ip=_peer(request),
        )
        return {"status": "ok"}

    @router.get("/api/csrf")
    async def csrf(request: Request) -> dict[str, str]:
        """Return the session's CSRF token, creating one on first call.

        Authenticated clients call this once after login and cache the
        result for the lifetime of the session. The token must be sent
        back in the ``X-Anglerfish-CSRF`` header on every state-changing
        request.
        """
        return {"token": issue_token(request)}

    return router


def _peer(request: Request) -> str:
    client = request.client
    return client.host if client is not None else "unknown"
