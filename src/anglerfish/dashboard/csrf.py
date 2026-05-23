"""CSRF protection for the dashboard's state-changing endpoints.

The dashboard runs behind an authenticated session cookie
(``SameSite=Strict``), so a cross-origin POST already cannot ride the
operator's session in any modern browser. CSRF tokens land here as
defence-in-depth for older clients and for the eventual operator-write
endpoints (acknowledging an alert, suppressing a session, etc.).

Pattern: synchronizer-token, signed with the same secret as the
session cookie. Token issuance is bound to a single Starlette
session — generated on first read of ``request.session["csrf"]``.
The browser must supply the token via the ``X-Anglerfish-CSRF`` header
on any non-GET non-HEAD non-OPTIONS request that is not an explicit
opt-out endpoint (``/api/login``, ``/api/health``, ``/api/logout``).

Why ``X-Anglerfish-CSRF`` and not a form field?

* The dashboard is a JSON API. Bodies are ``application/json``, and
  every state-changing call already sets a custom header. A custom
  header alone is enough to defeat cross-origin form-submission
  attacks (browsers reject custom headers on simple cross-origin
  requests without CORS preflight), but pinning the token in too
  catches the eventual case where the dashboard sends a form.

Endpoints that need CSRF protection apply :func:`require_csrf` as a
FastAPI dependency. The middleware variant is intentionally absent —
explicit beats implicit for security primitives.
"""

from __future__ import annotations

import hmac
import secrets

from fastapi import HTTPException, Request, status

__all__ = ["CSRF_HEADER", "CSRF_SESSION_KEY", "issue_token", "require_csrf"]


CSRF_HEADER = "X-Anglerfish-CSRF"
CSRF_SESSION_KEY = "csrf_token"


def issue_token(request: Request) -> str:
    """Return the CSRF token for ``request``'s session, creating one if absent.

    The token survives the session lifetime; rotating it on each
    response would force the SPA to re-fetch before every write, with
    no observable benefit over the SameSite=Strict cookie.
    """
    token = request.session.get(CSRF_SESSION_KEY)
    if not isinstance(token, str) or len(token) < 32:
        token = secrets.token_urlsafe(32)
        request.session[CSRF_SESSION_KEY] = token
    return token


def require_csrf(request: Request) -> None:
    """FastAPI dependency: reject when the CSRF header doesn't match the session.

    Open-mode (no session) endpoints don't need CSRF — the dashboard
    has no authenticated user to ride. When the session has no token
    yet, the request is rejected outright; the caller must hit
    ``GET /api/csrf`` first.
    """
    expected = request.session.get(CSRF_SESSION_KEY)
    if not isinstance(expected, str) or not expected:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="missing csrf token; fetch /api/csrf first",
        )
    supplied = request.headers.get(CSRF_HEADER, "")
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="csrf token mismatch",
        )
