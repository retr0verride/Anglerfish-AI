"""Security response headers for the dashboard.

A pure-ASGI middleware (not ``BaseHTTPMiddleware``) so it does not buffer
the CSV export's ``StreamingResponse``. It injects a Content-Security-
Policy plus the standard companion headers on every HTTP response. The CSP
carries a ``report-uri`` so violations are recorded as a tripwire (see
``/api/csp-report`` in ``routes.py``).

The CSP is the defence-in-depth backstop for the SPA: ``script-src
'self'`` means an injected inline ``<script>`` or event-handler attribute
cannot execute even if some value reached the DOM unescaped, complementing
the ``escapeText`` output encoding. ``style-src 'self'`` carries no
``'unsafe-inline'``: the only dynamic style, the score-bar width, is set
through the CSSOM (``element.style.width``), which CSP does not govern, so
no inline ``style`` attribute or ``<style>`` block appears on the page.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from starlette.datastructures import MutableHeaders

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

__all__ = ["SecurityHeadersMiddleware"]

_CSP = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
        # Violations POST to the auth-gated /api/csp-report tripwire, which
        # records them as dashboard.csp_violation audit events.
        "report-uri /api/csp-report",
    ],
)

# Strict-Transport-Security is deliberately absent. The dashboard supports
# running without TLS on an isolated internal net - SessionMiddleware sets
# https_only=False for the same reason (see create_app) - so an operator
# may legitimately serve over plain HTTP. HSTS would pin the operator's
# browser to HTTPS for this host after a single visit and lock them out of
# an HTTP deployment. A TLS-fronted deployment should set HSTS at the
# reverse proxy, where the TLS decision actually lives.
_SECURITY_HEADERS = {
    "content-security-policy": _CSP,
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
}


class SecurityHeadersMiddleware:
    """Inject CSP + companion security headers on every HTTP response."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in _SECURITY_HEADERS.items():
                    headers.setdefault(name, value)
            await send(message)

        await self._app(scope, receive, send_wrapper)
