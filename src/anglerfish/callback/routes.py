"""Routes for the Stage 11 slice 11.4 honeytoken callback receiver.

Two endpoints:

* ``GET /cb/{token_id}``: lookup ``token_id`` in the registry; on
  hit audit ``bridge.honeytoken_callback`` with both the registered
  source IP (the IP the bait was placed for) and the callback
  source IP (the IP that triggered the request - the attacker's
  exfil node). The response is always an AWS-style 403 ``Forbidden``
  XML body so a miss reveals nothing about which token IDs the
  registry contains.
* ``GET /health``: cheap 200 ``{"status": "ok"}`` for load-balancer
  + monitoring probes. Does NOT hit the SessionStoreReader so a
  reader outage still serves probes.

The 403 body intentionally mimics what real AWS returns for an
expired access key (``InvalidAccessKeyId``) so an attacker running
``aws s3 ls`` sees a plausible error and is less likely to spot the
honeypot.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Request, Response, status

if TYPE_CHECKING:
    from anglerfish.audit import AuditLog
    from anglerfish.sessions.reader import SessionStoreReader

__all__ = ["build_callback_router"]


# Base32 alphabet (RFC 4648), 16 chars. Matches Honeytoken.id's
# Pydantic pattern. The route's path validator rejects anything else
# before the SessionStoreReader is consulted; this keeps the read
# path off the floor for spam (random / oversized / non-base32 IDs).
_TOKEN_ID_RE = re.compile(r"^[A-Z2-7]{16}$")

# AWS-style XML body: matches the wire shape of an
# InvalidAccessKeyId / AccessDenied response so an attacker running
# aws-cli sees a plausible error rather than a generic 403.
_AWS_403_BODY = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    "<Error>"
    "<Code>InvalidAccessKeyId</Code>"
    "<Message>The AWS Access Key Id you provided does not exist in our records.</Message>"
    "<AWSAccessKeyId>{access_key}</AWSAccessKeyId>"
    "</Error>"
)
_AWS_403_CONTENT_TYPE = "application/xml"

# Per-request User-Agent cap. Operators see attacker tooling
# strings here; truncate to keep one weird client from bloating
# audit lines. Real aws-cli + curl + python-requests UAs fit well
# under this.
_USER_AGENT_MAX = 512


def _get_reader(request: Request) -> SessionStoreReader:
    """Pull the SessionStoreReader attached at app construction."""
    reader = getattr(request.app.state, "session_store_reader", None)
    if reader is None:  # pragma: no cover - guarded at create_callback_app
        raise RuntimeError("SessionStoreReader not attached to app.state")
    return reader  # type: ignore[no-any-return]


def _get_audit(request: Request) -> AuditLog:
    audit = getattr(request.app.state, "audit", None)
    if audit is None:  # pragma: no cover - guarded at create_callback_app
        raise RuntimeError("AuditLog not attached to app.state")
    return audit  # type: ignore[no-any-return]


def _callback_source_ip(request: Request) -> str:
    """Best-effort source IP of the callback request.

    Honours ``X-Forwarded-For`` when present (operators front the
    receiver with a reverse proxy that TLS-terminates); falls back
    to the connecting socket peer otherwise. The header's leftmost
    entry is the original client per the X-Forwarded-For convention.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        leftmost = forwarded.split(",", 1)[0].strip()
        if leftmost:
            return leftmost
    client = request.client
    return client.host if client is not None else "unknown"


def build_callback_router() -> APIRouter:
    """Build the callback receiver's route table.

    The reader + audit dependencies are pulled from ``app.state``
    rather than passed in via closures so tests can construct the
    app with their own stubs without re-wiring the router.
    """
    router = APIRouter()

    @router.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @router.get("/cb/{token_id}")
    async def callback(
        token_id: str,
        request: Request,
        reader: SessionStoreReader = Depends(_get_reader),  # noqa: B008
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> Response:
        # Reject malformed token IDs without consulting the registry.
        # The base32 alphabet + 16-char width is fixed; anything else
        # is either probe traffic or a bot fuzzing the path. Treat as
        # a miss but skip the SQL round-trip + audit line.
        if not _TOKEN_ID_RE.match(token_id):
            return _aws_403_response(token_id)

        token = await reader.get_honeytoken(token_id)
        callback_ip = _callback_source_ip(request)
        user_agent = (request.headers.get("user-agent") or "")[:_USER_AGENT_MAX]
        request_path = request.url.path

        if token is None:
            # Unknown token: still audit so operators can see probe
            # traffic against the receiver. ``kind`` is null because
            # we have no registry row; ``registered_source_ip`` +
            # ``registered_session_id`` likewise. Hit/miss split is
            # carried by the presence of those fields.
            audit.record(
                "bridge.honeytoken_callback",
                token_id=token_id,
                kind=None,
                registered_source_ip=None,
                registered_session_id=None,
                callback_source_ip=callback_ip,
                user_agent=user_agent,
                request_path=request_path,
            )
            return _aws_403_response(token_id)

        audit.record(
            "bridge.honeytoken_callback",
            token_id=token.id,
            kind=token.kind,
            registered_source_ip=token.source_ip,
            registered_session_id=(str(token.session_id) if token.session_id is not None else None),
            callback_source_ip=callback_ip,
            user_agent=user_agent,
            request_path=request_path,
        )
        return _aws_403_response(token_id)

    return router


def _aws_403_response(token_id: str) -> Response:
    """Build the canonical AWS-style 403 response.

    Body is XML matching the ``InvalidAccessKeyId`` shape; the
    ``AWSAccessKeyId`` field echoes back ``AKIA<token_id>`` so the
    response looks like a real IAM error to ``aws-cli`` clients.
    """
    body = _AWS_403_BODY.format(access_key=f"AKIA{token_id}")
    return Response(
        content=body,
        status_code=status.HTTP_403_FORBIDDEN,
        media_type=_AWS_403_CONTENT_TYPE,
    )
