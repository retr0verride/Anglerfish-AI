"""FastAPI application factory for the Stage 11 callback receiver.

Separate process from the bridge + dashboard. Owns the publicly-
reachable URL embedded in honeytokens; reads the sessions DB via a
:class:`SessionStoreReader`; writes audit lines to its own
:class:`AuditLog` which the operator ships back to the main
Anglerfish host.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from anglerfish import __version__
from anglerfish.audit import AuditLog
from anglerfish.callback.routes import build_callback_router
from anglerfish.config.settings import AnglerfishSettings
from anglerfish.sessions.reader import SessionStoreReader

__all__ = ["create_callback_app"]


def create_callback_app(
    settings: AnglerfishSettings,
    *,
    store_reader: SessionStoreReader | None = None,
    audit: AuditLog | None = None,
) -> FastAPI:
    """Build a FastAPI app for the callback receiver.

    The reader + audit handle default to fresh instances built from
    ``settings``; tests pass explicit ones. The reader is opened in
    the lifespan when this factory created it; a caller-supplied
    reader is left for the caller to manage (so the same instance
    can be shared across test cases).
    """
    audit_log = audit if audit is not None else AuditLog(settings.audit.log_path)
    reader_instance = (
        store_reader if store_reader is not None else SessionStoreReader(settings.sessions)
    )
    owns_reader = store_reader is None

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        if owns_reader:
            await reader_instance.open()
        try:
            yield
        finally:
            if owns_reader:
                await reader_instance.aclose()

    app = FastAPI(
        title="Anglerfish AI callback receiver",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.session_store_reader = reader_instance
    app.state.audit = audit_log
    app.include_router(build_callback_router())
    return app
