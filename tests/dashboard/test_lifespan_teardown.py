"""The dashboard lifespan teardown must close every resource even if an
earlier cleanup raises (best-effort shutdown)."""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from anglerfish.config import AnglerfishSettings
from anglerfish.dashboard import create_app
from anglerfish.dashboard.audit_tailer import AuditTailer


class _SpyCredentialStore:
    """Minimal credential-store stand-in that records its close."""

    def __init__(self) -> None:
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


def test_lifespan_closes_credential_store_when_tailer_stop_raises(
    settings: AnglerfishSettings,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A raise from an earlier closer (the audit tailer) must not skip the
    credential store's aclose, and must not propagate out of the lifespan."""
    spy = _SpyCredentialStore()

    async def _boom_stop(_self: object) -> None:
        raise RuntimeError("tailer stop blew up")

    # AuditTailer.stop runs before the credential store closes; make it raise.
    monkeypatch.setattr(AuditTailer, "stop", _boom_stop)

    app = create_app(settings, credential_store=spy)
    # Entering and exiting the client runs lifespan startup + teardown.
    with caplog.at_level(logging.ERROR, logger="anglerfish.dashboard.app"), TestClient(app):
        pass

    # The credential store still closed despite the tailer's stop() raising,
    # and the failure was logged rather than propagated.
    assert spy.closed is True
    assert any("shutdown cleanup" in r.message for r in caplog.records)
