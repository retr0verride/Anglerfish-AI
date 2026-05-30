"""Browser-driven tests for the dashboard SPA's client-side hardening.

Two regression guards that only a real DOM can exercise:

* The stored-XSS defence: a captured credential whose username is an
  ``<img onerror>`` payload must render as inert text - no element is
  created and its ``onerror`` never runs. This is the failure mode that
  shipped in 6cdbb9e, where the ``innerHTML`` call sites, not escapeText
  itself, were what forgot to escape.
* The CSP tightening: with ``style-src 'self'`` carrying no
  ``'unsafe-inline'``, the score-bar width (set through the CSSOM, which
  CSP does not govern) must still apply, and the real page must raise no
  ``securitypolicyviolation`` at all.

Both serve the real dashboard on a live uvicorn port and drive it with
headless chromium. Marked ``browser``: deselected from the default suite
(see addopts) and run only by the dedicated CI job that installs chromium.
"""

from __future__ import annotations

import asyncio
import base64
import socket
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from playwright.sync_api import Browser, Page, sync_playwright
from pydantic import SecretStr

from anglerfish.config import AnglerfishSettings
from anglerfish.config.models import CredentialsConfig, SessionStoreConfig
from anglerfish.credentials import CredentialStore
from anglerfish.dashboard import DashboardState, create_app
from anglerfish.models.session import SessionSnapshot
from anglerfish.models.threat import ThreatAssessment
from anglerfish.sessions import SessionStore

pytestmark = pytest.mark.browser

# Attacker-controlled username. If escapeText is bypassed at the credentials
# call site, chromium parses this as an <img> whose failed load fires
# onerror and sets the global flag the test asserts is never set.
_XSS_USERNAME = '<img src=x onerror="window.__xssFired = true">'

# A distinctive score so the rendered bar width is unambiguous.
_THREAT_SCORE = 73

# Capture every CSP violation the page raises, before any page script runs.
_CAPTURE_CSP = (
    "window.__cspViolations = [];"
    "document.addEventListener('securitypolicyviolation',"
    " (e) => window.__cspViolations.push("
    "   e.violatedDirective + ' ' + e.blockedURI));"
)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _snapshot() -> SessionSnapshot:
    ts = datetime(2026, 5, 22, tzinfo=UTC)
    return SessionSnapshot(
        session_id=uuid4(),
        source_ip="203.0.113.9",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=ts,
        last_activity_at=ts,
        turns=(),
    )


class _LiveServer:
    """Serve the dashboard on a real uvicorn port in a background thread.

    The session and credential stores are opened and seeded inside the
    server's own event loop because aiosqlite connections are loop-affine;
    opening them in the test thread would leave connections the request
    handlers cannot use.
    """

    def __init__(self, settings: AnglerfishSettings, tmp_path: Path) -> None:
        import uvicorn

        cred_cfg = CredentialsConfig(
            database_path=tmp_path / "creds.db",
            encryption_key=SecretStr(base64.b64encode(b"\x07" * 32).decode("ascii")),
        )
        self._cred_store = CredentialStore(cred_cfg)
        self._session_store = SessionStore(
            SessionStoreConfig(database_path=tmp_path / "sessions.db")
        )
        self._state = DashboardState(self._session_store)
        self._snapshot = _snapshot()

        port = _free_port()
        self.base_url = f"http://127.0.0.1:{port}"
        app = create_app(settings, state=self._state, credential_store=self._cred_store)
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        async def _main() -> None:
            await self._session_store.open()
            await self._cred_store.open()
            await self._state.update_session(self._snapshot)
            await self._state.record_threat(
                ThreatAssessment(session_id=self._snapshot.session_id, score=_THREAT_SCORE)
            )
            await self._cred_store.record_attempt(
                source_ip="203.0.113.9",
                username=_XSS_USERNAME,
                password="correct horse",
                session_id=self._snapshot.session_id,
                timestamp=datetime(2026, 5, 22, tzinfo=UTC),
            )
            try:
                # The app lifespan aclose()s the credential store on
                # shutdown; the session store is ours to close.
                await self._server.serve()
            finally:
                await self._session_store.aclose()

        asyncio.run(_main())

    def __enter__(self) -> _LiveServer:
        self._thread.start()
        deadline = time.monotonic() + 15
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("uvicorn live server did not start in time")
            time.sleep(0.02)
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=15)


@pytest.fixture
def live_server(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> Iterator[_LiveServer]:
    with _LiveServer(settings, tmp_path) as server:
        yield server


@pytest.fixture(scope="module")
def browser() -> Iterator[Browser]:
    with sync_playwright() as playwright:
        instance = playwright.chromium.launch(headless=True)
        try:
            yield instance
        finally:
            instance.close()


@pytest.fixture
def page(browser: Browser) -> Iterator[Page]:
    context = browser.new_context()
    pg = context.new_page()
    pg.add_init_script(_CAPTURE_CSP)
    try:
        yield pg
    finally:
        context.close()


def test_credential_username_payload_renders_inert(
    page: Page,
    live_server: _LiveServer,
) -> None:
    page.goto(live_server.base_url)

    # The seeded credential renders into #credentials-table on load. Wait
    # for the row itself (present whether or not escaping held) so the
    # decisive assertions below run - and fail clearly - in the regression
    # case rather than timing out on a payload-text locator.
    row = page.locator("#credentials-table tr").first
    row.wait_for(state="visible", timeout=10_000)
    # Give any (regression-case) onerror time to fire before asserting it
    # did not, so a real bypass cannot slip through a race.
    page.wait_for_timeout(250)

    # Decisive: the injected <img onerror> never executed.
    assert page.evaluate("() => window.__xssFired") is None
    # No live element was created from the payload; it stayed inert text.
    assert page.locator("#credentials-table img").count() == 0
    # The raw markup survives as escaped text, proving the value reached the
    # render path (the page is not blank or errored).
    assert "<img" in row.inner_text()


def test_score_bar_width_renders_under_tightened_csp(
    page: Page,
    live_server: _LiveServer,
) -> None:
    page.goto(live_server.base_url)

    fill = page.locator("#threat-table .score-bar__fill").first
    fill.wait_for(state="attached", timeout=10_000)

    # The width is applied via the CSSOM (element.style.width), which CSP
    # does not govern, so style-src 'self' without 'unsafe-inline' does not
    # block it. The inline style property reflects the seeded score.
    assert fill.evaluate("el => el.style.width") == f"{_THREAT_SCORE}%"
    # And it actually painted: computed width is a non-zero pixel value.
    assert (
        page.evaluate(
            "() => parseFloat(getComputedStyle("
            "document.querySelector('#threat-table .score-bar__fill')).width)"
        )
        > 0
    )

    # The real page, served with the tightened CSP, raised no violation.
    assert page.evaluate("() => window.__cspViolations") == []
