"""Browser-driven regression test for the dashboard SPA's stored-XSS defence.

Seeds a captured credential whose username is an ``<img onerror>`` payload,
serves the real dashboard on a live uvicorn port, loads it in headless
chromium, and asserts the payload renders as inert text: the injected
element never materialises and its ``onerror`` never executes. This is the
end-to-end check that the ``escapeText`` output encoding (plus the CSP
backstop) neutralises attacker markup at the ``innerHTML`` call sites - the
failure mode that shipped in the original bug (6cdbb9e), where the call
sites, not escapeText itself, were what forgot to escape.

Marked ``browser``: deselected from the default suite (see addopts) and run
only by the dedicated CI job that installs a chromium binary.
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
from anglerfish.config.models import CredentialsConfig
from anglerfish.credentials import CredentialStore
from anglerfish.dashboard import create_app

pytestmark = pytest.mark.browser

# Attacker-controlled username. If escapeText is bypassed at the credentials
# call site, chromium parses this as an <img> whose failed load fires
# onerror and sets the global flag the test asserts is never set.
_XSS_USERNAME = '<img src=x onerror="window.__xssFired = true">'


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class _LiveServer:
    """Serve the dashboard on a real uvicorn port in a background thread.

    The credential store is opened and seeded inside the server's own event
    loop because aiosqlite connections are loop-affine; opening it in the
    test thread would leave a connection the request handlers cannot use.
    """

    def __init__(self, settings: AnglerfishSettings, store: CredentialStore) -> None:
        import uvicorn

        self._store = store
        port = _free_port()
        self.base_url = f"http://127.0.0.1:{port}"
        app = create_app(settings, credential_store=store)
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        async def _main() -> None:
            await self._store.open()
            await self._store.record_attempt(
                source_ip="203.0.113.9",
                username=_XSS_USERNAME,
                password="correct horse",
                session_id=uuid4(),
                timestamp=datetime(2026, 5, 22, tzinfo=UTC),
            )
            # The app lifespan aclose()s the store on shutdown, same loop.
            await self._server.serve()

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
    cfg = CredentialsConfig(
        database_path=tmp_path / "creds.db",
        encryption_key=SecretStr(base64.b64encode(b"\x07" * 32).decode("ascii")),
    )
    with _LiveServer(settings, CredentialStore(cfg)) as server:
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
    try:
        yield context.new_page()
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
