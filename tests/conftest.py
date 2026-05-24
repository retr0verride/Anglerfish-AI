"""Shared pytest fixtures for the Anglerfish test suite.

Two autouse fixtures keep tests hermetic:

* :func:`_isolate_anglerfish_env` strips every ``ANGLERFISH_*`` variable
  from :data:`os.environ` for the duration of the test, so a stray
  variable in the developer's shell cannot influence config loading.
* :func:`_reset_load_settings_cache` clears the LRU cache around
  :func:`anglerfish.config.load_settings` between tests.

The :func:`session_store` and :func:`dashboard_state` fixtures provide
a per-test SQLite-backed :class:`SessionStore` rooted in ``tmp_path``
and a :class:`DashboardState` wired through it. These replace the
pre-Stage-4 in-memory ``DashboardState()`` no-arg constructor.
"""

from __future__ import annotations

import base64
import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
from pydantic import SecretStr

from anglerfish.config import (
    AnglerfishSettings,
    CredentialsConfig,
    DashboardConfig,
)
from anglerfish.config.models import SessionStoreConfig
from anglerfish.config.settings import load_settings
from anglerfish.dashboard.state import DashboardState
from anglerfish.sessions import SessionStore


@pytest.fixture(autouse=True)
def _isolate_anglerfish_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip ANGLERFISH_* env vars so tests run against a known baseline."""
    for key in list(os.environ):
        if key.startswith("ANGLERFISH_"):
            monkeypatch.delenv(key, raising=False)


@pytest.fixture(autouse=True)
def _reset_load_settings_cache() -> Iterator[None]:
    """Clear the load_settings LRU cache before and after each test."""
    load_settings.cache_clear()
    yield
    load_settings.cache_clear()


@pytest.fixture
def session_secret() -> str:
    return "anglerfish-test-secret-padded-to-32+"


@pytest.fixture
def encryption_key_b64() -> str:
    return base64.b64encode(b"\x01" * 32).decode("ascii")


@pytest.fixture
def settings(
    session_secret: str,
    encryption_key_b64: str,
    tmp_path: Path,
) -> AnglerfishSettings:
    """A fully-validated :class:`AnglerfishSettings` for use in tests."""
    return AnglerfishSettings(
        dashboard=DashboardConfig(session_secret=SecretStr(session_secret)),
        credentials=CredentialsConfig(encryption_key=SecretStr(encryption_key_b64)),
        sessions=SessionStoreConfig(database_path=tmp_path / "sessions.db"),
    )


@pytest.fixture
async def session_store(tmp_path: Path) -> AsyncIterator[SessionStore]:
    """An opened :class:`SessionStore` rooted in a per-test tmp file."""
    config = SessionStoreConfig(database_path=tmp_path / "sessions.db")
    async with SessionStore(config) as store:
        yield store


@pytest.fixture
async def dashboard_state(session_store: SessionStore) -> DashboardState:
    """A :class:`DashboardState` wired to the test session store."""
    return DashboardState(session_store)
