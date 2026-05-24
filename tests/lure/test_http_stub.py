"""Tests for the HTTP lure stub."""

from __future__ import annotations

import pytest

from anglerfish.config import AnglerfishSettings
from anglerfish.lure.http import run_http_lure


async def test_run_http_lure_raises_not_implemented(
    settings: AnglerfishSettings,
) -> None:
    with pytest.raises(NotImplementedError, match="TODO-1"):
        await run_http_lure(settings)


async def test_run_http_lure_error_points_at_todo_log(
    settings: AnglerfishSettings,
) -> None:
    with pytest.raises(NotImplementedError) as exc:
        await run_http_lure(settings)
    msg = str(exc.value)
    assert "docs/TODO.md" in msg
    assert "ANGLERFISH_LURE__HTTP_LURE_ENABLED" in msg


def test_http_lure_disabled_by_default_in_config(
    settings: AnglerfishSettings,
) -> None:
    assert settings.lure.http_lure_enabled is False
