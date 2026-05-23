"""Tests for :class:`anglerfish.fingerprint.TorExitList`."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from anglerfish.fingerprint.tor import TorExitList


class _FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, by: float) -> None:
        self.now += by


def _write_exits(path: Path, ips: list[str], *, with_comments: bool = False) -> None:
    lines: list[str] = []
    if with_comments:
        lines.append("# tor exit list")
        lines.append("")
    lines.extend(ips)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


async def test_constructor_rejects_zero_interval(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        TorExitList(tmp_path / "x.txt", refresh_interval_s=0)


async def test_contains_known_ip(tmp_path: Path) -> None:
    path = tmp_path / "exits.txt"
    _write_exits(path, ["198.51.100.7", "203.0.113.42"])
    tl = TorExitList(path, refresh_interval_s=60.0)
    assert await tl.contains("198.51.100.7") is True
    assert await tl.contains("10.0.0.1") is False


async def test_invalid_ip_query_returns_false(tmp_path: Path) -> None:
    path = tmp_path / "exits.txt"
    _write_exits(path, ["198.51.100.7"])
    tl = TorExitList(path, refresh_interval_s=60.0)
    assert await tl.contains("not-an-ip") is False


async def test_missing_file_loads_empty(tmp_path: Path) -> None:
    tl = TorExitList(tmp_path / "missing.txt", refresh_interval_s=60.0)
    assert await tl.contains("1.2.3.4") is False
    assert await tl.size() == 0


async def test_blank_lines_and_comments_ignored(tmp_path: Path) -> None:
    path = tmp_path / "exits.txt"
    _write_exits(path, ["198.51.100.7", "", "203.0.113.42"], with_comments=True)
    tl = TorExitList(path, refresh_interval_s=60.0)
    assert await tl.size() == 2


async def test_malformed_lines_silently_skipped(tmp_path: Path) -> None:
    path = tmp_path / "exits.txt"
    path.write_text("198.51.100.7\nnot-an-ip\n203.0.113.42\n", encoding="utf-8")
    tl = TorExitList(path, refresh_interval_s=60.0)
    assert await tl.size() == 2


async def test_interval_triggers_reload(tmp_path: Path) -> None:
    path = tmp_path / "exits.txt"
    _write_exits(path, ["198.51.100.7"])
    clock = _FakeClock()
    tl = TorExitList(path, refresh_interval_s=60.0, clock=clock)
    assert await tl.contains("198.51.100.7") is True
    # Update file but bump mtime forward so the mtime-check fires too,
    # then advance the clock so the interval condition is what we hit.
    _write_exits(path, ["198.51.100.7", "203.0.113.42"])
    # Reset cached mtime by reading a sentinel so we know reload happened.
    os.utime(path, (time.time(), time.time()))
    clock.advance(120.0)
    assert await tl.contains("203.0.113.42") is True


async def test_mtime_change_triggers_reload_within_interval(
    tmp_path: Path,
) -> None:
    path = tmp_path / "exits.txt"
    _write_exits(path, ["198.51.100.7"])
    clock = _FakeClock()
    tl = TorExitList(path, refresh_interval_s=3600.0, clock=clock)
    assert await tl.contains("198.51.100.7") is True
    # Without advancing the clock, change the file. mtime-detection should
    # pick this up regardless of the refresh interval.
    _write_exits(path, ["10.0.0.5"])
    now = time.time() + 1
    os.utime(path, (now, now))
    assert await tl.contains("10.0.0.5") is True
    assert await tl.contains("198.51.100.7") is False


async def test_explicit_reload(tmp_path: Path) -> None:
    path = tmp_path / "exits.txt"
    _write_exits(path, ["198.51.100.7"])
    tl = TorExitList(path, refresh_interval_s=3600.0)
    await tl.reload()
    assert await tl.size() == 1


async def test_properties(tmp_path: Path) -> None:
    path = tmp_path / "exits.txt"
    tl = TorExitList(path, refresh_interval_s=120.0)
    assert tl.path == path
    assert tl.refresh_interval_s == 120.0
