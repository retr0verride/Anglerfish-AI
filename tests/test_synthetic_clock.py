"""Synthetic clock + time/session command consistency (TODO-11).

The box's time surfaces (`date`, `uptime`, `timedatectl`, `w`, `last`, and
`/proc/uptime`) must agree and advance like a real host. These tests pin a
`SyntheticClock`, exercise each surface, and assert cross-surface
consistency (the load average matches `/proc/loadavg`, the `last` reboot
kernel matches the single identity source, `/proc/uptime` advances).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from anglerfish import synthetic_clock, system_identity
from anglerfish.bridge.fallback import fallback_response
from anglerfish.lure.commands import LatencyJitter, NativeCommands
from anglerfish.lure.config import LureConfig
from anglerfish.lure.fakefs import read
from anglerfish.lure.session import LureSessionContext

_BOOT = datetime(2026, 5, 20, 8, 0, 0, tzinfo=UTC)
# 14 days, 2 hours, 30 minutes after boot.
_NOW = _BOOT + timedelta(days=14, hours=2, minutes=30)


def _fixed_clock(now: datetime = _NOW) -> synthetic_clock.SyntheticClock:
    return synthetic_clock.SyntheticClock(boot_time=_BOOT, now_fn=lambda: now)


@pytest.fixture
def pinned_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> synthetic_clock.SyntheticClock:
    clk = _fixed_clock()
    monkeypatch.setattr(synthetic_clock, "_CLOCK", clk)
    return clk


def _session() -> LureSessionContext:
    return LureSessionContext(
        uuid4(),
        source_ip="203.0.113.7",
        username="alice",
        hostname="srv-prod-01",
        cwd="/home/alice",
    )


def _commands() -> NativeCommands:
    cfg = LureConfig(timing_jitter_enabled=False)
    return NativeCommands(cfg, jitter=LatencyJitter(cfg))


# -- SyntheticClock units ---------------------------------------------------


def test_uptime_is_now_minus_boot() -> None:
    clk = _fixed_clock()
    assert clk.uptime() == timedelta(days=14, hours=2, minutes=30)


def test_render_uptime_carries_days_and_single_source_load() -> None:
    line = _fixed_clock().render_uptime()
    assert "up 14 days" in line
    assert "1 user" in line
    assert "load average: 0.04, 0.11, 0.07" in line
    assert line.startswith(" 10:30:00")  # 08:00 boot + 2h30 = 10:30 "now"


def test_render_date_default_and_epoch() -> None:
    clk = _fixed_clock()
    # boot May 20 08:00 + 14d2h30m = Wed Jun 3 10:30:00.
    assert clk.render_date(["date"]) == "Wed Jun  3 10:30:00 UTC 2026"
    assert clk.render_date(["date", "-u"]) == "Wed Jun  3 10:30:00 UTC 2026"
    assert clk.render_date(["date", "+%s"]) == str(int(_NOW.timestamp()))
    # An unsupported format string routes to the bridge.
    assert clk.render_date(["date", "+%Y-%m-%d"]) is None


def test_proc_uptime_advances() -> None:
    early = synthetic_clock.SyntheticClock(boot_time=_BOOT, now_fn=lambda: _NOW)
    later = synthetic_clock.SyntheticClock(
        boot_time=_BOOT, now_fn=lambda: _NOW + timedelta(seconds=42)
    )
    e_secs = float(early.proc_uptime().split()[0])
    l_secs = float(later.proc_uptime().split()[0])
    assert l_secs == pytest.approx(e_secs + 42, abs=0.01)
    # Idle field ~ cpus * uptime (4 cores), not the legacy 8x ratio.
    up, idle = (float(x) for x in early.proc_uptime().split())
    assert 3.5 < idle / up < 4.0


def test_render_last_reboot_uses_single_kernel_source() -> None:
    out = _fixed_clock().render_last(username="alice", source_ip="203.0.113.7", login_at=_NOW)
    assert "still logged in" in out
    assert "reboot   system boot" in out
    assert system_identity.KERNEL_RELEASE in out


def test_render_w_header_equals_uptime_line() -> None:
    clk = _fixed_clock()
    w = clk.render_w(username="alice", source_ip="203.0.113.7", login_at=_NOW)
    assert w.splitlines()[0] == clk.render_uptime()
    assert "alice" in w
    assert "203.0.113.7" in w


def test_timedatectl_is_utc_and_synced() -> None:
    out = _fixed_clock().render_timedatectl()
    assert "Time zone: Etc/UTC (UTC, +0000)" in out
    assert "System clock synchronized: yes" in out
    assert "2026-06-03 10:30:00 UTC" in out


# -- native dispatch --------------------------------------------------------


@pytest.mark.usefixtures("pinned_clock")
async def test_native_time_commands_are_handled() -> None:
    cmds = _commands()
    for command in ("date", "uptime", "timedatectl", "w", "last", "uptime -p"):
        result = await cmds.dispatch(_session(), command)
        assert result.handled is True, command
        assert result.text.strip(), command


@pytest.mark.usefixtures("pinned_clock")
async def test_date_unknown_format_routes_to_bridge() -> None:
    result = await _commands().dispatch(_session(), "date +%Y")
    assert result.handled is False


# -- cross-surface consistency ----------------------------------------------


@pytest.mark.usefixtures("pinned_clock")
async def test_uptime_command_matches_proc_uptime() -> None:
    proc = read("/proc/uptime", _session())
    assert proc.status == "content"
    proc_secs = float(proc.content.split()[0])
    # 14d2h30m in seconds.
    assert proc_secs == pytest.approx(timedelta(days=14, hours=2, minutes=30).total_seconds())


@pytest.mark.usefixtures("pinned_clock")
async def test_proc_loadavg_matches_uptime_command_load() -> None:
    proc = read("/proc/loadavg", _session())
    assert proc.content.startswith("0.04 0.11 0.07")
    uptime_line = await _commands().dispatch(_session(), "uptime")
    assert "0.04, 0.11, 0.07" in uptime_line.text


@pytest.mark.usefixtures("pinned_clock")
def test_proc_uptime_is_not_the_frozen_legacy_value() -> None:
    content = read("/proc/uptime", _session()).content
    assert not content.startswith("1234567.89 9876543.21")


@pytest.mark.usefixtures("pinned_clock")
def test_fallback_uptime_now_consistent_no_7_days() -> None:
    out = fallback_response("uptime", hostname="srv-prod-01", username="root", cwd="/root")
    assert out == synthetic_clock.clock().render_uptime()
    assert "7 days" not in out
    assert "0.04, 0.11, 0.07" in out
