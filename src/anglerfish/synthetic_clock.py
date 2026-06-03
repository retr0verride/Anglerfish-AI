"""Synthetic clock for the lure's time and session commands (TODO-11).

`date`, `uptime`, `timedatectl`, `w`, and `last`, plus `/proc/uptime`, all
describe the same box's notion of time. Before this module they were either
unimplemented (routed to the LLM, which invents a different, non-advancing
answer each call) or hard-coded inconsistently: the bridge fallback `uptime`
claimed 7 days while `/proc/uptime` and the prompt hint claimed ~14, and the
two carried different load averages.

This module is the single source. A `SyntheticClock` anchors a fixed boot
time (a plausible long uptime before the process started, matching the
"forgotten box" persona) and reads the wall clock for "now", so uptime and
date advance like a real box while every surface derives from the same
values. Times render in UTC: servers commonly run UTC, and it avoids leaking
the real host timezone.

The clock is a process singleton (`clock()`); `now_fn` and `boot_time` are
injectable so tests can pin them.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Final

from anglerfish import system_identity

# Base uptime so a freshly started process already looks like a long-running
# box. ~14.3 days, matching the legacy /proc/uptime (1234567s) and the
# forgotten-debian-box persona.
INITIAL_UPTIME: Final = timedelta(seconds=1_234_567)

# Single source for the 1/5/15-minute load averages. /proc/loadavg, `uptime`,
# and `w` all render these, so they cannot disagree.
LOAD_AVG: Final[tuple[float, float, float]] = (0.04, 0.11, 0.07)

# Logical CPU count, kept in step with the 4-stanza /proc/cpuinfo. The
# /proc/uptime idle field is roughly cpus * uptime for a near-idle box; the
# legacy value implied 8 CPUs against a 4-core cpuinfo.
_CPU_COUNT: Final = 4


def _fmt_uptime_clause(up: timedelta) -> str:
    """Render the ``up ...`` clause exactly as procps `uptime` does."""
    total_minutes = int(up.total_seconds() // 60)
    days, rem = divmod(total_minutes, 60 * 24)
    hours, minutes = divmod(rem, 60)
    if days > 0:
        plural = "s" if days != 1 else ""
        return f"up {days} day{plural}, {hours:2d}:{minutes:02d}"
    if hours > 0:
        return f"up {hours:2d}:{minutes:02d}"
    return f"up {minutes} min"


class SyntheticClock:
    """Single source of the box's time-derived surfaces."""

    def __init__(self, *, boot_time: datetime, now_fn: Callable[[], datetime]) -> None:
        self._boot_time = boot_time
        self._now_fn = now_fn

    def now(self) -> datetime:
        return self._now_fn()

    def boot_time(self) -> datetime:
        return self._boot_time

    def uptime(self) -> timedelta:
        return self._now_fn() - self._boot_time

    # -- /proc -------------------------------------------------------------

    def proc_uptime(self) -> str:
        up = self.uptime().total_seconds()
        # Near-idle box: idle time ~ cpus * uptime, just under so it stays
        # plausible. Advances with uptime instead of being frozen.
        idle = up * (_CPU_COUNT - 0.1)
        return f"{up:.2f} {idle:.2f}\n"

    def proc_loadavg(self) -> str:
        one, five, fifteen = LOAD_AVG
        return f"{one:.2f} {five:.2f} {fifteen:.2f} 1/142 1432\n"

    # -- commands ----------------------------------------------------------

    def render_date(self, tokens: list[str]) -> str | None:
        """`date`, `date -u`, `date +%s`; other formats route to the bridge."""
        args = tokens[1:]
        now = self.now()
        if not args or args == ["-u"]:
            # C-locale default: "Tue Jun  3 14:23:01 UTC 2026".
            return now.strftime("%a %b %e %H:%M:%S UTC %Y")
        if args == ["+%s"] or args == ["-u", "+%s"]:
            return str(int(now.timestamp()))
        return None

    def render_uptime(self) -> str:
        now = self.now()
        one, five, fifteen = LOAD_AVG
        return (
            f" {now:%H:%M:%S} {_fmt_uptime_clause(self.uptime())},  1 user,  "
            f"load average: {one:.2f}, {five:.2f}, {fifteen:.2f}"
        )

    def render_uptime_pretty(self) -> str:
        """`uptime -p`, e.g. ``up 14 days, 6 hours, 24 minutes``."""
        total_minutes = int(self.uptime().total_seconds() // 60)
        days, rem = divmod(total_minutes, 60 * 24)
        hours, minutes = divmod(rem, 60)
        parts: list[str] = []
        if days:
            parts.append(f"{days} day{'s' if days != 1 else ''}")
        if hours:
            parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
        if minutes:
            parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
        return "up " + ", ".join(parts) if parts else "up 0 minutes"

    def render_uptime_since(self) -> str:
        """`uptime -s`, the boot timestamp."""
        return self.boot_time().strftime("%Y-%m-%d %H:%M:%S")

    def render_timedatectl(self) -> str:
        now = self.now()
        stamp = now.strftime("%a %Y-%m-%d %H:%M:%S UTC")
        rtc = now.strftime("%a %Y-%m-%d %H:%M:%S")
        return (
            f"               Local time: {stamp}\n"
            f"           Universal time: {stamp}\n"
            f"                 RTC time: {rtc}\n"
            f"                Time zone: Etc/UTC (UTC, +0000)\n"
            f"System clock synchronized: yes\n"
            f"              NTP service: active\n"
            f"          RTC in local TZ: no"
        )

    def render_w(self, *, username: str, source_ip: str, login_at: datetime) -> str:
        header = self.render_uptime()
        cols = "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT"
        row = (
            f"{username:<8} pts/0    {source_ip:<15.15}  {login_at:%H:%M}    2.00s  0.04s  0.00s w"
        )
        return f"{header}\n{cols}\n{row}"

    def render_last(self, *, username: str, source_ip: str, login_at: datetime) -> str:
        boot = self.boot_time()
        # A couple of plausible prior logins predating this boot, plus the
        # current session and the boot itself. Kernel matches the single
        # source so `last` agrees with `uname`.
        prior1 = boot - timedelta(days=3, hours=2, minutes=11)
        prior2 = boot - timedelta(days=9, hours=20, minutes=4)
        kernel = system_identity.KERNEL_RELEASE
        lines = [
            f"{username:<8} pts/0    {source_ip:<15.15}  "
            f"{login_at:%a %b %e %H:%M}   still logged in",
            f"reboot   system boot  {kernel:<15.15}  {boot:%a %b %e %H:%M}   still running",
            f"{username:<8} pts/0    {source_ip:<15.15}  {prior1:%a %b %e %H:%M} - down  (00:14)",
            f"{username:<8} pts/0    10.0.0.4         {prior2:%a %b %e %H:%M} - down  (01:02)",
            "",
            f"wtmp begins {prior2:%a %b %e %H:%M:%S %Y}",
        ]
        return "\n".join(lines)


def _build_default() -> SyntheticClock:
    boot = datetime.now(tz=UTC) - INITIAL_UPTIME
    return SyntheticClock(boot_time=boot, now_fn=lambda: datetime.now(tz=UTC))


_CLOCK: SyntheticClock = _build_default()


def clock() -> SyntheticClock:
    """Return the process-wide synthetic clock."""
    return _CLOCK
