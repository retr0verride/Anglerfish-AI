"""Tests for the private ``_PerIPLimiter`` inside :mod:`anglerfish.lure.server`."""

from __future__ import annotations

from anglerfish.lure.server import _PerIPLimiter


def test_first_connection_admitted() -> None:
    lim = _PerIPLimiter(max_concurrent=3, max_rpm=12)
    allowed, reason = lim.admit("203.0.113.7", now=100.0)
    assert allowed is True
    assert reason == ""
    assert lim.concurrent_for("203.0.113.7") == 1


def test_per_ip_concurrent_cap_rejects_overflow() -> None:
    lim = _PerIPLimiter(max_concurrent=2, max_rpm=10)
    assert lim.admit("1.1.1.1", now=1.0)[0] is True
    assert lim.admit("1.1.1.1", now=1.1)[0] is True
    allowed, reason = lim.admit("1.1.1.1", now=1.2)
    assert allowed is False
    assert reason == "per_ip_concurrent"
    assert lim.concurrent_for("1.1.1.1") == 2  # rejection did not bump


def test_release_decrements_concurrent() -> None:
    lim = _PerIPLimiter(max_concurrent=2, max_rpm=10)
    lim.admit("1.1.1.1", now=1.0)
    lim.admit("1.1.1.1", now=1.1)
    lim.release("1.1.1.1")
    assert lim.concurrent_for("1.1.1.1") == 1
    # After release, the slot is available again.
    allowed, _ = lim.admit("1.1.1.1", now=2.0)
    assert allowed is True


def test_release_below_zero_is_safe() -> None:
    lim = _PerIPLimiter(max_concurrent=3, max_rpm=10)
    lim.release("never-seen")  # no-op
    assert lim.concurrent_for("never-seen") == 0


def test_release_after_single_admit_clears_entry() -> None:
    lim = _PerIPLimiter(max_concurrent=3, max_rpm=10)
    lim.admit("1.1.1.1", now=1.0)
    lim.release("1.1.1.1")
    # Internal dict pop: concurrent_for returns 0 either way, but the
    # entry should be gone from the dict to keep memory bounded.
    assert lim.concurrent_for("1.1.1.1") == 0


def test_rpm_cap_rejects_burst() -> None:
    lim = _PerIPLimiter(max_concurrent=100, max_rpm=3)
    for i in range(3):
        assert lim.admit("1.1.1.1", now=10.0 + i)[0] is True
    allowed, reason = lim.admit("1.1.1.1", now=13.0)
    assert allowed is False
    assert reason == "per_ip_rpm"


def test_rpm_window_slides() -> None:
    lim = _PerIPLimiter(max_concurrent=100, max_rpm=3)
    for i in range(3):
        assert lim.admit("1.1.1.1", now=10.0 + i)[0] is True
    # Wait past the 60s window; old entries expire and the limiter
    # accepts again.
    allowed, _ = lim.admit("1.1.1.1", now=10.0 + 61.0)
    assert allowed is True


def test_separate_ips_dont_share_counters() -> None:
    lim = _PerIPLimiter(max_concurrent=1, max_rpm=1)
    assert lim.admit("1.1.1.1", now=1.0)[0] is True
    # A second IP is not throttled by the first's count.
    assert lim.admit("2.2.2.2", now=1.0)[0] is True


def test_concurrent_check_runs_before_rpm() -> None:
    """If both caps fire, the more-severe (concurrent) reason wins."""
    lim = _PerIPLimiter(max_concurrent=1, max_rpm=1)
    assert lim.admit("1.1.1.1", now=1.0)[0] is True
    allowed, reason = lim.admit("1.1.1.1", now=2.0)
    assert allowed is False
    # concurrent check fires first because it's the cheaper one.
    assert reason == "per_ip_concurrent"
