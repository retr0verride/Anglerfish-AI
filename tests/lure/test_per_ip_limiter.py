"""Tests for the private ``_PerIPLimiter`` inside :mod:`anglerfish.lure.server`."""

from __future__ import annotations

from anglerfish.lure.server import _RECENT_SWEEP_THRESHOLD, _PerIPLimiter


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


# ---------------------------------------------------------------------------
# Boundary cases (closed TODO-5)
# ---------------------------------------------------------------------------


def test_empty_source_ip_treated_as_valid_distinct_key() -> None:
    """An empty source_ip is its own bucket; behaviour is documented, not undefined.

    The limiter does not (and should not) treat empty / whitespace IPs
    specially: input validation lives in the caller (the asyncssh
    server records connections it already has a peer address for).
    This test pins the actual behaviour so a regression that
    silently coalesces every "" connection under one cap is caught.
    """
    lim = _PerIPLimiter(max_concurrent=1, max_rpm=10)
    # Empty + whitespace are SEPARATE buckets; both admit independently.
    assert lim.admit("", now=1.0) == (True, "")
    assert lim.admit("   ", now=1.0) == (True, "")
    # Repeated empty hits the per-bucket concurrent cap.
    allowed, reason = lim.admit("", now=1.1)
    assert allowed is False
    assert reason == "per_ip_concurrent"


def test_exact_edge_transition_at_max_concurrent() -> None:
    """The reject lands precisely at concurrent == max, not at max - 1.

    The existing tests jump from "well under" to "well over"; this
    pins the off-by-one behaviour at the boundary.
    """
    lim = _PerIPLimiter(max_concurrent=3, max_rpm=10)
    # 0 -> 1, 1 -> 2 admitted; concurrent is now exactly 2.
    assert lim.admit("1.1.1.1", now=1.0) == (True, "")
    assert lim.admit("1.1.1.1", now=1.1) == (True, "")
    assert lim.concurrent_for("1.1.1.1") == 2
    # 2 -> 3 is the last admit; concurrent is now exactly max.
    assert lim.admit("1.1.1.1", now=1.2) == (True, "")
    assert lim.concurrent_for("1.1.1.1") == 3
    # The next admit is the boundary reject; the predicate is
    # `current >= max_concurrent` BEFORE bump, so 3 == 3 rejects.
    allowed, reason = lim.admit("1.1.1.1", now=1.3)
    assert allowed is False
    assert reason == "per_ip_concurrent"
    # Reject did not bump.
    assert lim.concurrent_for("1.1.1.1") == 3


def test_same_tick_rapid_fire_does_not_double_count() -> None:
    """N admits at identical ``now`` count exactly N against the rpm window.

    A burst of admits in the same microsecond tick is plausible
    when an attacker pipelines connections through a Tor circuit;
    the limiter's per-minute deque must not double-count them
    (would prematurely reject the (N+1)th admit) and must not
    drop any (would silently exceed the cap).
    """
    lim = _PerIPLimiter(max_concurrent=100, max_rpm=3)
    # Three admits at identical timestamps fill the rpm bucket.
    assert lim.admit("1.1.1.1", now=100.0) == (True, "")
    assert lim.admit("1.1.1.1", now=100.0) == (True, "")
    assert lim.admit("1.1.1.1", now=100.0) == (True, "")
    # The fourth at the same tick must reject on per_ip_rpm
    # (concurrent cap is way above three).
    allowed, reason = lim.admit("1.1.1.1", now=100.0)
    assert allowed is False
    assert reason == "per_ip_rpm"


# ---------------------------------------------------------------------------
# Memory bound (audit finding H1)
# ---------------------------------------------------------------------------


def test_recent_map_bounded_under_ip_rotation() -> None:
    """The sliding-window ``_recent`` map must not grow without bound.

    ``release`` cleans ``_concurrent`` but never touches ``_recent``;
    without an eviction sweep, every distinct source IP that ever
    connects leaves a permanent ``_recent`` entry. A botnet / Tor /
    proxy rotation that cycles tens of thousands of one-shot IPs (the
    norm for an internet-facing honeypot) would grow ``_recent``
    forever and OOM the listener. After the clock advances past the
    window for the early IPs, a bounded limiter must have evicted their
    stale entries.
    """
    lim = _PerIPLimiter(max_concurrent=3, max_rpm=12)
    n = 30_000
    for i in range(n):
        # A distinct IP each iteration; the clock advances one second per
        # connection so the early entries fall out of the rpm window long
        # before the loop ends.
        ip = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
        lim.admit(ip, now=float(i))
    # The live set at any instant is only the IPs seen within the last
    # window; a bounded map holds far fewer than the n distinct IPs.
    assert len(lim._recent) < n // 2
    # The sweep is gated on a high-water mark, so the map is bounded to
    # the threshold plus the single entry that triggers the next sweep -
    # never the n distinct IPs.
    assert len(lim._recent) <= _RECENT_SWEEP_THRESHOLD + 1


def test_recent_map_hard_capped_under_distinct_ip_flood() -> None:
    """A flood of distinct IPs inside one window cannot exceed the cap.

    The stale-eviction sweep reclaims nothing when every window is still
    live (a high-distinct-rate flood: >threshold unique IPs within the
    60s window). Without a hard cap the map would grow with the live set
    instead of a constant, and the sweep would re-scan O(n) on every
    admit. The limiter must instead evict the least-recently-active
    windows down to a low-water mark, so memory stays a hard constant.
    """
    lim = _PerIPLimiter(max_concurrent=100, max_rpm=100)
    n = 30_000
    for i in range(n):
        # All at the SAME instant, so no window ever ages out of the
        # rpm cutoff: stale-eviction frees nothing and only the hard cap
        # can bound the map.
        ip = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
        lim.admit(ip, now=1000.0)
    assert len(lim._recent) <= _RECENT_SWEEP_THRESHOLD + 1


def test_global_concurrent_cap_blocks_distributed_flood() -> None:
    """Mythos M2: the global ceiling rejects new sessions across DIFFERENT
    source IPs once the aggregate live count is reached, even when each IP
    is under its per-IP cap."""
    lim = _PerIPLimiter(max_concurrent=3, max_rpm=1000, max_total=2)
    ok1, _ = lim.admit("10.0.0.1")
    ok2, _ = lim.admit("10.0.0.2")
    assert ok1 and ok2  # two distinct IPs, both under per-IP cap
    ok3, reason = lim.admit("10.0.0.3")  # third distinct IP -> global cap
    assert ok3 is False
    assert reason == "global_concurrent"
    # releasing one frees a global slot
    lim.release("10.0.0.1")
    ok4, _ = lim.admit("10.0.0.3")
    assert ok4 is True
