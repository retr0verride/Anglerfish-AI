"""Tests for :func:`anglerfish.lure.server.validate_bait_nic`."""

from __future__ import annotations

import pytest

from anglerfish.lure.server import BaitNicError, validate_bait_nic


def test_loopback_is_always_bindable() -> None:
    # 127.0.0.1 is always assigned (even on a fresh container).
    validate_bait_nic("127.0.0.1")  # must not raise


def test_unspecified_v4_rejected() -> None:
    with pytest.raises(BaitNicError, match="unspecified"):
        validate_bait_nic("0.0.0.0")


def test_unspecified_v6_rejected() -> None:
    with pytest.raises(BaitNicError, match="unspecified"):
        validate_bait_nic("::")


def test_invalid_ip_literal_rejected() -> None:
    with pytest.raises(BaitNicError, match="not a valid IP literal"):
        validate_bait_nic("not-an-ip")


def test_unassigned_ip_rejected() -> None:
    # 198.51.100.x is reserved for documentation (RFC 5737); never
    # assigned to a real interface. The test-bind returns EADDRNOTAVAIL.
    with pytest.raises(BaitNicError, match="not assigned"):
        validate_bait_nic("198.51.100.42")
