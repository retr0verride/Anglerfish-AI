"""Tests for :mod:`anglerfish.models.fingerprint`."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from anglerfish.models.fingerprint import SessionFingerprint, SshBannerInfo


def test_ssh_banner_info_minimal() -> None:
    info = SshBannerInfo(raw="SSH-2.0-x")
    assert info.protocol is None


def test_session_fingerprint_rejects_bad_hassh() -> None:
    with pytest.raises(ValidationError):
        SessionFingerprint(source_ip="1.2.3.4", hassh="not-hex")


def test_session_fingerprint_accepts_lowercase_hex() -> None:
    sf = SessionFingerprint(
        source_ip="1.2.3.4",
        hassh="0123456789abcdef0123456789abcdef",
    )
    assert sf.hassh == "0123456789abcdef0123456789abcdef"


def test_session_fingerprint_frozen() -> None:
    sf = SessionFingerprint(source_ip="1.2.3.4")
    with pytest.raises(ValidationError):
        sf.source_ip = "5.6.7.8"  # type: ignore[misc]
