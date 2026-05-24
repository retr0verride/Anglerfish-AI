"""Tests for :mod:`anglerfish.lure.banner`."""

from __future__ import annotations

import pytest

from anglerfish.lure.banner import debian_banner


def test_default_banner_matches_debian_12_stable() -> None:
    assert debian_banner() == "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"


def test_banner_with_custom_versions() -> None:
    assert (
        debian_banner(openssh_version="9.6p1", debian_version="3+deb12u5")
        == "SSH-2.0-OpenSSH_9.6p1 Debian-3+deb12u5"
    )


def test_banner_rejects_empty_openssh_version() -> None:
    with pytest.raises(ValueError, match="openssh_version"):
        debian_banner(openssh_version="")


def test_banner_rejects_empty_debian_version() -> None:
    with pytest.raises(ValueError, match="debian_version"):
        debian_banner(debian_version="")


def test_banner_starts_with_ssh_protocol_marker() -> None:
    # RFC 4253 section 4.2: identification string MUST start with SSH-2.0-
    assert debian_banner().startswith("SSH-2.0-")
