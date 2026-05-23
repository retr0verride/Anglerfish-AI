"""Tests for :func:`anglerfish.fingerprint.parse_ssh_banner`."""

from __future__ import annotations

import pytest

from anglerfish.fingerprint.ssh import parse_ssh_banner


def test_full_openssh_ubuntu_banner() -> None:
    info = parse_ssh_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
    assert info.protocol == "2.0"
    assert info.software == "OpenSSH_8.9p1"
    assert info.software_name == "OpenSSH"
    assert info.software_version == "8.9p1"
    assert info.comments == "Ubuntu-3ubuntu0.1"


def test_software_without_underscore() -> None:
    info = parse_ssh_banner("SSH-2.0-libssh2 1.10.0")
    assert info.protocol == "2.0"
    assert info.software_name == "libssh2"
    assert info.software_version is None
    assert info.comments == "1.10.0"


def test_putty_banner() -> None:
    info = parse_ssh_banner("SSH-2.0-PUTTY_Release_0.74")
    # The first '_' separates name from version, version contains the rest.
    assert info.software_name == "PUTTY"
    assert info.software_version == "Release_0.74"


def test_strips_trailing_crlf() -> None:
    info = parse_ssh_banner("SSH-2.0-OpenSSH_9.5\r\n")
    assert "\r" not in info.raw
    assert "\n" not in info.raw


def test_non_ssh_input_passes_through_raw() -> None:
    info = parse_ssh_banner("hello there")
    assert info.protocol is None
    assert info.software is None
    assert info.raw == "hello there"


def test_truncated_banner_protocol_only() -> None:
    info = parse_ssh_banner("SSH-2.0")
    assert info.protocol == "2.0"
    assert info.software is None


def test_truncated_banner_dash_no_software() -> None:
    info = parse_ssh_banner("SSH-2.0-")
    assert info.protocol == "2.0"
    assert info.software is None


def test_truncated_banner_no_protocol() -> None:
    info = parse_ssh_banner("SSH-")
    # body is empty after stripping prefix → no protocol set
    assert info.protocol is None


def test_overlong_banner_truncated_to_255() -> None:
    long_banner = "SSH-2.0-Soft_1.0 " + "x" * 500
    info = parse_ssh_banner(long_banner)
    assert len(info.raw) <= 255


def test_non_string_input_raises() -> None:
    with pytest.raises(TypeError):
        parse_ssh_banner(b"SSH-2.0-OpenSSH_8")  # type: ignore[arg-type]
