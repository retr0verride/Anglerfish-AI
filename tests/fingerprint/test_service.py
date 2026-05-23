"""Tests for :class:`anglerfish.fingerprint.Fingerprinter`."""

from __future__ import annotations

from pathlib import Path

import pytest

from anglerfish.config import AnglerfishSettings
from anglerfish.config.models import FingerprintConfig
from anglerfish.fingerprint import Fingerprinter, TorExitList


def _settings_with_tor_path(base: AnglerfishSettings, path: Path) -> AnglerfishSettings:
    return base.model_copy(
        update={
            "fingerprint": FingerprintConfig(
                tor_exit_list_path=path,
                tor_exit_refresh_interval_s=3600.0,
            ),
        },
    )


async def test_fingerprint_parses_banner_and_checks_tor(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> None:
    exits_path = tmp_path / "exits.txt"
    exits_path.write_text("198.51.100.7\n", encoding="utf-8")
    cfg = _settings_with_tor_path(settings, exits_path)
    fp = Fingerprinter(cfg)
    try:
        result = await fp.fingerprint(
            source_ip="198.51.100.7",
            ssh_banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu",
        )
    finally:
        await fp.aclose()
    assert result.is_tor_exit is True
    assert result.ssh_banner is not None
    assert result.ssh_banner.software_name == "OpenSSH"
    assert result.hassh is None
    assert result.ja3 is None


async def test_fingerprint_validates_hash_format(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> None:
    fp = Fingerprinter(
        _settings_with_tor_path(settings, tmp_path / "missing.txt"),
    )
    try:
        result = await fp.fingerprint(
            source_ip="10.0.0.5",
            hassh="ABCDEF0123456789ABCDEF0123456789",
            ja3="0123456789abcdef0123456789abcdef",
        )
    finally:
        await fp.aclose()
    assert result.hassh == "abcdef0123456789abcdef0123456789"
    assert result.ja3 == "0123456789abcdef0123456789abcdef"


async def test_fingerprint_rejects_bad_hash(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> None:
    fp = Fingerprinter(
        _settings_with_tor_path(settings, tmp_path / "missing.txt"),
    )
    with pytest.raises(ValueError):
        await fp.fingerprint(source_ip="10.0.0.5", hassh="too-short")
    with pytest.raises(ValueError):
        await fp.fingerprint(source_ip="10.0.0.5", ja3="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
    await fp.aclose()


async def test_fingerprint_no_banner(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> None:
    fp = Fingerprinter(
        _settings_with_tor_path(settings, tmp_path / "missing.txt"),
    )
    try:
        result = await fp.fingerprint(source_ip="10.0.0.5")
    finally:
        await fp.aclose()
    assert result.ssh_banner is None
    assert result.is_tor_exit is False


async def test_fingerprint_accepts_injected_tor_list(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> None:
    exits_path = tmp_path / "exits.txt"
    exits_path.write_text("203.0.113.42\n", encoding="utf-8")
    tor = TorExitList(exits_path, refresh_interval_s=60.0)
    fp = Fingerprinter(settings, tor_exit_list=tor)
    try:
        result = await fp.fingerprint(source_ip="203.0.113.42")
    finally:
        await fp.aclose()
    assert result.is_tor_exit is True
    assert fp.tor_exit_list is tor


async def test_async_context_manager(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> None:
    async with Fingerprinter(
        _settings_with_tor_path(settings, tmp_path / "missing.txt"),
    ) as fp:
        result = await fp.fingerprint(source_ip="10.0.0.5")
    assert result.source_ip == "10.0.0.5"


def test_fingerprinter_properties(
    settings: AnglerfishSettings,
    tmp_path: Path,
) -> None:
    cfg = _settings_with_tor_path(settings, tmp_path / "x.txt")
    fp = Fingerprinter(cfg)
    assert fp.settings is cfg
    assert isinstance(fp.tor_exit_list, TorExitList)
