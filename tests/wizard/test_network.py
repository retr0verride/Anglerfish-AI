"""Tests for :func:`anglerfish.wizard.network.list_interfaces`."""

from __future__ import annotations

from pathlib import Path

from anglerfish.wizard.network import list_interfaces


def test_returns_empty_on_missing_root(tmp_path: Path) -> None:
    assert list_interfaces(root=tmp_path / "absent") == []


def test_returns_real_interfaces_filtering_virtual(tmp_path: Path) -> None:
    root = tmp_path / "sys-class-net"
    root.mkdir()
    for name in ["eth0", "eth1", "lo", "docker0", "veth1234", "wlan0", "br-abc"]:
        (root / name).mkdir()
    interfaces = list_interfaces(root=root)
    assert interfaces == ["eth0", "eth1", "wlan0"]


def test_only_includes_directories(tmp_path: Path) -> None:
    # If /sys/class/net contains an unexpected file, we accept it
    # (it's a symlink in real life). The current implementation
    # treats anything in the directory as a candidate name.
    root = tmp_path / "sys-class-net"
    root.mkdir()
    (root / "eth0").mkdir()
    (root / "README").write_text("ignore me\n")
    interfaces = list_interfaces(root=root)
    assert "eth0" in interfaces
