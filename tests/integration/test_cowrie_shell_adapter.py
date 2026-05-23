"""Tests for :mod:`anglerfish.integration.cowrie_shell_adapter`.

The patch itself can only be installed when Cowrie is importable —
which it isn't in the test environment — so these tests target the
adapter's pure helpers and the install/uninstall idempotency guard.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from anglerfish.integration import cowrie_shell_adapter


def _shell(
    *,
    sessionno: int | None = 42,
    src_ip: str | None = "203.0.113.7",
    username: Any = "alice",
    has_protocol: bool = True,
) -> Any:
    """Build a duck-typed mock that approximates the bits of HoneyPotShell we read."""
    peer = SimpleNamespace(host=src_ip) if src_ip is not None else SimpleNamespace()
    inner_transport: Any = SimpleNamespace(getPeer=lambda: peer)
    if src_ip is None:
        del inner_transport.getPeer
    session = SimpleNamespace(sessionno=sessionno) if sessionno is not None else SimpleNamespace()
    outer_transport = SimpleNamespace(transport=inner_transport, session=session)
    user = SimpleNamespace(username=username) if username is not None else SimpleNamespace()
    protocol = SimpleNamespace(transport=outer_transport, user=user)
    if not has_protocol:
        return SimpleNamespace()
    return SimpleNamespace(protocol=protocol)


def test_extract_metadata_happy_path() -> None:
    sid, ip, user = cowrie_shell_adapter.extract_session_metadata(_shell())
    assert sid == "42"
    assert ip == "203.0.113.7"
    assert user == "alice"


def test_extract_metadata_bytes_username() -> None:
    _, _, user = cowrie_shell_adapter.extract_session_metadata(
        _shell(username=b"r\xf3\xf3t"),
    )
    assert isinstance(user, str)
    assert "r" in user  # decoded best-effort


def test_extract_metadata_missing_session_falls_back_to_id() -> None:
    shell = _shell(sessionno=None)
    sid, ip, user = cowrie_shell_adapter.extract_session_metadata(shell)
    # Falls back to Python's id(shell) — must be a non-empty digit string
    assert sid.isdigit()
    assert ip == "203.0.113.7"
    assert user == "alice"


def test_extract_metadata_missing_peer_falls_back() -> None:
    shell = _shell(src_ip=None)
    _, ip, _ = cowrie_shell_adapter.extract_session_metadata(shell)
    assert ip == "0.0.0.0"


def test_extract_metadata_missing_username_defaults_to_root() -> None:
    shell = _shell(username=None)
    _, _, user = cowrie_shell_adapter.extract_session_metadata(shell)
    assert user == "root"


def test_extract_metadata_missing_protocol_returns_defaults() -> None:
    shell = _shell(has_protocol=False)
    sid, ip, user = cowrie_shell_adapter.extract_session_metadata(shell)
    assert sid.isdigit()  # falls back to id(shell)
    assert ip == "0.0.0.0"
    assert user == "root"


def test_extract_metadata_getpeer_raises_returns_default() -> None:
    def _raise() -> Any:
        raise OSError("transport closed")

    peer_failing_transport = SimpleNamespace(getPeer=_raise)
    outer = SimpleNamespace(transport=peer_failing_transport, session=SimpleNamespace(sessionno=1))
    proto = SimpleNamespace(transport=outer, user=SimpleNamespace(username="x"))
    shell = SimpleNamespace(protocol=proto)
    _, ip, _ = cowrie_shell_adapter.extract_session_metadata(shell)
    assert ip == "0.0.0.0"


def test_install_without_cowrie_is_silent() -> None:
    # In the test env Cowrie is not installed; install() should log and return False.
    cowrie_shell_adapter.uninstall_for_tests()
    cowrie_shell_adapter.install()
    assert cowrie_shell_adapter.is_installed() is False


def test_uninstall_without_install_is_silent() -> None:
    cowrie_shell_adapter.uninstall_for_tests()  # must not raise
    assert cowrie_shell_adapter.is_installed() is False


def test_module_exports() -> None:
    assert "install" in cowrie_shell_adapter.__all__
    assert "is_installed" in cowrie_shell_adapter.__all__
    assert "extract_session_metadata" in cowrie_shell_adapter.__all__
