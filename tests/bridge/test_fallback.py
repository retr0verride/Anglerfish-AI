"""Tests for :func:`anglerfish.bridge.fallback_response`."""

from __future__ import annotations

import pytest

from anglerfish.bridge.fallback import fallback_response


@pytest.fixture
def env() -> dict[str, str]:
    return {"hostname": "srv-prod-01", "username": "root", "cwd": "/root"}


def test_empty_command_returns_empty(env: dict[str, str]) -> None:
    assert fallback_response("", **env) == ""
    assert fallback_response("   ", **env) == ""


def test_whoami_returns_username(env: dict[str, str]) -> None:
    assert fallback_response("whoami", **env) == "root"


def test_id_for_root(env: dict[str, str]) -> None:
    assert "uid=0(root)" in fallback_response("id", **env)  # type: ignore[operator]


def test_id_for_regular_user(env: dict[str, str]) -> None:
    env = env | {"username": "alice"}
    result = fallback_response("id", **env)
    assert result is not None
    assert "uid=1000(alice)" in result


def test_hostname(env: dict[str, str]) -> None:
    assert fallback_response("hostname", **env) == "srv-prod-01"


def test_pwd(env: dict[str, str]) -> None:
    env = env | {"cwd": "/var/log"}
    assert fallback_response("pwd", **env) == "/var/log"


@pytest.mark.parametrize(
    ("cmd", "expected_fragment"),
    [
        ("uname", "Linux"),
        ("uname -s", "Linux"),
        ("uname -r", "6.1.0-26-amd64"),
        ("uname -m", "x86_64"),
        ("uname -n", "srv-prod-01"),
        ("uname -o", "GNU/Linux"),
    ],
)
def test_uname_variants(cmd: str, expected_fragment: str, env: dict[str, str]) -> None:
    result = fallback_response(cmd, **env)
    assert result is not None
    assert expected_fragment in result


def test_uname_a_includes_kernel_and_hostname(env: dict[str, str]) -> None:
    result = fallback_response("uname -a", **env)
    assert result is not None
    assert "srv-prod-01" in result
    assert "6.1.0-26-amd64" in result


def test_echo(env: dict[str, str]) -> None:
    assert fallback_response("echo hello world", **env) == "hello world"


def test_uptime(env: dict[str, str]) -> None:
    result = fallback_response("uptime", **env)
    assert result is not None
    assert "load average" in result


@pytest.mark.parametrize("cmd", ["exit", "logout"])
def test_exit_commands_return_empty(cmd: str, env: dict[str, str]) -> None:
    assert fallback_response(cmd, **env) == ""


def test_unknown_returns_none(env: dict[str, str]) -> None:
    assert fallback_response("supersecrettool --rm-rf", **env) is None


def test_quote_imbalance_returns_none(env: dict[str, str]) -> None:
    # shlex.split raises on unterminated quotes — fallback should not match.
    assert fallback_response('echo "unterminated', **env) is None
