"""Tests for :class:`anglerfish.lure.commands.NativeCommands`."""

from __future__ import annotations

from uuid import uuid4

import pytest

from anglerfish.lure.commands import DispatchResult, LatencyJitter, NativeCommands, first_token
from anglerfish.lure.config import LureConfig
from anglerfish.lure.session import LureSessionContext


def _session(*, username: str = "alice") -> LureSessionContext:
    return LureSessionContext(
        uuid4(),
        source_ip="203.0.113.7",
        username=username,
        hostname="srv-prod-01",
        cwd=f"/home/{username}" if username != "root" else "/root",
    )


def _commands() -> NativeCommands:
    cfg = LureConfig(timing_jitter_enabled=False)
    return NativeCommands(cfg, jitter=LatencyJitter(cfg))


# ---------------------------------------------------------------------------
# first_token
# ---------------------------------------------------------------------------


def test_first_token_basic() -> None:
    assert first_token("ls -la") == "ls"


def test_first_token_empty_string() -> None:
    assert first_token("") == ""


def test_first_token_whitespace_only() -> None:
    assert first_token("   \t  ") == ""


def test_first_token_handles_quoted_args() -> None:
    assert first_token("echo 'hello world'") == "echo"


def test_first_token_falls_back_on_unbalanced_quotes() -> None:
    # shlex raises ValueError on unclosed quote; we fall back to whitespace split.
    assert first_token('echo "unterminated') == "echo"


# ---------------------------------------------------------------------------
# Native dispatch verbs
# ---------------------------------------------------------------------------


async def test_whoami_returns_session_username() -> None:
    result = await _commands().dispatch(_session(username="bob"), "whoami")
    assert result == DispatchResult(handled=True, text="bob\n")


async def test_id_for_root_returns_uid_zero() -> None:
    result = await _commands().dispatch(_session(username="root"), "id")
    assert result.handled is True
    assert "uid=0(root)" in result.text


async def test_id_for_non_root_returns_uid_1000() -> None:
    result = await _commands().dispatch(_session(username="alice"), "id")
    assert "uid=1000(alice)" in result.text
    assert "27(sudo)" in result.text


async def test_pwd_returns_session_cwd() -> None:
    s = _session(username="alice")
    s.update_cwd("/var/log")
    result = await _commands().dispatch(s, "pwd")
    assert result.text == "/var/log\n"


async def test_hostname_returns_session_hostname() -> None:
    s = _session()
    result = await _commands().dispatch(s, "hostname")
    assert result.text == "srv-prod-01\n"


async def test_uname_bare_returns_linux() -> None:
    result = await _commands().dispatch(_session(), "uname")
    assert result.text == "Linux\n"


async def test_uname_dash_a_full_output() -> None:
    result = await _commands().dispatch(_session(), "uname -a")
    assert result.handled is True
    assert "Linux srv-prod-01" in result.text
    assert "x86_64 GNU/Linux" in result.text


async def test_uname_dash_r_returns_kernel_version() -> None:
    result = await _commands().dispatch(_session(), "uname -r")
    assert "6.1" in result.text


async def test_uname_unknown_flag_routes_to_bridge() -> None:
    result = await _commands().dispatch(_session(), "uname --invalid")
    assert result.handled is False


async def test_echo_joins_with_single_space() -> None:
    result = await _commands().dispatch(_session(), "echo hello world")
    assert result.text == "hello world\n"


async def test_echo_preserves_quoted_strings() -> None:
    result = await _commands().dispatch(_session(), "echo 'hello there'")
    assert result.text == "hello there\n"


async def test_exit_returns_close_marker() -> None:
    result = await _commands().dispatch(_session(), "exit")
    assert result == DispatchResult(handled=True, text="", close_after=True)


async def test_logout_is_alias_for_exit() -> None:
    result = await _commands().dispatch(_session(), "logout")
    assert result.close_after is True


async def test_history_lists_recorded_commands() -> None:
    s = _session()
    s.record("ls", response_source="native")
    s.record("whoami", response_source="native")
    result = await _commands().dispatch(s, "history")
    assert "    1  ls" in result.text
    assert "    2  whoami" in result.text


async def test_history_empty_session_returns_empty_string() -> None:
    result = await _commands().dispatch(_session(), "history")
    assert result.text == ""


# ---------------------------------------------------------------------------
# cd
# ---------------------------------------------------------------------------


async def test_cd_absolute_path_updates_cwd() -> None:
    s = _session()
    result = await _commands().dispatch(s, "cd /etc")
    assert result.handled is True
    assert s.cwd == "/etc"


async def test_cd_relative_path_appends() -> None:
    s = _session()
    s.update_cwd("/home/alice")
    await _commands().dispatch(s, "cd .ssh")
    assert s.cwd == "/home/alice/.ssh"


async def test_cd_dotdot_traverses_up() -> None:
    s = _session()
    s.update_cwd("/etc/apt")
    await _commands().dispatch(s, "cd ..")
    assert s.cwd == "/etc"


async def test_cd_tilde_goes_home_for_user() -> None:
    s = _session(username="alice")
    s.update_cwd("/tmp")
    await _commands().dispatch(s, "cd ~")
    assert s.cwd == "/home/alice"


async def test_cd_bare_goes_to_root_for_root() -> None:
    s = _session(username="root")
    s.update_cwd("/tmp")
    await _commands().dispatch(s, "cd")
    assert s.cwd == "/root"


# ---------------------------------------------------------------------------
# ls
# ---------------------------------------------------------------------------


async def test_ls_renders_directory_from_fakefs() -> None:
    s = _session()
    s.update_cwd("/etc")
    result = await _commands().dispatch(s, "ls")
    assert result.handled is True
    assert "passwd" in result.text
    assert "fstab" in result.text


async def test_ls_long_form_includes_mode_string() -> None:
    s = _session()
    s.update_cwd("/etc")
    result = await _commands().dispatch(s, "ls -l")
    assert result.handled is True
    # rwxr-xr-x style perms appear in long form.
    assert "rw-r--r--" in result.text or "rwxr-xr-x" in result.text


async def test_ls_hidden_files_only_with_dash_a() -> None:
    s = _session()
    s.update_cwd("/root")  # has .bashrc and .bash_history
    plain = await _commands().dispatch(s, "ls")
    with_a = await _commands().dispatch(s, "ls -a")
    assert ".bashrc" not in plain.text
    assert ".bashrc" in with_a.text


async def test_ls_unknown_path_routes_to_bridge() -> None:
    result = await _commands().dispatch(_session(), "ls /totally/bogus")
    assert result.handled is False


async def test_ls_unknown_flag_routes_to_bridge() -> None:
    result = await _commands().dispatch(_session(), "ls -Z")
    assert result.handled is False


# ---------------------------------------------------------------------------
# cat
# ---------------------------------------------------------------------------


async def test_cat_known_path_returns_content() -> None:
    result = await _commands().dispatch(_session(), "cat /etc/passwd")
    assert result.handled is True
    assert "root:x:0:0" in result.text


async def test_cat_permission_denied_path_returns_canonical_error() -> None:
    result = await _commands().dispatch(_session(), "cat /etc/shadow")
    assert result.handled is True
    assert "Permission denied" in result.text


async def test_cat_unknown_path_routes_to_bridge() -> None:
    result = await _commands().dispatch(_session(), "cat /etc/totally-bogus")
    assert result.handled is False


async def test_cat_multiple_files_routes_to_bridge() -> None:
    result = await _commands().dispatch(_session(), "cat /etc/passwd /etc/group")
    assert result.handled is False


async def test_cat_with_flags_routes_to_bridge() -> None:
    result = await _commands().dispatch(_session(), "cat -n /etc/passwd")
    assert result.handled is False


async def test_cat_relative_path_uses_cwd() -> None:
    s = _session()
    s.update_cwd("/etc")
    result = await _commands().dispatch(s, "cat passwd")
    assert result.handled is True
    assert "root:x:0:0" in result.text


# ---------------------------------------------------------------------------
# Routing rules
# ---------------------------------------------------------------------------


async def test_unknown_command_routes_to_bridge() -> None:
    result = await _commands().dispatch(_session(), "wget http://x/y")
    assert result.handled is False


async def test_pipe_routes_to_bridge() -> None:
    result = await _commands().dispatch(_session(), "ls | wc -l")
    assert result.handled is False


async def test_semicolon_routes_to_bridge() -> None:
    result = await _commands().dispatch(_session(), "whoami ; id")
    assert result.handled is False


async def test_logical_and_routes_to_bridge() -> None:
    result = await _commands().dispatch(_session(), "whoami && id")
    assert result.handled is False


async def test_empty_command_handled_locally() -> None:
    result = await _commands().dispatch(_session(), "")
    assert result == DispatchResult(handled=True, text="")


async def test_whitespace_command_handled_locally() -> None:
    result = await _commands().dispatch(_session(), "   \t  ")
    assert result == DispatchResult(handled=True, text="")


async def test_first_token_match_not_substring() -> None:
    # `whoami; rm -rf /` starts with "whoami" but contains `;`, so it
    # routes to bridge (the semicolon short-circuit fires first).
    result = await _commands().dispatch(_session(), "whoami; rm -rf /")
    assert result.handled is False


# ---------------------------------------------------------------------------
# Jitter integration
# ---------------------------------------------------------------------------


async def test_jitter_called_only_on_handled_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps: list[float] = []

    async def _fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr("asyncio.sleep", _fake_sleep)
    cfg = LureConfig(
        timing_jitter_enabled=True,
        timing_jitter_bootstrap_min_ms=100,
        timing_jitter_bootstrap_max_ms=100,
    )
    cmds = NativeCommands(cfg)

    # Handled path - jitter fires.
    await cmds.dispatch(_session(), "whoami")
    # Unhandled (bridge-routed) path - jitter does NOT fire.
    await cmds.dispatch(_session(), "totally-not-a-real-command")

    assert len(sleeps) == 1
    assert sleeps[0] == pytest.approx(0.1)


def test_record_bridge_latency_forwards_to_jitter() -> None:
    cfg = LureConfig()
    cmds = NativeCommands(cfg)
    cmds.record_bridge_latency(1234.0)
    # Internal state isn't exposed; verify by sampling near the value.
    for _ in range(20):
        cmds.record_bridge_latency(1234.0)
    samples = [cmds.jitter.sample_native_delay_ms() for _ in range(100)]
    import statistics

    median = statistics.median(samples)
    assert 300.0 < median < 4000.0
