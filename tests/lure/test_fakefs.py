"""Tests for :mod:`anglerfish.lure.fakefs`."""

from __future__ import annotations

from uuid import uuid4

import pytest

from anglerfish.lure.fakefs import listdir, read, system_prompt_summary
from anglerfish.lure.session import LureSessionContext


def _session(*, username: str = "alice", hostname: str = "srv-prod-01") -> LureSessionContext:
    return LureSessionContext(
        uuid4(),
        source_ip="203.0.113.7",
        username=username,
        hostname=hostname,
        cwd=f"/home/{username}",
    )


# ---------------------------------------------------------------------------
# read() - file contents
# ---------------------------------------------------------------------------


def test_etc_passwd_includes_session_user() -> None:
    s = _session(username="alice")
    result = read("/etc/passwd", s)
    assert result.status == "content"
    assert "root:x:0:0:" in result.content
    assert "alice:x:1000:1000:" in result.content


def test_etc_passwd_includes_canonical_system_users() -> None:
    result = read("/etc/passwd", _session())
    for user in ("daemon", "bin", "sys", "mail", "www-data", "nobody", "sshd"):
        assert f"{user}:" in result.content


def test_etc_shadow_is_permission_denied() -> None:
    assert read("/etc/shadow", _session()).status == "permission_denied"


def test_etc_sudoers_is_permission_denied() -> None:
    assert read("/etc/sudoers", _session()).status == "permission_denied"


def test_var_log_btmp_is_permission_denied() -> None:
    assert read("/var/log/btmp", _session()).status == "permission_denied"


def test_proc_version_matches_debian_12() -> None:
    result = read("/proc/version", _session())
    assert result.status == "content"
    assert "Linux version 6.1" in result.content
    assert "Debian" in result.content


def test_proc_cpuinfo_includes_intel_xeon() -> None:
    result = read("/proc/cpuinfo", _session())
    assert result.status == "content"
    assert "Intel(R) Xeon(R)" in result.content


def test_etc_hostname_renders_session_hostname() -> None:
    s = _session(hostname="my-prod-server")
    result = read("/etc/hostname", s)
    assert result.status == "content"
    assert result.content.strip() == "my-prod-server"


def test_etc_os_release_is_bookworm() -> None:
    result = read("/etc/os-release", _session())
    assert result.status == "content"
    assert "bookworm" in result.content


def test_home_user_bashrc_lookup_uses_username() -> None:
    s = _session(username="bob")
    result = read("/home/bob/.bashrc", s)
    assert result.status == "content"
    assert "HISTSIZE" in result.content


def test_root_bash_history_has_canonical_sysadmin_commands() -> None:
    result = read("/root/.bash_history", _session())
    assert result.status == "content"
    assert "df -h" in result.content
    assert "systemctl status sshd" in result.content


def test_var_log_auth_log_includes_session_user() -> None:
    s = _session(username="alice")
    result = read("/var/log/auth.log", s)
    assert result.status == "content"
    assert "alice" in result.content


def test_unknown_path_returns_not_in_fakefs() -> None:
    assert read("/etc/totally/made-up/path", _session()).status == "not_in_fakefs"


def test_unknown_top_level_path_returns_not_in_fakefs() -> None:
    assert read("/srv/secret", _session()).status == "not_in_fakefs"


# ---------------------------------------------------------------------------
# read() - determinism across sessions
# ---------------------------------------------------------------------------


def test_fakefs_is_static_across_sessions() -> None:
    s1 = _session(username="alice")
    s2 = _session(username="alice")
    assert read("/etc/passwd", s1).content == read("/etc/passwd", s2).content
    assert read("/proc/version", s1).content == read("/proc/version", s2).content


# listdir() tests -----------------------------------------------------------


def test_root_listing_includes_canonical_top_level_entries() -> None:
    result = listdir("/", _session())
    assert result.status == "entries"
    names = {e.name for e in result.entries}
    for name in ("bin", "boot", "etc", "home", "root", "proc", "sys", "usr", "var"):
        assert name in names


def test_etc_listing_includes_canonical_files() -> None:
    result = listdir("/etc", _session())
    assert result.status == "entries"
    names = {e.name for e in result.entries}
    for name in ("passwd", "group", "hostname", "fstab", "crontab", "sudoers", "shadow"):
        assert name in names


def test_var_listing_includes_log() -> None:
    result = listdir("/var", _session())
    assert result.status == "entries"
    names = {e.name for e in result.entries}
    assert "log" in names


def test_var_log_listing_has_recent_log_files() -> None:
    result = listdir("/var/log", _session())
    assert result.status == "entries"
    names = {e.name for e in result.entries}
    for name in ("auth.log", "syslog", "dpkg.log", "wtmp", "btmp", "lastlog"):
        assert name in names


def test_proc_listing_has_kernel_files() -> None:
    result = listdir("/proc", _session())
    assert result.status == "entries"
    names = {e.name for e in result.entries}
    for name in ("cpuinfo", "meminfo", "mounts", "version", "uptime", "loadavg"):
        assert name in names


def test_home_listing_shows_session_user_only() -> None:
    result = listdir("/home", _session(username="alice"))
    assert result.status == "entries"
    assert len(result.entries) == 1
    assert result.entries[0].name == "alice"


def test_home_user_listing_has_dotfiles() -> None:
    s = _session(username="alice")
    result = listdir("/home/alice", s)
    assert result.status == "entries"
    names = {e.name for e in result.entries}
    assert ".bashrc" in names
    assert ".profile" in names
    assert ".ssh" in names


def test_home_user_ssh_listing_has_keys_and_known_hosts() -> None:
    s = _session(username="alice")
    result = listdir("/home/alice/.ssh", s)
    assert result.status == "entries"
    names = {e.name for e in result.entries}
    assert "authorized_keys" in names
    assert "known_hosts" in names


def test_root_listing_separate_from_user_home() -> None:
    result = listdir("/root", _session())
    assert result.status == "entries"
    names = {e.name for e in result.entries}
    assert ".bashrc" in names
    assert ".bash_history" in names


def test_listdir_unknown_path_returns_not_in_fakefs() -> None:
    assert listdir("/totally/bogus", _session()).status == "not_in_fakefs"


def test_trailing_slash_is_tolerated() -> None:
    assert listdir("/etc/", _session()).status == "entries"


# system_prompt_summary() tests --------------------------------------------


def test_system_prompt_summary_fits_in_fs_context_budget() -> None:
    # CommandRequest.fs_context max_length is 4096 chars.
    assert len(system_prompt_summary()) <= 4096


def test_system_prompt_summary_mentions_etc_passwd() -> None:
    assert "/etc/passwd" in system_prompt_summary()


def test_system_prompt_summary_mentions_permission_denied_paths() -> None:
    text = system_prompt_summary()
    assert "/etc/shadow" in text
    assert "/etc/sudoers" in text


def test_system_prompt_summary_is_deterministic() -> None:
    assert system_prompt_summary() == system_prompt_summary()


# ---------------------------------------------------------------------------
# Coverage of the design's 50-path target
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "/etc/group",
        "/etc/hostname",
        "/etc/issue",
        "/etc/os-release",
        "/etc/debian_version",
        "/etc/machine-id",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/nsswitch.conf",
        "/etc/fstab",
        "/etc/crontab",
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/motd",
        "/etc/ssh/sshd_config",
        "/etc/ssh/ssh_config",
        "/etc/apt/sources.list",
        "/etc/network/interfaces",
        "/proc/version",
        "/proc/cpuinfo",
        "/proc/meminfo",
        "/proc/mounts",
        "/proc/loadavg",
        "/proc/uptime",
        "/proc/self/status",
        "/root/.bashrc",
        "/root/.bash_history",
        "/root/.ssh/authorized_keys",
        "/root/.ssh/known_hosts",
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/dpkg.log",
    ],
)
def test_required_paths_all_present(path: str) -> None:
    assert read(path, _session()).status == "content"


# ---------------------------------------------------------------------------
# Stage 9: persona overlay
# ---------------------------------------------------------------------------


def _persona_session(
    overlay: dict[str, str] | None = None,
    *,
    persona_name: str | None = "gpu-rig",
) -> LureSessionContext:
    return LureSessionContext(
        uuid4(),
        source_ip="203.0.113.7",
        username="ml",
        hostname="gpu-rig-04",
        cwd="/home/ml",
        persona_name=persona_name,
        persona_overlay=overlay or {},
    )


def test_overlay_overrides_static_etc_hostname() -> None:
    session = _persona_session({"/etc/hostname": "gpu-rig-04\n"})
    result = read("/etc/hostname", session)
    assert result.status == "content"
    assert result.content == "gpu-rig-04\n"


def test_overlay_overrides_permission_denied_path() -> None:
    """An operator-defined overlay can serve a path that would normally 403."""
    session = _persona_session({"/etc/shadow": "operator-defined\n"})
    result = read("/etc/shadow", session)
    assert result.status == "content"
    assert result.content == "operator-defined\n"


def test_overlay_adds_path_not_in_static_base() -> None:
    """A persona can introduce a path that the static fakefs does not know."""
    session = _persona_session(
        {"/opt/gpu-rig/config.toml": '[gpu]\nmodel = "rtx-4090"\n'},
    )
    result = read("/opt/gpu-rig/config.toml", session)
    assert result.status == "content"
    assert "rtx-4090" in result.content


def test_no_overlay_means_static_base_serves_etc_hostname() -> None:
    """A session with empty overlay still hits the static /etc/hostname."""
    session = _persona_session({})
    result = read("/etc/hostname", session)
    assert result.status == "content"
    # The static base renders from session.hostname.
    assert "gpu-rig-04" in result.content


def test_unrelated_path_falls_through_to_static_base() -> None:
    """Overlay only affects overlaid paths; everything else hits static."""
    session = _persona_session({"/etc/hostname": "x"})
    result = read("/etc/passwd", session)
    assert result.status == "content"
    assert "root:x:0:0:" in result.content


# ---------------------------------------------------------------------------
# system_prompt_summary: session-aware overlay block
# ---------------------------------------------------------------------------


def test_system_prompt_summary_without_session_returns_static() -> None:
    text = system_prompt_summary()
    assert "Persona overlay" not in text


def test_system_prompt_summary_with_empty_overlay_returns_static() -> None:
    text = system_prompt_summary(_persona_session({}))
    assert "Persona overlay" not in text


def test_system_prompt_summary_appends_overlay_block() -> None:
    session = _persona_session(
        {
            "/etc/hostname": "gpu-rig-04\n",
            "/proc/version": "Linux ...\n",
        },
    )
    text = system_prompt_summary(session)
    assert "Persona overlay" in text
    assert "/etc/hostname" in text
    assert "/proc/version" in text


def test_system_prompt_summary_stays_under_4096_chars() -> None:
    """A persona with 64 paths and long values still fits the fs_context cap."""
    overlay = {f"/path/{i:03d}": "x" * 256 for i in range(64)}
    text = system_prompt_summary(_persona_session(overlay))
    assert len(text) <= 4096


def test_system_prompt_summary_sorts_overlay_keys() -> None:
    """Deterministic ordering so grepping the bridge prompt log is stable."""
    session = _persona_session(
        {
            "/zzz-last": "z",
            "/aaa-first": "a",
            "/mmm-middle": "m",
        },
    )
    text = system_prompt_summary(session)
    a_pos = text.index("/aaa-first")
    m_pos = text.index("/mmm-middle")
    z_pos = text.index("/zzz-last")
    assert a_pos < m_pos < z_pos
