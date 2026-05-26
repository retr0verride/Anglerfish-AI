"""Tests for :mod:`anglerfish.bridge.prompts`."""

from __future__ import annotations

from datetime import UTC, datetime

from anglerfish.bridge.prompts import build_messages, build_system_prompt
from anglerfish.config.models import BridgeConfig
from anglerfish.models.session import CommandTurn, ResponseSource


def _turn(command: str, response: str) -> CommandTurn:
    return CommandTurn(
        command=command,
        response=response,
        source=ResponseSource.AI,
        timestamp=datetime(2026, 5, 22, tzinfo=UTC),
        latency_ms=12.5,
    )


def test_system_prompt_fills_environment() -> None:
    cfg = BridgeConfig(fake_hostname="srv-prod-01", fake_username="root", fake_cwd="/root")
    prompt = build_system_prompt(cfg, cwd="/var/log")
    assert "Hostname: srv-prod-01" in prompt
    assert "Current user: root" in prompt
    assert "Working directory: /var/log" in prompt
    assert "honeypot" in prompt  # the rule forbidding the word appears here
    assert "Debian" in prompt


def test_build_messages_no_history() -> None:
    cfg = BridgeConfig()
    messages = build_messages("ls /etc", config=cfg, cwd="/root", history=())
    assert len(messages) == 2
    assert messages[0].role == "system"
    assert messages[1].role == "user"
    assert messages[1].content == "ls /etc"


def test_build_messages_replays_history_in_order() -> None:
    cfg = BridgeConfig()
    history = (_turn("whoami", "root"), _turn("id", "uid=0(root)"))
    messages = build_messages("ls /etc", config=cfg, cwd="/root", history=history)
    roles = [m.role for m in messages]
    assert roles == ["system", "user", "assistant", "user", "assistant", "user"]
    contents = [m.content for m in messages]
    assert contents[1] == "whoami"
    assert contents[2] == "root"
    assert contents[3] == "id"
    assert contents[4] == "uid=0(root)"
    assert contents[5] == "ls /etc"


def test_build_messages_cwd_appears_in_system_prompt() -> None:
    cfg = BridgeConfig(fake_cwd="/root")
    messages = build_messages("pwd", config=cfg, cwd="/etc", history=())
    assert "Working directory: /etc" in messages[0].content


# ---------------------------------------------------------------------------
# Stage 10: persistence-state prompt block
# ---------------------------------------------------------------------------


def _persistence_event(kind: str, payload: str, sub_key: str | None = None):  # type: ignore[no-untyped-def]
    from anglerfish.models.persistence import PersistenceEvent

    return PersistenceEvent(
        kind=kind,  # type: ignore[arg-type]
        sub_key=sub_key,
        payload=payload,
        source="regex",
    )


def test_persistence_block_omitted_when_no_events() -> None:
    """Empty / None persistence_events preserves the pre-Stage-10 prompt shape."""
    cfg = BridgeConfig()
    prompt = build_system_prompt(cfg, cwd="/root", persistence_events=None)
    assert "Installed cron entries" not in prompt
    assert "Installed/enabled systemd units" not in prompt
    assert "Appended ~/.ssh/authorized_keys" not in prompt


def test_persistence_block_renders_crontab_entry() -> None:
    cfg = BridgeConfig()
    events = [_persistence_event("crontab", "0 * * * * /tmp/.beacon")]
    prompt = build_system_prompt(cfg, cwd="/root", persistence_events=events)
    assert "Installed cron entries" in prompt
    assert "0 * * * * /tmp/.beacon" in prompt


def test_persistence_block_renders_systemctl_unit() -> None:
    cfg = BridgeConfig()
    events = [
        _persistence_event("systemctl", "backdoor.service", sub_key="backdoor.service"),
    ]
    prompt = build_system_prompt(cfg, cwd="/root", persistence_events=events)
    assert "Installed/enabled systemd units" in prompt
    assert "backdoor.service" in prompt


def test_persistence_block_renders_authorized_keys_entry() -> None:
    cfg = BridgeConfig()
    events = [_persistence_event("authorized_keys", "ssh-ed25519 AAAA attacker@x")]
    prompt = build_system_prompt(cfg, cwd="/root", persistence_events=events)
    assert "Appended ~/.ssh/authorized_keys entries" in prompt
    assert "ssh-ed25519 AAAA attacker@x" in prompt


def test_persistence_block_groups_all_three_kinds() -> None:
    """Mixed events render under per-kind sections in the same prompt."""
    cfg = BridgeConfig()
    events = [
        _persistence_event("crontab", "0 * * * * /tmp/.x"),
        _persistence_event("systemctl", "evil.service", sub_key="evil.service"),
        _persistence_event("authorized_keys", "ssh-rsa AAAA attacker"),
    ]
    prompt = build_system_prompt(cfg, cwd="/root", persistence_events=events)
    assert "Installed cron entries" in prompt
    assert "Installed/enabled systemd units" in prompt
    assert "Appended ~/.ssh/authorized_keys" in prompt
