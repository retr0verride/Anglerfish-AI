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
