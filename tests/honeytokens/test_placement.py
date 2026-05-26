"""Tests for the Stage 11 slice 11.3 :class:`HoneytokenPlacementService`."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from anglerfish.honeytokens import HoneytokenGenerator, HoneytokenPlacementService


class _CaptureAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    def record(self, event_type: str, **fields: object) -> None:
        self.events.append((event_type, fields))


def _generator() -> HoneytokenGenerator:
    return HoneytokenGenerator(callback_base_url="https://honey.example.com")


async def test_placement_emits_two_audits_per_session() -> None:
    """One AWS + one SSH token per schedule_placement call."""
    audit = _CaptureAudit()
    service = HoneytokenPlacementService(
        generator=_generator(),
        audit_log=audit,  # type: ignore[arg-type]
    )
    sid = uuid4()
    task = service.schedule_placement(source_ip="203.0.113.7", session_id=sid)
    await task
    placed = [e for e in audit.events if e[0] == "bridge.honeytoken_placed"]
    assert len(placed) == 2
    kinds = {e[1]["kind"] for e in placed}
    assert kinds == {"aws", "ssh_key"}


async def test_placement_audit_carries_full_token_shape() -> None:
    """Each placement audit has all fields the slice 11.2 parser expects."""
    audit = _CaptureAudit()
    service = HoneytokenPlacementService(
        generator=_generator(),
        audit_log=audit,  # type: ignore[arg-type]
    )
    sid = uuid4()
    await service.schedule_placement(source_ip="203.0.113.7", session_id=sid)
    placed = [e for e in audit.events if e[0] == "bridge.honeytoken_placed"]
    for _, fields in placed:
        assert isinstance(fields["token_id"], str)
        assert len(fields["token_id"]) == 16
        assert fields["kind"] in {"aws", "ssh_key"}
        assert isinstance(fields["payload"], str)
        assert fields["payload"]
        assert fields["callback_url"].startswith("https://honey.example.com/cb/")  # type: ignore[union-attr]
        assert isinstance(fields["placed_at"], str)
        assert fields["placed_at"]
        assert fields["source_ip"] == "203.0.113.7"
        assert fields["session_id"] == str(sid)
        # ISO-parseable created_at.
        datetime.fromisoformat(fields["created_at"])  # type: ignore[arg-type]


async def test_placement_swallows_generator_failure_and_audits_error() -> None:
    """A generator exception lands as bridge.honeytoken_placement_error, no raise."""
    audit = _CaptureAudit()

    class _RaisingGenerator:
        def generate_aws(self, **_kwargs):  # type: ignore[no-untyped-def]
            raise RuntimeError("aws boom")

        def generate_ssh(self, **_kwargs):  # type: ignore[no-untyped-def]
            raise RuntimeError("ssh boom")

    service = HoneytokenPlacementService(
        generator=_RaisingGenerator(),  # type: ignore[arg-type]
        audit_log=audit,  # type: ignore[arg-type]
    )
    task = service.schedule_placement(source_ip="203.0.113.7", session_id=uuid4())
    await task  # must not raise
    errors = [e for e in audit.events if e[0] == "bridge.honeytoken_placement_error"]
    assert len(errors) == 2  # one per kind
    error_kinds = {e[1]["kind"] for e in errors}
    assert error_kinds == {"aws", "ssh_key"}
    for _, fields in errors:
        assert fields["error_type"] == "RuntimeError"
        assert "boom" in str(fields["error"])
    # No successful placements emitted.
    assert not [e for e in audit.events if e[0] == "bridge.honeytoken_placed"]


async def test_placement_does_not_swap_audit_format_on_partial_failure() -> None:
    """AWS succeeds but SSH raises: one placed + one error event."""
    audit = _CaptureAudit()

    class _SshFailingGenerator:
        def __init__(self) -> None:
            self._real = _generator()

        def generate_aws(self, **kwargs):  # type: ignore[no-untyped-def]
            return self._real.generate_aws(**kwargs)

        def generate_ssh(self, **_kwargs):  # type: ignore[no-untyped-def]
            raise RuntimeError("ssh boom")

    service = HoneytokenPlacementService(
        generator=_SshFailingGenerator(),  # type: ignore[arg-type]
        audit_log=audit,  # type: ignore[arg-type]
    )
    await service.schedule_placement(source_ip="203.0.113.7", session_id=uuid4())
    placed = [e for e in audit.events if e[0] == "bridge.honeytoken_placed"]
    errors = [e for e in audit.events if e[0] == "bridge.honeytoken_placement_error"]
    assert len(placed) == 1
    assert placed[0][1]["kind"] == "aws"
    assert len(errors) == 1
    assert errors[0][1]["kind"] == "ssh_key"


async def test_placement_task_set_self_cleans_on_completion() -> None:
    """Spawned task self-discards from _tasks via done_callback."""
    audit = _CaptureAudit()
    service = HoneytokenPlacementService(
        generator=_generator(),
        audit_log=audit,  # type: ignore[arg-type]
    )
    task = service.schedule_placement(source_ip="203.0.113.7", session_id=uuid4())
    await task
    # Yield once so the done-callback fires.
    import asyncio

    await asyncio.sleep(0)
    assert task not in service._tasks  # type: ignore[attr-defined]
