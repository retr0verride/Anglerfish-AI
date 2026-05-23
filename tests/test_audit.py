"""Tests for :class:`anglerfish.audit.AuditLog`."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from anglerfish.audit import DEFAULT_AUDIT_PATH, AuditLog


def test_default_path_is_var_log() -> None:
    assert DEFAULT_AUDIT_PATH.as_posix() == "/var/log/anglerfish/audit.jsonl"


def test_record_writes_one_jsonl_line(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("wizard.run", source="test")
    content = (tmp_path / "audit.jsonl").read_text("utf-8").splitlines()
    assert len(content) == 1
    entry = json.loads(content[0])
    assert entry["event_type"] == "wizard.run"
    assert entry["source"] == "test"
    assert "ts" in entry


def test_record_appends(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("a")
    log.record("b")
    log.record("c")
    lines = (tmp_path / "audit.jsonl").read_text("utf-8").splitlines()
    assert [json.loads(line)["event_type"] for line in lines] == ["a", "b", "c"]


def test_record_creates_parent_dir(tmp_path: Path) -> None:
    target = tmp_path / "deep" / "nested" / "audit.jsonl"
    AuditLog(target).record("e")
    assert target.exists()


def test_record_rejects_empty_event_type(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        AuditLog(tmp_path / "audit.jsonl").record("")


def test_record_serialises_non_json_safely(tmp_path: Path) -> None:
    from uuid import uuid4

    target = tmp_path / "audit.jsonl"
    sid = uuid4()
    AuditLog(target).record("threat.alert_fired", session_id=sid)
    entry = json.loads(target.read_text("utf-8").strip())
    assert entry["session_id"] == str(sid)


def test_record_unserialisable_is_silent(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    target = tmp_path / "audit.jsonl"
    cycle: dict[str, object] = {}
    cycle["self"] = cycle
    # MUST NOT raise.
    AuditLog(target).record("x", payload=cycle)
    # File should not have been opened.
    assert not target.exists()


def test_record_oserror_is_silent(tmp_path: Path) -> None:
    # Path that cannot be created — point at a regular file as parent.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir", encoding="utf-8")
    target = blocker / "child" / "audit.jsonl"
    AuditLog(target).record("x")  # must not raise


def test_path_property(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    assert AuditLog(p).path == p


def test_context_manager(tmp_path: Path) -> None:
    target = tmp_path / "audit.jsonl"
    with AuditLog(target) as log:
        log.record("x")
    assert target.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission semantics")
def test_record_fsyncs(tmp_path: Path) -> None:
    """Smoke test — file exists and is readable after record() returns."""
    target = tmp_path / "audit.jsonl"
    AuditLog(target).record("event")
    assert target.exists()
    assert target.read_text("utf-8").strip()
