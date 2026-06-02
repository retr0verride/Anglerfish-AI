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


def test_record_rejects_reserved_ts_field(tmp_path: Path) -> None:
    # A caller passing ts= in **fields must not be able to forge the
    # canonical timestamp via last-write-wins; record() rejects it.
    target = tmp_path / "audit.jsonl"
    log = AuditLog(target)
    with pytest.raises(ValueError, match="reserved"):
        log.record("x", ts="2000-01-01T00:00:00+00:00")
    assert not target.exists()  # rejected before any write


def test_record_canonical_ts_is_not_overridable(tmp_path: Path) -> None:
    # Even if a future path allowed it, the recorded ts is the canonical
    # stamp, never the caller's value.
    target = tmp_path / "audit.jsonl"
    log = AuditLog(target)
    log.record("ok", note="hi")
    entry = json.loads(target.read_text("utf-8").strip())
    assert entry["ts"] != "2000-01-01T00:00:00+00:00"
    assert entry["note"] == "hi"


def test_record_is_thread_safe_under_concurrency(tmp_path: Path) -> None:
    import threading

    target = tmp_path / "audit.jsonl"
    log = AuditLog(target)
    count = 50

    def worker(i: int) -> None:
        log.record("concurrent", i=i)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = target.read_text("utf-8").splitlines()
    assert len(lines) == count  # no lost writes
    # Every line is intact JSON (no torn/interleaved writes under the lock).
    ids = sorted(json.loads(line)["i"] for line in lines)
    assert ids == list(range(count))


def test_record_calls_fsync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    real_fsync = os.fsync
    calls: list[int] = []

    def _spy(fd: int) -> None:
        calls.append(fd)
        real_fsync(fd)

    # audit.py calls os.fsync against the shared stdlib module, so patching
    # os.fsync here is observed there (avoids the implicit-reexport of
    # anglerfish.audit.os that bare mypy rejects).
    monkeypatch.setattr(os, "fsync", _spy)
    AuditLog(tmp_path / "audit.jsonl").record("x")
    assert len(calls) == 1
