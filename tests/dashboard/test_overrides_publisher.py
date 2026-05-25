"""Tests for :class:`anglerfish.dashboard.overrides_publisher.RuntimeOverridesPublisher`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from anglerfish.audit import AuditLog
from anglerfish.dashboard.overrides import build_runtime_overrides
from anglerfish.dashboard.overrides_publisher import RuntimeOverridesPublisher
from tests.dashboard.test_overrides import _settings as _make_settings


def _read_events(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def test_ensure_writable_creates_parent_directory(tmp_path: Path) -> None:
    publish_path = tmp_path / "new" / "subdir" / "runtime_overrides.json"
    publisher = RuntimeOverridesPublisher(publish_path)
    publisher.ensure_writable()
    assert publish_path.parent.is_dir()


def test_ensure_writable_raises_on_unwritable_parent(tmp_path: Path) -> None:
    publish_path = tmp_path / "ro" / "runtime_overrides.json"
    publish_path.parent.mkdir()
    publish_path.parent.chmod(0o400)  # read-only
    publisher = RuntimeOverridesPublisher(publish_path)
    try:
        with pytest.raises(PermissionError, match="not writable"):
            publisher.ensure_writable()
    finally:
        publish_path.parent.chmod(0o700)


def test_publish_writes_atomic_snapshot(tmp_path: Path) -> None:
    publish_path = tmp_path / "runtime_overrides.json"
    publisher = RuntimeOverridesPublisher(publish_path)
    overrides = build_runtime_overrides(_make_settings())
    publisher.publish(overrides)
    assert publish_path.exists()
    payload = json.loads(publish_path.read_text(encoding="utf-8"))
    assert payload["bridge"]["wasting_strategy"] == "off"


def test_publish_records_audit_event(tmp_path: Path) -> None:
    publish_path = tmp_path / "runtime_overrides.json"
    audit = AuditLog(tmp_path / "audit.jsonl")
    publisher = RuntimeOverridesPublisher(publish_path, audit_log=audit)
    publisher.publish(build_runtime_overrides(_make_settings()))
    events = _read_events(audit.path)
    assert len(events) == 1
    assert events[0]["event_type"] == "dashboard.overrides_published"
    assert events[0]["path"] == str(publish_path)
    assert events[0]["bridge_snapshot"]["wasting_strategy"] == "off"


def test_publish_quiet_skips_audit_event(tmp_path: Path) -> None:
    publish_path = tmp_path / "runtime_overrides.json"
    audit = AuditLog(tmp_path / "audit.jsonl")
    publisher = RuntimeOverridesPublisher(publish_path, audit_log=audit)
    publisher.publish(build_runtime_overrides(_make_settings()), quiet=True)
    assert publish_path.exists()
    events = _read_events(audit.path)
    assert events == []


def test_publish_swallows_oserror(tmp_path: Path) -> None:
    publish_path = tmp_path / "ro_publish" / "runtime_overrides.json"
    publish_path.parent.mkdir()
    publish_path.parent.chmod(0o400)
    audit = AuditLog(tmp_path / "audit.jsonl")
    publisher = RuntimeOverridesPublisher(publish_path, audit_log=audit)
    try:
        # Must not raise even though the write will fail.
        publisher.publish(build_runtime_overrides(_make_settings()))
    finally:
        publish_path.parent.chmod(0o700)
    events = _read_events(audit.path)
    assert any(e["event_type"] == "dashboard.overrides_publish_failed" for e in events)
