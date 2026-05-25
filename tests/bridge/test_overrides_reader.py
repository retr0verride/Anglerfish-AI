"""Tests for :class:`anglerfish.bridge.overrides_reader.BridgeOverridesReader`."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from anglerfish.audit import AuditLog
from anglerfish.bridge.overrides_reader import BridgeOverridesReader


class _FakeClock:
    def __init__(self, start: float = 100.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, by: float) -> None:
        self.now += by


@pytest.fixture
def overrides_path(tmp_path: Path) -> Path:
    return tmp_path / "runtime_overrides.json"


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


def _write_overrides(path: Path, strategy: str) -> None:
    payload = {
        "bridge": {
            "wasting_strategy": strategy,
            "max_concurrent_requests": 8,
            "requests_per_session_per_minute": 30,
        },
        "features": {},
        "applied_at": "2026-05-25T00:00:00+00:00",
        "applies_to": "dashboard_process_and_bridge",
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _read_events(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def test_constructor_rejects_zero_ttl(overrides_path: Path) -> None:
    with pytest.raises(ValueError, match="positive"):
        BridgeOverridesReader(
            overrides_path,
            cache_ttl_s=0.0,
            static_fallback="off",
        )


def test_constructor_rejects_invalid_static_fallback(overrides_path: Path) -> None:
    with pytest.raises(ValueError, match="static_fallback must be"):
        BridgeOverridesReader(
            overrides_path,
            cache_ttl_s=1.0,
            static_fallback="bogus",
        )


def test_missing_file_returns_static_fallback(overrides_path: Path) -> None:
    reader = BridgeOverridesReader(
        overrides_path,
        cache_ttl_s=1.0,
        static_fallback="light",
    )
    assert reader.current_wasting_strategy() == "light"


def test_well_formed_file_returns_published_strategy(
    overrides_path: Path,
) -> None:
    _write_overrides(overrides_path, "aggressive")
    reader = BridgeOverridesReader(
        overrides_path,
        cache_ttl_s=1.0,
        static_fallback="off",
    )
    assert reader.current_wasting_strategy() == "aggressive"


def test_cache_ttl_skips_file_reads_within_window(overrides_path: Path) -> None:
    _write_overrides(overrides_path, "light")
    clock = _FakeClock()
    reader = BridgeOverridesReader(
        overrides_path,
        cache_ttl_s=10.0,
        static_fallback="off",
        clock=clock,
    )
    assert reader.current_wasting_strategy() == "light"
    # Tampering during the TTL window must not bleed into the result.
    _write_overrides(overrides_path, "aggressive")
    clock.advance(1.0)
    assert reader.current_wasting_strategy() == "light"


def test_mtime_change_after_ttl_triggers_reread(overrides_path: Path) -> None:
    _write_overrides(overrides_path, "light")
    clock = _FakeClock()
    reader = BridgeOverridesReader(
        overrides_path,
        cache_ttl_s=1.0,
        static_fallback="off",
        clock=clock,
    )
    assert reader.current_wasting_strategy() == "light"
    _write_overrides(overrides_path, "aggressive")
    # Bump mtime forward so the change is detectable; advance the
    # logical clock past the TTL.
    now = time.time() + 1
    os.utime(overrides_path, (now, now))
    clock.advance(2.0)
    assert reader.current_wasting_strategy() == "aggressive"


def test_malformed_json_audits_and_falls_back(
    overrides_path: Path,
    audit: AuditLog,
) -> None:
    overrides_path.write_text("not-json{", encoding="utf-8")
    reader = BridgeOverridesReader(
        overrides_path,
        cache_ttl_s=1.0,
        static_fallback="off",
        audit_log=audit,
    )
    assert reader.current_wasting_strategy() == "off"
    events = _read_events(audit.path)
    assert any(e["event_type"] == "bridge.overrides_read_failed" for e in events)


def test_non_object_payload_falls_back(
    overrides_path: Path,
    audit: AuditLog,
) -> None:
    overrides_path.write_text("[1, 2, 3]", encoding="utf-8")
    reader = BridgeOverridesReader(
        overrides_path,
        cache_ttl_s=1.0,
        static_fallback="off",
        audit_log=audit,
    )
    assert reader.current_wasting_strategy() == "off"


def test_missing_bridge_section_falls_back(
    overrides_path: Path,
    audit: AuditLog,
) -> None:
    overrides_path.write_text(json.dumps({"features": {}}), encoding="utf-8")
    reader = BridgeOverridesReader(
        overrides_path,
        cache_ttl_s=1.0,
        static_fallback="off",
        audit_log=audit,
    )
    assert reader.current_wasting_strategy() == "off"


def test_invalid_strategy_value_falls_back(
    overrides_path: Path,
    audit: AuditLog,
) -> None:
    overrides_path.write_text(
        json.dumps({"bridge": {"wasting_strategy": "bogus"}}),
        encoding="utf-8",
    )
    reader = BridgeOverridesReader(
        overrides_path,
        cache_ttl_s=1.0,
        static_fallback="off",
        audit_log=audit,
    )
    assert reader.current_wasting_strategy() == "off"
    events = _read_events(audit.path)
    assert any(e["event_type"] == "bridge.overrides_read_failed" for e in events)
