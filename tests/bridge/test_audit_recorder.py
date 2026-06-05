"""BridgeAuditRecorder writes the bridge's per-command audit events.

These exercise the recorder in isolation (the property the extraction
buys). The full event set is also covered through the service's
integration tests; here we lock the two things the split changed: the
recorder takes the budget snapshot as data, and it can be driven without
the orchestrator."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from anglerfish.audit import AuditLog
from anglerfish.bridge.audit_recorder import BridgeAuditRecorder
from anglerfish.bridge.session import SessionContext
from anglerfish.llm.budget import BudgetExhaustedError


def _session() -> SessionContext:
    return SessionContext(
        uuid4(),
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        history_window=20,
    )


def _events(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_budget_exhausted_records_the_snapshot_it_is_given(tmp_path: Path) -> None:
    """The recorder emits the budget snapshot it is handed, decoupled from
    the service's per-session _budgets map."""
    log_path = tmp_path / "audit.jsonl"
    recorder = BridgeAuditRecorder(AuditLog(log_path))
    session = _session()
    snapshot = {"fast": {"consumed": 10, "remaining": 0, "cap": 10}}

    recorder.record_budget_exhausted(
        session,
        BudgetExhaustedError("fast tier exhausted"),
        budget_snapshot=snapshot,
    )

    events = _events(log_path)
    assert len(events) == 1
    evt = events[0]
    assert evt["event_type"] == "bridge.budget_exhausted"
    assert evt["session_id"] == str(session.session_id)
    assert evt["budget"] == snapshot
    assert "fast tier exhausted" in str(evt["error"])


def test_handler_error_emits_event(tmp_path: Path) -> None:
    """A representative emitter writes its event verbatim in isolation."""
    log_path = tmp_path / "audit.jsonl"
    recorder = BridgeAuditRecorder(AuditLog(log_path))
    session = _session()

    recorder.record_handler_error(session, ValueError("boom"))

    evt = _events(log_path)[0]
    assert evt["event_type"] == "bridge.handler_error"
    assert evt["session_id"] == str(session.session_id)
    assert "ValueError: boom" in str(evt["error"])
