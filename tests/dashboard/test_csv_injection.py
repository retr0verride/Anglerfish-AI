"""CSV formula-injection guard for both CSV exports (audit M1)."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from anglerfish.dashboard.export import csv_safe_cell, session_csv_rows
from anglerfish.dashboard.exporters import build_honeytoken_report_rows
from anglerfish.dashboard.state import DashboardState
from anglerfish.honeytokens.schema import Honeytoken
from anglerfish.models import CommandTurn, ResponseSource, SessionSnapshot

_AT = datetime(2026, 5, 29, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize("trigger", ["=", "+", "-", "@", "\t", "\r"])
def test_csv_safe_cell_neutralises_formula_triggers(trigger: str) -> None:
    out = csv_safe_cell(f"{trigger}cmd|'/c calc'!A1")
    assert out.startswith("'")  # prefixed so a spreadsheet treats it as text
    assert out[1] == trigger


def test_csv_safe_cell_leaves_normal_values_untouched() -> None:
    assert csv_safe_cell("203.0.113.7") == "203.0.113.7"
    assert csv_safe_cell("root") == "root"
    assert csv_safe_cell(None) == ""
    assert csv_safe_cell(42) == "42"


async def test_session_export_guards_malicious_username(dashboard_state: DashboardState) -> None:
    # A captured SSH username is attacker-controlled and lands in the CSV.
    snap = SessionSnapshot(
        session_id=uuid4(),
        source_ip="203.0.113.7",
        username="=cmd|'/c calc'!A1",
        fake_hostname="srv",
        fake_username="root",
        fake_cwd="/root",
        started_at=_AT,
        last_activity_at=_AT,
        turns=(
            CommandTurn(
                command="id",
                response="",
                source=ResponseSource.AI,
                timestamp=_AT,
                latency_ms=1.0,
            ),
        ),
    )
    await dashboard_state.update_session(snap)
    body = b"".join(
        [
            chunk
            async for chunk in session_csv_rows(
                dashboard_state,
                start=_AT.replace(hour=0),
                end=_AT.replace(hour=23),
            )
        ]
    ).decode("utf-8")
    rows = list(csv.DictReader(io.StringIO(body)))
    assert rows[0]["username"] == "'=cmd|'/c calc'!A1"


def test_honeytoken_report_guards_malicious_source_ip() -> None:
    token = Honeytoken(
        id="MFRGGZDFMZTWQ2LK",
        kind="aws",
        payload="SECRET",
        callback_url="https://cb.example/h1",
        placed_at="/root/.aws/credentials",
        source_ip="=HYPERLINK(\"http://evil\")",
        session_id=uuid4(),
        created_at=_AT,
    )
    raw = b"".join(build_honeytoken_report_rows([token], [])).decode("utf-8")
    row = next(r for r in csv.DictReader(io.StringIO(raw)))
    assert row["source_ip"].startswith("'=HYPERLINK")
