"""Mythos M5/M7 regression: bounded reads + naive-timestamp handling."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from anglerfish.dashboard.audit_reader import (
    iter_events,
    iter_events_in_range,
    parse_event_timestamp,
)


def test_parse_event_timestamp_coerces_naive_to_utc() -> None:
    # Mythos M7: a forwarded/hand-edited line without an offset must not
    # crash the aware-vs-naive comparison in iter_events_in_range.
    ts = parse_event_timestamp({"ts": "2026-06-04T00:00:00"})
    assert ts is not None
    assert ts.tzinfo is not None
    assert ts == datetime(2026, 6, 4, tzinfo=UTC)


def test_iter_events_in_range_survives_naive_ts_line(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(
        json.dumps({"ts": "2026-06-04T00:00:00", "event_type": "x"}) + "\n",  # naive
        encoding="utf-8",
    )
    start = datetime(2026, 6, 1, tzinfo=UTC)
    end = datetime(2026, 6, 30, tzinfo=UTC)
    # Would raise TypeError before the M7 fix.
    events = list(iter_events_in_range(log, start=start, end=end))
    assert len(events) == 1


def test_iter_events_max_bytes_tails_the_file(tmp_path: Path) -> None:
    # Mythos M5: a bounded read returns only the tail and drops the
    # partial first line.
    log = tmp_path / "audit.jsonl"
    lines = [json.dumps({"ts": "2026-06-04T00:00:00Z", "n": i}) for i in range(1000)]
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    full = list(iter_events(log))
    assert len(full) == 1000
    bounded = list(iter_events(log, max_bytes=2000))
    # newest-first, only the tail, strictly fewer than the full set
    assert 0 < len(bounded) < 1000
    assert bounded[0]["n"] == 999  # newest first
