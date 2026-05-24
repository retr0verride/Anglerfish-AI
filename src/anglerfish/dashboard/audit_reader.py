"""Read helpers over the append-only JSONL audit log.

Dashboard-only; not used by any code path that writes to the log.
Lives next to the dashboard so the audit module itself stays
write-focused.

The audit JSONL is small per record but can be large per file. Both
consumers (the alerts panel and the health probes) only ever need
the tail. The helpers below read the whole file but expose two
iteration modes:

* :func:`iter_events` - newest-first, parsed dicts.
* :func:`iter_events_in_range` - newest-first, filtered to a
  closed time interval.

Neither holds the file open across yields; both read the bytes up
front. The audit file is fsynced per write and rotates by external
log management, so the in-memory snapshot is consistent with what
the operator can grep.

Performance note: the alerts panel paginates by reading the file
once per request. For a single-host Anglerfish deployment this is
fine; for a multi-tenant control plane (which is not the product),
a persistent index would be the next step.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

__all__ = [
    "iter_events",
    "iter_events_in_range",
    "parse_event_timestamp",
]


_logger = logging.getLogger(__name__)


def iter_events(path: Path) -> Iterator[dict[str, Any]]:
    """Yield parsed audit-log events newest-first.

    Returns an empty iterator if the file does not exist. Lines
    that fail to parse as JSON are logged at warning and skipped;
    the audit log MUST stay readable even when a single line is
    truncated.
    """
    if not path.is_file():
        return
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        _logger.warning("audit_reader: %s open failed: %s", path, exc)
        return
    # Reverse-iterate the lines so the newest event yields first.
    for raw_line in reversed(raw.splitlines()):
        line = raw_line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            _logger.warning("audit_reader: skipping malformed line in %s", path)
            continue
        if isinstance(event, dict):
            yield event


def iter_events_in_range(
    path: Path,
    *,
    start: datetime,
    end: datetime,
) -> Iterator[dict[str, Any]]:
    """Yield events whose ``ts`` falls within ``[start, end]`` inclusive.

    Both bounds are required. Newest-first like :func:`iter_events`.
    Events with no ``ts`` field or an unparseable one are skipped
    silently (the read helper logs at parse time).

    Stops early as soon as an event older than ``start`` is hit, so
    a tight range on a large log is cheap.
    """
    if end < start:
        # Empty range; nothing to yield. Callers should validate at
        # the request boundary, but defending here keeps the helper
        # total.
        return
    for event in iter_events(path):
        ts = parse_event_timestamp(event)
        if ts is None:
            continue
        if ts > end:
            continue
        if ts < start:
            # Newest-first iteration; we are now in the past beyond
            # the start bound, so the rest of the file is older too.
            break
        yield event


def parse_event_timestamp(event: dict[str, Any]) -> datetime | None:
    """Parse the ``ts`` field as an ISO-8601 datetime.

    Returns ``None`` when ``ts`` is missing, not a string, or fails
    parsing. The audit log writer uses ``datetime.now(tz=UTC).isoformat()``
    so well-formed events always succeed; the defensive checks here
    cover hand-edited or rotated-mid-write lines.
    """
    raw = event.get("ts")
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None
