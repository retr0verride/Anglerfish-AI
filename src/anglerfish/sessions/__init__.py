"""Persistent session store (Stage 4).

Public surface:

* :class:`SessionStore` - async SQLite-backed CRUD for sessions,
  turns, and threat assessments.
* :func:`import_jsonl_into_store` - deprecated one-shot helper for
  operators upgrading from a pre-removal install: imports the
  historical forwarder JSONL fallback file (Cowrie + forwarder
  were removed in 2026-05) into the store. Documented in
  ``docs/RUNBOOK.md`` under "Import old forwarder JSONL";
  intentionally not exposed as a CLI subcommand because the
  operation is one-shot per install.

See ``docs/design/STAGE_4_session_store.md`` for the design.
"""

from __future__ import annotations

from anglerfish.sessions.migrate import import_jsonl_into_store
from anglerfish.sessions.store import SessionStore, SessionStoreStats

__all__ = [
    "SessionStore",
    "SessionStoreStats",
    "import_jsonl_into_store",
]
