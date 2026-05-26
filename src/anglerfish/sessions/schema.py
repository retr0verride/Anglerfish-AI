"""SQLite schema + forward-only migrations for the session store.

The schema is defined in one place so the store, the migration
helper, and any future schema-inspection tooling all read from the
same source. Adding a new schema version means adding a
``_MIGRATION_<n>`` constant and an entry in :data:`_MIGRATIONS`;
``run_migrations`` walks the chain from whatever ``schema_version``
is recorded in ``meta`` up to :data:`CURRENT_SCHEMA_VERSION`.

Forward-only: there is no downgrade path. Operators that need to
roll back to an older Anglerfish revert from a database backup
(see ``docs/RUNBOOK.md``).
"""

from __future__ import annotations

import sqlite3
from typing import Final

__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "PRAGMAS",
    "current_schema_version",
    "run_migrations",
]


CURRENT_SCHEMA_VERSION: Final[int] = 4


# Connection-level pragmas applied on every open. WAL gives us
# multi-reader concurrency (dashboard reads while bridge/lure writes
# through DashboardState); foreign_keys enforces the session->turns
# cascade. synchronous=NORMAL trades a vanishingly small durability
# window for ~2x write throughput on rotational disks; sessions are
# operational telemetry, not financial transactions, so the trade is
# uncontroversial.
PRAGMAS: Final[tuple[str, ...]] = (
    "PRAGMA journal_mode = WAL",
    "PRAGMA synchronous = NORMAL",
    "PRAGMA foreign_keys = ON",
)


# v0 -> v1: initial schema. sessions + turns + threats + meta.
_MIGRATION_1: Final[str] = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id        TEXT PRIMARY KEY,
    source_ip         TEXT NOT NULL,
    username          TEXT NOT NULL,
    fake_hostname     TEXT NOT NULL,
    fake_username     TEXT NOT NULL,
    fake_cwd          TEXT NOT NULL,
    started_at        TEXT NOT NULL,
    last_activity_at  TEXT NOT NULL,
    ended_at          TEXT,
    command_count     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_started_at ON sessions(started_at);
CREATE INDEX IF NOT EXISTS idx_sessions_source_ip  ON sessions(source_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_active     ON sessions(ended_at)
    WHERE ended_at IS NULL;

CREATE TABLE IF NOT EXISTS turns (
    id           INTEGER PRIMARY KEY,
    session_id   TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    sequence_n   INTEGER NOT NULL,
    command      TEXT NOT NULL,
    response     TEXT NOT NULL,
    source       TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    latency_ms   REAL NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_turns_session_seq
    ON turns(session_id, sequence_n);
CREATE INDEX IF NOT EXISTS idx_turns_timestamp ON turns(timestamp);

CREATE TABLE IF NOT EXISTS threats (
    session_id              TEXT PRIMARY KEY
        REFERENCES sessions(session_id) ON DELETE CASCADE,
    score                   INTEGER NOT NULL,
    persistence_attempted   INTEGER NOT NULL DEFAULT 0,
    high_severity           INTEGER NOT NULL DEFAULT 0,
    techniques_json         TEXT NOT NULL DEFAULT '[]',
    notes_json              TEXT NOT NULL DEFAULT '[]',
    last_updated_at         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_threats_score ON threats(score);

CREATE TABLE IF NOT EXISTS meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
"""


# v1 -> v2: Stage 7 intents table. One row per session keyed on
# session_id (1:1 with sessions); cascade-delete with the session.
_MIGRATION_2: Final[str] = """
CREATE TABLE IF NOT EXISTS intents (
    session_id              TEXT PRIMARY KEY
        REFERENCES sessions(session_id) ON DELETE CASCADE,
    actor_profile           TEXT NOT NULL,
    intent                  TEXT NOT NULL,
    why                     TEXT NOT NULL,
    matched_techniques_json TEXT NOT NULL DEFAULT '[]',
    confidence              TEXT NOT NULL,
    summary                 TEXT NOT NULL,
    extracted_at            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_intents_extracted_at ON intents(extracted_at);
CREATE INDEX IF NOT EXISTS idx_intents_confidence   ON intents(confidence);
"""


# v2 -> v3: Stage 8 embeddings table. One row per session keyed on
# session_id (1:1 with sessions); cascade-delete with the session.
# The vector is stored as a packed float32 blob; the dimension is
# stored separately so a read can validate the blob length matches
# without unpacking. The model column lets find_similar exclude
# cross-model comparisons (vectors from different embed models
# live in different spaces).
_MIGRATION_3: Final[str] = """
CREATE TABLE IF NOT EXISTS embeddings (
    session_id      TEXT PRIMARY KEY
        REFERENCES sessions(session_id) ON DELETE CASCADE,
    vector_blob     BLOB NOT NULL,
    dimension       INTEGER NOT NULL,
    model           TEXT NOT NULL,
    generated_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_embeddings_generated_at ON embeddings(generated_at);
CREATE INDEX IF NOT EXISTS idx_embeddings_model        ON embeddings(model);
"""


# v3 -> v4: Stage 9 adaptive persona. The sessions table gains a
# persona column (NULL for pre-Stage-9 rows; the selector's
# recurrence query filters WHERE persona IS NOT NULL). The new
# persona_pins table stores operator-driven per-source-IP pins
# that the selector consults first. A composite index on
# (source_ip, started_at DESC) keeps the selector's recurrence
# lookup O(log n) regardless of total session count.
_MIGRATION_4: Final[str] = """
ALTER TABLE sessions ADD COLUMN persona TEXT;

CREATE INDEX IF NOT EXISTS idx_sessions_source_ip_started_at
    ON sessions(source_ip, started_at DESC);

CREATE TABLE IF NOT EXISTS persona_pins (
    source_ip   TEXT PRIMARY KEY,
    persona     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    created_by  TEXT NOT NULL
);
"""


# Migration chain: index = target version. Adding v5 means adding
# _MIGRATION_5 and appending here; run_migrations walks the chain.
_MIGRATIONS: Final[tuple[str, ...]] = (
    _MIGRATION_1,
    _MIGRATION_2,
    _MIGRATION_3,
    _MIGRATION_4,
)


def current_schema_version(conn: sqlite3.Connection) -> int:
    """Read the recorded schema version from ``meta``; returns 0 if absent.

    Used by ``run_migrations`` to decide which migrations to apply.
    A fresh database has no ``meta`` row and reports version 0; the
    first migration creates the table and the row.
    """
    try:
        cur = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'")
    except sqlite3.OperationalError:
        # meta table not created yet -> version 0.
        return 0
    row = cur.fetchone()
    if row is None:
        return 0
    try:
        return int(row[0])
    except (TypeError, ValueError):
        return 0


def run_migrations(conn: sqlite3.Connection) -> int:
    """Bring ``conn`` up to :data:`CURRENT_SCHEMA_VERSION`.

    Idempotent: runs only the migrations whose target version is
    above the recorded one. Returns the version the database is at
    after the call (which equals :data:`CURRENT_SCHEMA_VERSION` on
    success).

    All migrations run inside an implicit SQLite transaction; on
    failure the partial work rolls back and the recorded version
    stays at its prior value.
    """
    starting = current_schema_version(conn)
    if starting >= CURRENT_SCHEMA_VERSION:
        return starting

    # Apply each migration whose target index > starting. The list is
    # 0-indexed but version numbers are 1-indexed: index 0 -> v1.
    for target_version in range(starting + 1, CURRENT_SCHEMA_VERSION + 1):
        statements = _MIGRATIONS[target_version - 1]
        conn.executescript(statements)
        # Use INSERT OR REPLACE so re-running over an existing meta
        # row (operator manually edited it, schema bumped) succeeds.
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
            (str(target_version),),
        )
    return CURRENT_SCHEMA_VERSION
