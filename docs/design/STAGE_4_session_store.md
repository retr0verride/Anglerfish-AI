# Stage 4 - Persistent rich session store

## Problem

Sessions today live in a bounded in-memory ring buffer at
[`src/anglerfish/dashboard/state.py`](../../src/anglerfish/dashboard/state.py).
Three things this is wrong for:

1. **Data loss on restart.** A `systemctl restart anglerfish-dashboard`
   drops every active session, every command turn, every threat
   assessment. Operators lose the morning's attacker corpus the
   moment they apply a config tweak.
2. **Bounded for working set, not for history.** The cap is 500
   active sessions and 1000 commands. On a quiet honeypot that
   covers a week; on a noisy one (or during a deliberate stress test)
   it covers minutes. Stage 3's export endpoint pulls from this
   buffer, so its "7-day export cap" is currently aspirational.
3. **No second consumer.** Stages 7-11 all need to query session
   data they did not produce: intent extraction (Stage 7) reads
   completed sessions, behavioural clustering (Stage 8) reads
   commands across sessions, decoy poisoning (Stage 11) reads the
   honeytoken registry. Each would otherwise need its own ring
   buffer or replay-from-JSONL pass.

The historical forwarder JSONL fallback (now removed alongside
Cowrie in 2026-05) was *not* a session store: it was an
envelope-per-event append log written when Splunk HEC was
unreachable. Reconstructing sessions from those legacy files is
possible but non-trivial; the `sessions/migrate.py` helper handles
it for operators upgrading off the Cowrie pipeline.

Stage 4 ships an explicit session store: a SQLite database with a
small async API mirroring [`CredentialStore`](../../src/anglerfish/credentials/storage.py).
`DashboardState` becomes a thin façade around it for the existing
pub/sub fan-out the WebSocket layer relies on. Stage 3's export
endpoints switch from the in-memory list to a date-range query
against SQLite.

## Proposed interface

### Module layout

```text
src/anglerfish/sessions/
    __init__.py        # public re-exports: SessionStore
    store.py           # async SessionStore class (mirrors CredentialStore)
    schema.py          # DDL + (single-statement) migration helpers
    migrate.py         # CLI helper: import historical JSONL into the store
```

The lure subsystem's existing
[`anglerfish.lure.session.LureSessionContext`](../../src/anglerfish/lure/session.py)
stays where it is - that's per-attacker shell state inside the
lure process. The new `anglerfish.sessions` package is the
operator-facing persistent store for the dashboard.

### SessionStore class

```python
class SessionStore:
    """SQLite-backed persistent session + turn + threat store.

    Construct once at app startup. Mirrors `CredentialStore` in
    shape:

    * `await store.open()` once before the first call.
    * Every public method is async; SQLite work runs under
      `asyncio.to_thread`.
    * `await store.aclose()` (or async-context-manager) closes
      cleanly.
    * Database file written with mode 0600; parent dir 0700.
    * `PRAGMA journal_mode=WAL` for multi-reader concurrency
      (the dashboard reads while the bridge/lure writes).
    """

    def __init__(self, config: SessionStoreConfig) -> None: ...

    async def open(self) -> None: ...
    async def aclose(self) -> None: ...
    async def __aenter__(self) -> Self: ...
    async def __aexit__(self, *_exc: object) -> None: ...

    # Writes (called from DashboardState; eventually from bridge/lure
    # directly when the persistence-vs-pubsub split lands).
    async def upsert_session(self, snapshot: SessionSnapshot) -> None: ...
    async def record_turn(self, session_id: UUID, turn: CommandTurn) -> None: ...
    async def record_threat(self, assessment: ThreatAssessment) -> None: ...
    async def end_session(self, session_id: UUID, ended_at: datetime) -> None: ...

    # Reads (called by routes.py + export.py)
    async def get_session(self, session_id: UUID) -> SessionSnapshot | None: ...
    async def get_active_sessions(self, *, limit: int = 500) -> list[SessionSnapshot]: ...
    async def get_sessions_in_range(
        self, *, start: datetime, end: datetime, limit: int = 10_000,
    ) -> list[SessionSnapshot]: ...
    async def get_recent_commands(
        self, *, limit: int = 100,
    ) -> list[tuple[UUID, CommandTurn]]: ...
    async def get_recent_threats(
        self, *, limit: int = 50,
    ) -> list[ThreatAssessment]: ...
    async def get_stats(self) -> SessionStoreStats: ...
```

`SessionStoreStats` is a frozen Pydantic model with the same fields
`DashboardStats` exposes today (active_sessions, total_commands,
total_threats, high_severity_count, persistence_attempt_count) so
the `/api/stats` route can swap its source with no schema change.

### Schema (v1)

```sql
CREATE TABLE sessions (
    session_id     TEXT PRIMARY KEY,        -- UUID stringified
    source_ip      TEXT NOT NULL,
    username       TEXT NOT NULL,
    fake_hostname  TEXT NOT NULL,
    fake_username  TEXT NOT NULL,
    fake_cwd       TEXT NOT NULL,
    started_at     TEXT NOT NULL,           -- ISO 8601 UTC
    last_activity_at TEXT NOT NULL,
    ended_at       TEXT,                    -- NULL while active
    command_count  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_sessions_started_at ON sessions(started_at);
CREATE INDEX idx_sessions_source_ip  ON sessions(source_ip);
CREATE INDEX idx_sessions_active     ON sessions(ended_at) WHERE ended_at IS NULL;

CREATE TABLE turns (
    id             INTEGER PRIMARY KEY,
    session_id     TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    sequence_n     INTEGER NOT NULL,        -- 1-based position in the session
    command        TEXT NOT NULL,
    response       TEXT NOT NULL,
    source         TEXT NOT NULL,           -- ResponseSource enum value
    timestamp      TEXT NOT NULL,
    latency_ms     REAL NOT NULL
);

CREATE UNIQUE INDEX idx_turns_session_seq ON turns(session_id, sequence_n);
CREATE INDEX idx_turns_timestamp ON turns(timestamp);

CREATE TABLE threats (
    session_id            TEXT PRIMARY KEY REFERENCES sessions(session_id) ON DELETE CASCADE,
    score                 INTEGER NOT NULL,
    persistence_attempted INTEGER NOT NULL DEFAULT 0,
    high_severity         INTEGER NOT NULL DEFAULT 0,
    techniques_json       TEXT NOT NULL DEFAULT '[]',
    notes_json            TEXT NOT NULL DEFAULT '[]',
    last_updated_at       TEXT NOT NULL
);

CREATE INDEX idx_threats_score ON threats(score);
```

Three forward-looking tables (`observations`, `intent_summaries`,
`embeddings`) are **explicitly deferred** to the stages that produce
them (7, 7, 8). Stage 4 ships the foundation those stages add to,
not the speculative tables themselves; future-stage tables have
their own design constraints (vector indexing, embedding dimensions,
etc.) that should not be guessed now.

Schema versioning lives in a `meta` table:

```sql
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO meta(key, value) VALUES ('schema_version', '1');
```

Stage 7+ migrations add `ALTER TABLE` / `CREATE TABLE` statements
guarded on `schema_version`. The migration runner lives in
`schema.py` and is invoked from `SessionStore.open()`.

### SessionStoreConfig

Lives in `anglerfish.config.models` alongside `CredentialsConfig`:

```python
class SessionStoreConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    database_path: Path = Field(default=Path("/var/lib/anglerfish/sessions.db"))
    max_active_sessions_returned: int = Field(default=500, ge=1, le=10_000)
```

No encryption key. The session data is operator-visible by design
(commands, responses, source IPs, threat assessments). The
file-system control is mode 0600 + dir ownership, same posture as
the existing audit log. Operators that need encryption at rest get
it via the filesystem (LUKS on `/var/lib`), not at the application
layer.

### DashboardState refactor

`DashboardState` keeps two of its three responsibilities and loses
the third:

* **Kept**: WebSocket pub/sub fan-out. `subscribe()`, `publish()`,
  `subscriber_count()` are unchanged. The pub/sub is in-memory
  ephemeral by design - it's about pushing events to active
  WebSocket subscribers, not history.
* **Kept**: `get_stats()` shape and behaviour, but now delegates
  to `SessionStore.get_stats()`.
* **Moved to SessionStore**: every other read and write
  (`update_session`, `end_session`, `record_threat`,
  `get_active_sessions`, `get_session`, `get_recent_commands`,
  `get_recent_threats`).

The refactor pattern:

```python
class DashboardState:
    def __init__(self, store: SessionStore, *, ...subscriber knobs...) -> None:
        self._store = store
        self._subscribers: set[asyncio.Queue[DashboardEvent]] = set()
        ...

    async def update_session(self, snapshot: SessionSnapshot) -> None:
        # 1. persist
        # 2. compute the diff so the COMMAND events are accurate
        # 3. fan out
        previously_known = await self._store.get_session(snapshot.session_id)
        existing_turns = previously_known.turns if previously_known else ()
        await self._store.upsert_session(snapshot)
        added_turns = snapshot.turns[len(existing_turns):]
        for turn in added_turns:
            await self._store.record_turn(snapshot.session_id, turn)
        # ... publish events (unchanged) ...
```

The constructor signature changes (now requires a SessionStore).
`create_app` builds one and passes it. Tests build a SessionStore
against an in-process tmp_path SQLite file (fast; the test suite
already uses CredentialStore the same way).

### Stage 3 export integration

`anglerfish.dashboard.export.session_export_payload` and
`session_csv_rows` switch from `dashboard_state.get_active_sessions()`
+ in-memory filter to `store.get_sessions_in_range(start=, end=)`.
The 7-day cap stays. Pagination is unchanged.

`audit_export_payload` is unaffected; it reads the audit JSONL,
not the session store.

### Migration CLI

A small one-shot:

```bash
anglerfish sessions migrate-from-jsonl \
    --path /var/lib/anglerfish/sessions.jsonl \
    --batch-size 1000
```

Reads each line of the JSONL forwarder fallback, picks out
`cowrie.session.connect` / `cowrie.command.input` /
`cowrie.session.closed` events, groups by `session` (cowrie's
session-id field), and writes one `upsert_session` +
`record_turn(s)` + `end_session` per group.

This is **optional, post-MVP** in the sense that Stage 4 ships
clean: no data is required to migrate. Operators that want their
historical corpus run the CLI once after upgrading.

### Audit event additions

* `sessions.store_opened` - at `SessionStore.open` time, with
  `database_path` + `schema_version`.
* `sessions.migration_completed` - emitted by the CLI helper with
  imported row counts.

## Out of scope

* **Forward-looking tables.** `observations`, `intent_summaries`,
  `embeddings` land with the stages that produce them.
* **Encryption at rest.** Session content is operator-visible.
  Filesystem encryption is the operator's option.
* **Cross-host replication.** Single-host product. Multi-host is a
  product decision, not a stage.
* **Schema-version downgrade.** Forward-only migrations; downgrade
  is a restore-from-backup operation, not an application concern.
* **GC of old sessions.** A `sessions purge --older-than 90d`
  command can land later if disk pressure shows up; v1 grows
  unboundedly because operators usually want the full corpus.
* **Replacing the audit log.** The audit log is a separate
  append-only stream for security-relevant events. The session
  store holds operational session data. They serve different
  consumers; merging them would muddy both.

## Threat-model delta

### New attack surface: SQLite file on disk

* **Mitigation.** Mode 0600 on the file, dir 0700, owned by the
  anglerfish service user. Same posture as the existing
  CredentialStore database and the audit log. No new auth surface.
* **Residual risk.** A root attacker on the host can read the
  file. Same threat as the audit log + credential store; no new
  exposure.

### SQL injection through user-controlled data

* **Mitigation.** All queries use parameterised SQL via
  `sqlite3.Connection.execute(sql, params)`. The two test cases
  enforce this: a session ID with an embedded quote round-trips
  intact, and a command containing `'; DROP TABLE sessions; --`
  becomes one literal row, not a structural change.
* **Residual risk.** A bug in a future query string could
  reintroduce string interpolation. Test discipline + code review
  carry this.

### Concurrent writers

* **Mitigation.** `PRAGMA journal_mode=WAL` permits one writer
  with concurrent readers - matches what we need (dashboard reads
  while the bridge/lure writes through DashboardState). One
  `asyncio.Lock` inside `SessionStore` serialises writes from the
  dashboard process; cross-process serialisation comes from
  SQLite's own locking.
* **Residual risk.** A second writer process (a custom operator
  tool, or a future Stage 6+ component) would contend on the WAL
  lock. SQLite handles that cleanly but with reduced throughput.
  Future stages should write through `SessionStore`, not directly
  to the file.

### Migration tool replays attacker data

* **New threat.** `migrate-from-jsonl` reads attacker-controlled
  bytes from `sessions.jsonl` and writes them to the new database.
* **Mitigation.** All writes are parameterised. Lengths are
  enforced at the Pydantic-model layer (`SessionSnapshot`,
  `CommandTurn` already cap field sizes). Lines that fail Pydantic
  validation are logged and skipped, not crashed-on.
* **Residual risk.** A malformed JSONL line could DoS the import
  if the per-line parse cost is unbounded. The line reader uses
  the same `iter_events` pattern from `audit_reader.py` which is
  bounded by file size.

## LLM defense delta

No new LLM call. The session store is plumbing. The Stage 1
defense corpus is unchanged.

## Test plan

### Unit: `tests/sessions/test_store.py` (~20 cases)

* Open/close round-trip; idempotent open.
* Schema version recorded in `meta` after fresh open.
* `upsert_session` inserts new row; second call updates existing.
* `record_turn` appends with monotonic `sequence_n`; duplicate
  sequence rejected by the UNIQUE constraint.
* `record_threat` upserts; second call replaces prior values.
* `end_session` sets `ended_at`; subsequent `get_active_sessions`
  excludes it.
* `get_session_in_range` filters correctly; inclusive bounds.
* `get_recent_commands` ordering (newest first); limit respected.
* `get_recent_threats` ordering (newest first); limit respected.
* `get_stats` matches the in-memory `DashboardStats` for a known
  fixture (parity check during transition).
* SQL injection round-trip: command containing `'; DROP TABLE
  sessions; --` lands as one row, table still exists.
* Mode-0600 file permissions on POSIX after `open()`.
* `record_threat` requires the session to exist (FK enforcement).
* `get_sessions_in_range` past 10 000 limit raises ValueError.

### Unit: `tests/sessions/test_migrate.py` (~6 cases)

* Round-trip: write a 3-session JSONL fixture, import, verify
  every session + turn + close event materialised.
* Malformed line: skipped + logged; remaining lines import.
* `--batch-size` parameter caps memory.
* CLI exit codes: 0 on success, 1 on import-time IO error.
* Idempotent on a second run: existing sessions get upserted
  cleanly, no duplicate turns (UNIQUE on session_id+sequence_n).

### Integration: `tests/dashboard/test_state_persistence.py` (~10 cases)

* DashboardState constructed with a tmp_path SessionStore.
* `update_session` persists; bouncing the state then reading the
  store returns the same snapshot.
* `end_session` clears active list AND publishes the
  SESSION_ENDED event (unchanged).
* `get_active_sessions` reads from the store.
* WebSocket subscribers still receive events.
* `get_stats` parity with the in-memory implementation on a known
  fixture.

### Integration: Stage 3 export endpoints

* Update existing `tests/dashboard/test_export_endpoints.py`
  fixtures to construct a SessionStore + DashboardState pair.
* `GET /api/export/sessions?from=...&to=...` returns rows from
  the store, not the in-memory list.
* CSV streaming still works against a 1000-row store fixture.
* 7-day cap still rejected.

### Coverage target

≥90% on the new `sessions/` package, total project coverage stays
≥90%. The audit-event additions get smoke tests for the event
shape (matches the pattern from the Stage 3 `dashboard.*` events).

## Rollback plan

* **Per-commit.** Stage 4 ships as one commit. Three modules + the
  DashboardState refactor + the Stage 3 export wiring touch enough
  files that slicing would create broken intermediate states.
* **Disable at runtime.** No env-var switch. To roll back: revert
  the commit. Sessions written between deploy and rollback are
  in the SQLite file; operators that want to keep them can copy
  the file aside before reverting.
* **Schema-only revert.** A `sessions.db` from this commit is
  forward-compatible with later stages (schema version is
  monotonic). Reverting to before Stage 4 leaves the file orphaned
  on disk; it's safe to delete.
* **DashboardState rollback.** The refactor preserves every
  existing public method signature. Tests that touched
  `DashboardState` directly continue to pass without modification.

## Success criteria

* All Stage 4 tests pass.
* Total coverage stays ≥90% (existing gate).
* `anglerfish dashboard serve`, kill, restart - active sessions
  from before the kill reappear in `GET /api/sessions`.
* `GET /api/export/sessions?from=<7d-ago>&to=<now>` returns rows
  from across the full 7-day window, not just whatever was in the
  in-memory ring at request time.
* `anglerfish sessions migrate-from-jsonl --path <fixture>` exits
  0 and the imported sessions appear in `GET /api/sessions`.
* `sqlite3 /var/lib/anglerfish/sessions.db '.schema'` shows the
  v1 schema plus a `meta` row at `schema_version=1`.
* `ls -la /var/lib/anglerfish/sessions.db` shows mode `0600`
  owned by the service user.
* `docs/ROADMAP.md` Stage 4 row flips to ✅ shipped.

## Notes for future-me

* **Stage 7 (intent extraction).** When you add the
  `intent_summaries` table, increment `schema_version` to 2 and
  guard the migration on `schema_version < 2`. Don't drop
  `intent_summaries` if it already exists (idempotent migrations
  matter for re-run safety).
* **Stage 8 (clustering).** The `embeddings` table you add needs
  a vector column. SQLite has no native vector type; the two
  options are (a) `BLOB` of packed floats with a Python-side
  cosine-similarity scan, (b) `sqlite-vec` extension. Decide
  based on corpus size when Stage 8 starts; for <10k sessions (a)
  is faster to ship and good enough.
* **DashboardState two-pronged refactor.** This commit makes
  DashboardState a façade over SessionStore. A subsequent
  refactor could split them entirely: bridge/lure writes
  directly to `SessionStore`, and `DashboardState` becomes purely
  the WebSocket pub/sub class. Don't do that yet - the current
  pattern keeps the call sites unchanged, which is the whole
  point of the façade.
* **WAL file cleanup.** SQLite in WAL mode creates `-wal` and
  `-shm` sidecar files. Operators sometimes back up the `.db`
  alone and lose recent writes. Document in the runbook (Stage 4
  release commit, RUNBOOK.md update): back up all three files or
  `sqlite3 sessions.db '.backup main /path/to/backup.db'`.
* **Why no SessionStore-side encryption.** CredentialStore
  encrypts because operators sometimes capture real passwords from
  misconfigured automation; those are bystander credentials with
  legal weight. Session command text is attacker-provided and
  attacker-owned (by definition - they sent it to a honeypot);
  the operator's right to read it is exactly the product. Adding
  encryption here would block the routine use case (`sqlite3
  sessions.db 'SELECT * FROM turns WHERE ...'` during incident
  response) for no threat-model benefit.
* **For Stage 6 (time-wasting) design author.** The Stage 3
  control-plane settings live in dashboard process memory only.
  Now that Stage 4 has SQLite, you might be tempted to persist
  the override toggle there. Don't - the design boundary still
  holds: a service restart should revert overrides to env-file
  values. Tmpfs JSON is still the propagation primitive Stage 6
  should build.
