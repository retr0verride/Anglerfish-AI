# Stage 4.2 - Audit-log tailer wires the lure into the session store

## Problem

The Stage 4 SessionStore is a working data layer with no production
writer. The Stage 4 scoped re-review confirmed that nothing in the
bridge, lure, or threat engine calls
[`DashboardState.update_session`](../../src/anglerfish/dashboard/state.py)
in production - the only writers are tests. The dashboard's
session/threat/stats endpoints return empty until a writer exists.

The lure is the producing subsystem: it emits structured per-session
events via `audit.record(...)` for every meaningful lifecycle moment
(`lure.session_opened`, `lure.command_native`, `lure.command_bridge`,
`lure.fallback_served`, `lure.session_closed`, plus refusal +
fingerprint + rate-limit signals). These already land in
`/var/log/anglerfish/audit.jsonl`. The dashboard process has full
read access (same `anglerfish` user). All the data the SessionStore
needs is already on disk, in JSONL, ten yards from the consumer.

Stage 4.2 ships an audit-log tailer that runs inside the dashboard
process, reads `audit.jsonl` continuously, translates relevant lure
events into SessionStore writes, and publishes via the existing
DashboardState pub/sub. No new IPC, no new HTTP surface, no new
auth token - the audit log itself is the wire format.

The design is symmetric with the Stage 4 migration helper
([`sessions/migrate.py`](../../src/anglerfish/sessions/migrate.py)):
that helper does a one-shot replay of the historical Cowrie
forwarder JSONL into the store; the tailer does the same translation
continuously against Anglerfish's own audit JSONL.

## Constraints discovered during design

Two pre-existing facts shape what 4.2 can do:

1. **No `session_id` in audit records.** The lure tracks
   `state.bridge_uuid` internally
   ([`lure/server.py:206`](../../src/anglerfish/lure/server.py#L206))
   but never includes it in `audit.record(...)` kwargs. Every per-
   session event today carries only `(source_ip, username, ts)` -
   not enough to correlate concurrent sessions from the same IP.
   This is a tiny writer-side fix and 4.2 makes it: every lure
   audit event that ties to a session gets a `session_id` field.
2. **No command response text in audit records.** The lure logs
   `command=command[:200]` but not the response (likely on size
   grounds, since attacker output can be large). The tailer
   populates `CommandTurn.response = ""` and the existing
   `CommandTurn` schema accepts the empty string. Response text
   lives only in the lure process's `LureSessionContext`. Stages
   7/8/9 that need response analysis will either accept this
   limitation or extend the audit format - a decision for those
   stages, not 4.2.

The audit log's rotation behaviour is already operator-locked to
`copytruncate` ([`docs/RUNBOOK.md:228-243`](../RUNBOOK.md)). The
tailer is designed against that exact rotation strategy and will
break if an operator switches to rename-based rotation.

## Proposed interface

### Module layout

```text
src/anglerfish/dashboard/
    audit_tailer.py    # AuditTailer class (background async task)
    audit_reader.py    # (existing) one-shot range reader, unchanged
```

The tailer lives under `dashboard/` rather than `sessions/`
because it is a consumer-side concern: it knows about the audit
schema, the dashboard's `DashboardState` facade, and the
dashboard's process lifecycle. The `sessions/` package stays
ignorant of who writes to it.

### AuditTailer class

```python
class AuditTailer:
    """Background task that translates audit-log lure events into
    SessionStore writes via DashboardState.

    Lifecycle:
    - Constructed at dashboard startup; takes the audit-log path,
      the DashboardState facade, and an offset-cache path.
    - `await tailer.start()` spawns the background task.
    - `await tailer.stop()` requests shutdown, drains pending
      events, persists the final offset, returns.
    - One instance per dashboard process. Re-entry safe via
      asyncio.Lock; concurrent start() calls are rejected.

    Polling:
    - Sleeps `poll_interval_seconds` between reads (default 0.5s).
    - Each cycle: open audit.jsonl, seek to last persisted offset,
      read available lines, parse, dispatch, persist new offset.
    - File is reopened every cycle. Same pattern as audit_reader.py
      and AuditLog itself - works with copytruncate.

    Copytruncate detection:
    - If `stat().st_size < last_offset`, the file rotated. Reset
      offset to 0 and re-process from the new beginning. Records
      processed in the pre-rotation generation stay processed
      (offset cache persists the dedupe set on close).
    """

    def __init__(
        self,
        *,
        audit_path: Path,
        dashboard_state: DashboardState,
        offset_cache_path: Path,
        poll_interval_seconds: float = 0.5,
        max_batch_size: int = 1000,
    ) -> None: ...

    async def start(self) -> None: ...
    async def stop(self) -> None: ...
```

### Event-to-store mapping

| Audit `event_type`           | SessionStore op                                                     |
|------------------------------|---------------------------------------------------------------------|
| `lure.session_opened`        | `upsert_session(SessionSnapshot(turns=()))` with FK-safe defaults   |
| `lure.command_native`        | `record_turn(session_id, CommandTurn(source=NATIVE, response=""))`  |
| `lure.command_bridge`        | `record_turn(session_id, CommandTurn(source=AI,     response=""))`  |
| `lure.fallback_served`       | `record_turn(session_id, CommandTurn(source=FALLBACK, response=""))`|
| `lure.session_closed`        | `end_session(session_id, ts)`                                       |
| everything else (refusals, fingerprints, rate limits, login attempts) | ignored by 4.2 - those are threat-engine concerns, not session-shape concerns |

The DashboardState facade is the call surface (not the store
directly) so the WebSocket fan-out fires for every translated event.

### Offset cache

A small sidecar JSON file at `/var/lib/anglerfish/audit_tailer.json`:

```json
{
  "audit_path": "/var/log/anglerfish/audit.jsonl",
  "offset": 12345,
  "last_processed_ts": "2026-05-24T14:30:21.123456+00:00",
  "schema_version": 1
}
```

Written atomically (write-temp + os.replace) on every successful
batch and on shutdown. Lost / corrupt cache → start from offset 0,
which is safe because the SessionStore writes are idempotent on
session_id + turn sequence; `record_turn` would create gap-free
duplicates only if the lure ever re-emitted the same audit line,
which it doesn't.

The cache file lives under `/var/lib/anglerfish` (data dir), NOT
under `/var/log/anglerfish` (which is `chattr +a`). Operator
permissions match the SQLite DB (0600 anglerfish:anglerfish).

### Lure-side change

Add `session_id=str(state.bridge_uuid)` to every per-session
audit emission in `lure/server.py`. The `_ConnectionState` already
holds `bridge_uuid: UUID | None`. Events that fire before
`bridge_uuid` is assigned (`lure.rate_limited`,
`lure.fingerprint_observed`, `lure.login_attempt`) stay without a
session_id; the tailer ignores those event types anyway.

This is the only writer-side change in 4.2. It's backward
compatible: extra kwargs in audit records are flattened into the
JSON object; existing audit log consumers (alerts, health, export)
ignore unknown fields.

### Dashboard app wiring

In `create_app`:

```python
audit_tailer = AuditTailer(
    audit_path=settings.audit_log_path,  # new SettingsField? or hardcode default
    dashboard_state=state_instance,
    offset_cache_path=settings.data_dir / "audit_tailer.json",
)
@asynccontextmanager
async def lifespan(_app: FastAPI):
    if owns_session_store:
        await store_instance.open()
    await audit_tailer.start()
    try:
        yield
    finally:
        await audit_tailer.stop()
        if owns_session_store:
            await store_instance.aclose()
        if credential_store is not None:
            await credential_store.aclose()
```

If `settings.audit_log_path` doesn't exist, the tailer logs a
warning and the start() call no-ops (returns without spawning
the background task). Dashboard remains functional; the
session/stats endpoints just keep returning empty.

## Failure modes

| Failure                            | Behaviour                                                                                                |
|------------------------------------|----------------------------------------------------------------------------------------------------------|
| Audit log missing at startup       | Warning logged; tailer no-ops; dashboard endpoints still serve (returning empty).                        |
| Audit log disappears mid-run       | Next poll detects, logs `audit_tailer.path_disappeared`, sleeps `5 * poll_interval`, retries.            |
| Audit log copytruncated            | `st_size < offset` detected; offset reset to 0; processing resumes from new start.                       |
| Audit log renamed (operator changed logrotate config) | Same as "disappears"; tailer keeps retrying. RUNBOOK section documents that copytruncate is required.   |
| Malformed JSON line                | Logged at warning (`audit_tailer.parse_failed`), line skipped, offset advanced past it.                  |
| Unknown event_type                 | Silently ignored. Future stages add types without churning the tailer.                                   |
| SessionStore unavailable           | Tailer's write call raises; the offset is NOT advanced; the same batch retries on the next poll cycle. After 3 consecutive batch failures, tailer logs `audit_tailer.store_unhealthy` and backs off to 5x poll interval until success. |
| Offset cache corrupt               | Logged; cache treated as empty; tailer starts from offset 0 (idempotent on session_id + turn sequence).  |
| `lure.session_opened` for a `session_id` already in the store | `upsert_session` is the right op; second event overwrites with the same values. No-op effectively.       |
| `lure.command_*` for a session_id with no prior `lure.session_opened` (because the open event fell off before the offset cache was first written) | `record_turn` would raise FK error. The tailer first attempts to upsert a `SessionSnapshot` with placeholder fields derived from the command event's source_ip / username, then records the turn. |

## Non-goals

- **Forwarder integration.** The forwarder fan-out path (Path γ in
  the design discussion) is out of scope. The audit log is the
  source of truth for 4.2.
- **Splunk HEC parity.** Historical context: pre-removal, events
  went to HEC via the forwarder when Cowrie was the bait listener.
  The forwarder package was deleted in the 2026-05 Cowrie removal,
  so there is no live HEC sink to keep parity with. Operators that
  want HEC must build it on top of `/api/threats` and the
  SessionStore.
- **Cross-process notification.** The tailer runs in the dashboard
  process, so WebSocket fan-out works natively. Operators that want
  to run multiple dashboard replicas behind a load balancer get one
  tailer per replica; they'll both write the same rows
  idempotently. Not recommended; this is a single-process honeypot
  not a microservices fleet.
- **Backfill.** The Stage 4 `import_jsonl_into_store` migration
  helper already covers historical Cowrie-era JSONL; backfilling
  lure events from a pre-4.2 audit log is the same idea and can be
  added later as a `--from-offset 0` CLI flag if operators need it.
- **Response capture.** As above; left to the stage that actually
  needs response text (probably Stage 7 intent extraction).

## Migration / rollback

There's nothing to migrate; the SessionStore is currently empty
in production. On rollback, deleting the tailer code and the
offset cache file is sufficient. The DashboardState facade and
SessionStore stay untouched and revert to "writable but unwritten."

The lure-side `session_id=...` audit fields are forward-compatible;
they don't need to be removed on rollback. Existing audit consumers
(alerts, health, export) ignore unknown fields.

## Test plan

New: `tests/dashboard/test_audit_tailer.py`. ~20 cases:

- Startup with no audit file logs warning, no crash.
- Startup with empty audit file processes zero events.
- Single `lure.session_opened` produces one active session.
- Sequence: opened + 2 commands + closed produces correct row +
  2 turns + ended_at populated.
- `lure.command_bridge` before `lure.session_opened` (offset-cache
  edge case) creates a placeholder session row.
- Malformed JSON line logged + skipped, offset advances.
- Unknown event_type silently ignored.
- Copytruncate detected via shrinking file size, offset reset.
- Offset cache persisted across stop + restart; no duplicate writes.
- Multiple concurrent IPs with their own session_ids stay isolated.
- Backpressure: SessionStore-unavailable simulation; offset does
  not advance until store recovers.

Existing tests updated:

- `tests/dashboard/test_app.py` - any test that asserts the
  dashboard endpoints return data via direct
  `state.update_session(...)` calls keeps working; the tailer is
  spawned by lifespan but the audit file is empty in TestClient
  context, so it produces no events.
- `tests/lure/test_server.py` (or wherever the lure audit fields
  are asserted) - assert the new `session_id` field is present
  on the relevant events.

Quality gates (non-negotiable): ruff clean, mypy --strict clean,
pytest at >= 90% coverage. Stage 4's gates already lock these in.

## Decisions (locked during operator review)

1. **Tailer poll interval: 0.5s, ship and tune.** A 0.5-second
   `stat()` against a file on local disk is negligible CPU
   overhead, and the dashboard's user-perceived freshness
   tolerance is well under 1s. Hard-code as a module constant;
   no env knob until production data says otherwise.
2. **Add `ANGLERFISH_AUDIT__LOG_PATH` now.** Two process domains
   (the bridge/lure writer side and the dashboard reader side)
   must agree on this path. Parameterizing once in
   `AnglerfishSettings` makes that agreement structural rather
   than coincidental. Both `AuditLog()` construction sites and
   the tailer read the same setting; an operator who relocates
   the log on one side automatically updates the other.
3. **Auto-create placeholder session row from command-before-open.**
   Symmetric with the Stage 4 `import_jsonl_into_store` helper,
   and the right call for a security tool: losing a recorded
   attacker command because a prior lifecycle event was missed
   is the worst possible outcome. The placeholder row carries
   the source_ip/username from the command event and a started_at
   equal to the command's audit timestamp; if a `lure.session_opened`
   for the same session_id arrives later, the subsequent
   `upsert_session` overwrites the placeholder with the real
   metadata.
4. **Tailer runs in the dashboard process.** The dashboard owns
   the SessionStore and the WebSocket fan-out; putting the tailer
   anywhere else would require rebuilding IPC, which is the
   problem Path α exists to avoid. If the dashboard dies, the UI
   is dead anyway — the tailer dying with it is correct state
   alignment, not a failure mode worth defending against.
