# Stage 3 - Dashboard control plane

> **Renumbered in Stage 2C.** What was Stage 11 ("Dashboard +
> export overhaul") split: the four control-plane panels (settings,
> health, alerts, export) pulled forward into this new Stage 3 so
> the operator surface exists before the capability stages start
> producing data. The remaining dashboard work (per-session detail
> view, cluster visualization, honeytoken registry, STIX/MISP, live
> narrator) is now Stage 13.

## Problem

The dashboard is read-only today. Operators have no way to flip
features, change concurrency caps, or pull export data without
editing `/etc/anglerfish/anglerfish.env` and restarting services.
Two consequences:

1. **Stages 6-12 will land features the operator cannot toggle.**
   Time-wasting (6), engaged persistence (10), decoy poisoning (11),
   counter-deception (12) all ship as opt-in flags. Without a
   control plane, each requires an env-file edit + service restart.
   That friction kills experimentation and pushes operators toward
   "set once and forget," which is the wrong posture for aggressive
   features that affect attacker behaviour.

2. **No live operator visibility into subsystem health.** The
   existing `/api/health` returns `{"status":"ok"}` once the
   dashboard process is up. Operators can't see whether Ollama
   responded recently, whether the Splunk forwarder is draining its
   fallback queue, or how close the bridge is to its concurrency
   cap. They have to `journalctl -u` and grep, which is fine for
   one host and impossible for a fleet.

3. **No export pipeline.** Splunk forwarding is push-only.
   Operators that need a one-shot extract (incident response,
   compliance audit, threat-intel hand-off) have to dump SQLite
   tables and the JSONL fallback by hand. Stage 13 will add STIX
   2.1 and MISP exports on top of what we ship here; the
   in-memory JSON/CSV path is the foundation.

The Stage 3 scope is the four panels named in the operator-locked
scope (`memory/project_dashboard_pullforward.md`): **settings**,
**system health**, **alerts**, **export**.

## Proposed interface

### Scope boundary: dashboard-process-only mutation

A foundational decision the design must declare up front: the
dashboard and the bridge run as separate processes. `AIBridgeService`
reads `self._settings` (a frozen Pydantic `AnglerfishSettings`
instance) at construction; it does not poll a config file or
subscribe to an IPC channel. The dashboard cannot mutate the
bridge's frozen settings object from across process boundaries.

**Stage 3 mutates only the dashboard process's runtime overrides.**
The bridge does not see them. The settings endpoint response makes
this explicit:

```json
{
  "applies_to": "dashboard_process",
  "note": "Service restart reverts to env-file values. Bridge-side propagation lands in a later stage."
}
```

This keeps Stage 3 self-contained. Cross-process propagation
(probably a small RAM-only state file under `/run/anglerfish/` that
the bridge re-reads per request, or a tiny IPC channel) gets its
own design pass when we know which Stage 6-12 features actually
need it. Stage 6 (time-wasting) is the first capability stage that
needs the bridge to honour the wasting-strategy setting; the
propagation design lands at the start of Stage 6.

### Module layout

```text
src/anglerfish/dashboard/
    routes.py          # existing - new endpoints land here
    overrides.py       # NEW: RuntimeOverrides dataclass + accessors
    health.py          # NEW: dependency probes (ollama, forwarder, sessions)
    alerts.py          # NEW: audit-log alert reader
    export.py          # NEW: session + audit-log exporters
```

The existing `routes.py` grows new endpoints rather than spawning a
sibling router; one APIRouter is easier for operators to introspect
via the dashboard's own `/api/openapi.json`.

### Runtime overrides

```python
# anglerfish/dashboard/overrides.py
@dataclass
class BridgeRuntimeOverrides:
    """Mutable per-process snapshot the dashboard owns.

    Initialised from settings.bridge + settings.rate_limit at app
    startup. The settings endpoint mutates this; nothing else does.
    """
    max_concurrent_requests: int
    requests_per_session_per_minute: int
    wasting_strategy: Literal["off", "light", "aggressive"] = "off"


@dataclass
class FeatureFlagOverrides:
    """Opt-in capability toggles. All default False; flipped by the
    operator at runtime, reset on dashboard restart."""
    time_wasting: bool = False
    engaged_persistence: bool = False
    decoy_poisoning: bool = False
    counter_deception: bool = False


@dataclass
class RuntimeOverrides:
    bridge: BridgeRuntimeOverrides
    features: FeatureFlagOverrides
    applied_at: datetime  # last successful POST
```

Attached to `app.state.runtime_overrides` in `create_app`. Lifetime
is the dashboard process. Reset on restart by being re-built from
`settings` at startup.

### Settings endpoints

| Method | Path                       | Auth                     | Purpose                              |
| ------ | -------------------------- | ------------------------ | ------------------------------------ |
| GET    | `/api/settings`            | `require_auth`           | Return current overrides + provenance |
| POST   | `/api/settings/bridge`     | `require_auth + require_csrf` | Update bridge overrides         |
| POST   | `/api/settings/features`   | `require_auth + require_csrf` | Flip feature flags              |

#### `GET /api/settings`

```json
{
  "bridge": {
    "max_concurrent_requests": 8,
    "requests_per_session_per_minute": 30,
    "wasting_strategy": "off"
  },
  "features": {
    "time_wasting": false,
    "engaged_persistence": false,
    "decoy_poisoning": false,
    "counter_deception": false
  },
  "applied_at": "2026-05-24T14:01:03Z",
  "applies_to": "dashboard_process",
  "note": "Service restart reverts to env-file values. Bridge-side propagation lands in a later stage."
}
```

#### `POST /api/settings/bridge`

Request (all fields optional; absent fields keep current value):

```json
{
  "max_concurrent_requests": 16,
  "requests_per_session_per_minute": 60,
  "wasting_strategy": "light"
}
```

Bounds (from `RateLimitConfig` + the new strategy literal):

* `max_concurrent_requests`: 1-128
* `requests_per_session_per_minute`: 1-600
* `wasting_strategy`: one of `"off"`, `"light"`, `"aggressive"`

Response: the full `GET /api/settings` body with the new values
applied + the audit-event ID for the change.

Validation failures return `422` with the Pydantic error body
(consistent with the rest of the API).

#### `POST /api/settings/features`

Request (all fields optional, default False on first construction):

```json
{
  "time_wasting": true,
  "engaged_persistence": false,
  "decoy_poisoning": false,
  "counter_deception": false
}
```

Response: same shape as `GET /api/settings` plus the audit-event ID.

### System health endpoints

| Method | Path                      | Auth           | Purpose                                                    |
| ------ | ------------------------- | -------------- | ---------------------------------------------------------- |
| GET    | `/api/health/ollama`      | `require_auth` | Reachability + integrity-check result + last checked       |
| GET    | `/api/health/forwarder`   | `require_auth` | Splunk HEC last-delivery status, fallback queue depth      |
| GET    | `/api/health/sessions`    | `require_auth` | Active session count vs cap, token-consumption rate        |

The existing unauthenticated `GET /api/health` stays — it's the
liveness probe load balancers hit.

#### `GET /api/health/ollama`

```json
{
  "reachable": true,
  "reachable_at": "2026-05-24T14:01:03Z",
  "model": "qwen3:14b",
  "integrity_check": {
    "status": "passed",                  // passed | failed | skipped
    "last_checked_at": "2026-05-24T13:58:14Z",
    "expected_hash_present": true
  }
}
```

The dashboard polls Ollama with a 2 s GET to its own base URL on a
30-second cache. The integrity-check result reads from the audit log
(grep for the most recent `bridge.model_integrity_*` event).

#### `GET /api/health/forwarder`

```json
{
  "splunk_enabled": true,
  "last_delivery_status": "success",      // success | failed | unknown
  "last_delivery_at": "2026-05-24T14:00:55Z",
  "fallback_queue_depth_bytes": 0,
  "last_event_at": "2026-05-24T14:00:55Z"
}
```

`fallback_queue_depth_bytes` is `os.stat(splunk.fallback_path).st_size`.
Status fields read from the audit log; if no recent event, fields
return `"unknown"` / `null`.

#### `GET /api/health/sessions`

```json
{
  "active_sessions": 3,
  "max_concurrent_requests": 8,
  "utilisation_pct": 37.5,
  "tokens_per_minute": {
    "window_minutes": 5,
    "rate": 142.6
  }
}
```

`active_sessions` from `DashboardState.get_stats`. Token rate from
the audit log (count `bridge.command_*` events in the last 5
minutes).

### Alerts endpoint

| Method | Path                  | Auth           | Purpose                              |
| ------ | --------------------- | -------------- | ------------------------------------ |
| GET    | `/api/alerts`         | `require_auth` | Recent alert events, paginated       |

```json
{
  "items": [
    {
      "id": "1716553200000-0",
      "ts": "2026-05-24T14:00:00Z",
      "kind": "defense_fired",          // defense_fired | persistence_attempt | high_severity_session
      "available": true,
      "session_id": "9f9f9b4a-...",
      "source_ip": "203.0.113.42",
      "detail": "injection:override_instructions (score=1.0)"
    }
  ],
  "next_cursor": "1716553100000-7",       // null when no more
  "stubs": {
    "honeytoken_callback_hits": { "available": false, "stage": 11 },
    "behavioral_cluster_matches": { "available": false, "stage": 8 },
    "intent_summary_alerts": { "available": false, "stage": 7 }
  }
}
```

Query params:

* `cursor` (optional, opaque) - paginate from a previous response's
  `next_cursor`.
* `limit` (optional, default 50, max 200).
* `kind` (optional) - filter to one kind.

Implementation: reverse-iterate the audit log JSONL, parse each
line, filter to the recognised alert kinds, page until `limit`
events. The cursor is `"<ts_ms>-<offset>"` so a re-request can
resume from a known position.

### Export endpoints

| Method | Path                                     | Auth           | Purpose                              |
| ------ | ---------------------------------------- | -------------- | ------------------------------------ |
| GET    | `/api/export/sessions?format=json|csv&from=<iso>&to=<iso>` | `require_auth` | Session snapshots in date range |
| GET    | `/api/export/audit?from=<iso>&to=<iso>`  | `require_auth` | Audit log entries in date range      |

Query params:

* `format` - `json` (default) or `csv`. Sessions endpoint only;
  audit log is JSONL natively so the `format` knob is JSON-only
  on that endpoint.
* `from` / `to` - ISO-8601 UTC. Optional; defaults are "last 24 h"
  and "now."

Date-range bounds: at most 7 days per request to keep the response
size sane. Beyond that returns `400` with a clear message asking the
operator to narrow the range.

#### Response shape (JSON)

```json
{
  "available": true,
  "format": "json",
  "from": "2026-05-23T14:00:00Z",
  "to": "2026-05-24T14:00:00Z",
  "count": 142,
  "items": [
    { "session_id": "...", "source_ip": "...", "started_at": "...", "commands": [...] }
  ]
}
```

#### Response shape (CSV)

`Content-Type: text/csv; charset=utf-8`, `Content-Disposition:
attachment; filename="sessions-<from>-<to>.csv"`. Header row:

```text
session_id,source_ip,username,started_at,ended_at,command_count,fake_hostname,fake_username
```

Streamed via `StreamingResponse` so a 7-day export doesn't load
into memory.

#### `available: false` stubs

The export panel returns a top-level stubs object listing the
exports not yet built, so the UI knows which buttons to grey out:

```json
{
  "available": true,
  "format": "json",
  "from": "...",
  "to": "...",
  "items": [...],
  "stubs": {
    "stix2": { "available": false, "stage": 13 },
    "misp_json": { "available": false, "stage": 13 },
    "intent_summary": { "available": false, "stage": 7 },
    "honeytoken_report": { "available": false, "stage": 11 }
  }
}
```

### Audit-event additions

New event keys the new endpoints emit:

* `dashboard.settings_changed` - request body, who (session
  authenticated user), what changed (per-field diff), `applies_to`.
* `dashboard.feature_toggled` - feature name, old → new, who.
* `dashboard.export_served` - kind, format, from/to, item count,
  bytes written.

## Out of scope

* **Cross-process propagation of overrides.** Stage 6 (time-wasting)
  is the first stage that needs the bridge to honour the wasting
  strategy; the propagation design lands there. Stage 3 ships the
  override store + the dashboard-process mutation only.
* **Writing back to `/etc/anglerfish/anglerfish.env`.** Constraint
  from the operator; restart-reverts is the design.
* **A new auth layer.** All endpoints reuse `require_auth` from
  [auth.py](../../src/anglerfish/dashboard/auth.py).
* **DashboardState changes.** Constraint from the operator. The
  existing in-memory cache + WebSocket pub/sub stay untouched.
* **STIX 2.1 / MISP / honeytoken / intent summary exports.** Stubs
  only. Real implementations land in their owning stages (Stage 7,
  11, 13).
* **WebSocket push of alerts or health changes.** GET-only in Stage
  3. The existing WebSocket layer in
  [websocket.py](../../src/anglerfish/dashboard/websocket.py) is
  untouched per the operator constraint.
* **History / undo of settings changes.** The audit log is the
  history; a UI for reverting comes later.

## Threat-model delta

The four new endpoint groups widen the dashboard's attack surface.
Each new vector with mitigation:

### State-changing endpoints behind CSRF

* **New threat.** CSRF: a malicious site lures an authenticated
  operator into POSTing to `/api/settings/bridge` with values that
  weaken the honeypot (drop `max_concurrent_requests` to 1 so the
  bridge queues attackers, etc.).
* **Mitigation.** `require_csrf` dependency on every POST. Token
  is the existing synchronizer in [csrf.py](../../src/anglerfish/dashboard/csrf.py),
  bound to the session, supplied via `X-Anglerfish-CSRF` header.
  `GET /api/csrf` is the existing issuance endpoint.
* **Residual risk.** An operator running in open mode (no admin
  password) bypasses CSRF too. Open mode is explicitly opt-in and
  documented as "only safe behind nftables isolation."

### Export endpoints leak captured data

* **New threat.** A compromised operator account exfiltrates the
  full session corpus + audit log.
* **Mitigation.** Both behind `require_auth`. Per-request 7-day
  cap bounds the volume per request. `dashboard.export_served`
  audit event records every export (kind, format, range, item
  count, bytes) so post-compromise analysis can identify what was
  exfiltrated.
* **Residual risk.** A determined attacker can paginate. The audit
  log surfaces the pattern; rate-limiting exports is a follow-up.

### Health endpoints reveal subsystem topology

* **New threat.** Unauthenticated probing of `/api/health/*`
  reveals whether Ollama is reachable, what model is loaded,
  whether Splunk is configured. An attacker on the service NIC
  who somehow got past nftables (or a misconfigured operator)
  gets useful recon.
* **Mitigation.** All health endpoints behind `require_auth`. The
  existing `/api/health` stays unauthenticated for the load
  balancer's liveness probe (it returns nothing operator-sensitive).
* **Residual risk.** Same as the existing `/api/stats` endpoint;
  the auth boundary is the perimeter.

### Audit log access via alerts endpoint

* **New threat.** A malicious operator account uses
  `GET /api/alerts` to enumerate every defense-fired event and
  refine their next attack.
* **Mitigation.** Behind `require_auth`. The audit log is
  append-only (`chattr +a` on supported filesystems); reads cannot
  rewrite. `dashboard.audit_read` (new event) records every alerts
  fetch with cursor + kind filter.
* **Residual risk.** Open-mode bypass (documented).

### Runtime overrides poisoning the dashboard process

* **New threat.** A compromised operator flips every feature flag
  to True, including counter-deception, on a fleet where they're
  contractually-forbidden.
* **Mitigation.** Every flip writes `dashboard.feature_toggled`
  with who, when, old → new. Restart reverts. Operators that need
  hard locks set the env-file values + remove operator login.
* **Residual risk.** Pre-restart window. Operator policy + audit
  log are the controls.

## LLM defense delta

No new LLM call. The dashboard control plane does not call
Ollama. The Stage 1 defense corpus is unchanged.

## Test plan

| Module                  | Tests                                                                                              |
| ----------------------- | -------------------------------------------------------------------------------------------------- |
| `overrides.py`          | RuntimeOverrides construction from settings; mutation visibility; reset semantics                  |
| `routes.py` (new)       | GET /api/settings returns defaults; POST /api/settings/bridge updates + returns new state          |
| `routes.py` (new)       | POST /api/settings/* without CSRF returns 403; with bad CSRF returns 403                            |
| `routes.py` (new)       | POST /api/settings/bridge with out-of-bounds values returns 422                                    |
| `routes.py` (new)       | POST /api/settings/features defaults missing fields to current; flips persist in-process           |
| `health.py`             | /api/health/ollama returns reachable=true when Ollama responds; false on connect refused           |
| `health.py`             | /api/health/forwarder reads fallback queue depth from disk; returns "unknown" with no recent event |
| `health.py`             | /api/health/sessions returns rate-per-minute from audit log; utilisation_pct is correct ratio      |
| `alerts.py`             | /api/alerts paginates audit log; kind filter narrows; cursor resumes; stubs present                |
| `export.py`             | /api/export/sessions JSON shape; CSV streaming + header row; 7-day cap returns 400                  |
| `export.py`             | /api/export/audit JSON entries match the audit log within range; out-of-range entries excluded     |
| Audit                   | dashboard.settings_changed / feature_toggled / export_served audit events fire with right shape   |
| Existing tests          | Every existing dashboard test still passes (the constraint is non-regression)                     |

**Coverage target:** ≥90% on new modules, total project coverage
stays ≥90% per the existing `--cov-fail-under=90` gate.

## Rollback plan

* **Per-commit rollback.** Stage 3 ships as one commit (the four
  panels are tightly coupled in routing / auth / CSRF wiring).
* **Disabling the endpoints at runtime.** No env-var switch; the
  routes are added in `routes.py:build_router`. To disable, revert
  the commit or comment out the relevant `@router.<verb>`
  decorators in a hotfix.
* **State.** Runtime overrides are in-memory only; rollback loses
  no on-disk state.
* **Test rollback.** The Stage 3 tests fail closed if reverted; no
  existing tests gain reliance on the new endpoints.

## Success criteria

* All Stage 3 tests pass.
* Total coverage ≥90% (existing gate).
* Settings endpoint round-trips: `POST /api/settings/bridge` with
  `{"max_concurrent_requests": 16}` then `GET /api/settings` shows
  `16`.
* Settings endpoint enforces CSRF: a POST without
  `X-Anglerfish-CSRF` returns 403 with a clear `detail` field.
* Health endpoints return non-empty JSON on a freshly-booted
  dashboard with no traffic (`reachable: false`, `last_event_at:
  null` etc., not 500s).
* Alerts endpoint paginates: response with `next_cursor` resumes
  cleanly on re-request.
* Export endpoint with `format=csv` returns `Content-Type:
  text/csv` and a streaming body.
* Operator restarts the dashboard; runtime overrides reset to the
  env-file-loaded defaults. `applies_to: "dashboard_process"` is
  always present in the response.
* `docs/ROADMAP.md` Stage 3 row flips to ✅ shipped.

## Notes for future-me

* **Cross-process propagation needs its own design pass.** Stage 6
  (time-wasting) is the first stage that actually needs the bridge
  to honour `wasting_strategy`. The two leading options are a
  small tmpfs JSON file the bridge polls per request (~0.1 ms),
  and a fire-and-forget HTTP push from the dashboard to a new
  bridge endpoint. The tmpfs option is operationally simpler
  (atomic write via rename, no new endpoint to auth). Decide when
  Stage 6 starts.
* **The 7-day export cap is arbitrary.** Picked because a typical
  honeypot session is <30 min and the in-memory store rotates well
  under 7 days of activity. If operators routinely request larger
  windows, lift the cap when the persistent session store (Stage 4)
  lands and exports stream from SQLite.
* **`dashboard.settings_changed` per-field diff.** Audit-log
  consumers should be able to reconstruct the override timeline
  from the audit JSONL alone. Field-level diff (vs whole-snapshot)
  keeps the log size manageable for fleets that flip flags often.
* **Why CSV on sessions, JSON-only on audit.** Sessions are
  tabular - operators pipe them into spreadsheets or SOAR
  pipelines. Audit events have variable shape (different fields
  per `event_type`), so flattening into CSV is lossy. JSON-only
  preserves the schema.
* **Health endpoints poll on read, not push.** A push-based health
  cache (subscribe to a "subsystem changed state" channel) would
  give the SPA real-time updates but is more code than the SPA
  needs. The SPA polls /api/health/* every 30 s; the underlying
  Ollama probe caches for 30 s so we don't hammer it.
* **For Stage 6 (time-wasting) design author.** When you add the
  bridge-side override consumer, the response shape on
  `/api/settings` should NOT change. Add a new `bridge_synced_at`
  field describing when the bridge last picked up the override,
  but keep the existing keys.
* **For Stage 13 (dashboard capability views) design author.** The
  export endpoints from this stage become the JSON / CSV escape
  hatch alongside your STIX / MISP work. Don't duplicate the
  date-range filtering; extend.
