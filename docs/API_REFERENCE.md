# API reference

Anglerfish AI exposes two HTTP services:

| Service       | Default bind                                | Purpose                                          | Auth                |
| ------------- | ------------------------------------------- | ------------------------------------------------ | ------------------- |
| **Bridge**    | `127.0.0.1:8421`                            | Lure command handler                             | `Bearer` token      |
| **Dashboard** | `127.0.0.1:8420`                            | Operator UI, REST queries, live event stream     | Session cookie / Basic |

Both bind to loopback by default. To expose the dashboard on the service
NIC, set `ANGLERFISH_DASHBOARD__HOST` to the interface IP and front it
with a reverse proxy that terminates TLS. The bridge **must** stay on
loopback, its threat model assumes the lure is the only caller.

All request and response bodies are JSON unless noted. Pydantic models are
frozen with `extra="forbid"`: unknown fields are rejected, all timestamps
are ISO-8601 UTC.

The dashboard sends a `Server: Anglerfish-AI/<version>` header. The bridge
adds `X-Anglerfish-Protocol: 2` on every response; clients should send the
same header on every request and treat a mismatch as a fatal version skew.

---

## Bridge API

Internal API the lure calls. Everything except `/api/health`
requires `Authorization: Bearer <secret>`, where the secret is
`ANGLERFISH_BRIDGE__SHARED_SECRET` from the wizard-generated `.env`.

If the secret is unset (development mode only), authentication is
bypassed entirely, every endpoint is open. Production deployments must
set the secret; the wizard generates a 32-byte URL-safe token and writes
it to the env file shared by the bridge daemon and the lure.

### Endpoints

| Method   | Path                                       | Purpose                                  | Auth |
| -------- | ------------------------------------------ | ---------------------------------------- | ---- |
| `GET`    | `/api/health`                              | Liveness + version                       | -    |
| `POST`   | `/api/v1/session`                          | Open a new attacker session              | ✓    |
| `POST`   | `/api/v1/session/{session_id}/command`     | Run one command in an open session       | ✓    |
| `DELETE` | `/api/v1/session/{session_id}`             | End a session and release its state      | ✓    |
| `GET`    | `/api/v1/sessions`                         | List currently-open sessions             | ✓    |

### `GET /api/health`

```json
{ "status": "ok", "version": "0.1.0" }
```

Returns `200` once the bridge has loaded its config and connected to the
Ollama endpoint. Use for `livenessProbe` / `readinessProbe`.

### `POST /api/v1/session`

Request:

```json
{
  "source_ip": "203.0.113.42",
  "username": "root"
}
```

| Field       | Type           | Constraints                |
| ----------- | -------------- | -------------------------- |
| `source_ip` | string         | 1 – 64 chars, attacker IP  |
| `username`  | string         | 1 – 64 chars, attacker login |

Response `200`:

```json
{
  "session_id": "9f9f9b4a-…",
  "fake_hostname": "prod-app-04",
  "fake_username": "root",
  "fake_cwd": "/root"
}
```

The bridge derives a stable but unpredictable hostname per `source_ip` so
the same attacker sees the same shell across reconnects. The `session_id`
is a UUIDv4 used in every subsequent call.

### `POST /api/v1/session/{session_id}/command`

Request:

```json
{ "command": "uname -a" }
```

| Field     | Type   | Constraints           |
| --------- | ------ | --------------------- |
| `command` | string | 1 – 32768 chars       |

The command is length-capped and stripped of C0 control characters before
reaching the prompt template, see [`THREAT_MODEL.md`](THREAT_MODEL.md).

Response `200`:

```json
{
  "text": "Linux prod-app-04 5.10.0-19-cloud-amd64 #1 SMP Debian 5.10.149-1 …",
  "source": "ai",
  "latency_ms": 412.7,
  "cwd": "/root"
}
```

| Field        | Type             | Meaning                                                   |
| ------------ | ---------------- | --------------------------------------------------------- |
| `text`       | string           | What the attacker sees on their terminal                  |
| `source`     | enum             | `ai` (LLM), `fallback` (scripted), `rejected` (no reply)  |
| `latency_ms` | number           | Wall-clock time to produce the response                   |
| `cwd`        | string           | Working-directory the session thinks it's in              |

When `source = "fallback"` the LLM call failed or rate-limited and a
scripted response was substituted. When `source = "rejected"` the LLM
failed *and* fallbacks were disabled, the attacker receives an empty
reply. Either way the response always returns 200; the operator
distinguishes the cases via `source` and via the threat engine's
notes field, not via HTTP status.

Errors:

- `404` - `session_id` is unknown or already ended
- `422` - request body fails Pydantic validation

### `DELETE /api/v1/session/{session_id}`

Response `204 No Content`. Idempotent, deleting an already-ended session
also returns 204.

### `GET /api/v1/sessions`

```json
[
  { "session_id": "9f9f9b4a-…", "source_ip": "203.0.113.42", "cwd": "/root" }
]
```

Returns only sessions currently in memory. Closed sessions are not
returned; use the dashboard `/api/sessions` for the audit-log view.

### Rate limiting

The bridge enforces two layers, both configured under the
`ANGLERFISH_RATE_LIMIT__*` env-var section:

1. **Global concurrency cap**, `ANGLERFISH_RATE_LIMIT__MAX_CONCURRENT_REQUESTS`
   (default `8`). Requests beyond the cap wait in a queue up to
   `ANGLERFISH_RATE_LIMIT__QUEUE_TIMEOUT_S` (default `10.0`); a timeout
   returns a `fallback` response, never a 503.
2. **Per-session token bucket** -
   `ANGLERFISH_RATE_LIMIT__REQUESTS_PER_SESSION_PER_MINUTE` (default
   `30`) with burst `ANGLERFISH_RATE_LIMIT__SESSION_BURST` (default
   `10`). Excess commands in the same session return a `fallback`
   response. Idle buckets are evicted after
   `ANGLERFISH_RATE_LIMIT__BUCKET_IDLE_EVICTION_S` seconds (default
   `300`) to keep memory bounded.

Either limiter fires *transparently*, the attacker always receives a
plausible response so the limiter cannot be used as a probe. Operators
see the fallback rate climb via `/api/stats` on the dashboard.

### Example: drive a session end-to-end

```bash
SECRET="$(grep ANGLERFISH_BRIDGE__SHARED_SECRET .env | cut -d= -f2)"
BASE="http://127.0.0.1:8421"

SID=$(curl -fsS -X POST "$BASE/api/v1/session" \
  -H "Authorization: Bearer $SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"source_ip":"203.0.113.42","username":"root"}' \
  | jq -r .session_id)

curl -fsS -X POST "$BASE/api/v1/session/$SID/command" \
  -H "Authorization: Bearer $SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"command":"ls -la"}'

curl -fsS -X DELETE "$BASE/api/v1/session/$SID" \
  -H "Authorization: Bearer $SECRET"
```

---

## Dashboard API

The dashboard serves both the operator SPA (`GET /`) and a REST + WebSocket
API used by that SPA and by external integrations (SIEM dashboards,
SOAR, custom tooling).

### Authentication

Three modes, checked in this order:

1. **Session cookie** (`anglerfish_session`); set on `POST /api/login`.
   `HttpOnly`, `SameSite=Strict`, `max_age=86400` (24h), signed with
   `ANGLERFISH_DASHBOARD__SESSION_SECRET`. The browser SPA uses this.
2. **HTTP Basic**, `Authorization: Basic <base64(user:password)>`.
   Validated against the bcrypt hash in
   `ANGLERFISH_DASHBOARD__ADMIN_PASSWORD_HASH`. The username is
   `ANGLERFISH_DASHBOARD__ADMIN_USERNAME` (default `admin`). Use this
   for non-browser clients.
3. **Open mode**: if `ADMIN_PASSWORD_HASH` is unset, all auth checks
   are bypassed. Only safe when nftables fully isolates the service NIC
   - see [`THREAT_MODEL.md`](THREAT_MODEL.md).

Unauthenticated requests to protected endpoints return `401` with
`WWW-Authenticate: Basic realm=anglerfish`.

### CSRF

All state-changing requests (any `POST`, `PUT`, `DELETE` except `/api/login`,
`/api/logout`, `/api/health`) require:

```
X-Anglerfish-CSRF: <token>
```

Fetch the token first:

```bash
curl -fsS -b cookies.txt -c cookies.txt 'http://dashboard:8420/api/csrf'
# {"token":"…"}
```

The token is bound to the session cookie and signed with the session
secret. Missing or invalid → `403 Forbidden`. Tokens do not expire on
their own; they expire when the session cookie does.

### Endpoints

| Method | Path                          | Auth | CSRF | Purpose                                    |
| ------ | ----------------------------- | ---- | ---- | ------------------------------------------ |
| `GET`  | `/`                           | -    | -    | Operator SPA (HTML)                        |
| `GET`  | `/api/health`                 | -    | -    | Liveness + version                         |
| `POST` | `/api/login`                  | -    | -    | Establish a session                        |
| `POST` | `/api/logout`                 | ✓    | -    | Clear the session                          |
| `GET`  | `/api/csrf`                   | ✓    | -    | Mint a CSRF token for the current session  |
| `GET`  | `/api/stats`                  | ✓    | -    | Top-line counters                          |
| `GET`  | `/api/sessions`               | ✓    | -    | All sessions, newest first                 |
| `GET`  | `/api/sessions/{session_id}`  | ✓    | -    | One session and its full command history   |
| `GET`  | `/api/commands`               | ✓    | -    | Recent commands across all sessions        |
| `GET`  | `/api/threats`                | ✓    | -    | Recent threat assessments                  |
| `GET`  | `/api/credentials`            | ✓    | -    | Decrypted credential records (paginated)   |
| `GET`  | `/api/credentials/stats`      | ✓    | -    | Credential-table aggregates                |

### `POST /api/login`

```json
{ "username": "operator", "password": "…" }
```

Response `200` sets the session cookie:

```json
{ "status": "ok" }
```

Failures:

- `401` - bad username or password
- `429` - too many failed attempts from this IP (see Rate limiting below);
  response includes `Retry-After: <seconds>`

### `POST /api/logout`

Clears the session cookie. `200 {"status": "ok"}`. Idempotent.

### `GET /api/stats`

```json
{
  "active_sessions": 3,
  "total_commands_observed": 18412,
  "total_threat_assessments": 612,
  "high_severity_count": 47,
  "persistence_attempt_count": 9
}
```

Counters are in-memory and reset on dashboard restart. Use the
SessionStore SQLite file for durable history.

### `GET /api/sessions`

```json
[
  {
    "session_id": "9f9f9b4a-…",
    "source_ip": "203.0.113.42",
    "username": "root",
    "fake_hostname": "prod-app-04",
    "fake_username": "root",
    "fake_cwd": "/root",
    "started_at": "2026-05-23T14:02:11Z",
    "last_activity_at": "2026-05-23T14:03:48Z",
    "turns": [
      {
        "command": "uname -a",
        "response": "Linux prod-app-04 …",
        "source": "ai",
        "timestamp": "2026-05-23T14:02:14Z",
        "latency_ms": 412.7
      }
    ]
  }
]
```

Sorted by `last_activity_at` descending. Returns every session held in
the in-memory ring buffer. Older sessions age out as new ones arrive;
query the SessionStore SQLite file for historical data.

### `GET /api/sessions/{session_id}`

Same shape as one element of `/api/sessions`. `404` if the session is not
in the ring buffer (older sessions are evicted; query the SessionStore
SQLite file for historical data).

### `GET /api/commands`

| Query param | Type | Default | Range  |
| ----------- | ---- | ------- | ------ |
| `limit`     | int  | 100     | 1–1000 |

```json
[
  {
    "session_id": "9f9f9b4a-…",
    "command": "uname -a",
    "response": "Linux prod-app-04 …",
    "source": "ai",
    "timestamp": "2026-05-23T14:02:14Z",
    "latency_ms": 412.7
  }
]
```

### `GET /api/threats`

| Query param | Type | Default | Range  |
| ----------- | ---- | ------- | ------ |
| `limit`     | int  | 50      | 1–500  |

```json
[
  {
    "session_id": "9f9f9b4a-…",
    "score": 78,
    "techniques": [
      { "id": "T1059.004", "name": "Unix Shell", "weight": 5 },
      { "id": "T1136",     "name": "Create Account", "weight": 20 }
    ],
    "persistence_attempted": true,
    "high_severity": true,
    "notes": "useradd + chmod + crontab edit within 30s"
  }
]
```

`score` is 0–100. `high_severity = score >= 60`. `persistence_attempted`
is true when the session touched any technique tagged as a persistence
mechanism, see [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) §threat-engine.

### `GET /api/credentials`

| Query param | Type   | Default | Range / format     |
| ----------- | ------ | ------- | ------------------ |
| `limit`     | int    | 100     | 1–1000             |
| `offset`    | int    | 0       | 0–100000           |
| `source_ip` | string | -       | exact match, ≤64ch |

```json
{
  "records": [
    {
      "source_ip": "203.0.113.42",
      "username": "root",
      "password": "hunter2",
      "first_seen": "2026-05-21T08:14:02Z",
      "last_seen": "2026-05-23T14:02:11Z",
      "attempt_count": 47
    }
  ],
  "configured": true
}
```

`configured: false` means the credentials subsystem is not initialised
(`ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY` unset); `records` will be empty.
Credentials are decrypted server-side and sent over TLS, never exposed
in plaintext on disk outside the encrypted SQLite database.

### `GET /api/credentials/stats`

```json
{
  "total_attempts": 4128,
  "unique_combinations": 612,
  "unique_usernames": 84,
  "unique_passwords": 1041,
  "unique_source_ips": 178,
  "configured": true
}
```

Aggregates are computed from HMAC fingerprints, not the plaintext -
unique counts work without decrypting every row.

### Rate limiting

- **Login attempts** - per-IP token bucket, capacity 5, refill 1 token
  every 12 seconds (≈5/min). Exceeded → `429 Retry-After: <seconds>`.
  A successful login clears the bucket for that IP.
- **All other endpoints** - no per-endpoint limit. Protect with a reverse
  proxy (nginx `limit_req`, Caddy `rate_limit`) if you expose the dashboard
  outside the service NIC.

---

## WebSocket: live event stream

```
ws://dashboard:8420/ws/events
```

Read-only push channel for everything the operator SPA shows live -
sessions, commands, threat assessments. Same data as the REST endpoints
above but streamed.

The route is mounted only when `ANGLERFISH_DASHBOARD__ENABLE_WEBSOCKETS`
is `true` (the default). Set it to `false` for deployments that prefer
polling `/api/stats` + `/api/commands` over a long-lived connection.

### Handshake

The upgrade request must satisfy three guards in order:

1. **Origin**: the `Origin` header must match the dashboard's own
   `host:port`, or be in `ANGLERFISH_DASHBOARD__ALLOWED_ORIGINS`
   (comma-separated). Missing or non-matching → close code `4403`.
2. **Authentication**: the connection inherits the HTTP session, so the
   browser must already have a valid `anglerfish_session` cookie (or
   open-mode must be active). Failed → close code `4401`.
3. **State**: the dashboard's in-memory state must be initialised. If
   the dashboard has just started and is still loading, the close code
   is `1011`.

There is no client-side authentication message, the cookie does the work.

### Server → client messages

```json
{
  "kind":      "command",
  "timestamp": "2026-05-23T14:02:14Z",
  "payload":   { /* shape depends on kind */ }
}
```

| `kind`             | `payload` shape                              | When emitted                              |
| ------------------ | -------------------------------------------- | ----------------------------------------- |
| `ping`             | `{}`                                         | Every 25s, even when idle                 |
| `session_started`  | `SessionSnapshot` (see `/api/sessions`)      | New attacker session                      |
| `session_updated`  | `SessionSnapshot`                            | Session state changed (e.g. new command)  |
| `session_ended`    | `SessionSnapshot`                            | Attacker disconnected / bridge DELETEd it |
| `command`          | `{session_id, command, response, source, latency_ms}` | One command executed              |
| `threat`           | `ThreatAssessment` (see `/api/threats`)      | Threat engine scored a session            |

Treat `ping` as a keep-alive only, no payload, no need to ack. If you
don't see one for >60s, the connection is dead; reconnect.

### Client → server messages

None. The dashboard does not accept WebSocket messages from clients -
all writes go via the REST API. Any frame the client sends is silently
discarded.

### Subscription semantics

Each connected client has its own queue (default size 256). If your
client falls behind, **old events are dropped** to keep the queue from
growing without bound. Use `/api/commands` or query the SessionStore
SQLite file for guaranteed delivery, the WebSocket is best-effort.

### Close codes

| Code   | Meaning                                                  |
| ------ | -------------------------------------------------------- |
| `1000` | Normal close (client disconnected)                       |
| `1011` | Internal server error / state not ready                  |
| `4401` | Authentication failed (not logged in)                    |
| `4403` | Origin not in allow-list                                 |

### Example: tail the event stream from Python

```python
import asyncio, json
import httpx, websockets

DASHBOARD = "http://dashboard:8420"
WS = "ws://dashboard:8420/ws/events"

async def main():
    async with httpx.AsyncClient(base_url=DASHBOARD) as http:
        await http.post("/api/login", json={"username": "operator", "password": "…"})
        cookie = http.cookies.get("anglerfish_session")

    async with websockets.connect(WS, additional_headers={
        "Origin": DASHBOARD,
        "Cookie": f"anglerfish_session={cookie}",
    }) as ws:
        async for raw in ws:
            ev = json.loads(raw)
            if ev["kind"] == "threat" and ev["payload"]["high_severity"]:
                print("ALERT:", ev["payload"])

asyncio.run(main())
```

---

## Integration recipes

### Pull recent threats for ingestion elsewhere

The REST API is for *pulling* historical data. Tail it from a script
and ship the result wherever your existing alert or SIEM pipeline
lives:

```bash
curl -fsS -u "operator:$PASSWORD" \
  'http://dashboard:8420/api/threats?limit=500' \
  | jq -c '.[]' \
  > threats.ndjson
```

### Notify Slack on high-severity threats

The threat engine has a webhook alerter built in
(`ANGLERFISH_THREAT__ALERT_WEBHOOK_URL`). If you'd rather build it
yourself, tail the WebSocket, see the Python example above.

### Health-check both services from a load balancer

```bash
# Bridge
curl -fsS http://127.0.0.1:8421/api/health

# Dashboard
curl -fsS http://dashboard:8420/api/health
```

Both return `{"status":"ok","version":"…"}` with HTTP 200 once the
service has finished its startup checks.

---

## Versioning

API endpoints are versioned in the path (`/api/v1/…`). Breaking changes
to existing v1 endpoints will not happen, new fields may be added to
response bodies (clients should ignore unknown fields), new endpoints
may be added under `/api/v1/…`, and new versions under `/api/v2/…` will
ship alongside `/api/v1/…` for at least one minor release before v1
removal.

The `X-Anglerfish-Protocol` header (currently `2`) tracks the
*wire-level* protocol between bridge and lure. If you write a custom
client and the bridge starts returning a higher
`X-Anglerfish-Protocol` value, treat your client as out of date and
fail closed.
