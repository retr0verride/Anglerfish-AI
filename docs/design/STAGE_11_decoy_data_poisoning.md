# Stage 11 - Decoy data poisoning

## Problem

Attackers who land on a Linux honeypot reliably exfiltrate the
same handful of files: ``/root/.aws/credentials``,
``~/.ssh/id_rsa``, ``~/.bash_history``, ``/var/lib/postgresql/...``
DSNs, the contents of ``~/.npmrc`` and ``~/.docker/config.json``.
Stage 9's persona overlay (per
[STAGE_9_adaptive_persona.md](STAGE_9_adaptive_persona.md))
lets operators put plausible static content at those paths; Stage
10's engaged persistence (per
[STAGE_10_engaged_persistence.md](STAGE_10_engaged_persistence.md))
reflects installed backdoors at the attacker. Neither helps after
the attacker disconnects with the file contents in hand.

Stage 11 puts traceable beacons in those files. AWS access keys
that look real (``AKIA`` prefix + 16 random chars + 40-char
secret) but whose access-key-ID encodes a registry lookup. SSH
keypairs whose comment field holds a registry UUID. When the
attacker tries the AWS key (typically via ``aws s3 ls`` against a
sinkhole region) or pastes the SSH public key into Shodan, the
callback receiver records the hit and the operator gets the
long-tail signal: "we caught the same actor reusing our token six
weeks later."

The deliverable list in the roadmap entry
([ROADMAP.md:319-337](../ROADMAP.md#L319-L337)):

* Honeytoken generator (AWS keys, SSH keys, DB connection
  strings, API tokens). Each generated with a registered
  identifier.
* Honeytoken registry in the session store.
* Callback receivers correlate hits back to the source session.
* Legal/ethical doc ``docs/HONEYTOKENS.md`` operators must
  acknowledge.
* Operator opt-in flag (Stage 3 features endpoint).
* Stage 3 alerts panel switches ``honeytoken_callback_hits`` from
  ``available:false`` to live.

Stage 3 reserved the alerts-panel stub at
[alerts.py:56](../../src/anglerfish/dashboard/alerts.py#L56)
(``{"available": False, "stage": 11}``). Stage 11 flips it.

This is the second highest-risk stage on the roadmap, behind only
Stage 12 (active counter-deception). We are now distributing
tracking beacons that an honest visitor could accidentally
trigger if they exfiltrate a file from a misconfigured
honeypot they think is a real host. The threat-model delta and
the HONEYTOKENS.md doc both treat this as the load-bearing
responsibility.

## Proposed interface

### Honeytoken schema + generator

```text
src/anglerfish/honeytokens/
    __init__.py
    schema.py         # Honeytoken pydantic model
    generators.py     # AWS + SSH generators
    registry.py       # SessionStore CRUD
    placement.py      # bridge-side placement logic
```

```python
class Honeytoken(BaseModel):
    """One generated honeytoken + provenance + callback URL."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    kind: Literal["aws", "ssh_key"]
    payload: str = Field(min_length=1, max_length=8192)
    callback_url: str = Field(min_length=1, max_length=512)
    placed_at: str = Field(min_length=1, max_length=4096)
    source_ip: str | None  # None on static base tokens
    session_id: UUID | None  # None on static base tokens
    created_at: datetime


class HoneytokenGenerator:
    def __init__(
        self,
        *,
        callback_base_url: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None: ...

    def generate_aws(
        self,
        *,
        source_ip: str | None,
        session_id: UUID | None,
        placed_at: str = "/root/.aws/credentials",
    ) -> Honeytoken: ...

    def generate_ssh(
        self,
        *,
        source_ip: str | None,
        session_id: UUID | None,
        placed_at: str = "/root/.ssh/id_rsa",
    ) -> Honeytoken: ...
```

The AWS generator produces a string of the form:

```ini
[default]
aws_access_key_id = AKIA<16-char-id>
aws_secret_access_key = <40-char-base64>
region = us-east-1
```

The ``<16-char-id>`` is a base32-encoded slice of the
honeytoken's UUID; the operator's callback receiver decodes it
back to the registry id on hit. The 40-char secret is
crypto-random padding; AWS API failures use the access-key-ID
shape for routing, so the secret value never needs to round-
trip.

The SSH generator runs ``cryptography``'s Ed25519 keypair gen
(already a runtime dep since Stage 1) and writes:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
<base64>
-----END OPENSSH PRIVATE KEY-----
```

The public key comment field carries ``honeytoken-<uuid>`` so
an operator who finds the key in a paste site or Shodan dump
can grep for it.

### Registry (schema v6)

```sql
CREATE TABLE honeytokens (
    id            TEXT PRIMARY KEY,           -- the UUID
    kind          TEXT NOT NULL,               -- 'aws' | 'ssh_key'
    payload       TEXT NOT NULL,
    callback_url  TEXT NOT NULL,
    placed_at     TEXT NOT NULL,               -- fakefs path
    source_ip     TEXT,                        -- NULL on static base
    session_id    TEXT,                        -- NULL on static base
    created_at    TEXT NOT NULL
);

CREATE INDEX idx_honeytokens_source_ip ON honeytokens(source_ip);
CREATE INDEX idx_honeytokens_kind      ON honeytokens(kind);
```

No FK to sessions: honeytokens outlive the session that
generated them (a callback can land months later). No UNIQUE
constraint on ``id`` beyond the PK; replay-via-audit-log uses
the PK to dedup.

``SessionStore`` gains:

- ``register_honeytoken(token)`` — INSERT OR IGNORE on the PK.
- ``get_honeytoken(id) -> Honeytoken | None`` — used by the
  callback receiver to look up hits.
- ``list_honeytokens_for_source_ip(source_ip) -> list[Honeytoken]``
  — used by the bridge at session-open + the dashboard
  registry view.

``SessionStoreReader`` gets the read-only equivalents the
bridge uses.

### Placement: static base + threat-gated per-session

Two tiers:

1. **Static base**: at bridge startup, the placement service
   ensures a small set of operator-defined static honeytokens
   exist in the registry (source_ip + session_id both NULL).
   These render in every persona's fakefs overlay so every
   attacker sees them. Cheap; one-time bootstrap; the
   registry ID identifies the operator's install but not the
   specific session.

2. **Per-session unique**: when the threat scorer records a
   ThreatAssessment with score above
   ``settings.honeytokens.placement_threshold`` (default 50),
   the placement service generates fresh AWS + SSH tokens
   for the source IP, registers them, and they ship in the
   NEXT session's ``SessionStartResponse.fakefs_overlay``
   payload from this source IP. This is the Stage-9 + Stage-10
   cross-session pattern reused.

   The current session does NOT see the fresh tokens (the
   lure overlay was set at session-open). This is the same
   v1 simplification Stage 10 took — mid-session overlay
   updates land in Stage 13.

### Bridge integration

- ``AIBridgeService.__init__`` accepts an optional
  ``honeytoken_placement: HoneytokenPlacementService``.
- ``record_threat_assessment(session_id, threat)`` (the
  existing Stage 1.5 hook) gains a side effect: when
  ``threat.score >= settings.honeytokens.placement_threshold``,
  it spawns a fire-and-forget task that:
  - Calls ``HoneytokenGenerator.generate_aws`` + ``generate_ssh``
    for the source IP.
  - Calls ``SessionStore.register_honeytoken`` for each.
  - Audits ``bridge.honeytoken_placed`` per token (kind,
    placed_at, id, source_ip, session_id, callback_url).
- The next ``SessionStartResponse`` for this source IP merges
  the registered tokens into the existing ``fakefs_overlay``
  (the same Stage 9 + Stage 10 dict). The lure serves the
  payload content via its native ``cat`` handler.

### Callback receiver (new bundled service)

A separate FastAPI app the operator deploys on a publicly
reachable URL:

```text
src/anglerfish/callback/
    __init__.py
    app.py         # FastAPI factory
    routes.py      # GET /cb/{token_id} + GET /health
```

```python
def create_callback_app(
    settings: AnglerfishSettings,
    *,
    store_reader: SessionStoreReader,
    audit: AuditLog,
) -> FastAPI: ...
```

Endpoint shape:

- ``GET /cb/{token_id}``: look up ``token_id`` in the
  registry. On hit, audit ``bridge.honeytoken_callback`` with
  the request's source IP, the registered source_ip /
  session_id, the User-Agent, and the request path the
  attacker hit; return ``403 Forbidden`` with an
  AWS-style XML error body so an attacker running ``aws
  s3 ls`` sees a plausible "invalid credentials" response.
  On miss, return the same 403 (no information leak about
  which token IDs exist).
- ``GET /health``: 200 ``{"status": "ok"}`` for load-balancer
  / monitoring probes.

The callback receiver runs as a separate Anglerfish CLI
subcommand: ``anglerfish callback serve --host 0.0.0.0
--port 443``. Operators front it with a reverse proxy (the
hostname embedded in callback URLs is whatever they
configured at install).

Process topology:

- Bridge on loopback (existing).
- Dashboard on loopback or operator-bound (existing).
- Callback receiver on a publicly-reachable host (new).

All three read the same SQLite ``sessions.db`` via
``SessionStoreReader``. The callback receiver writes nothing
to the DB; it writes to its own ``AuditLog`` which the
operator ships back via the existing audit-tailer mechanism
(syslog forwarder, rsync, Splunk — operator's choice). v1
does not attempt real-time correlation back to the bridge.

### Dashboard surface

Two new auth-gated routes:

- ``GET /api/honeytokens/state?source_ip=<ip>``: list registry
  rows for this source IP, oldest first. Mirrors the slice
  10.4 ``GET /api/persistence/state`` shape.
- ``GET /api/honeytokens/callbacks?since=<iso>``: list
  recent callback hits from the audit log, newest first.
  This is the operator-facing "did anything happen lately?"
  view.

The alerts panel:

- ``_ALERT_EVENT_TYPES`` gains
  ``bridge.honeytoken_callback -> honeytoken_callback_hit``.
- ``ALERT_STUBS`` drops ``honeytoken_callback_hits`` (the
  Stage 3-reserved stub flipped live).
- ``_summarise_honeytoken_callback`` renderer emits
  operator-readable lines like ``aws callback from
  198.51.100.42 to /cb/<uuid>`` or ``ssh-key callback hit
  from 203.0.113.7``.

### Config

```python
class HoneytokensConfig(BaseModel):
    enabled: bool = False
    callback_base_url: HttpUrl | None = None    # required if enabled
    placement_threshold: int = Field(default=50, ge=0, le=100)
    static_base_paths: tuple[str, ...] = (
        "/root/.aws/credentials",
        "/root/.ssh/id_rsa",
    )
```

``HoneytokenConfig.enabled=True`` without
``callback_base_url`` set raises a config-load
``ValidationError`` so the bridge never starts with
tokens that point at nothing.

### Wizard prompt

The first-boot wizard adds a new step (per the locked
decision):

```
Stage 11 — Decoy data poisoning is OFF by default. Enabling it
means Anglerfish will distribute traceable AWS access keys + SSH
keypairs in the fake filesystem. An honest visitor who exfiltrates
files from this host could accidentally trigger callbacks from
their own machine. You MUST read docs/HONEYTOKENS.md before
enabling. Have you read HONEYTOKENS.md? [y/N]:
```

On y, the wizard then prompts for ``callback_base_url`` and
writes ``ANGLERFISH_HONEYTOKENS__ENABLED=true`` +
``ANGLERFISH_HONEYTOKENS__CALLBACK_BASE_URL=<url>`` to the
env file.

The Stage 3 ``POST /api/settings/features`` endpoint also
gates: the operator can flip honeytokens on/off at runtime,
but the flip is audited as
``dashboard.settings_changed`` with ``section=honeytokens``.

### Audit events

- ``bridge.honeytoken_placed`` (per token registration):
  ``token_id``, ``kind``, ``placed_at``, ``source_ip``,
  ``session_id``, ``callback_url``.
- ``bridge.honeytoken_callback`` (per callback hit, emitted
  by the callback receiver): ``token_id``,
  ``registered_source_ip``, ``registered_session_id``,
  ``callback_source_ip`` (the IP that triggered the
  callback — usually the attacker's exfil node),
  ``user_agent``, ``request_path``.
- ``dashboard.settings_changed`` already covers the
  runtime opt-in flip.

## Out of scope

- **DB connection strings + generic API tokens.** Roadmap
  items deferred to v1.1. AWS + SSH carry the highest
  signal-to-noise; the registry + callback shapes for the
  other two land cleanly once the bridge integration ships.
- **DNS sinkhole receivers.** A future stage could add
  authoritative-DNS callbacks (the operator points a domain's
  NS at Anglerfish + we record every lookup for
  ``<token>.honey.example.com``). Out for v1; the HTTP path
  is enough.
- **Real-time callback-to-bridge correlation.** The callback
  receiver writes its own audit log; the operator ships it
  back. A future stage could add an authenticated
  bridge-to-receiver gossip channel; v1's correlation is by
  ``token_id`` lookup in the registry.
- **Per-persona honeytoken policies.** All personas serve
  the same static-base + threat-gated per-session shape in
  v1. A future ``policy`` field on ``Persona`` could let
  ad-joined-workstation include kerberos.keytab tokens, etc.
- **Mid-session token rotation.** Tokens generated mid-
  session (above the threshold) become visible on the NEXT
  session from the same source IP. Same v1 simplification
  Stage 10 took for engaged persistence; lifted in Stage 13
  when the protocol bump for overlay deltas lands.
- **Token revocation.** Once registered, a token stays in the
  registry forever (callbacks remain trackable). Operators
  who want a token to stop firing rotate by writing a new
  one + deleting the old via SQL. A dashboard DELETE
  endpoint is a Stage-11-follow-up admin tool, not v1.
- **Counter-deception around honeytokens.** Stage 12 owns
  garbled-binary / time-bomb strategies that could ride on
  the honeytoken trigger. Stage 11 just generates +
  tracks; Stage 12 acts on the signal.

## Threat-model delta

This is the biggest threat-model delta on the roadmap. Five
new STRIDE rows land in ``THREAT_MODEL.md`` under a new
"Decoy data poisoning" section.

| Threat | Mitigation | Residual risk |
|---|---|---|
| **Honest visitor exfiltrates a file from a misconfigured honeypot, the callback fires from their machine, operator misreads as malicious actor** | ``honeytokens.enabled`` defaults to False. Wizard explicitly requires the operator to confirm they read ``docs/HONEYTOKENS.md`` (which explains exactly this risk) before enabling. The callback audit event carries User-Agent + the callback source IP so operators can distinguish ``aws-cli/2.x`` (likely attacker tool) from ``curl/7.x manually pasted`` (likely researcher). | No technical means distinguishes "real attacker" from "researcher who exfiltrated a file from a bait NIC they thought was real". Operators are responsible for deployment context (bait NICs, internet-facing only). HONEYTOKENS.md is the load-bearing doc. |
| **Attacker recognises the AKIA prefix as a CanaryToken-style honeypot** | Tokens are generated with random 16-char IDs that look syntactically valid; the operator's callback URL is operator-chosen (not ``canarytokens.org``). An attacker who knows about the canary-token pattern can identify the bait IS a honeytoken; but they still leak the source-IP correlation when they probe the callback URL to confirm. | Determined attackers DO recognise the pattern + avoid touching the file. Documented residual; the value is the long-tail less-careful actors. |
| **An attacker controls the network path between the callback receiver and the operator** | The callback receiver TLS-terminates (operator's reverse proxy responsibility); the audit log writes locally; the ship-back to the main Anglerfish instance uses whatever audit-log forwarding the operator already runs (Splunk forwarder, rsync over SSH, etc.). | Operators who run the callback receiver over plaintext HTTP leak callback hits to network observers. Documented in HONEYTOKENS.md; the wizard prompts for an ``https://`` URL only. |
| **Registry growth unbounded** | Per-session tokens are gated by the threat-scorer threshold (default 50). At a 10k-attacker fleet over a year, expect O(10k) registry rows total (one per high-confidence session); each row is < 10 KB. Operators monitor row count via SQL in v1; a future admin tool adds bulk-cleanup. | A long-running honeypot accumulates honeytokens. Estimated <100 MB at a year of moderate traffic. Acceptable. |
| **Callback receiver is itself a service the attacker can attack** | Callback receiver is a minimal FastAPI app with one GET endpoint + a health check. No persistent state; no authentication surface; bounded request rate via the operator's reverse proxy. The receiver process runs as an unprivileged systemd-managed user with the same sandboxing primitives as the bridge unit. | A 0-day in FastAPI / asyncio / Python's HTTP stack could land remote code execution on the receiver host. Operators run the receiver on a host with no other sensitive workload; isolated bait infrastructure. |

## LLM defense delta

**No new LLM calls.** Stage 11 is non-LLM end-to-end:

- Honeytoken generation: pure crypto + format generation.
- Callback receiver: pure HTTP routing + registry lookup.
- Bridge integration: piggybacks on Stage 1.5
  ``record_threat_assessment`` (synchronous regex-based
  scoring, no LLM).

Therefore no ``tests/llm_defense/`` corpus entry. The
threat-model delta above covers the entire new attack
surface.

## Test plan

1. **Unit**, ``tests/honeytokens/test_generators.py`` (~8):
   AWS access-key format matches the ``AKIA[A-Z0-9]{16}``
   shape; AWS secret is 40 chars; access-key-ID round-trips
   to the registry UUID; SSH keypair generated; ED25519 by
   default; comment field carries ``honeytoken-<uuid>``;
   placed_at + callback_url propagate; source_ip + session_id
   pass through (None for static base).
2. **Unit**, ``tests/honeytokens/test_registry.py`` (~6):
   register + get round-trip; INSERT OR IGNORE on duplicate
   id; list_by_source_ip filters + orders oldest-first;
   static base tokens (NULL source_ip) returned for any IP
   lookup; SessionStoreReader read-only equivalent.
3. **Schema**, ``tests/sessions/test_honeytokens_persistence.py``
   (~5): v6 migration creates the table + indexes;
   register + get round-trips through the writer; cascade-
   FREE delete (deleting a session does NOT remove its
   honeytokens); placed_at + callback_url survive round-
   trip.
4. **Integration**, ``tests/bridge/test_honeytoken_integration.py``
   (~6): record_threat_assessment above threshold triggers
   per-session token generation + registration + audit;
   below threshold is a no-op; honeytokens.enabled=False
   disables the entire path; SessionStartResponse merges
   prior-session tokens into fakefs_overlay; placement
   service handles classifier-error shapes gracefully (does
   not raise into the threat-engine call site).
5. **Callback receiver**, ``tests/callback/test_app.py`` (~5):
   GET /cb/<unknown> returns 403 AWS-style XML; GET
   /cb/<known> returns 403 AND audits with the right fields;
   GET /health returns 200; missing token_id path component
   returns 404; oversized token_id (>256 chars) returns 400.
6. **Dashboard**, ``tests/dashboard/test_honeytokens_endpoint.py``
   (~4): /api/honeytokens/state returns rows sorted oldest-
   first + filters by source_ip; /api/honeytokens/callbacks
   returns recent hits; alerts panel surfaces
   honeytoken_callback events.
7. **Tailer**, ``tests/dashboard/test_audit_tailer.py``
   (extension, ~3): bridge.honeytoken_placed event
   recognised; bridge.honeytoken_callback audit-log line
   from the callback receiver is parsed correctly when
   replayed into the main audit log; malformed payload
   skipped with warning.
8. **Wizard**, ``tests/wizard/test_honeytokens_prompt.py``
   (~3): wizard prompts for HONEYTOKENS.md acknowledgement;
   No-answer leaves enabled=False; Yes-answer requires
   callback_base_url + writes both env-vars to the env file.

**Coverage target**: 90 % across the new modules. The
callback receiver is small (~50 lines) so coverage there is
trivially 100 %.

## Rollback plan

1. **Per-environment switch.** Set
   ``ANGLERFISH_HONEYTOKENS__ENABLED=false`` (env var or via
   POST /api/settings/features). New per-session tokens
   stop generating; existing registry rows stay so callback
   receivers continue to log hits on tokens already in the
   wild (this is the safer posture — turning off
   ``enabled`` should NOT silently mute the receivers, only
   stop NEW poisoning).
2. **Receiver shutdown.** ``systemctl stop
   anglerfish-callback.service`` removes the public
   endpoint. Tokens in the wild stop firing visibly; the
   operator's bait domain returns whatever the fallback
   reverse-proxy serves (likely a generic 404).
3. **Schema rollback.** Drop the ``honeytokens`` table.
   Forward-only migration policy; operators restore from a
   pre-Stage-11 backup. Token IDs leaked in the wild become
   permanently un-correlatable.
4. **Code rollback.** Revert the slice commits. The
   ``honeytokens`` + ``callback`` packages are isolated; the
   bridge's ``record_threat_assessment`` hook short-
   circuits when no placement service is wired.

## Success criteria

- All tests pass; coverage stays >= 90 %.
- ``anglerfish config show`` reveals
  ``honeytokens.enabled``, ``honeytokens.callback_base_url``,
  ``honeytokens.placement_threshold``,
  ``honeytokens.static_base_paths``.
- A session with score >= placement_threshold triggers
  ``bridge.honeytoken_placed`` audit events for both AWS
  and SSH tokens.
- The next session from the same source IP sees the
  tokens in ``cat /root/.aws/credentials`` /
  ``cat /root/.ssh/id_rsa`` (lure-served, via the same
  Stage 9/10 fakefs_overlay shipping mechanism).
- ``GET /cb/<token_id>`` against the callback receiver
  returns a 403 with AWS-style XML body and audits
  ``bridge.honeytoken_callback``.
- The alerts panel surfaces ``honeytoken_callback_hit``
  events with the registered source_ip + the callback
  source_ip both visible.
- ``honeytoken_callback_hits`` is no longer in
  ``ALERT_STUBS``.
- ``docs/HONEYTOKENS.md`` exists and is referenced by the
  wizard prompt.

## Decisions (locked during operator review)

1. **Token types: AWS keys + SSH keys.** Most universally
   tracked formats; covers the two highest-value targets
   attackers exfiltrate. DB strings + API tokens defer to
   v1.1.
2. **Callback receiver: bundled FastAPI app.** Anglerfish
   ships ``anglerfish callback serve``; the operator
   deploys on a public URL behind their own reverse proxy.
   External services (canarytokens.org, Thinkst) are not
   used; the design preserves the project's self-contained
   posture.
3. **Placement: static base + per-session unique above the
   threat threshold.** Static placeholder tokens visible to
   every session (cheap); per-session unique tokens
   generated when the threat scorer crosses
   ``placement_threshold`` (default 50). Per-session tokens
   visible on the NEXT session from the same source IP
   (mirrors Stage 10 cross-session overlay shipping).
4. **Opt-in: wizard prompt + env var + Stage 3 endpoint.**
   The wizard explicitly asks operators to confirm they
   read ``docs/HONEYTOKENS.md`` before enabling. Operators
   can flip at runtime via the env var or the settings
   endpoint, but the wizard is the heaviest gate. Matches
   the threat-model responsibility transfer.

## Slicing

Four slices, each shippable green mid-flight:

- **11.1**: ``anglerfish.honeytokens`` package — Honeytoken
  schema + AWS/SSH generators + registry CRUD. Pure in-
  process; tests use stable RNG seed for reproducible
  outputs.
- **11.2**: schema v6 + SessionStore writes + SessionStoreReader
  reads + audit-tailer dispatch for bridge.honeytoken_placed
  and bridge.honeytoken_callback. Persistence half; no
  bridge integration yet.
- **11.3**: bridge integration — HoneytokenPlacementService,
  record_threat_assessment hook, SessionStartResponse
  fakefs_overlay merge, bridge.honeytoken_placed audit
  emit, CLI wiring. The fake-token-bait loop is live after
  this slice.
- **11.4**: callback receiver + dashboard surface +
  wizard prompt + HONEYTOKENS.md + THREAT_MODEL.md
  update. The operator-facing surface lands here; the
  alerts-panel ``honeytoken_callback_hits`` stub flips
  live in the same commit.

## Notes for future-me

- The AWS access-key-ID encodes the registry UUID via a
  reversible base32 slice. CanaryTokens uses a similar
  trick with the secret-access-key half; we use the public
  half so a operator who finds a leaked token in a Github
  search can paste the access key ID into the dashboard
  and identify the registry entry without needing the
  secret. Documented in HONEYTOKENS.md.
- The callback receiver's 403 body is AWS-XML-shaped on
  purpose — an attacker running ``aws s3 ls`` sees an
  ``InvalidAccessKeyId`` error that mirrors what a real
  expired key returns. Operators who switch to a fake
  AWS API mock (Stage 12 territory) should reuse the same
  endpoint with a richer response.
- SSH-key callbacks are weaker — there's no equivalent of
  ``aws s3 ls`` for "did anyone try this key?". The v1
  signal is purely lure-side ("attacker cat'd
  ~/.ssh/id_rsa"). Operators get the long-tail value via
  pastebin scrapers / Shodan greps. A future stage could
  add an SSH honeypot listener that records auth attempts
  with the honeytoken's public key as the offered key,
  but that's Stage 11.5 territory.
- The static base tokens are operator-defined paths +
  generated content. We do NOT ship pre-generated tokens
  in the bundled persona YAML — every install generates
  its own at first boot so two Anglerfish operators
  cannot collide on the same registry IDs.
- The wizard prompt for HONEYTOKENS.md acknowledgement is
  a yes/no, not a "type this exact phrase". A more
  paranoid future stage could require the operator to
  type the SHA-256 of the doc; rejected for v1 as
  operator-hostile.
- Stage 12 (active counter-deception) builds on the
  honeytoken trigger. The HoneytokenPlacementService's
  hook into record_threat_assessment is the natural
  point for Stage 12 to splice in garbled-binary /
  time-bomb strategies. The interface stays clean as
  long as Stage 12's strategies follow the same
  fire-and-forget + audit pattern Stage 10 + 11
  established.
