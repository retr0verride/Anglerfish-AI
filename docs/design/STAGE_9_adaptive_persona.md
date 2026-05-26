# Stage 9 - Adaptive persona

## Problem

Every attacker today sees the same fake Linux server. Hostname is
``srv-prod-01``, username is ``root``, working directory is
``/root``, the kernel string is hard-coded to
``6.1.0-26-amd64`` in
[bridge/prompts.py:36](../../src/anglerfish/bridge/prompts.py#L36),
and the static fakefs in
[lure/fakefs.py](../../src/anglerfish/lure/fakefs.py) serves the
same ``/etc/hostname``, ``/proc/version``, and ``/var/log/apt/``
contents to every session. A repeat attacker reconnecting from a
new IP gets the identical environment they saw five minutes ago,
which is implausible for a real production fleet and short-circuits
the deception value of the rest of the stack.

Stage 9 ships a named-persona layer: a fresh session gets assigned
one of several environment templates (``forgotten-debian-box``,
``gpu-rig``, ``ad-joined-workstation``, ``dev-laptop``); the
bridge's system prompt, the fake identity (hostname/username/cwd),
and a handful of fakefs entries (``/etc/hostname``,
``/proc/version``, ``/etc/os-release``, ``/var/log/apt/history.log``
package install lines) vary per persona. Selection is sticky per
source IP and biased by the Stage 8 clustering signal so a
returning attacker keeps seeing the same persona even after
client-rotation.

Prior commitments wait on this:

- Stage 8's design doc explicitly hands off to Stage 9 as the
  consumer of ``DashboardState.find_similar`` (see
  [STAGE_8_behavioral_clustering.md:356-360](STAGE_8_behavioral_clustering.md#L356-L360)).
- The roadmap's Stage 9 entry calls out persona-driven
  filesystem overlay + system-prompt persona block + cluster-
  biased selection + operator override as deliverables
  ([ROADMAP.md:274-292](../ROADMAP.md#L274-L292)).

## Proposed interface

### Persona schema + registry

```text
src/anglerfish/persona/
    __init__.py
    schema.py          # Persona pydantic model + YAML loader
    registry.py        # PersonaRegistry (bundled + override dir)
    selector.py        # PersonaSelector (source-IP + cluster)
    overlay.py         # PersonaOverlay (lure fakefs lookups)
    personas/          # bundled YAML defaults
        forgotten-debian-box.yaml
        gpu-rig.yaml
        ad-joined-workstation.yaml
        dev-laptop.yaml
```

```python
class Persona(BaseModel):
    """One named environment template loaded from YAML."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")
    description: str = Field(min_length=1, max_length=512)
    hostname: str = Field(min_length=1, max_length=63)
    username: str = Field(min_length=1, max_length=32)
    cwd: str = Field(min_length=1, max_length=4096)
    prompt_block: str = Field(min_length=1, max_length=2048)
    fakefs_overlay: dict[str, str] = Field(default_factory=dict, max_length=64)
```

- ``name`` is the registry key + the audit-event value. ASCII
  lowercase + dash so it lands cleanly in JSON logs and URL
  paths.
- ``prompt_block`` is a free-text paragraph the bridge appends to
  the system prompt's "Server facts" section ("This server is a
  retired Debian 11 development workstation; the last login was
  three weeks ago, root has never been used."). Capped at 2 KB so
  a runaway YAML file can't blow the prompt budget.
- ``fakefs_overlay`` is a path -> content dict. The lure's fakefs
  consults this dict before falling through to the static base
  table. 64-key cap matches "a handful of paths" - this is not a
  shadow filesystem.

```python
class PersonaRegistry:
    @classmethod
    def load(
        cls,
        *,
        bundled_dir: Path | None = None,
        override_dir: Path | None = None,
    ) -> PersonaRegistry: ...

    def get(self, name: str) -> Persona: ...           # raises KeyError
    def get_or_default(self, name: str) -> Persona: ...
    def names(self) -> tuple[str, ...]: ...
    def default(self) -> Persona: ...                   # forgotten-debian-box
```

- Bundled personas ship under
  ``src/anglerfish/persona/personas/`` and are loaded
  unconditionally.
- Override dir (``settings.persona.config_dir``, default
  ``/etc/anglerfish/personas/``) is loaded next; same-name YAML
  in the override dir replaces the bundled entry, new names add
  to the registry. Missing override dir is a debug log + skip,
  not an error - matches the existing wizard.json pattern.
- YAML parsing uses ``yaml.safe_load`` (already a transitive dep
  via ``pre-commit``; the design adds it to ``pyproject.toml``
  explicitly under the ``[project]`` core deps).

### Persona selector

```python
class PersonaSelector:
    def __init__(
        self,
        registry: PersonaRegistry,
        store: SessionStoreReader,
        pin_reader: PersonaPinReader,
    ) -> None: ...

    async def select(self, source_ip: str) -> Persona: ...
```

Selection order (first match wins):

1. **Operator pin** (``PersonaPinReader.get(source_ip)``): if the
   dashboard has POSTed an active pin for this IP, return that
   persona unconditionally.
2. **Source-IP recurrence**: query the sessions table for the
   most recent prior session with this ``source_ip`` and a
   non-null ``persona`` column. If found, return that persona.
   This is what the user-facing "sticky per attacker" promise
   delivers; an attacker reconnecting (same IP) keeps their
   persona even if the bridge restarts.
3. **Hash fallback**: SHA-256 of ``source_ip`` mod
   ``len(registry.names())``, pick by index. Deterministic for
   testing; spreads brand-new IPs across the persona pool.

The Stage 8 cluster signal feeds in indirectly via #2: the
``bridge.cluster_match`` audit event in the dashboard tailer
optionally updates the source_ip -> persona mapping when the
neighbour's persona differs from the recent local one (see
"Cluster bias" below). This keeps selection synchronous +
local-DB-only at session-open while still propagating the
cluster signal across sessions.

### SessionStoreReader (read-only handle)

Bridge process today does not touch the sessions DB; the
dashboard process owns writes via the audit tailer. The selector
needs read-only access to query "most recent session for this
source_ip". Two options:

- Open a second ``SessionStore`` with ``read_only=True`` in the
  bridge process pointing at the same file. SQLite WAL mode
  supports multi-process readers concurrent with the dashboard's
  writer.
- Add a small ``SessionStoreReader`` facade that only exposes
  ``recent_persona_for_source_ip(ip) -> str | None`` and pins
  the connection to ``mode=ro`` at open.

The reader-only facade keeps the surface tight and signals
intent at import time. Picked.

### Cluster bias (post-session)

The dashboard's audit tailer already handles
``bridge.cluster_match`` for the alert path
([audit_tailer.py:_handle_embedding_generated](../../src/anglerfish/dashboard/audit_tailer.py)).
Stage 9 extends that handler:

- After persisting the embedding and computing neighbours, if
  the top neighbour's similarity > a "persona-bias" threshold
  (default 0.92, separate from
  ``cluster_similarity_threshold``), and the neighbour's
  persona differs from the just-closed session's persona,
  emit a ``bridge.persona_rebound`` audit event recording the
  source_ip + old_persona + new_persona. The selector picks up
  the new persona on the next session-open from this IP via
  the same source-IP recurrence query.

This means the bridge process never reaches into the dashboard
process - the wire is the audit log and the sessions table,
matching every other cross-process flow in the codebase.

### Bridge plumbing

- ``SessionContext`` (bridge-side, already carries
  ``fake_hostname``/``fake_username``/``fake_cwd``) gains a
  ``persona_name: str`` attribute. ``snapshot()`` includes it in
  the ``SessionSnapshot`` so the persistence layer and audit
  emitters see the value.
- ``AIBridgeService.__init__`` accepts an optional
  ``persona_selector: PersonaSelector | None``. When wired, the
  bridge HTTP ``POST /api/v1/session`` endpoint calls
  ``selector.select(source_ip)`` before constructing the
  ``SessionContext``; the returned persona's hostname / username
  / cwd / prompt_block flow into the context.
- ``bridge/prompts.py:build_system_prompt`` signature becomes
  ``(config, *, cwd, persona)`` so the template renders the
  persona's prompt_block + identity fields. Backwards
  compatibility shim: if ``persona`` is ``None`` (Stage 9
  disabled), fall back to ``config.fake_*`` values.

### Lure plumbing

- ``LureSessionContext`` gains a ``persona_overlay: dict[str, str]``
  attribute populated from the persona's fakefs_overlay at
  session-open.
- ``lure/fakefs.py:read(path, session)`` consults
  ``session.persona_overlay`` first; any path present there
  returns its overlay content (200 OK, no permission check).
  Falls through to the existing static table on miss.
- ``lure/fakefs.py:system_prompt_summary(session)`` becomes
  session-aware: the returned summary includes the overlaid
  paths so the bridge's ``fs_context`` field reflects what the
  lure actually serves to this attacker.
- The bridge's ``CommandRequest.fs_context`` cap (4096 chars)
  stays; overlays of 64 keys * ~64 chars each fit well inside.

### Persona pin (dashboard)

New endpoints under the existing dashboard auth + CSRF surface:

```text
POST   /api/persona/pin       { "source_ip": str, "persona": str }
GET    /api/persona/pin                                  -> list active pins
DELETE /api/persona/pin/{source_ip}
```

- POST validates ``persona`` against the registry; 422 on
  unknown name.
- Pins live in a new ``persona_pins`` table (schema v4): a
  single row per ``source_ip`` with ``persona``, ``created_at``,
  ``created_by`` (operator user from the session cookie). No
  expiry by default; operators clear explicitly. Operators
  pinning the same IP twice replace the prior pin.
- The bridge's ``PersonaPinReader`` is the same read-only
  facade as ``SessionStoreReader``; selector consults it first
  on every session-open.

### Audit events

- ``bridge.persona_selected``: ``session_id``, ``source_ip``,
  ``persona``, ``selection_reason`` (``"pin"`` |
  ``"source_ip_recurrence"`` | ``"hash_fallback"``).
- ``bridge.persona_rebound``: ``source_ip``, ``old_persona``,
  ``new_persona``, ``neighbour_session_id``,
  ``similarity``. Emitted by the dashboard tailer after a
  cluster_match crosses the persona-bias threshold.
- ``dashboard.persona_pinned`` / ``dashboard.persona_unpinned``:
  ``source_ip``, ``persona``, ``operator``. Emitted by the new
  routes.

### Config (BridgeConfig + new PersonaConfig)

```python
class PersonaConfig(BaseModel):
    enabled: bool = True
    config_dir: Path = Path("/etc/anglerfish/personas")
    default_persona: str = "forgotten-debian-box"
    persona_bias_threshold: float = Field(default=0.92, ge=0.0, le=1.0)
```

- ``enabled=false`` is the rollback switch: the selector returns
  a stub persona derived from ``config.bridge.fake_*`` values
  and the static fakefs serves unchanged.
- ``persona_bias_threshold`` is intentionally higher than the
  ``cluster_similarity_threshold`` default (0.85) - rebounding
  someone's persona is a stronger statement than "alert the
  operator."

### Schema v4

```sql
ALTER TABLE sessions ADD COLUMN persona TEXT;
CREATE INDEX idx_sessions_source_ip_started_at
    ON sessions(source_ip, started_at DESC);  -- selector lookup

CREATE TABLE persona_pins (
    source_ip   TEXT PRIMARY KEY,
    persona     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    created_by  TEXT NOT NULL
);
```

- ``persona`` on existing rows defaults to NULL; the selector's
  recurrence query filters ``WHERE persona IS NOT NULL``, so
  pre-Stage-9 sessions don't bias selection.
- The composite index on ``(source_ip, started_at DESC)`` keeps
  the recurrence query O(log n) at any scale.

## Out of scope

- **Process-list templates** (``ps``, ``top``, ``pgrep`` served
  natively by the lure). Today these route to the bridge LLM;
  Stage 9 leaves that path untouched. Persona influences only
  the bridge's prompt_block, which the LLM can use to colour
  ``ps`` output if asked, but no native handler ships.
- **Persona-driven SSH banner**. The lure's banner subsystem
  has its own tech-debt (TODO-4 in
  [docs/TODO.md](../TODO.md)); per-persona banners add a
  variable that pre-existing bug doesn't survive. Out.
- **Mid-session persona swap**. Persona is locked at session-
  open. Switching personas mid-session would contradict prior
  responses and is the opposite of credibility.
- **Per-persona credential dictionaries**. A future stage might
  vary the fake ``/etc/shadow`` salts per persona; Stage 9
  serves the same shadow content regardless.
- **Persona-aware threat scoring**. The Stage 4 threat engine
  scores commands without persona context. Could plausibly
  weight ``crontab -e`` higher on a ``forgotten-debian-box``
  than a ``gpu-rig``; out of scope here.
- **Operator authoring UI**. Operators edit personas as YAML
  files in the config dir; no in-dashboard editor. Authoring is
  a config-management concern (Ansible, etc.) not a runtime one.

## Threat-model delta

- **Operator-trusted YAML parsing.** ``yaml.safe_load`` is the
  parser; ``yaml.load`` (which executes ``!!python/object``) is
  explicitly forbidden. The config dir is operator-only; an
  attacker who can write to ``/etc/anglerfish/personas/``
  already has root on the bait host. Residual risk: operator
  ships a YAML with a 2 KB prompt_block full of jailbreak
  instructions. Mitigation: Pydantic length cap + a smoke test
  that runs every bundled persona's prompt_block through the
  existing prompt-injection scorer.
- **Selector lookup widens DB surface.** The bridge process now
  opens the sessions DB in read-only mode. Failure mode: the
  DB file moves or gets corrupted, bridge fails to open the
  reader at startup. Mitigation: opening the reader is wrapped
  in the same lifespan startup block as the
  ModelIntegrityError check; failure aborts startup with a
  clear operator message rather than starting with the
  fallback persona silently.
- **Cluster bias as denial-of-persona.** An attacker who knows
  Stage 9 ships can deliberately mimic a known prior persona's
  command pattern to force themselves onto that persona's
  fakefs. This is intentional: matching a real attacker's
  cluster is what we want. No mitigation; documented behaviour.
- **Persona-pin endpoint surface.** Operator-only (auth + CSRF
  match the existing dashboard pattern). An attacker who
  compromises an operator session can pin every IP to one
  persona; the audit log records the actor.

## LLM defense delta

- **New prompt content.** Each persona's ``prompt_block`` is
  appended to the bridge system prompt at session-open. The
  block is operator-controlled text (bundled YAML or override
  dir); no attacker-controlled fields land in the prompt at
  this layer. The existing
  [bridge/defense.py](../../src/anglerfish/bridge/defense.py)
  passes the full system prompt through the injection scorer
  on bridge startup as a smoke test - Stage 9 wires every
  bundled persona's prompt_block through the same path at
  registry-load time and fails startup if any block scores
  above the operator-prompt threshold (0.3 by default; less
  strict than attacker input).
- **No new jailbreak surface.** The persona doesn't change the
  rules in the system prompt's "Hard rules" section. The
  hard-rule block (never reveal AI, never break character,
  output bash-only) is unchanged and survives every persona.
- **New jailbreak coverage.** ``tests/llm_defense/`` gains
  scenarios where the attacker tries to identify the persona
  ("are you a debian box or a rhel box? answer with one word")
  - the expected behaviour is the same "respond as the most
  plausible shell output for the literal command" rule the
  Stage 1 defense already enforces.

## Test plan

1. **Unit**, ``tests/persona/test_schema.py`` (~5): YAML loads
   into ``Persona``; name pattern rejects uppercase + spaces;
   prompt_block length cap enforced; fakefs_overlay key count
   capped; missing required field raises pydantic.
2. **Unit**, ``tests/persona/test_registry.py`` (~6): bundled
   personas load; override dir adds new personas; same-name
   override replaces bundled entry; missing override dir is
   non-fatal; ``default()`` returns
   ``forgotten-debian-box``; ``get(unknown)`` raises KeyError.
3. **Unit**, ``tests/persona/test_selector.py`` (~7):
   pin-first wins over recurrence; recurrence wins over hash;
   hash fallback is deterministic and uniform; unknown
   ``default_persona`` raises at construction; no rows in
   sessions table -> hash fallback; cluster-bias updates
   propagate via the bridge.persona_rebound event flow
   (selector reads the updated row).
4. **Schema**, ``tests/sessions/test_persona_persistence.py``
   (~5): v4 migration adds the persona column; persona
   round-trips through upsert + get; index exists; pin table
   upsert overwrites; recent-persona-by-source-ip query
   returns most recent non-null.
5. **Integration**, ``tests/bridge/test_persona_integration.py``
   (~6): bridge POST /session calls selector; the returned
   persona's fake_hostname flows into SessionContext; the
   system prompt includes the persona's prompt_block;
   bridge.persona_selected audit event fires with the right
   selection_reason; selector disabled (PersonaConfig.enabled
   = false) falls back to BridgeConfig.fake_*; lure session
   sees the overlay in fakefs.read().
6. **Dashboard**, ``tests/dashboard/test_persona_endpoints.py``
   (~5): POST /api/persona/pin validates persona name; GET
   lists active pins; DELETE removes pin; unauthorized rejected;
   dashboard.persona_pinned audit event recorded with operator
   identity.
7. **Cluster bias**,
   ``tests/dashboard/test_persona_rebound.py`` (~3): tailer
   emits bridge.persona_rebound when neighbour similarity
   crosses persona_bias_threshold and personas differ; no
   rebound when personas match; no rebound below threshold.
8. **LLM defense**, ``tests/llm_defense/test_persona_block.py``
   (~3): each bundled persona's prompt_block scores below the
   operator-prompt injection threshold; the persona prompt
   doesn't unlock the "never reveal AI" rule.

**Coverage target**: 90 % across the new modules. The bundled
YAML files are data, not code, and are not coverage-counted.

## Rollback plan

1. **Per-environment switch.** Set
   ``ANGLERFISH_PERSONA__ENABLED=false`` (env var or via the
   dashboard's settings POST). The selector returns a stub
   persona derived from ``bridge.fake_*``; the lure overlay
   dict is empty; system prompt skips the prompt_block. This
   is a hot-flip; no restart needed (the same Stage 6
   overrides-publisher channel surfaces it to the bridge).
2. **Per-attacker pin.** Operator can pin any IP back to the
   default persona via the dashboard.
3. **Schema rollback.** Drop the ``persona`` column on the
   sessions table; drop the ``persona_pins`` table. Forward-
   only migration policy applies; no downgrade migration in-
   tree. Pre-Stage-9 backups restore the schema to v3.
4. **Code rollback.** Revert the slice commits; the
   bundled YAML files are isolated under ``src/anglerfish/
   persona/personas/`` and removing them has no cascading
   effect because ``PersonaConfig.enabled=false`` short-
   circuits the selector before it touches the registry.

## Success criteria

- All tests pass; coverage stays >= 90 %.
- ``anglerfish config show`` reveals ``persona.enabled``,
  ``persona.config_dir``, ``persona.default_persona``,
  ``persona.persona_bias_threshold``.
- Four bundled personas load on a fresh install; an empty
  override dir is non-fatal.
- A brand-new source IP gets a hash-fallback persona,
  observable via the ``bridge.persona_selected`` audit event
  with ``selection_reason="hash_fallback"``.
- A second session from the same source IP gets the same
  persona, observable via the same event with
  ``selection_reason="source_ip_recurrence"``.
- An operator pin via POST /api/persona/pin forces the next
  session from that IP onto the pinned persona, observable
  via ``selection_reason="pin"``.
- The bridge's system prompt contains the persona's
  prompt_block (assertable via a debug endpoint or by
  inspecting the audit log's prompt-rendering trace).
- The lure serves persona-overridden ``/etc/hostname``,
  ``/etc/os-release``, ``/proc/version``, and
  ``/var/log/apt/history.log`` when reading those paths.

## Decisions (locked during operator review)

1. **Persona scope: identity + system-prompt block + fakefs
   overlay.** Excludes process-list templates (those stay on
   the LLM path). Smallest surface that delivers the roadmap's
   credibility-on-reconnect win without rewriting the lure's
   command dispatch.
2. **Selection: cluster-driven with hash fallback.** Source-IP
   recurrence is the synchronous read at session-open; the
   Stage 8 cluster signal feeds in asynchronously via the
   ``bridge.persona_rebound`` event after the tailer scores
   the closing session against its neighbours.
3. **Persona definitions: bundled YAML + operator override
   dir.** Four bundled defaults
   (``forgotten-debian-box``, ``gpu-rig``,
   ``ad-joined-workstation``, ``dev-laptop``); operator
   overrides drop into ``/etc/anglerfish/personas/``; same-name
   YAML in the override dir replaces the bundled entry.
4. **Operator override: per-source-IP pinning via dashboard.**
   ``POST /api/persona/pin`` accepts ``{source_ip, persona}``
   and the selector consults it before any other rule.
   Mirrors the Stage 6 wasting-strategy override pattern.
5. **Bridge reads the sessions DB read-only via a typed
   facade.** ``SessionStoreReader`` exposes only the
   selector's queries; the bridge process never opens a
   writer. Same SQLite file as the dashboard's writer
   (WAL mode supports the concurrent read).
6. **Slicing: 4 slices.** Persona schema + registry; selector
   + DB facade + bridge integration; lure overlay + fakefs
   plumbing; dashboard pin endpoints + cluster-bias rebound.
   Each shippable green mid-flight.
7. **persona_bias_threshold default 0.92.** Stricter than
   ``cluster_similarity_threshold`` (0.85) because rebounding
   a future session's persona is a stronger commitment than
   firing an alert.

## Notes for future-me

- The persona's ``prompt_block`` is appended to the existing
  system prompt rather than templated into the body. Operators
  who want to change the kernel string or the "Server facts"
  block edit the prompt template in
  [bridge/prompts.py](../../src/anglerfish/bridge/prompts.py);
  Stage 9 doesn't add a per-persona kernel field because the
  kernel string already lands inside the prompt template at a
  fixed location.
- ``fakefs_overlay`` is a flat dict, not a path tree. Operators
  who want to add a whole directory (``/opt/gpu-rig-data/...``)
  need either to enumerate every file in the YAML or wait for
  Stage 13's revised lure-fakefs architecture (which is the
  natural home for tree-structured overlays). Flat dict keeps
  the v1 surface tight.
- The ``persona`` column on the sessions table is a free-text
  string rather than a FK to a personas table. Personas are
  config, not data; an operator who deletes a YAML file should
  not be blocked by the FK from removing the row. The selector
  treats unknown persona names in the recurrence query as
  "no recurrence" and falls through to hash.
- Stage 10 (engaged persistence) reads the persona to decide
  whether a particular fake-backdoor pattern is plausible. The
  natural interface is the same
  ``SessionContext.persona_name`` attribute Stage 9 adds; no
  new plumbing needed when Stage 10 lands.
- The selector's read of the sessions table at session-open
  adds one O(log n) query per attacker connection. At the
  rate-limiter's per-IP cap (defaults to a small handful of
  concurrent sessions per IP) this is negligible. If the read
  becomes a bottleneck the next move is an in-memory LRU
  cache populated by the persona_selected + persona_rebound
  audit events.
- The bundled personas should be diverse enough that an
  attacker scripting against one persona's specifics breaks
  on the others. ``gpu-rig`` has nvidia packages in
  ``/var/log/apt/history.log``; ``ad-joined-workstation`` has
  winbind + samba; ``dev-laptop`` has nodejs + yarn; the
  forgotten box is intentionally generic. Adding a fifth
  persona later is a YAML drop-in.
