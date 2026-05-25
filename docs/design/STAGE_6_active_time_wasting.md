# Stage 6 - Active time-wasting

## Problem

The Stage 5 LLM layer answers every command with one fast LLM
call. Human attackers triage the host in seconds, find nothing
that pays back the cost, and disconnect. Anglerfish's value to
the operator is proportional to attacker dwell time: the longer
an attacker stays, the more credentials they spray, the more
implants they try, the richer the telemetry the threat engine
and the future Stage 7 intent-extractor have to work with.

Two prior commitments are also waiting on this stage:

- Stage 3 shipped `BridgeRuntimeOverrides.wasting_strategy` in
  `src/anglerfish/dashboard/overrides.py:51` with values `off` /
  `light` / `aggressive`. The dashboard `POST /api/settings/bridge`
  endpoint already accepts a setting change and audits it. The
  bridge ignores the value today.
- Stage 3's [design doc](STAGE_3_dashboard_control_plane.md) line
  526-533 flagged cross-process propagation as a deferred design
  question: "Stage 6 (time-wasting) is the first stage that
  actually needs the bridge to honour `wasting_strategy`. The two
  leading options are a small tmpfs JSON file the bridge polls
  per request (~0.1 ms), and a fire-and-forget HTTP push from the
  dashboard to a new bridge endpoint." Stage 6 picks one and
  ships it.

Stage 6 wires Stage 3's existing operator-facing knob to a real
mechanism, and adds a per-session ceiling so the strategy cannot
keep one attacker forever.

## Proposed interface

### Module layout

```text
src/anglerfish/bridge/strategies/
    __init__.py              # public re-exports: WastingStrategy, get_strategy
    base.py                  # protocol/ABC + StrategyContext + StrategyEffect
    off.py                   # passthrough (always available)
    light.py                 # light wasting
    aggressive.py            # aggressive wasting
```

`WastingStrategy` selection is a string from
`Literal["off", "light", "aggressive"]` (matches Stage 3's existing
type alias in `dashboard/overrides.py`). The factory
`get_strategy(name)` returns one of the three concrete classes.

### Strategy interface

```python
class WastingStrategyBase(ABC):
    """Per-command transform applied between the bridge service
    and the LLM client. Operates in-place on the streaming flow."""

    @abstractmethod
    async def pre_command(
        self,
        ctx: StrategyContext,
    ) -> StrategyPreEffect:
        """Called once before the LLM call.

        Returns a StrategyPreEffect that may instruct the bridge to:
        - emit a pre-message chunk ("Loading...", "Almost ready...")
          before the LLM response begins
        - inject a clarification-loop turn (aggressive only)
        - pass through unchanged
        """

    @abstractmethod
    async def between_chunks(
        self,
        ctx: StrategyContext,
        chunk: BridgeChunk,
    ) -> float:
        """Called after each AI chunk. Returns inter-chunk sleep
        in seconds. 0.0 means no delay. Strategies use this to
        pace streaming output."""
```

`StrategyContext` carries `session_id`, current per-session
`wasted_ms_so_far`, the `bridge` settings snapshot, and the
sanitised command text. The strategy gets the information it
needs to decide without reaching into bridge internals.

`StrategyPreEffect` is a small frozen dataclass:

```python
@dataclass(frozen=True)
class StrategyPreEffect:
    pre_message: str | None = None      # written to attacker before LLM starts
    pre_message_delay_ms: int = 0        # delay before pre_message
    pre_delay_ms: int = 0                # delay before LLM call begins
```

### Cross-process override propagation

Bridge and dashboard are separate processes. The dashboard owns
the operator-facing `POST /api/settings/bridge` endpoint and
updates its in-process `BridgeRuntimeOverrides`. The bridge needs
the new value within seconds of the operator clicking save.

Picked: **tmpfs JSON file with atomic rename**.

- Dashboard writes
  `/run/anglerfish/runtime_overrides.json` on every successful
  POST. Path is configurable via `dashboard.overrides_publish_path`.
  Write is atomic via tempfile + `os.replace`.
- Bridge reads the same path lazily (per-request) with a 1-second
  mtime-cached read: if mtime hasn't changed since the last
  successful read, the cached value wins. Configurable via
  `bridge.overrides_poll_path` and `bridge.overrides_cache_ttl_s`.
- File is JSON with the same `bridge.snapshot()` shape the
  dashboard emits on GET. Schema-validated on read; an unparseable
  or schema-mismatched file logs a warning, audits
  `bridge.overrides_read_failed`, and falls back to the bridge's
  static config (`BridgeConfig.wasting_strategy`).
- Missing file is the common steady-state (operator never visited
  the dashboard); not an error, falls back to static config.

Why not HTTP push from dashboard to bridge:

- New auth surface (the bridge would need its own bearer for
  inbound from the dashboard).
- Restart ordering becomes load-bearing (dashboard cannot push
  during bridge restart).
- Failure mode is louder: a push 500 surfaces in the dashboard
  HTTP path; an unread file goes silent.

Why not just config + SIGHUP:

- Breaks Stage 3's contract that the POST endpoint flips
  behaviour immediately, no restart.

### Configuration shape

Adds to `BridgeConfig`:

```python
wasting_strategy: Literal["off", "light", "aggressive"] = "off"
# Static default; dashboard overrides via the runtime JSON.

overrides_poll_path: Path = Path("/run/anglerfish/runtime_overrides.json")
overrides_cache_ttl_s: float = 1.0
# Reads no more than once per second per bridge process.

session_wasted_ms_cap: int = 1_800_000  # 30 minutes
# Per-attacker-session ceiling on total time padding the
# strategy may add. When exhausted, the session drops to "off"
# regardless of operator setting. 0 disables the cap (legitimate
# in closed-lab analysis runs).

aggressive_clarification_rate: float = 0.05
# Probability per command that aggressive strategy emits a
# "did you mean X?" follow-up requiring another command turn.
```

Adds to `DashboardConfig`:

```python
overrides_publish_path: Path = Path("/run/anglerfish/runtime_overrides.json")
# Dashboard side of the bridge ↔ dashboard handshake. Must match
# bridge.overrides_poll_path for the channel to work; mismatched
# paths fail open (bridge uses its static config).
```

The dashboard validates `overrides_publish_path.parent` is writable
at startup; missing tmpfs aborts the dashboard process with a
clean error (better than failing silently on the first override).

### Concrete strategy behaviour

**`off`** (default, always available):

- `pre_command` returns empty `StrategyPreEffect`.
- `between_chunks` returns `0.0`.
- No latency cost, no behaviour change vs Stage 5.

**`light`**:

- `pre_command`: 5% probability of returning a pre-message
  (cycling through `"Loading...\n"`, `"One moment.\n"`,
  `"Working...\n"`) with `pre_message_delay_ms=500` and
  `pre_delay_ms=300`. The remaining 95% of commands return empty.
- `between_chunks`: returns `random.uniform(0.05, 0.15)` seconds
  per chunk. Streaming feels noticeably slower than `off` but
  the response itself is unchanged.
- Expected wall-clock impact: +15-30% per session.

**`aggressive`**:

- `pre_command`: 20% probability of pre-message (same set + a
  `"Compiling response...\n"`, `"Resolving symbols...\n"` variant)
  with longer delays (`pre_message_delay_ms=1200`,
  `pre_delay_ms=800`).
- `between_chunks`: `random.uniform(0.2, 0.5)` seconds per chunk.
- Additionally: 5% (= `aggressive_clarification_rate`) of commands
  produce a clarification question instead of executing,
  forcing the attacker to send another command. The bridge
  prompt is augmented with a one-shot system message ("ask the
  user to clarify whether they meant `X` or `Y`") and the
  resulting AI text is shipped as the response. The follow-up
  command runs normally; only one clarification per "command
  chain" to avoid infinite loops.
- Expected wall-clock impact: +50-100% per session.

The strategy classes use a deterministic PRNG seeded with
`(session_id, command_count)` so a single attacker session has a
reproducible interaction pattern across the bridge restart - and
so the unit tests can pin behaviour by feeding a fixed seed.

### Per-session time budget

`AIBridgeService` gains a per-session counter mirroring the
Stage 5 `TokenBudget` pattern:

```python
self._wasted_ms: dict[UUID, int] = {}
```

After each command, the strategy's added time
(pre_message_delay_ms + pre_delay_ms + sum of between_chunks
delays) is summed and added to the per-session counter. When
the counter exceeds `bridge.session_wasted_ms_cap`, the strategy
is forced to `off` for that session for the rest of its
lifetime. Audit event `bridge.wasting_budget_exhausted` fires
once per session at the transition.

Lifecycle: created lazily on first command, dropped via
`AIBridgeService.end_session_budget` (which already exists and
is called from `DELETE /api/v1/session/{id}` - extended to also
drop the wasted_ms entry). The bridge per-session state leak
(TODO-8) is unchanged.

### Dashboard metric: "avg time wasted per session"

The dashboard's `/api/health` panel already includes
`/api/health/sessions`. Add to that endpoint's response a
`wasting` block:

```json
"wasting": {
  "strategy": "light",
  "active_sessions_under_strategy": 4,
  "avg_wasted_ms_per_session": 9_400,
  "baseline_avg_ms_per_session": 0,
  "sessions_at_budget_cap": 0
}
```

`avg_wasted_ms_per_session` and `baseline_avg_ms_per_session` are
computed from the audit log: scan the last N session-end events
(window-bounded), group by whether the session had
`bridge.wasting_budget_exhausted` or saw any
`bridge.wasting_applied` events, and average. The baseline cohort
is sessions where the active strategy at the time was `off`
(read from `dashboard.settings_changed` events to know the
strategy history).

`sessions_at_budget_cap` counts the number of currently-active
sessions that have hit `session_wasted_ms_cap` (read from
`_wasted_ms` snapshot via a new
`AIBridgeService.wasting_stats()` method).

### New audit events

- `bridge.wasting_applied` - per command that the strategy
  touched. Fields: `session_id`, `attacker_ip`, `strategy`,
  `pre_message_present`, `inter_chunk_delay_ms_total`,
  `clarification_injected`.
- `bridge.wasting_budget_exhausted` - per session transition.
  Fields: `session_id`, `attacker_ip`, `total_wasted_ms`.
- `bridge.overrides_read_failed` - per failed read of the
  runtime overrides JSON. Fields: `path`, `error`.
- `dashboard.overrides_published` - per write to the runtime
  overrides JSON. Fields: `path`, `bridge_snapshot`.

All four are registered in `anglerfish/audit.py`'s event catalog.

## Out of scope

- **Adaptive strategy.** No machine learning on attacker
  behaviour to pick the strategy. Operator picks; Stage 6 honours.
  A future stage could add adaptive selection on top.
- **Decoy poisoning.** Stage 3's `decoy_poisoning` feature flag
  is independent; Stage 6 does not implement it.
- **HTTP transport for cross-process state.** Picked tmpfs JSON;
  not building an HTTP RPC for this.
- **Multi-bridge fleet coordination.** One bridge per honeypot
  VM. If a fleet adopts this, the publish path becomes
  per-bridge and the dashboard writes N files; out of scope.
- **Streaming the clarification follow-up.** The clarification
  message in `aggressive` mode is treated as a normal LLM
  response and streamed via the existing path. No new
  stream-of-streams plumbing.

## Threat-model delta

New attack surfaces:

- **Operator-controlled DoS via clarification loops.** If an
  attacker can force the strategy into infinite clarification
  loops, the session never produces a real LLM response and
  Anglerfish accumulates no command telemetry. Mitigation: only
  one clarification per "command chain" (the follow-up command
  always runs normally), enforced via a per-session
  `last_clarification_at_command_count` field.
- **Runtime overrides JSON tampering.** If an attacker can write
  to `/run/anglerfish/runtime_overrides.json`, they can flip the
  strategy. Mitigation: the file is on tmpfs (root-only by
  default with `mode=0640`), written 0640 by the dashboard
  process running as the dashboard user, read by the bridge
  process running as the bridge user. The dashboard's
  validate-on-startup step checks the directory permissions and
  refuses to start if they are open. Residual risk: a
  compromised dashboard process can flip the bridge's strategy -
  but a compromised dashboard process can already issue arbitrary
  commands via its existing internal channels.
- **LLM prompt manipulation via clarification mode.** The
  clarification system message includes attacker-supplied
  command text. Standard injection defenses apply
  (InjectionScorer pre-call); no new bypass path.

No new entries in THREAT_MODEL.md are required - the existing
"operator misconfiguration" and "LLM prompt injection" entries
cover the surfaces above.

## LLM defense delta

The aggressive clarification mode is the only new LLM call
pattern:

- **Prompt content**: existing system prompt + a one-shot
  injected system message ("Ask the user to clarify whether
  they meant `token_a` or `token_b`, where the tokens are
  shell-disambiguation candidates pulled from the command's
  first argument.") + the sanitised attacker command.
- **Expected return**: free-text shell-style clarification
  question, typically one line. Goes through the normal
  OutputFilter post-stream.
- **Post-filter rule**: unchanged from Stage 5 - the assembled
  stream runs through `OutputFilter.check` and audits on fire.
- **New jailbreak coverage**: `tests/llm_defense/test_wasting_clarification.py`
  with cases for an attacker command crafted to make the
  clarification question itself leak the AI persona ("Did you
  mean to ask the AI a question?"). The InjectionScorer pre-call
  catches the explicit cases; the OutputFilter catches the
  rendered cases.

## Test plan

`tests/bridge/test_strategies/` is the new package.

1. **Unit**, `tests/bridge/test_strategies/test_off.py`. Trivial:
   `off.pre_command` returns empty effect; `off.between_chunks`
   returns 0.0.
2. **Unit**, `tests/bridge/test_strategies/test_light.py` (~6):
   pre-message rate ~5% over 1000 trials, inter-chunk delays in
   range, deterministic given fixed seed.
3. **Unit**, `tests/bridge/test_strategies/test_aggressive.py`
   (~8): pre-message rate ~20%, inter-chunk delays in range,
   clarification rate ~5%, only-one-clarification-per-chain
   invariant.
4. **Unit**, `tests/bridge/test_overrides.py` (~8): tmpfs JSON
   read happy path, mtime cache hits, missing file falls back to
   static config, malformed JSON audits + falls back,
   schema-mismatch ditto.
5. **Integration**, `tests/bridge/test_service_wasting.py` (~6):
   `handle_command_stream` honours the active strategy
   (chunk-spacing observable in collected chunks via injected
   `asyncio.sleep` stub); per-session cap exhausts and reverts
   to `off`; `bridge.wasting_budget_exhausted` audit fires once.
6. **Integration**, `tests/dashboard/test_settings_propagation.py`
   (~4): POST `/api/settings/bridge` writes the JSON file;
   bridge picks up the new value within one cache TTL.
7. **Security**, `tests/llm_defense/test_wasting_clarification.py`
   (~3): clarification prompt cannot be made to leak "I am an
   AI" via crafted command, injection scorer catches override
   attempts in the clarification path.
8. **Coverage target**: ≥90% total (no exemptions).

## Rollback plan

1. Set `ANGLERFISH_BRIDGE__WASTING_STRATEGY=off` in the bridge's
   env file (or flip via dashboard POST). Effective on next
   command.
2. Delete `/run/anglerfish/runtime_overrides.json` if its
   presence is causing problems; bridge falls back to env-file
   default.
3. To fully back the stage out: revert the slice commits, run
   `pytest`. No DB migrations to reverse - the only persistent
   state is audit-log events, which an old reader silently
   ignores.

## Success criteria

- All tests pass; coverage ≥90 %.
- `anglerfish config show` reveals `bridge.wasting_strategy`,
  `bridge.overrides_poll_path`, `bridge.overrides_cache_ttl_s`,
  `bridge.session_wasted_ms_cap`,
  `bridge.aggressive_clarification_rate`,
  `dashboard.overrides_publish_path` with documented defaults.
- POST `/api/settings/bridge` with
  `{"wasting_strategy": "light"}` causes the next attacker
  command (within `overrides_cache_ttl_s` seconds) to receive
  light-paced streaming output. Observable via collecting chunks
  from a test SSH client.
- `/api/health/sessions` includes a populated `wasting` block.
- A session that hits `session_wasted_ms_cap` produces exactly
  one `bridge.wasting_budget_exhausted` audit event and
  subsequent commands in that session show `off` behaviour.

## Decisions (locked during operator review)

1. **Cross-process mechanism: tmpfs JSON poll** (recommended over
   HTTP push). Operational simplicity, no new auth surface,
   atomic via rename. Stage 3 flagged both options; this picks
   the simpler one and ships it.
2. **Per-session wasted-ms cap: 30 minutes** (`1_800_000` ms).
   Default chosen to be well above the median attacker dwell time
   (current production median is ~4 min) so the cap rarely
   bites; operators tighten if needed.
3. **Aggressive clarification rate: 5%** (`0.05`). At one
   clarification per ~20 commands the attacker is unlikely to
   pattern-match the injection but the per-session wall-clock
   impact still lands in the 50-100% range.
4. **Strategy classes ship in `bridge/strategies/`** (not
   `llm/strategies/`). The strategy operates on
   `BridgeChunk` and per-command latency; the LLM client stays
   strategy-agnostic. Symmetric to Stage 5's defense layer that
   lives in `bridge/defense.py`.
5. **Inter-chunk delays use `asyncio.sleep`**, injected via a
   `sleep: Callable[[float], Awaitable[None]]` constructor arg
   on the strategy classes so tests can pin behaviour without
   real time elapsing. Symmetric to the existing `clock` pattern
   on `TorExitList`.

## Notes for future-me

- The runtime-overrides JSON channel is generic. Stage 7 (intent
  extraction) and Stage 8 (clustering) will both want to flip
  their own knobs at runtime; both can publish/poll the same
  file with their own schema keys. Keep the per-feature schema
  flat under the top-level `bridge` / `dashboard` / `features`
  sections matching Stage 3's snapshot shape.
- The `bridge.overrides_read_failed` audit event is per-failed-read
  but the bridge polls per request; a corrupted file would spam
  the audit log. Future improvement: rate-limit the audit event
  via a single-flight latch keyed on
  `(path, mtime, error_signature)`. Not in scope for slice 1 -
  if the corrupted-file scenario actually fires in production,
  the spam will be noticeable enough that the rate-limit lands
  as a fix commit.
- The aggressive clarification mode is the only LLM behaviour
  change. If operator review wants to defer clarification to a
  Stage 6.5 sub-stage and ship Stage 6 with only delay-based
  wasting, the strategy interface supports that cleanly - just
  return empty `StrategyPreEffect` from `aggressive.pre_command`
  for the clarification path until 6.5 lands.

## Slicing

Stage 6 ships in five slices, each green mid-flight:

- **6.1** Strategy plug-in skeleton + cross-process overrides
  publish/poll + bridge consumes (only `off` works). Bridge
  service wires `wasting_stats()` placeholder; dashboard
  `POST /api/settings/bridge` writes the JSON file. No
  behaviour change for attackers yet.
- **6.2** `light` strategy implementation + the per-command
  audit event + integration test verifying chunk spacing.
- **6.3** `aggressive` strategy without clarification injection
  (delays only). Tests for the pre-message + chunk delays.
- **6.4** Aggressive clarification mode + the one-per-chain
  invariant + the LLM defense tests.
- **6.5** Per-session wasted-ms cap + budget-exhausted audit +
  dashboard `wasting` block in `/api/health/sessions`.
