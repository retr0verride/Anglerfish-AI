# Stage 5 - Local-LLM leverage layer

## Problem

Today there is one LLM call pattern: `OllamaClient.chat(messages)`
returns a single buffered string from one hard-coded model. That
shape worked for Stage 1's bridge — every command, one round
trip, plain text. It does not survive what stages 6-12 need:

* **Streaming** so the attacker sees output appear progressively.
  Time-wasting (Stage 6) depends on this; a 20-second buffered
  reply that arrives in one chunk is implausible and obvious.
* **Multi-model orchestration.** Stage 7 needs a slower reasoning
  model (intent extraction, session summarisation) alongside the
  fast model that handles every command. Stage 8 adds an
  embedding model on top for behavioural clustering. Single
  `settings.ollama.model` cannot represent multiple roles. Stage
  5 lands the fast/deep roles; Stage 8 adds embed when its
  consumer exists to validate the shape.
* **Structured output with schema validation.** Intent extraction
  (Stage 7) produces a Pydantic record; a free-form LLM string is
  the wrong shape. The current client returns `str` and has no
  hook for JSON-schema validation or retry-on-malformed.
* **Per-session token budgets.** A pathological attacker can keep
  one connection open for hours; without a budget the deep model
  becomes a denial-of-service vector against the dashboard. The
  Stage 3 control plane already promises a `wasting_strategy`
  knob; a token-budget knob belongs alongside it.
* **Warm-pool management.** First request after process boot
  pays the model-load cost (seconds to tens of seconds). For a
  honeypot's plausibility window that matters.

The fact that the current `OllamaClient` already discards
Ollama's `prompt_eval_count` / `eval_count` ([bridge/client.py:114](../../src/anglerfish/bridge/client.py#L114))
makes the token-budget gap especially cheap to close: the data
is on the wire, we just throw it away.

Stage 5 introduces `src/anglerfish/llm/` as the single LLM
boundary. The bridge stops importing `OllamaClient` directly;
the defense layer (which already wraps strings, not the client)
keeps its existing contract.

## Scope decision: one stage or split?

The roadmap lists Stage 5 at ~8h with five distinct capabilities.
Two natural sub-stages:

* **Stage 5A (foundation).** Module skeleton, multi-model config,
  warm-pool orchestration, refactored `LLMClient` that the bridge
  uses for the existing single-call path. No external behaviour
  change: every command still gets one buffered string back.
* **Stage 5B (capabilities).** Streaming, structured output,
  per-session token budgets. These ship together because the
  bridge HTTP protocol bump (additive `stream` flag) and the
  dashboard budget surface land in the same operator-visible
  release.

Both must land before Stage 6 starts. Splitting reduces the
single-PR review burden but pays a re-coordination cost; the
docstring of every Stage 5A class would describe an interface
that grows in 5B.

This doc covers the **unified Stage 5** scope. A note at the end
of "Test plan" calls out a clean cut point if review prefers the
split. Implementation order inside one stage: foundation →
streaming → budgets → structured output, so each slice is
shippable green even if the stage is paused mid-flight.

## Proposed interface

### Module layout

```text
src/anglerfish/llm/
    __init__.py      # public re-exports: LLMClient, LLMRole, ...
    client.py        # LLMClient class (replaces bridge.client.OllamaClient)
    roles.py         # LLMRole enum + role→model mapping
    streaming.py     # async-iterator helper for Ollama NDJSON streams
    structured.py    # JSON-schema / Pydantic-validated call wrapper
    budget.py        # per-session token accounting
    warmup.py        # background pre-load task
```

`anglerfish.bridge.client` stays as a one-line re-export of the
new client for one release cycle, then deletes (mirrors the
Stage 2 Cowrie pattern).

### Configuration shape

`OllamaConfig` grows from one model field to two roles (embed
deferred to Stage 8):

```python
class OllamaConfig(BaseModel):
    base_url: HttpUrl
    trusted_remote_host: IPvAnyAddress | None = None
    fast_model: str = "qwen3:14b"
    deep_model: str = "phi-4"
    # Existing single-model knobs become per-role under a nested
    # OllamaModelConfig (temperature, top_p, num_predict, timeouts).
    fast: OllamaModelConfig = Field(default_factory=...)
    deep: OllamaModelConfig = Field(default_factory=...)
    # Stage 8 adds: embed_model + embed: OllamaModelConfig
```

Backward compatibility: a `model_validator(mode="before")` accepts
the legacy `model=` key and routes it to `fast_model`. Operators
who upgraded from Stage 1-4.x with a single `ANGLERFISH_OLLAMA__MODEL`
keep working. After one release cycle the shim is removed; the
deprecation lands in CHANGELOG with a wizard `--reconfigure` prompt
that writes the two keys.

### LLMClient

```python
class LLMRole(StrEnum):
    FAST = "fast"
    DEEP = "deep"
    # Stage 8 adds: EMBED = "embed"


class LLMClient:
    """Single LLM boundary. Replaces bridge.client.OllamaClient.

    All methods are async; the underlying httpx client is shared
    across calls. The client is constructed once at startup and
    closed via aclose() / async context manager.
    """

    def __init__(
        self,
        config: OllamaConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None: ...

    async def chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        role: LLMRole = LLMRole.FAST,
        budget: TokenBudget | None = None,
    ) -> ChatResult: ...

    async def stream_chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        role: LLMRole = LLMRole.FAST,
        budget: TokenBudget | None = None,
    ) -> AsyncIterator[ChatChunk]: ...

    async def structured_chat[T: BaseModel](
        self,
        messages: Sequence[ChatMessage],
        schema: type[T],
        *,
        role: LLMRole = LLMRole.DEEP,
        budget: TokenBudget | None = None,
        max_retries: int = 2,
    ) -> T: ...

    # Stage 8 adds: async def embed(text, *, budget) -> EmbeddingVector

    async def aclose(self) -> None: ...
```

`ChatResult` carries both `content: str` and `usage: TokenUsage`
(`prompt_tokens`, `completion_tokens`) parsed from Ollama's
existing response fields. `ChatChunk` carries `delta: str` and a
final `usage` field on the last chunk. Defense-layer wrapping at
`AIBridgeService` consumes `result.content` and is unchanged.

### Streaming through the lure

The Ollama API supports `stream=true` natively (NDJSON). The
gap is the **bridge HTTP API** between lure and bridge: today
`POST /api/v1/session/{id}/command` returns one JSON body. Two
options:

1. **Synthesised streams.** Bridge buffers the full LLM stream,
   returns one JSON. Lure still writes one `process.stdout.write`.
   No protocol change. Attacker sees current behaviour. This
   defeats Stage 6's whole point.
2. **Additive `stream=true` flag** (chosen). The bridge command
   endpoint accepts `?stream=1`; when set, response is NDJSON
   chunks (`{"delta": "..."}` per line, terminated by
   `{"delta": "", "usage": {...}}`). Protocol version bumps from
   "2" to "3"; lure's bridge client negotiates on connect. The
   lure's `_handle_one_command` iterates chunks and
   `process.stdout.write` each.

Stage 2A already pattern-bumped v1 → v2 with the additive
`fs_context` field; the same approach (additive flag, bumped
version, lure handles both for one release cycle) keeps a clean
migration.

### Structured output

```python
class IntentSummary(BaseModel):
    """Stage 7 will own the schema; the structured_chat API is built
    here so Stage 7 just supplies it."""

    intent: str
    confidence: float = Field(ge=0, le=1)
    matched_techniques: tuple[str, ...]
    profile: Literal["opportunistic", "targeted", "automated"]
    summary: str
```

`structured_chat(messages, schema=IntentSummary)`:

1. Compose a system prompt suffix asking the LLM for JSON
   matching `schema.model_json_schema()`.
2. Call `chat()` with `role=DEEP`, response_format hint (Ollama
   supports `format="json"` since v0.1.26).
3. Parse + validate. On `ValidationError`, retry with a
   correction message that includes the validation failure.
4. After `max_retries`, raise `StructuredOutputError`.

Token budget covers all retries.

### Per-session token budget

```python
@dataclass
class TokenBudget:
    """Soft cap on tokens consumed within one logical scope.

    Construct one per session at session_opened; pass to every
    LLMClient call within the session. The client decrements the
    remaining budget after each successful call (Ollama reports
    actual usage on the response). When consumed, subsequent calls
    raise BudgetExhaustedError; the bridge's existing
    OutputFilterFiredError handling pattern turns this into a
    scripted fallback so the attacker sees a plausible response,
    not a 500.
    """

    fast_token_cap: int = 50_000
    deep_token_cap: int = 20_000
    consumed_fast: int = 0
    consumed_deep: int = 0
    # Stage 8 adds: embed_token_cap + consumed_embed
```

The bridge maintains a `dict[UUID, TokenBudget]` keyed on
session_id, parallel to the existing `sessions: dict` in
`bridge/server.py`. Budgets are constructed at session-open
with defaults from `settings.llm.budget_defaults` (new
`LLMBudgetConfig` model) and may be overridden via the existing
Stage 3 `/api/settings/bridge` endpoint.

Dashboard surface: `GET /api/sessions/{id}` payload gains a
`token_budget` field (consumed / remaining per role). The new
`/api/stats` already aggregates per-session counters; adding
`total_tokens_consumed_fast/deep/embed` to it is one query.

### Warm-pool

Background task started in the bridge lifespan. For each role
present in `OllamaConfig`, the warmup task issues a no-op
`/api/generate` with `prompt=""` and `keep_alive=-1` at startup
and every `warmup_refresh_seconds` (default 600). Ollama's
keep-alive then holds the model in memory until the next refresh.

Failure semantics: warmup failures log + swallow. The first real
request to that role pays the cold-start cost but doesn't crash.
Operators see `llm.warmup_failed` audit events; the dashboard's
health panel adds a `models[].warmed_at` field per role.

### ModelIntegrity

Currently verifies one model's layer-digest manifest
([bridge/defense.py:444](../../src/anglerfish/bridge/defense.py#L444)).
Extended to verify each configured role's manifest. The
`DefenseConfig.model_expected_hash` field becomes a dict
`{fast: hash, deep: hash, embed: hash}`; legacy single-string
input routes to `fast` via the same backward-compat shim as the
model name.

Verification runs once per role at startup with the existing
10s budget per role (not 10s total — two roles in Stage 5 get
20s; Stage 8 adds a third). Hash mismatch on any role still
hard-fails the bridge process, same as Stage 1.4.

### Defense layer interaction

Unchanged. `OutputFilter.check(text)` and `InjectionScorer.score(text)`
already accept plain strings ([bridge/defense.py:240](../../src/anglerfish/bridge/defense.py#L240),
[334](../../src/anglerfish/bridge/defense.py#L334)). The
`AIBridgeService.handle_command` wraps `LLMClient.chat()` return
value the same way it currently wraps `OllamaClient.chat()`. The
streaming path applies the OutputFilter to the assembled string
after the stream completes, not per-chunk — chunk-level filtering
would force two passes for no security gain.

## Failure modes

| Failure                                  | Behaviour                                                                                                          |
|------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| Ollama unreachable                       | `OllamaUnavailableError` propagates as today; bridge falls back to scripted response. Unchanged from Stage 1.       |
| Model not loaded (Ollama 404)            | Mapped to `OllamaUnavailableError` (current behaviour). Warm-pool reduces frequency but is not a guarantee.        |
| Stream interrupted mid-response          | Lure receives partial chunks, prints them, then a `BridgeUnavailableError`-equivalent. Existing `lure.fallback_served` path catches it. |
| Budget exhausted                         | `BudgetExhaustedError`. Bridge serves scripted fallback. Audit event `bridge.budget_exhausted` fires.              |
| Structured output validation fails after max_retries | `StructuredOutputError` raised to caller (Stage 7+). Stage 5 does not call structured_chat itself; no production caller in 5.       |
| Warmup permanently failing               | Audit event per refresh cycle; dashboard health panel shows `warmed_at: null`. No request blocking.                |
| Operator config has only legacy `model=` | Shim routes to `fast_model`; `deep_model` defaults to phi-4. Wizard `--reconfigure` resolves.                          |
| Hash mismatch on one role                | Bridge fails to start, same as Stage 1.4 single-model behaviour. Operator sees which role mismatched in the error. |

## Non-goals

- **Replacing the lure's bridge_client transport.** Lure → bridge
  is still HTTP. Stage 5 changes the bridge → Ollama transport
  and the bridge HTTP API (additive `stream` flag). The lure's
  HTTP client gains chunk-iteration but stays HTTP.
- **Cost accounting in dollars.** Anglerfish is local-only. Token
  counters are for backpressure and dashboard surface, not
  billing.
- **Per-IP budgets.** Per-session is enough; per-IP would need a
  separate aggregator and isn't required by stages 6-12.
- **Speculative decoding / batching.** Single-process honeypot;
  attacker throughput isn't a target.
- **Cross-process model sharing.** One Ollama instance, one
  bridge. Multi-host is out of scope.

## Migration / rollback

Settings: legacy `ANGLERFISH_OLLAMA__MODEL` env var keeps working
via the validator shim. Rollback (revert to single-model) is
config-only — set `fast_model` and ignore the others.

Bridge HTTP protocol: v2 stays valid for one release cycle. The
lure's `bridge_client` advertises v3 support but accepts v2
responses (non-streaming path is unchanged). Rolling back the
bridge to a v2-only build does not require touching the lure.

Token budgets: rollback is the empty `LLMBudgetConfig` (caps set
to maxint). Code path stays live but never trips.

## Test plan

`tests/llm/` is the new package. Targets:

* `test_client.py` (~20): role selection (fast/deep), error
  mapping (parity with existing `tests/bridge/test_client.py`),
  usage parsing, budget decrement.
* `test_streaming.py` (~10): NDJSON chunk iteration, partial
  stream interruption, final usage chunk parsing, OutputFilter
  applied to assembled string.
* `test_structured.py` (~10): valid JSON first try, validation
  failure → retry → success, validation failure exhausted →
  `StructuredOutputError`, budget covers retries.
* `test_budget.py` (~8): per-role decrement (fast vs deep),
  exhaustion raises, thread-safety under concurrent calls.
* `test_warmup.py` (~6): startup + refresh schedule, failure
  swallows, audit event emission.
* `test_defense_integration.py` (~5): OutputFilter wraps
  LLMClient unchanged; InjectionScorer pre-call unchanged.

Existing tests updated:

* `tests/bridge/test_client.py`: keep, point at the
  re-exported alias for one release cycle, then delete with the
  shim.
* `tests/bridge/test_service.py`: pass an `LLMClient` instance
  in place of `OllamaClient`; assertions on `result.content`
  unchanged.
* `tests/config/test_models.py`: legacy `model=` shim test;
  two-role positive test; mixed (one explicit role, the other
  default) test.

Quality gates: ruff clean, ruff format clean, mypy --strict
clean, pytest ≥ 90% total coverage. Same gates as Stage 4.

## Decisions (locked during operator review)

1. **Unified Stage 5.** One PR, one review pass. Implementation
   order inside the stage: foundation (module + multi-model config
   + LLMClient parity) → warm-pool → streaming → token budgets →
   structured output. Each slice ships green mid-flight so a
   review pause never leaves the tree broken.
2. **Defer embed to Stage 8.** Stage 5 ships fast + deep only.
   `EmbeddingVector`, the `embed()` method, `LLMRole.EMBED`, and
   `embed_model` config land in Stage 8 alongside the clustering
   code that consumes them. The shape (numpy ndarray vs tuple vs
   dedicated type) gets designed against a real caller, not in
   the abstract. The interface sketches below are pre-edited to
   remove embed; the doc keeps the original three-role
   `MODEL_SETUP.md` doc-of-record intact since operators will
   already be planning the embed model rollout.
3. **Additive `?stream=1` flag on the existing command endpoint.**
   Protocol version bumps v2 → v3 with the additive flag. Mirrors
   the Stage 2A `fs_context` pattern. Avoids doubling the bridge
   HTTP surface with a parallel `/stream` endpoint that would
   then need its own auth + rate-limit + audit wiring.
4. **Ship budget defaults; tune in production.** Fast 50k / Deep
   20k per session land as `LLMBudgetConfig` defaults. Forcing a
   wizard prompt with no data behind the chosen numbers just
   moves the guesswork to the operator. Defaults are overridable
   via the existing Stage 3 `/api/settings/bridge` endpoint.
5. **Schema location: Stage 7 owns it.** Stage 5 ships the
   `structured_chat[T: BaseModel](messages, schema=T)` API but no
   production caller and no concrete schema. `IntentSummary` is
   illustrative only in this doc — Stage 7 introduces
   `anglerfish.models.intent` with the real shape. Locking the
   schema here would freeze it before the consumer (the intent
   extractor's prompt design) gets to validate it.
