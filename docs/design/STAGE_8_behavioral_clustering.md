# Stage 8 - Behavioural clustering

## Problem

Anglerfish recognises "same attacker" today only through exact
JA3/HASSH match. That works against a single misconfigured
scanner; it fails the moment the attacker rotates clients, runs
through a proxy, or shifts to a different binary. Real botnets do
all three within hours. The operator-facing question is "have I
seen this behaviour before, regardless of identity?" - a
behavioural fingerprint, not a transport fingerprint.

Stage 8 ships per-session embedding vectors over the command
history, persists them in the session store, and exposes
similarity queries. A new session is "clustered" with prior
sessions whose vectors cosine-match above a configurable
threshold. Stage 9 (adaptive persona) reads the cluster info to
choose which persona to present; this stage delivers the data.

Two prior commitments wait on this:

- Stage 5's design doc deferred the ``LLMRole.EMBED`` role and
  ``LLMClient.embed`` API to this stage so the embedding-vector
  shape could be designed against a real consumer.
- Stage 3 reserved ``behavioral_cluster_matches`` in the alerts
  stub at [alerts.py:53](../../src/anglerfish/dashboard/alerts.py#L53)
  with ``{"available": false, "stage": 8}``. This stage flips it
  to live.

## Proposed interface

### LLM-layer extensions (deferred from Stage 5)

```python
class LLMRole(StrEnum):
    FAST = "fast"
    DEEP = "deep"
    EMBED = "embed"   # Stage 8 addition


class LLMClient:
    async def embed(
        self,
        text: str,
        *,
        budget: TokenBudget | None = None,
    ) -> tuple[float, ...]: ...
```

- ``embed()`` issues ``POST /api/embeddings`` against the
  embedding model and returns the vector as a frozen tuple of
  floats. Errors map the same as ``chat()``
  (``OllamaUnavailableError`` / ``OllamaResponseError``).
- ``TokenBudget`` gains ``embed_token_cap`` /
  ``consumed_embed`` mirroring fast + deep.
- ``OllamaConfig`` gains ``embed_model`` (default
  ``nomic-embed-text``) and ``session_embed_token_cap``.
- ``WarmPool`` includes EMBED in its default role tuple so the
  embed model also stays resident.

The ``Stage 8 adds EMBED`` TODO comments in
[llm/roles.py:9](../../src/anglerfish/llm/roles.py#L9) and
[llm/budget.py:87](../../src/anglerfish/llm/budget.py#L87) get
resolved.

### Embedding generator

```text
src/anglerfish/intel/
    embeddings.py     # EmbeddingGenerator (new)
```

```python
class SessionEmbedding(BaseModel):
    """Persisted per-session embedding vector + metadata."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: UUID
    vector: tuple[float, ...] = Field(min_length=64, max_length=4096)
    dimension: int = Field(ge=64, le=4096)
    model: str = Field(min_length=1, max_length=128)
    generated_at: datetime


class EmbeddingGenerator:
    def __init__(
        self,
        client: LLMClient,
        *,
        min_commands: int = 3,
        budget_cap_tokens: int = 2000,
        max_command_chars: int = 4096,
        logger: logging.Logger | None = None,
    ) -> None: ...

    async def generate(
        self,
        snapshot: SessionSnapshot,
    ) -> SessionEmbedding | None: ...
```

- Sessions below ``min_commands`` return ``None`` (no embedding,
  no Ollama call). Mirrors the intent-extractor short-circuit.
- The embedded text is the joined command list (one per line),
  truncated to ``max_command_chars``. Responses are intentionally
  excluded - they are LLM-generated and would make the embedding
  reflect the bridge's behaviour rather than the attacker's.
- ``budget_cap_tokens`` constructs a fresh ``TokenBudget`` for
  the call (embed tier only); the per-session command budget is
  untouched.

### Vector storage

SQLite, inline blob column. ``sqlite-vec`` is the right answer
at fleet scale (>50k sessions); we're firmly in single-honeypot
territory where Python-side cosine over a few thousand vectors
finishes in milliseconds. Sticking with inline keeps operators
running a stock SQLite build without compiling an extension.

Schema v3 (next migration):

```sql
CREATE TABLE embeddings (
    session_id      TEXT PRIMARY KEY
        REFERENCES sessions(session_id) ON DELETE CASCADE,
    vector_blob     BLOB NOT NULL,         -- packed float32 little-endian
    dimension       INTEGER NOT NULL,
    model           TEXT NOT NULL,
    generated_at    TEXT NOT NULL
);

CREATE INDEX idx_embeddings_generated_at ON embeddings(generated_at);
CREATE INDEX idx_embeddings_model        ON embeddings(model);
```

``SessionStore`` gains:

- ``upsert_embedding(embedding: SessionEmbedding)``
- ``get_embedding(session_id) -> SessionEmbedding | None``
- ``find_similar(session_id, *, k, min_similarity)
  -> list[tuple[SessionEmbedding, float]]`` -
  loads the query vector, scans every stored vector with the
  same ``model``, computes cosine similarity in pure Python
  (numpy not required for the dimensions in play), returns the
  top ``k`` above ``min_similarity`` excluding self. The full
  scan is bounded by the index on ``model`` so cross-model
  comparisons are silently skipped (different models produce
  different vector spaces; comparing them is nonsense).

### Bridge integration

The DELETE endpoint already calls ``schedule_intent_extraction``
on session close. Stage 8 adds a sibling call:

- ``AIBridgeService.schedule_embedding_generation(snapshot)``
  spawns a fire-and-forget task that calls
  ``EmbeddingGenerator.generate(snapshot)`` under a 30-second
  timeout, audits ``bridge.embedding_generated`` on success
  (or ``bridge.embedding_failed`` on any failure shape).
- Both tasks run in parallel; neither blocks the other.
- ``end_session_budget`` drops the per-session state symmetrically.

Audit events:

- ``bridge.embedding_generated`` carrying ``session_id``,
  ``model``, ``dimension``, and a compact base64 of the vector
  blob so the tailer can reconstruct without a separate read.
- ``bridge.embedding_failed`` carrying ``session_id``,
  ``error_type``, ``error``.

### Cross-process persistence

Same pattern as Stage 7: bridge audits, dashboard tailer
dispatches. ``audit_tailer._dispatch_event`` gains a branch for
``bridge.embedding_generated`` that calls
``DashboardState.upsert_embedding``. Malformed records drop with
a warning log (vector length mismatch, base64 decode failure,
schema validation failure).

### Cluster-match alerts

The alerts panel grows a new live kind. The bridge fires a new
``bridge.cluster_match`` audit event when a freshly-stored
embedding has at least one neighbour above the configured
similarity threshold. Event carries the new session_id, the
matched session_id(s) (up to 5), and the similarity score(s).

``_ALERT_EVENT_TYPES`` adds the mapping. The
``behavioral_cluster_matches`` stub in ``ALERT_STUBS`` is
deleted in the same commit.

### Dashboard surface

- ``GET /api/sessions/{id}/similar?k=5&min_similarity=0.85``
  returns the neighbour list (session_ids + similarities +
  basic session metadata for each). Defaults: k=5 (max=20),
  min_similarity from
  ``settings.bridge.cluster_similarity_threshold``.
- The session-detail view (operator HTML) reads the route and
  renders a "Similar sessions" block alongside the existing
  intent + threat blocks. Stage 13 will add the formal cluster
  visualisation; Stage 8 just lists the top neighbours.
- ``GET /api/alerts?kind=cluster_match`` surfaces the new
  audit events (same shape as the existing alerts kinds).

## Out of scope

- **Formal cluster visualisation.** Stage 13 owns the
  visualisation (force-directed graph, cluster-quality metrics).
  Stage 8 ships the underlying data + the most basic list view.
- **Cross-model comparison.** Sessions embedded with model A
  cannot be compared with sessions embedded with model B; the
  similarity query filters on the ``model`` column. Operators
  who switch embedding models start a fresh cluster space.
- **Re-embedding historical sessions.** Stage 8 only generates
  embeddings for sessions that close after it ships. A
  back-fill helper could land later if operators ask.
- **Approximate nearest-neighbour indexing.** Linear scan over
  a few thousand vectors finishes in single-digit
  milliseconds; ANN structures (sqlite-vec, FAISS) become
  worth the operational cost above ~50k vectors.

## Threat-model delta

- **Inference-cost DoS via session size.** A session with
  thousands of commands produces a large embed-input text.
  ``max_command_chars`` (default 4096) truncates; the embed
  model's own context window is the hard ceiling beyond that.
- **Vector-pollution attacks.** An attacker who can run many
  sessions can pollute the cluster space with synthetic
  "neighbour" vectors. The threshold + per-session command
  count floor + recent-N filter (the similarity query only
  considers vectors from the last 30 days) bound the
  exposure; full mitigation is operator-side rate limiting
  and out of scope here.
- **Audit-log size.** Each ``bridge.embedding_generated`` event
  carries the vector base64. A 384-dim float32 vector is
  ~2 KB. At 100 sessions/hour that's ~5 MB/day - same
  envelope as Stage 7's intent payload.

## LLM defense delta

- **New prompt content**: the embed call passes the joined
  command list verbatim. Embedding models do not produce
  natural-language output; there is no OutputFilter pass to
  run because the response is a vector. The existing
  InjectionScorer is run on every command at the lure boundary
  before it reaches the bridge, so commands that fired the
  scorer never reach the embed input either.
- **New jailbreak coverage**: ``tests/llm_defense/`` is the
  natural-language defense corpus; not extended for Stage 8
  because there is no natural-language attack surface in the
  embed call.

## Test plan

`tests/intel/` gains a second module + new tests.

1. **Unit**, ``tests/llm/test_embed.py`` (~6): role passed
   through to the embed model tag, budget consumed, BudgetExhausted
   raised pre-call when exhausted, transport / 5xx / 4xx error
   mapping, vector shape validation.
2. **Unit**, ``tests/intel/test_embeddings.py`` (~8):
   below-min-commands returns None, happy path returns
   ``SessionEmbedding`` with correct shape, max_command_chars
   truncates, propagates LLM errors.
3. **Schema**, ``tests/sessions/test_embedding_persistence.py``
   (~8): v3 migration creates the table, upsert + get round-
   trip, vector blob round-trip (float32 byte order), cascade
   delete, dimension mismatch on get raises, model-filtered
   find_similar, top-k ordering correct.
4. **Integration**, ``tests/bridge/test_embedding_integration.py``
   (~5): bridge spawns the task on DELETE, audit fires,
   timeout audits with TimeoutError, parallel execution with
   intent extraction.
5. **Dashboard**, ``tests/dashboard/test_similar_endpoint.py``
   (~5): GET /api/sessions/{id}/similar returns k neighbours,
   404 when no embedding, alerts panel surfaces
   cluster_match events.

Coverage stays ≥ 90 %.

## Rollback plan

1. ``ANGLERFISH_BRIDGE__EMBEDDING_ENABLED=false``: the bridge
   stops spawning the embedding task; the alerts panel keeps
   showing historical events but no new ones fire.
2. Operators who want to fully back the stage out revert the
   slice commits + restore a schema-v2 DB backup. The forward-
   only migration policy applies; no downgrade migration in-
   tree.
3. The ``embeddings`` table is independent of every other
   table; dropping it has no cascading effect.

## Success criteria

- All tests pass; coverage ≥ 90 %.
- ``anglerfish config show`` reveals
  ``bridge.embedding_enabled`` (default true),
  ``bridge.embedding_timeout_s`` (default 30.0),
  ``bridge.cluster_similarity_threshold`` (default 0.85),
  ``ollama.embed_model`` (default ``nomic-embed-text``),
  ``ollama.session_embed_token_cap`` (default 10_000).
- A session with 5+ commands closes; within 30 seconds
  ``/api/sessions/{id}/similar`` returns either a populated
  neighbour list or an empty list (no similar prior sessions).
- ``behavioral_cluster_matches`` stub on the alerts panel
  reports ``available: true``.
- A second session with similar commands fires
  ``bridge.cluster_match`` and surfaces on the alerts panel.

## Decisions (locked during operator review)

1. **Vector storage: inline BLOB + Python cosine.** Single-
   honeypot scale, no extension to install; sqlite-vec is the
   correct answer above ~50k sessions and is a one-line
   substitution if the time comes.
2. **Embed input: joined attacker commands only.** Excludes the
   bridge's responses (which are LLM output and would skew the
   embedding toward the bridge's behaviour rather than the
   attacker's).
3. **min_commands: 3.** Matches intent extraction. Below that,
   there's no behavioural signal worth embedding.
4. **Similarity threshold: 0.85 default.** Configurable. Above
   0.85 cosine means "very likely the same script / botnet
   client / human operator".
5. **Trigger: same DELETE endpoint, parallel task.** Mirrors
   the Stage 7 intent extraction; both run fire-and-forget.
   The bridge does not wait for either before returning 204.
6. **k=5 default, k_max=20.** Operators rarely need more than
   the top handful; 20 caps the response size for the UI.
7. **Slicing: 5 slices** - LLM extensions, EmbeddingGenerator,
   schema + persistence, bridge integration + cluster-match
   audit, dashboard surface. Each shippable green mid-flight.

## Notes for future-me

- The vector base64 in the audit event is verbose. A future
  optimisation is to store the vector blob directly in a
  bridge-shared tmpfs and have the tailer read by path rather
  than parsing the base64; out of scope for slice 1 and
  measurably noticeable only above ~1000 sessions/hour.
- ``find_similar``'s linear scan starts to drag above ~10k
  rows. The first sign in production will be the
  ``/api/sessions/{id}/similar`` route taking >100ms. At that
  point the right move is sqlite-vec (drop-in via a custom
  function); we keep the inline blob column so the migration
  is one alembic step.
- The cluster-match alert threshold of 0.85 is somewhat
  arbitrary; once Stage 13's visualisation lands operators
  will have visual feedback to retune. Surface the knob in
  the dashboard control plane (Stage 6 publish/poll channel)
  so it can be flipped at runtime, same as
  ``wasting_strategy``.
- Stage 9 (adaptive persona) reads the cluster information.
  Cleanest interface for Stage 9 is a ``cluster_neighbours()``
  method on ``DashboardState`` (which Stage 8 already
  provides for the dashboard route); Stage 9 calls the same
  method during session-open to bias persona selection.
