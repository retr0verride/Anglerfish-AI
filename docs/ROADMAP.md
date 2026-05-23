# Anglerfish AI — roadmap

11 stages from foundation to full adaptive-deception product. Each
stage is its own design doc, its own PR, ships green, and is
independently rollback-able. See [`PRODUCT.md`](PRODUCT.md) for the
thesis and design principles that constrain every stage.

Status legend: `🟦 not started` · `🟨 in design` · `🟩 in progress` · `✅ shipped`

---

## Stage table

| #   | Stage                          | Status        | Est. effort | Design doc                              | Depends on |
| --- | ------------------------------ | ------------- | ----------- | --------------------------------------- | ---------- |
| 0   | Positioning + product spec     | ✅ shipped     | ~2h         | n/a (the docs themselves)               | —          |
| 1   | LLM defense layer              | ✅ shipped     | ~6h         | `design/STAGE_1_llm_defense.md`         | 0          |
| 2   | Persistent rich session store  | 🟦 not started | ~8h         | `design/STAGE_2_session_store.md`       | 0          |
| 3   | Local-LLM leverage layer       | 🟦 not started | ~8h         | `design/STAGE_3_llm_leverage.md`        | 1          |
| 4   | Capability: active time-wasting | 🟦 not started | ~6h         | `design/STAGE_4_time_wasting.md`        | 1, 3       |
| 5   | Capability: intent extraction  | 🟦 not started | ~6h         | `design/STAGE_5_intent_extraction.md`   | 1, 2, 3    |
| 6   | Capability: behavioral clustering | 🟦 not started | ~10h     | `design/STAGE_6_clustering.md`          | 2, 3       |
| 7   | Capability: adaptive persona   | 🟦 not started | ~12h        | `design/STAGE_7_persona.md`             | 3, 5       |
| 8   | Capability: engaged persistence | 🟦 not started | ~14h       | `design/STAGE_8_persistence.md`         | 1, 7       |
| 9   | Capability: decoy data poisoning | 🟦 not started | ~14h      | `design/STAGE_9_poisoning.md`           | 2, 5       |
| 10  | Capability: counter-deception  | 🟦 not started | ~10h        | `design/STAGE_10_counter_deception.md`  | 1, 3, 8    |
| 11  | Dashboard + export overhaul    | 🟦 not started | ~12h        | `design/STAGE_11_dashboard.md`          | 2, 5, 6, 7 |

**Total estimated effort:** ~108 hours. Spread over weeks/months at a
sustainable pace, not a sprint.

---

## Stage details

### Stage 0 — Positioning + product spec ✅

Done in this commit. Establishes the thesis, design principles,
non-goals, and the design-doc convention everything else hangs off.

Deliverables shipped: [`PRODUCT.md`](PRODUCT.md),
[`design/TEMPLATE.md`](design/TEMPLATE.md), this file, README docs
index updated.

### Stage 1 — LLM defense layer ✅

**Problem.** The bridge had zero defense against LLM-targeted
attacks. Jailbreak prompts could extract "I am an AI" confessions.
Prompt injection could flip persona mid-session. Model degradation
(corrupt weights, swapped tag, backdoored upstream) went undetected.

**Shipped** in seven slices, each green at commit:

| Slice | Commit  | What                                                   |
| ----- | ------- | ------------------------------------------------------ |
| Design | `a58b6d6` | `docs/design/STAGE_1_llm_defense.md`                   |
| 1.1   | `b6b9efb` | `DefenseConfig` Pydantic model + validation tests     |
| 1.2   | `e07ba2e` | `defense.py` (DefenseVerdict + ModelIntegrityError) + `defense_patterns.py` (45 patterns across 14 categories) + structural tests |
| 1.3   | `fb7ef66` | `OutputFilter` + `InjectionScorer` + TOML overrides   |
| 1.4   | `7d93f79` | `ModelIntegrity` with Ollama layer-digest pinning     |
| 1.5   | `d8ad066` | Bridge request-flow + startup integration             |
| 1.6   | `4e5a5d4` | 116-file corpus (35 leak / 20 safe-output / 36 inj / 25 safe-input) + 6 pattern refinements driven by corpus |
| 1.7   | (this PR) | `.env.example` + `THREAT_MODEL.md` + roadmap flip     |

**Artifacts the rest of the roadmap depends on:**

* `src/anglerfish/bridge/defense.py` — `OutputFilter`, `InjectionScorer`,
  `ModelIntegrity`, `DefenseVerdict`, `ModelIntegrityError`,
  `load_pattern_overrides`.
* `src/anglerfish/bridge/defense_patterns.py` — in-tree default patterns;
  every later stage that touches the bridge adds cases to the corpus.
* `DefenseConfig` under `ANGLERFISH_DEFENSE__*` env vars.
* Audit events: `bridge.defense_fired`, `bridge.model_integrity_verified`,
  `bridge.model_integrity_failed`, `bridge.model_integrity_skipped`.
* Bridge errors: `InjectionDetectedError`, `OutputFilterFiredError`.
* 116 test-corpus files in `tests/llm_defense/corpus/` — the source of
  truth for what Stage 1 catches and what it deliberately doesn't.

**Numbers at completion:** 891 tests pass at 92%+ coverage; mypy
strict clean across 147 source files; ruff lint + format clean.

**Why this ordering.** Every later stage adds LLM-driven behaviour.
Building defense once, then layering features on top, means each new
feature inherits the defense automatically. Building features first
and bolting on defense later means re-auditing every feature.

### Stage 2 — Persistent rich session store

**Problem.** Sessions today live in an in-memory ring buffer
([`src/anglerfish/dashboard/state.py`](../src/anglerfish/dashboard/state.py)).
The buffer is fixed-size, lost on restart, not query-able by anything
but the dashboard. Stages 5/6/7 all need to persist rich per-session
data: turns, observations, embeddings, intent summaries.

**Deliverables:**

* SQLite schema for sessions, turns, observations, embeddings,
  intent summaries.
* `src/anglerfish/sessions/store.py` — async API mirroring
  `CredentialStore`.
* Replaces in-memory ring; dashboard reads from store.
* Export endpoints: `GET /api/sessions/export?format=csv|json|stix2`.
* Migration: existing `sessions.jsonl` fallback file is importable.

**Why second** (after defense). Foundational data layer that stages
5/6/7 sit on top of. Built once, stable interface for years.

### Stage 3 — Local-LLM leverage layer

**Problem.** Today there's one LLM call pattern: bridge → Ollama →
text response. For stages 4-10 we need: streaming responses (for
time-wasting), structured JSON output (for intent extraction),
multi-model orchestration (cheap+fast for routine, expensive+accurate
for analysis), token-budget tracking (per-session limits), warm-pool
management (eliminate cold-start latency).

**Deliverables:**

* `src/anglerfish/llm/` — new module replacing
  `src/anglerfish/bridge/client.py`.
* Multi-model config: `ANGLERFISH_LLM__FAST_MODEL` (default
  `deepseek-coder:1.3b`-class), `ANGLERFISH_LLM__DEEP_MODEL` (default
  `deepseek-coder:6.7b`-class), `ANGLERFISH_LLM__EMBED_MODEL` (default
  `nomic-embed-text`).
* Streaming response API.
* Structured-output mode (JSON schema validation).
* Per-session token budget tracking surfaced in dashboard.

**Why third** (after defense + store). Stages 4-10 all use this
runtime. Defense layer wraps it; store persists its outputs.

### Stage 4 — Active time-wasting

**Problem.** Today every command gets a fast LLM response. Human
attackers move on quickly. We want to *stretch* sessions: more
multi-turn back-and-forth, longer responses, plausible "loading"
moments, occasional asks-for-clarification.

**Deliverables:**

* `src/anglerfish/bridge/strategies/wasting.py` — strategy plug-in.
* Config: `ANGLERFISH_BRIDGE__WASTING_STRATEGY=off|light|aggressive`.
* Per-session time budget so we don't keep one attacker forever.
* New dashboard metric: avg time-wasted per session, vs baseline
  (sessions with strategy=off).

**Why fourth.** Smallest LLM-driven feature, proves the Stage 3
runtime end-to-end before we build harder things on it.

### Stage 5 — LLM intent extraction

**Problem.** Today threat intel is rule-based MITRE techniques: useful
but low-abstraction. Operators want natural-language summaries: *"this
attacker brute-forced SSH from a compromised IoT device, then
deployed XMRig with a pool config pointing to pool.attacker.example.
Profile: opportunistic cryptojacking. Confidence: high."*

**Deliverables:**

* `src/anglerfish/intel/intent.py` — end-of-session summarizer.
* Structured output schema (Pydantic): who, what, why, confidence,
  matched techniques.
* Dashboard panel showing the intent summary per session.
* Splunk forward of intent summaries (separate sourcetype).
* Stored in session store (Stage 2).

**Why fifth.** Highest user-facing value of any single capability.
Demonstrates "intel, not logs" — the thesis in one feature.

### Stage 6 — Behavioral clustering

**Problem.** Today the only way to recognize "same attacker, different
IP" is exact JA3/HASSH match. Real botnets rotate identifiers. We
want vector embeddings of session behavior and clustering on top.

**Deliverables:**

* `src/anglerfish/intel/embeddings.py` — generate session embeddings
  via the local embedding model (Stage 3).
* Vector storage in SQLite (sqlite-vec or inline).
* Re-identification queries: "show me sessions similar to session X."
* Dashboard cluster view.

**Why sixth.** Needs persistent store (Stage 2) and multi-model
runtime (Stage 3). Unlocks attacker-profile features in Stage 7.

### Stage 7 — Adaptive persona

**Problem.** Today every attacker sees the same fake hostname /
filesystem / process list. A real production environment serves
different attackers different views.

**Deliverables:**

* Persona definitions: `forgotten-debian-box`, `gpu-rig`,
  `ad-joined-workstation`, `dev-laptop`, etc.
* Per-persona filesystem overlay, system-prompt persona block,
  process-list template.
* Behavior-driven persona selection: cluster info from Stage 6 +
  intent inference from Stage 5 → which persona to present.
* Operator override: pin a session to a persona for testing.

**Why seventh.** Needs intent extraction (Stage 5) to choose persona
and clustering (Stage 6) to bias choice based on similar past
attackers.

### Stage 8 — Engaged persistence

**Problem.** Today when an attacker installs a backdoor (`crontab -e`,
`systemctl enable malicious.service`, `~/.ssh/authorized_keys`), the
LLM acknowledges but we never see what they'd do *next* — because the
session ends and they don't come back to "their" foothold.

**Deliverables:**

* Detection of persistence attempts (regex + LLM classifier).
* Per-session "fake state" tracking: stored "backdoor" identity,
  pretended-installed cron, fake systemd unit, etc.
* `crontab -l` returns the fake entry. `systemctl status backdoor`
  returns plausible status. `~/.ssh/authorized_keys` echoes their key.
* Operator opt-in: `ANGLERFISH_BRIDGE__ENGAGED_PERSISTENCE=true` (default
  `false` — this is aggressive and changes the threat model).
* THREAT_MODEL.md update: we're now generating attacker-facing
  falsehoods that could affect attacker decisions; that's the design
  goal but also a new responsibility.

**Why eighth.** Highest-risk capability. Needs adaptive persona
(Stage 7) for credibility (a "backdoor" on the "wrong" persona type
is unconvincing).

### Stage 9 — Decoy data poisoning

**Problem.** Attackers steal `/etc/passwd`, `~/.aws/credentials`,
`~/.ssh/config` etc. We could generate plausible-but-traceable content
they steal, then track where those tokens get used.

**Deliverables:**

* Honeytoken generator: AWS access keys, SSH keys, DB connection
  strings, API tokens. Each generated with a registered identifier.
* Honeytoken registry in the session store.
* Callback receivers: when a honeytoken hits a tracked endpoint
  (sinkhole URL, fake AWS-style API), correlate back to the source
  session.
* Legal/ethical doc: `docs/HONEYTOKENS.md`. We are now actively
  distributing tracking beacons. Operator must read + acknowledge.
* Operator opt-in flag.

**Why ninth.** Needs intent extraction (Stage 5) to trigger
(only poison when attacker is high-confidence malicious) and the
session store (Stage 2) for the registry.

### Stage 10 — Active counter-deception

**Problem.** When a high-confidence malicious session is detected, we
have options beyond passive observation. Serve garbled binaries when
the attacker tries to `wget` a payload. Return wrong-but-plausible
output that wastes the attacker's analysis time. Inject random
delays to confuse timing-sensitive malware.

**Deliverables:**

* Counter-deception strategies, opt-in per session via the persona
  layer.
* `garbled-binary` strategy: when attacker downloads a tracked file,
  serve a byte-corrupted version.
* `time-bomb` strategy: responses gradually become wrong over the
  session lifetime.
* THREAT_MODEL.md update: we're now actively producing wrong outputs
  meant to harm attacker workflows. Risk of false-positive
  counter-deception against a security researcher who *is* legitimately
  studying the honeypot. Operator must understand.
* Operator opt-in flag, default off.

**Why tenth.** Most aggressive capability. Needs every prior defense
layer mature.

### Stage 11 — Dashboard + export overhaul

**Problem.** After 10 stages of new data, the dashboard is the
weakest link — built for the v0.1 schema, not for intent summaries,
embeddings, personas, honeytokens, counter-deception state.

**Deliverables:**

* Per-session detail view showing: turns, intent summary, persona
  selected, time-wasted, honeytokens served, counter-deception state.
* Cluster visualization (Stage 6).
* Honeytoken registry view (Stage 9).
* Export pipeline: STIX 2.1, MISP JSON, CSV, JSON, PDF report.
* Live narrator: optional dashboard panel where the LLM produces a
  running natural-language commentary of in-progress sessions.

**Why last.** Surfaces everything built in stages 1-10. Builds on
top of a stable data layer rather than re-rendering as that layer
changes.

---

## Working agreement with future-me

When picking up the next stage:

1. Re-read [`PRODUCT.md`](PRODUCT.md). The thesis hasn't changed; make
   sure the stage still serves it.
2. Open the design doc template, fill it in, commit it BEFORE writing
   any production code.
3. Self-review the design doc the next day. Sleep-on-it test catches
   bad ideas cheaply.
4. Implement against the design doc. Deviations require updating the
   doc, not silent code drift.
5. Update this file's stage table when status changes.

When status drifts from this roadmap (which it will), update this
file. A roadmap that's out of date is worse than no roadmap.
