# Anglerfish AI - roadmap

14 stages from foundation to full adaptive-deception product. Each
stage is its own design doc, its own PR, ships green, and is
independently rollback-able. See [`PRODUCT.md`](PRODUCT.md) for the
thesis and design principles that constrain every stage.

Status legend: `🟦 not started` · `🟨 in design` · `🟩 in progress` · `✅ shipped`

> **Renumbered in Stage 2C.** The original roadmap had Stage 2 as
> the session store and Stage 11 as a single dashboard overhaul.
> Replacing Cowrie with the native lure landed as the new Stage 2,
> and the dashboard control plane (settings + health + alerts +
> export) pulled forward into Stage 3 so the operator surface is
> in place before the capability stages start producing data.
> The remaining dashboard capability views became Stage 13. Every
> stage after the lure shifted by 1 or 2.

---

## Stage table

| #   | Stage                              | Status         | Est. effort | Design doc                              | Depends on |
| --- | ---------------------------------- | -------------- | ----------- | --------------------------------------- | ---------- |
| 0   | Positioning + product spec         | ✅ shipped     | ~2h         | n/a (the docs themselves)               | -          |
| 1   | LLM defense layer                  | ✅ shipped     | ~6h         | `design/STAGE_1_llm_defense.md`         | 0          |
| 2   | Lure subsystem (Cowrie replacement) | ✅ shipped    | ~12h        | `design/STAGE_2_lure_subsystem.md`      | 1          |
| 3   | Dashboard control plane            | 🟦 not started | ~8h         | `design/STAGE_3_dashboard_control_plane.md` | 2      |
| 4   | Persistent rich session store      | 🟦 not started | ~8h         | `design/STAGE_4_session_store.md`       | 0          |
| 5   | Local-LLM leverage layer           | 🟦 not started | ~8h         | `design/STAGE_5_llm_leverage.md`        | 1          |
| 6   | Capability: active time-wasting    | 🟦 not started | ~6h         | `design/STAGE_6_time_wasting.md`        | 1, 5       |
| 7   | Capability: intent extraction      | 🟦 not started | ~6h         | `design/STAGE_7_intent_extraction.md`   | 1, 4, 5    |
| 8   | Capability: behavioral clustering  | 🟦 not started | ~10h        | `design/STAGE_8_clustering.md`          | 4, 5       |
| 9   | Capability: adaptive persona       | 🟦 not started | ~12h        | `design/STAGE_9_persona.md`             | 5, 7       |
| 10  | Capability: engaged persistence    | 🟦 not started | ~14h        | `design/STAGE_10_persistence.md`        | 1, 9       |
| 11  | Capability: decoy data poisoning   | 🟦 not started | ~14h        | `design/STAGE_11_poisoning.md`          | 4, 7       |
| 12  | Capability: counter-deception      | 🟦 not started | ~10h        | `design/STAGE_12_counter_deception.md`  | 1, 5, 10   |
| 13  | Dashboard capability views overhaul | 🟦 not started | ~10h       | `design/STAGE_13_dashboard_views.md`    | 4, 7, 8, 9 |

**Total estimated effort:** ~126 hours. Spread over weeks/months at a
sustainable pace, not a sprint.

---

## Stage details

### Stage 0 - Positioning + product spec ✅

Done in this commit. Establishes the thesis, design principles,
non-goals, and the design-doc convention everything else hangs off.

Deliverables shipped: [`PRODUCT.md`](PRODUCT.md),
[`design/TEMPLATE.md`](design/TEMPLATE.md), this file, README docs
index updated.

### Stage 1 - LLM defense layer ✅

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

* `src/anglerfish/bridge/defense.py` - `OutputFilter`, `InjectionScorer`,
  `ModelIntegrity`, `DefenseVerdict`, `ModelIntegrityError`,
  `load_pattern_overrides`.
* `src/anglerfish/bridge/defense_patterns.py` - in-tree default patterns;
  every later stage that touches the bridge adds cases to the corpus.
* `DefenseConfig` under `ANGLERFISH_DEFENSE__*` env vars.
* Audit events: `bridge.defense_fired`, `bridge.model_integrity_verified`,
  `bridge.model_integrity_failed`, `bridge.model_integrity_skipped`.
* Bridge errors: `InjectionDetectedError`, `OutputFilterFiredError`.
* 116 test-corpus files in `tests/llm_defense/corpus/` - the source of
  truth for what Stage 1 catches and what it deliberately doesn't.

**Numbers at completion:** 891 tests pass at 92%+ coverage; mypy
strict clean across 147 source files; ruff lint + format clean.

**Why this ordering.** Every later stage adds LLM-driven behaviour.
Building defense once, then layering features on top, means each new
feature inherits the defense automatically. Building features first
and bolting on defense later means re-auditing every feature.

### Stage 2 - Lure subsystem (Cowrie replacement) ✅

Shipped in three commits, each green at commit:

| Slice | Commit  | What                                                  |
| ----- | ------- | ----------------------------------------------------- |
| Design | `3e4584d` | `docs/design/STAGE_2_lure_subsystem.md`              |
| 2A    | `00205a2` | scaffold: `bridge/path.py` extraction, protocol bump 1→2, `CommandRequest.fs_context`, full `src/anglerfish/lure/` package (config, banner, session, fakefs ~50 paths, bridge_client, keys, fallback, commands + LatencyJitter, http stub), 250+ unit tests, `docs/TODO.md` |
| 2B    | `2e517e8` | runtime: `asyncssh`-backed `LureSSHServer`, `_PerIPLimiter`, `_process_handler` shell loop, `runner.py` signal handling, `anglerfish lure serve / validate-config` CLI, 33 integration tests against a real asyncssh client |
| 2C    | (this PR) | env-file rendering + nftables wiring + operator docs + ROADMAP renumber |

**Replaced:** the Cowrie integration shim. Cowrie itself stays in the
tree through a deprecation window (one release cycle) so operators
upgrading in place can run both. A later commit deletes
`src/anglerfish/integration/cowrie*.py`, the `cowrie/` directory, the
`CowrieConfig` model, and the related tests.

**Artifacts the rest of the roadmap depends on:**

* `src/anglerfish/lure/` package: `LureConfig`, `LureServer`,
  `LureSessionContext`, `BridgeClient`, `NativeCommands`,
  `LatencyJitter`, host-key management.
* `LureConfig` under `ANGLERFISH_LURE__*` env vars. Default opt-out
  (the honeypot listener is the product), bait-NIC presence checked
  at startup, per-IP concurrent + sliding-window rpm limits.
* Bridge wire-protocol v2 with optional `fs_context` field.
* `bridge/path.py` shared `normalise_path` helper.
* Audit events: `lure.server_started`, `lure.server_stopped`,
  `lure.session_opened`, `lure.session_closed`, `lure.login_attempt`,
  `lure.fingerprint_observed`, `lure.command_native`,
  `lure.command_bridge`, `lure.bridge_unavailable`,
  `lure.fallback_served`, `lure.rate_limited`, `lure.subsystem_refused`.

**Numbers at completion:** 1170+ tests at 92%+ coverage.

### Stage 3 - Dashboard control plane

**Problem.** The dashboard is read-only today. Operators have no way
to flip features, change concurrency caps, or pull export data
without editing `/etc/anglerfish/anglerfish.env` and restarting
services. Stages 6-12 (capability work) all expect a control plane
to flip them on per-session.

**Deliverables (locked in `project_dashboard_pullforward.md`):**

* `POST /api/settings/bridge` - concurrency cap, per-session token
  budget, wasting strategy. Live-config mutation; no env-file write.
* `POST /api/settings/features` - opt-in toggles for time-wasting,
  engaged persistence, decoy poisoning, counter-deception. Bool,
  default False.
* `GET /api/settings` - current runtime values.
* `GET /api/health/{ollama,forwarder,sessions}` - reachability,
  delivery status, queue depth, token consumption rate.
* `GET /api/alerts` - recent alert events from the audit log,
  paginated, newest first. Stub future stages with `available:false`.
* `GET /api/export/sessions?format=json|csv&from=&to=` and
  `/api/export/audit` - in-memory store + audit log export.
* CSRF on every POST using the existing `csrf.py` synchronizer token.
  No new auth layer.

**Why third** (after the lure). The capability stages (6+) need
operator-visible levers from the moment they ship. Building the
control plane first means later stages add settings keys to it
rather than retro-fitting the UI.

### Stage 4 - Persistent rich session store

**Problem.** Sessions today live in an in-memory ring buffer
([`src/anglerfish/dashboard/state.py`](../src/anglerfish/dashboard/state.py)).
The buffer is fixed-size, lost on restart, not query-able by anything
but the dashboard. Stages 7/8/9 all need to persist rich per-session
data: turns, observations, embeddings, intent summaries.

**Deliverables:**

* SQLite schema for sessions, turns, observations, embeddings,
  intent summaries.
* `src/anglerfish/sessions/store.py` - async API mirroring
  `CredentialStore`.
* Replaces in-memory ring; dashboard reads from store.
* Migration: existing `sessions.jsonl` fallback file is importable.

**Why fourth** (after lure + dashboard). Foundational data layer
that stages 7/8/9 sit on top of. Built once, stable interface for
years. The Stage 3 export endpoints get a richer underlying store
on the day this lands.

### Stage 5 - Local-LLM leverage layer

**Problem.** Today there's one LLM call pattern: bridge → Ollama →
text response. For stages 6-12 we need: streaming responses (for
time-wasting), structured JSON output (for intent extraction),
multi-model orchestration (cheap+fast for routine, expensive+accurate
for analysis), token-budget tracking (per-session limits), warm-pool
management (eliminate cold-start latency).

**Deliverables:**

* `src/anglerfish/llm/` - new module replacing
  `src/anglerfish/bridge/client.py`.
* Multi-model config: `ANGLERFISH_LLM__FAST_MODEL` (default
  `qwen3:14b`-class), `ANGLERFISH_LLM__DEEP_MODEL` (default
  `phi-4` or similar 14B+ reasoning model),
  `ANGLERFISH_LLM__EMBED_MODEL` (default `nomic-embed-text`).
  Deepseek family avoided in defaults, third-party security reviews
  flagged CCP-aligned content moderation that surfaces in shell
  honeypot contexts. See `docs/MODEL_SETUP.md`.
* Streaming response API.
* Structured-output mode (JSON schema validation).
* Per-session token budget tracking surfaced in dashboard.

**Why fifth** (after defense + lure + dashboard + store). Stages
6-12 all use this runtime. Defense layer wraps it; store persists
its outputs; the dashboard surfaces token-budget metrics.

### Stage 6 - Active time-wasting

**Problem.** Today every command gets a fast LLM response. Human
attackers move on quickly. We want to *stretch* sessions: more
multi-turn back-and-forth, longer responses, plausible "loading"
moments, occasional asks-for-clarification.

**Deliverables:**

* `src/anglerfish/bridge/strategies/wasting.py` - strategy plug-in.
* Config: `ANGLERFISH_BRIDGE__WASTING_STRATEGY=off|light|aggressive`,
  flippable via Stage 3's `POST /api/settings/bridge` endpoint.
* Per-session time budget so we don't keep one attacker forever.
* New dashboard metric: avg time-wasted per session, vs baseline
  (sessions with strategy=off).

**Why sixth.** Smallest LLM-driven feature, proves the Stage 5
runtime end-to-end before we build harder things on it.

### Stage 7 - LLM intent extraction

**Problem.** Today threat intel is rule-based MITRE techniques: useful
but low-abstraction. Operators want natural-language summaries: *"this
attacker brute-forced SSH from a compromised IoT device, then
deployed XMRig with a pool config pointing to pool.attacker.example.
Profile: opportunistic cryptojacking. Confidence: high."*

**Deliverables:**

* `src/anglerfish/intel/intent.py` - end-of-session summarizer.
* Structured output schema (Pydantic): who, what, why, confidence,
  matched techniques.
* Dashboard panel showing the intent summary per session.
* Splunk forward of intent summaries (separate sourcetype).
* Stored in session store (Stage 4).
* Stage 3 alerts panel switches `intent summary alerts` from
  `available:false` to live data.

**Why seventh.** Highest user-facing value of any single capability.
Demonstrates "intel, not logs"; the thesis in one feature.

### Stage 8 - Behavioral clustering

**Problem.** Today the only way to recognize "same attacker, different
IP" is exact JA3/HASSH match. Real botnets rotate identifiers. We
want vector embeddings of session behavior and clustering on top.

**Deliverables:**

* `src/anglerfish/intel/embeddings.py` - generate session embeddings
  via the local embedding model (Stage 5).
* Vector storage in SQLite (sqlite-vec or inline).
* Re-identification queries: "show me sessions similar to session X."
* Dashboard cluster view (lands here as a Stage 13 preview, formal
  visualization in Stage 13).
* Stage 3 alerts panel switches `cluster matches` from
  `available:false` to live data.

**Why eighth.** Needs persistent store (Stage 4) and multi-model
runtime (Stage 5). Unlocks attacker-profile features in Stage 9.

### Stage 9 - Adaptive persona

**Problem.** Today every attacker sees the same fake hostname /
filesystem / process list. A real production environment serves
different attackers different views.

**Deliverables:**

* Persona definitions: `forgotten-debian-box`, `gpu-rig`,
  `ad-joined-workstation`, `dev-laptop`, etc.
* Per-persona filesystem overlay, system-prompt persona block,
  process-list template.
* Behavior-driven persona selection: cluster info from Stage 8 +
  intent inference from Stage 7 → which persona to present.
* Operator override: pin a session to a persona for testing.

**Why ninth.** Needs intent extraction (Stage 7) to choose persona
and clustering (Stage 8) to bias choice based on similar past
attackers.

### Stage 10 - Engaged persistence

**Problem.** Today when an attacker installs a backdoor (`crontab -e`,
`systemctl enable malicious.service`, `~/.ssh/authorized_keys`), the
LLM acknowledges but we never see what they'd do *next*, because the
session ends and they don't come back to "their" foothold.

**Deliverables:**

* Detection of persistence attempts (regex + LLM classifier).
* Per-session "fake state" tracking: stored "backdoor" identity,
  pretended-installed cron, fake systemd unit, etc.
* `crontab -l` returns the fake entry. `systemctl status backdoor`
  returns plausible status. `~/.ssh/authorized_keys` echoes their key.
* Operator opt-in: `ANGLERFISH_BRIDGE__ENGAGED_PERSISTENCE=true`
  (default `false`, this is aggressive and changes the threat model;
  flip via Stage 3's settings endpoint).
* THREAT_MODEL.md update: we're now generating attacker-facing
  falsehoods that could affect attacker decisions; that's the design
  goal but also a new responsibility.

**Why tenth.** Highest-risk capability. Needs adaptive persona
(Stage 9) for credibility (a "backdoor" on the "wrong" persona type
is unconvincing).

### Stage 11 - Decoy data poisoning

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
* Operator opt-in flag (via Stage 3's features endpoint).
* Stage 3 alerts panel switches `honeytoken callback hits` from
  `available:false` to live data.

**Why eleventh.** Needs intent extraction (Stage 7) to trigger
(only poison when attacker is high-confidence malicious) and the
session store (Stage 4) for the registry.

### Stage 12 - Active counter-deception

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
* Operator opt-in flag, default off (via Stage 3's features endpoint).

**Why twelfth.** Most aggressive capability. Needs every prior
defense layer mature.

### Stage 13 - Dashboard capability views overhaul

**Problem.** Stage 3 shipped the control plane (settings, health,
alerts, export) on top of the v0.1 in-memory state. By the time
Stages 7-12 land, there is far more data to surface: per-session
intent summaries, cluster maps, honeytoken registries, persona +
counter-deception state. The Stage 3 endpoints are extended in
each capability stage; this stage builds the visual layer on top
of them.

**Deliverables:**

* Per-session detail view showing: turns, intent summary, persona
  selected, time-wasted, honeytokens served, counter-deception state.
* Cluster visualization (Stage 8 data).
* Honeytoken registry view (Stage 11 data).
* Export pipeline: STIX 2.1, MISP JSON, PDF report (Stage 3 already
  ships JSON + CSV).
* Live narrator: optional dashboard panel where the LLM produces a
  running natural-language commentary of in-progress sessions.

**Why last.** Surfaces everything built in stages 7-12. Builds on
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
