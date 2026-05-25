# Anglerfish AI - product spec

Personal planning doc. This is what I'm building, why, and how I'll
know I'm off-track. Not user-facing copy, meant for future-me opening
this file in six months and asking "wait, what was this for again?"

---

## Thesis

> Anglerfish is an **adaptive-deception** SSH honeypot. Where other
> honeypots observe and log, Anglerfish engages, wastes time,
> poisons attacker loot, and produces machine-readable intelligence
> about who attackers are, what they want, and what tooling they ship -
> all driven by a local LLM with no cloud dependencies.

Every feature has to answer one question: *does this advance adaptive
deception, local-LLM leverage, security posture, presentable intel, or
defense against AI-targeted attacks?* If no, it doesn't ship.

---

## Why this exists (and why not just use T-Pot)

T-Pot is the gold standard honeypot platform: 20+ honeypot types,
built-in ELK, automatic submission to HoneyDB/DShield, large community.
For "I want to run a honeypot today and contribute data to the
community" T-Pot wins.

Anglerfish is a different bet. Three things T-Pot can't do:

1. **Dynamic LLM-driven responses to any command**. Static-fakefs
   honeypots return canned errors for anything outside their pickle.
   Anglerfish hallucinates a plausible answer for anything.
2. **Adaptive engagement**: same physical honeypot, different
   apparent persona per session. Cred-stuffer sees a small forgotten
   box; crypto-miner sees a fat GPU rig; APT recon sees an AD-joined
   workstation.
3. **Active counter-deception**: pretend backdoors work, serve
   poisoned credentials, garble malware downloads. T-Pot is passive;
   Anglerfish disrupts.

This is research-grade infrastructure. The audience is one operator
(me) who wants to study attacker behavior in depth and produce
threat intel of higher quality than "this IP tried to SSH."

---

## Design principles

These constrain every stage. Holding them is what separates engineering
from AI-assisted slop.

### 1. Spec before code

Each stage opens with a design doc under `docs/design/STAGE_N_*.md`,
written from the [template](design/TEMPLATE.md). PR doesn't start until
the doc is committed.

### 2. Local LLM only, for resilience

Local Ollama is the only LLM interface, not because cloud is bad,
but because:

* If a cloud provider gets compromised, my honeypot keeps running.
* If a cloud provider rate-limits or deprecates a model, my honeypot
  keeps running.
* If a cloud provider's TOS changes to forbid security-research use,
  my honeypot keeps running.
* If the cloud provider's outputs are subpoenaed, my attacker data
  doesn't leak to them.

**Implications enforced at every stage:**

* Ollama is the only LLM client. No `httpx.post("https://api.openai.com/...")`
  anywhere in the codebase, even for "quality" intent extraction.
* Model integrity verified at startup: hash check against an
  operator-supplied expected value. A backdoored model swap should
  cause the bridge to refuse to start.
* Multi-model support - small fast model for routine generation,
  larger model for deep analysis. Both local. Operator can swap models
  with one config change.
* Output post-filter catches the case where the model has been
  swapped or corrupted (returns garbage, refuses, or leaks "I am an
  AI"; all caught the same way).

### 3. Two-layer LLM defense at every boundary

The LLM is an attack surface. Every stage adds tests against:

* **Prompt injection** from attacker input (jailbreaks, role-play,
  "ignore previous instructions", multi-language injection).
* **Output integrity** - model leaks "I am an AI", "language model",
  "honeypot", "Anthropic", "OpenAI", etc.
* **Model degradation** - model returns empty, refusal, or repetitive
  garbage.

Defense fires → hard fallback to scripted response, audit log entry,
no quiet failure.

A fixed jailbreak/injection corpus lives at `tests/llm_defense/`.
Every stage that touches the bridge adds new test cases.

### 4. Data is presented three ways

Every new piece of intel:

* **Dashboard view** - operator can see it.
* **REST endpoint** - operator can query it programmatically.
* **Export format** - at least CSV + JSON; STIX 2.1 / MISP for
  threat-intel data where it makes sense.

No data lives only in logs. If I can't view it on the dashboard or
export it in 30 seconds, it doesn't ship.

### 5. Token-budget discipline (even though local)

Every LLM call has a token budget. Cheap-model first, expensive-model
only when needed (per-session high-stakes decisions). Tracked
per-session, surfaced in the dashboard. Reasons:

* Local inference is not free - GPU/CPU time, power, latency budget.
* Forces honest cost/benefit on each new LLM call.
* Provides an attack-surface metric: a session that burns 10× the
  token budget is suspicious.

### 6. Each stage ships green

Ruff, mypy strict, pytest ≥90% coverage gate stays enforced for every
stage. No "we'll fix it later." If a stage can't ship green, the spec
was wrong, back to step 1.

### 7. Security review every stage

* New attack surface → new entry in `THREAT_MODEL.md`.
* New LLM-driven output → entry in the audit-log spec.
* New "engaging" feature (persona, persistence, poisoning, disruption)
  → operator opt-in flag, default off.
* New external integration → entry in
  [`SECURITY.md`](../SECURITY.md) scope.

---

## The seven capabilities

These are what makes Anglerfish different from the static-fakefs
SSH honeypot pattern. Order is the implementation order from
[`ROADMAP.md`](ROADMAP.md), which is deliberately *not* "highest
user-value first"; it's "lowest foundational risk first."

| # | Capability | What it does | Why it's unique |
|---|------------|--------------|-----------------|
| 1 | **Active time-wasting** | Stretch human-attacker sessions with verbose error messages, multi-turn clarifications, fake-lag responses | No other honeypot deliberately engages to consume attacker time |
| 2 | **Adaptive persona** | Same honeypot, different apparent identity per attacker, chosen from observed TTPs | Static-fakefs honeypots ship one fixed filesystem; Anglerfish's is dynamic |
| 3 | **Engaged persistence** | Pretend installed backdoors actually work; capture the attacker's stage-2 TTPs that would otherwise never run | Other honeypots log entry; Anglerfish captures the whole kill chain |
| 4 | **Decoy data poisoning** | Generate honeytokens (creds, AWS keys, SSH keys) the attacker steals; track them globally | Turns one honeypot into a tracking-beacon factory |
| 5 | **LLM intent extraction** | End-of-session natural-language summary: who, what, why, confidence | Higher abstraction than rule-based MITRE - what an operator actually wants |
| 6 | **Behavioral clustering** | Session-level vector embeddings; re-identify attackers across IP/JA3 changes | Botnet correlation without network identifiers |
| 7 | **Active counter-deception** | Corrupt attacker loot: garbled binaries, wrong-but-plausible outputs, time-bomb responses | Going from passive observation to active disruption |

---

## Non-goals

Things I will not build, so future-me doesn't get distracted:

* **More honeypot types.** T-Pot already bundles Dionaea, Honeytrap,
  Elasticpot, etc. If I want non-SSH coverage, I run T-Pot alongside.
* **Bulk submission to community feeds (HoneyDB, DShield).** T-Pot does
  this. The alert webhook can post to whatever the operator wants;
  bulk-feed integration is duplication.
* **Cloud-LLM fallback.** Even for "high-quality intent extraction"
  where a 70B cloud model would do better than a 7B local one.
  Resilience > quality. See [Design principle 2](#2-local-llm-only-for-resilience).
* **Multi-tenant operation.** One operator, one deployment, one
  attacker population. No "Anglerfish-as-a-service."
* **Dashboards-as-a-service.** No SaaS dashboard. The whole stack runs
  on the honeypot host or one VM next to it.

---

## Non-goals I might revisit

* **Sharing honeytoken registry across deployments.** Stage 4 ships
  with single-deployment tokens. A multi-deployment registry would be
  much more powerful (the whole point of honeytokens is global
  tracking) but it requires shared infrastructure, would need to
  re-read this doc and decide.
* **MISP / OpenCTI integration.** Stage 11 lists STIX 2.1 export; full
  MISP/OpenCTI push integrations are an obvious follow-on if I ever
  want to share data with an info-sharing group.

---

## Success criteria

In one year, Anglerfish is successful if:

* All 11 roadmap stages have shipped and remain green on the quality
  gates.
* I have at least one real captured attack session per week with an
  LLM-extracted intent summary I'd be willing to share with a SOC team.
* The local-LLM-only constraint hasn't forced an architectural
  compromise.
* No LLM-targeted attack (jailbreak, injection, model swap) has
  bypassed the defense layer without being caught and logged.
* I can explain any piece of the codebase to a stranger in <5 minutes.

In one year, Anglerfish is failing if:

* I'm copy-pasting code from one stage to the next instead of
  refactoring.
* I've added a "cloud API just for this one thing" exception.
* The dashboard shows data nobody (including me) actually looks at.
* I can't tell the difference between an LLM hallucination and a real
  attacker action in the captured intel.
