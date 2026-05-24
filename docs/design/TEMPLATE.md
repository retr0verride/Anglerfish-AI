# Stage N - <one-line title>

Every stage from [`ROADMAP.md`](../ROADMAP.md) opens with a copy of
this template, filled in, committed to `docs/design/STAGE_N_<slug>.md`.
The PR for the stage doesn't open until the design doc is committed
and self-reviewed.

Keep each section honest. Empty sections that hide trade-offs are
worse than no doc. If the threat-model delta is "none," say "none and
here's why I'm sure."

---

## Problem

What's broken / missing without this stage? One paragraph. Cite
specific user-visible behavior or specific code paths (file:line).
If the problem is "I want to build a cool feature," go back to
[`PRODUCT.md`](../PRODUCT.md) and find which design principle it
serves, or kill the stage.

## Proposed interface

What this stage exposes to the rest of the system. Include:

* New or modified Python module(s) with the public function/class
  signatures.
* New config keys (under `ANGLERFISH_*`) with type, default, validation
  rules.
* New REST endpoints with path, method, request/response shape.
* New dashboard views (sketch the layout in text - boxes and arrows
  are fine).
* New export format(s).
* New audit-log event types.

Be specific enough that if a stranger implemented from this spec, the
result would be 95% identical to what I'd write.

## Out of scope

What this stage explicitly does not do, with a one-line reason each.
Catches scope creep early.

## Threat-model delta

What new attack surface this stage introduces. Pull from
[`THREAT_MODEL.md`](../THREAT_MODEL.md) categories: STRIDE, trust
boundaries, untrusted-input handling. For each:

* The new threat.
* The mitigation in this stage's code.
* The residual risk (what we accept).

If the answer is "no new attack surface," explain why convincingly -
adding any LLM-driven behavior at minimum widens the AI-attack
surface.

## LLM defense delta

Specific to Anglerfish's local-LLM architecture. For each new LLM
call this stage adds:

* What gets sent in the prompt (attacker-controlled? operator-only?).
* What the model is expected to return (free text? structured JSON?).
* The output post-filter rule.
* The new entries in `tests/llm_defense/` (jailbreak cases this stage
  must defend against).

If this stage doesn't add LLM calls, write "no LLM delta."

## Test plan

Concrete enumerated tests, mapping 1:1 to `pytest` functions:

1. **Unit**, `tests/<module>/test_<feature>.py::test_X`. One line per
   case.
2. **Integration**: full pipeline tests using `tmp_path` and real
   SQLite/Ollama where possible.
3. **Security**: new entries in `tests/llm_defense/` and
   `tests/threat/test_*.py` for the threats listed above.
4. **Coverage target**: must keep total coverage ≥90% after this
   stage merges. List any new files exempt from the gate (with
   reason).

## Rollback plan

How to undo this stage if it goes wrong in production. Concrete steps:

1. Config switch to disable the new behavior.
2. Database migration to reverse any schema change.
3. Files to delete.
4. Services to restart.

If "no rollback needed because the change is purely additive," say so.

## Success criteria

How I know the stage is done. Bullet list of observable, testable
conditions:

* All tests pass.
* Coverage ≥90%.
* `anglerfish config show` reveals the new keys with their defaults.
* The new dashboard view renders against a populated session DB.
* The new export format round-trips a captured session.
* Etc.

If a criterion isn't observable, rewrite it until it is. "It feels
good" is not a criterion.

## Notes for future-me

Anything that surprised me during design, edge cases I considered but
didn't handle, links to outside reading, decisions I made for
non-obvious reasons. The point of this section is to spare future-me
from re-deriving the same conclusions in six months.
