"""LLM-targeted-attack defense layer.

Stage 1 of the roadmap. Three defenses:

* :class:`OutputFilter` — post-filters LLM responses for leaks
  (``"I am an AI"``, model names, markdown drift, conversational
  filler). Binary fire on any pattern match. Fallback response
  substituted when fired. See :mod:`anglerfish.bridge.defense_patterns`
  for the shipped pattern set.
* :class:`InjectionScorer` — scores attacker input against known
  prompt-injection signatures (override-instructions, persona-switch,
  special chat-template tokens, encoding-evasion, …). Score above
  :attr:`DefenseConfig.injection_threshold` skips the LLM entirely.
* :class:`ModelIntegrity` — verifies at bridge startup that the Ollama
  model's blob layer digest matches an operator-supplied expected
  SHA256. Defends against silent tag re-pointing and supply-chain
  swaps. Opt-in; when unset, a loud structured warning + audit
  entry surfaces the unverified state.

This module ships data types only in Stage 1.2. The filter/scorer
logic lands in Stage 1.3; ``ModelIntegrity`` lands in Stage 1.4.

See ``docs/design/STAGE_1_llm_defense.md`` for the architecture, the
threat-model delta, and the test plan.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "DefenseVerdict",
    "ModelIntegrityError",
]


class DefenseVerdict(BaseModel):
    """Result of one defense check (output filter or injection scorer).

    Frozen, log-friendly. Every defense fire produces one of these and
    writes it to the audit log via the ``bridge.defense_fired`` event.

    The ``snippet`` field is intentionally short (≤120 chars) — long
    enough for an operator to recognize the matched signature, short
    enough that the audit log doesn't grow unbounded on a single
    attacker session full of injection attempts.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    fired: bool = Field(
        description=(
            "True when the defense should take the fallback path. "
            "Output filter: any pattern match → True. Injection scorer: "
            "score ≥ threshold → True."
        ),
    )
    detector: str = Field(
        min_length=1,
        max_length=64,
        description=(
            "Identifier of the rule that fired, namespaced as "
            "'<filter>:<category>' (e.g. 'output_filter:ai_self_disclosure', "
            "'injection:override_instructions'). Use 'injection:no_match' "
            "for the empty-input verdict."
        ),
    )
    snippet: str = Field(
        max_length=120,
        description=(
            "Matched substring from the input, truncated. Empty string "
            "when the verdict reports no match."
        ),
    )
    score: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Confidence/severity in 0.0-1.0. 1.0 for explicit pattern "
            "matches (output filter always uses 1.0 since it's binary). "
            "0.0 for the empty-match case."
        ),
    )


class ModelIntegrityError(Exception):
    """Raised when the Ollama model's layer digest does not match
    :attr:`DefenseConfig.model_expected_hash`.

    The bridge catches this only at startup and exits non-zero — a
    backdoored or silently-swapped model is a refuse-to-serve condition,
    not a runtime fallback.

    Raising at runtime (after bridge boot) is a programmer error: the
    integrity check is a startup-only contract by design.
    """
