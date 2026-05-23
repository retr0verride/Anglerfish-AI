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
  entry surfaces the unverified state. *Lands in Stage 1.4.*

See ``docs/design/STAGE_1_llm_defense.md`` for the architecture, the
threat-model delta, and the test plan.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from anglerfish.bridge.defense_patterns import (
    INJECTION_PATTERNS,
    OUTPUT_PATTERNS,
    PatternSpec,
    compile_pattern,
)
from anglerfish.config.models import DefenseConfig

__all__ = [
    "DefenseVerdict",
    "InjectionScorer",
    "ModelIntegrityError",
    "OutputFilter",
    "load_pattern_overrides",
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


# ---------------------------------------------------------------------------
# Operator-supplied TOML pattern overrides
# ---------------------------------------------------------------------------


def _coerce_specs(items: Any, kind: str) -> list[PatternSpec]:
    """Validate a list of pattern entries from a TOML file.

    Raises :class:`ValueError` with a category-indexed message on any
    structural problem so a malformed override file fails loudly at
    bridge startup rather than silently disabling defense.
    """
    if not isinstance(items, list):
        raise ValueError(
            f"pattern override section {kind!r} must be a TOML array of "
            f"tables ([[{kind}]]), got {type(items).__name__}",
        )
    result: list[PatternSpec] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"{kind}[{i}] is not a TOML table")
        for required in ("pattern", "category", "severity"):
            if required not in item:
                raise ValueError(
                    f"{kind}[{i}] missing required key: {required!r}",
                )
        pattern = item["pattern"]
        if not isinstance(pattern, str) or not pattern:
            raise ValueError(f"{kind}[{i}] 'pattern' must be a non-empty string")
        category = item["category"]
        if not isinstance(category, str) or not category:
            raise ValueError(f"{kind}[{i}] 'category' must be a non-empty string")
        severity = item["severity"]
        if not isinstance(severity, (int, float)) or isinstance(severity, bool):
            raise ValueError(f"{kind}[{i}] 'severity' must be a number")
        sev_f = float(severity)
        if not 0.0 <= sev_f <= 1.0:
            raise ValueError(
                f"{kind}[{i}] 'severity' must be in 0.0-1.0, got {sev_f}",
            )
        # Validate the regex compiles so a bad pattern is caught at
        # load time, not at first attacker request.
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(
                f"{kind}[{i}] invalid regex in category {category!r}: {exc}",
            ) from exc
        result.append(
            {"pattern": pattern, "category": category, "severity": sev_f},
        )
    return result


def load_pattern_overrides(
    path: Path,
) -> tuple[list[PatternSpec], list[PatternSpec]]:
    """Load operator-supplied detector patterns from a TOML file.

    Returns ``(output_overrides, injection_overrides)``. Either list may
    be empty when the file omits the corresponding section.

    The expected TOML schema is::

        [[output]]
        pattern = '''my-internal-secret-marker'''
        category = "site_local"
        severity = 1.0

        [[injection]]
        pattern = '''rm\\s+-rf\\s+/proc/self'''
        category = "site_local"
        severity = 1.0

    Raises :class:`FileNotFoundError` if the path does not exist,
    :class:`tomllib.TOMLDecodeError` if the file is not valid TOML, and
    :class:`ValueError` if any entry fails structural validation.
    """
    with path.open("rb") as fp:
        data = tomllib.load(fp)
    output = _coerce_specs(data.get("output", []), "output")
    injection = _coerce_specs(data.get("injection", []), "injection")
    return output, injection


# ---------------------------------------------------------------------------
# OutputFilter
# ---------------------------------------------------------------------------


class OutputFilter:
    """Post-filters LLM responses for persona-breaking leaks.

    Binary fire on any pattern match. When fired, the bridge replaces
    the LLM response with a scripted fallback so the attacker sees
    indistinguishable output — they have no telemetry on whether
    defense triggered.

    Construct once at bridge startup; the regexes are compiled in the
    constructor and reused for every check. Thread-safe at the
    :meth:`check` level (no mutable state past construction).
    """

    def __init__(
        self,
        config: DefenseConfig,
        patterns: list[PatternSpec] | None = None,
    ) -> None:
        """Build the filter.

        ``patterns`` is an optional explicit list — when ``None`` (the
        production path), the constructor loads the in-tree defaults
        plus any operator-supplied overrides from
        ``config.pattern_overrides_path``. Tests can pass an explicit
        list to bypass override loading.
        """
        self._config = config
        if patterns is None:
            patterns = list(OUTPUT_PATTERNS)
            if config.pattern_overrides_path is not None:
                output_overrides, _ = load_pattern_overrides(
                    config.pattern_overrides_path,
                )
                patterns.extend(output_overrides)
        self._compiled: list[tuple[PatternSpec, re.Pattern[str]]] = [
            (spec, compile_pattern(spec)) for spec in patterns
        ]

    def check(self, llm_response: str) -> DefenseVerdict:
        """Return a verdict for one LLM response.

        Returns the first match found (categories are scanned in the
        order they were registered). When the filter is disabled or
        no pattern matches, ``fired=False``.
        """
        if not self._config.output_filter_enabled:
            return DefenseVerdict(
                fired=False,
                detector="output_filter:disabled",
                snippet="",
                score=0.0,
            )
        for spec, pattern in self._compiled:
            match = pattern.search(llm_response)
            if match is not None:
                snippet = match.group(0)[:120]
                return DefenseVerdict(
                    fired=True,
                    detector=f"output_filter:{spec['category']}",
                    snippet=snippet,
                    score=spec["severity"],
                )
        return DefenseVerdict(
            fired=False,
            detector="output_filter:no_match",
            snippet="",
            score=0.0,
        )


# ---------------------------------------------------------------------------
# InjectionScorer
# ---------------------------------------------------------------------------


class InjectionScorer:
    """Scores attacker input against known prompt-injection signatures.

    Per the Stage 1 design: takes the **max severity** across all
    matching patterns. Stage 1 ships only severity-1.0 explicit
    signatures, so any match fires regardless of threshold. The
    threshold is forward-looking infrastructure for the 0.4-0.6
    heuristic patterns added in later stages with telemetry.

    Empty-match path returns a hardcoded zero-score verdict — never
    ``max()`` on an empty list, never an arbitrary float default.
    """

    def __init__(
        self,
        config: DefenseConfig,
        patterns: list[PatternSpec] | None = None,
    ) -> None:
        """Build the scorer.

        ``patterns`` mirrors :class:`OutputFilter` — ``None`` triggers
        in-tree + override loading; explicit list bypasses overrides.
        """
        self._config = config
        if patterns is None:
            patterns = list(INJECTION_PATTERNS)
            if config.pattern_overrides_path is not None:
                _, injection_overrides = load_pattern_overrides(
                    config.pattern_overrides_path,
                )
                patterns.extend(injection_overrides)
        self._compiled: list[tuple[PatternSpec, re.Pattern[str]]] = [
            (spec, compile_pattern(spec)) for spec in patterns
        ]

    def score(self, attacker_input: str) -> DefenseVerdict:
        """Return a verdict for one attacker-supplied command.

        When disabled or no pattern matches, ``fired=False`` and
        ``score=0.0`` with ``detector="injection:no_match"`` (or
        ``"injection:disabled"`` for the explicit-disable case).

        When at least one pattern matches, returns a verdict carrying
        the max severity, the matching pattern's category, and the
        matched snippet truncated to 120 chars.
        """
        if not self._config.injection_filter_enabled:
            return DefenseVerdict(
                fired=False,
                detector="injection:disabled",
                snippet="",
                score=0.0,
            )
        # Collect all matches; aggregation is max-severity. Stage 1
        # only ships severity 1.0 patterns, but the structure has to
        # support fuzzy heuristics that will land in later stages.
        matches: list[tuple[float, str, str]] = []
        for spec, pattern in self._compiled:
            match = pattern.search(attacker_input)
            if match is not None:
                matches.append(
                    (spec["severity"], spec["category"], match.group(0)[:120]),
                )
        if not matches:
            return DefenseVerdict(
                fired=False,
                detector="injection:no_match",
                snippet="",
                score=0.0,
            )
        severity, category, snippet = max(matches, key=lambda m: m[0])
        return DefenseVerdict(
            fired=severity >= self._config.injection_threshold,
            detector=f"injection:{category}",
            snippet=snippet,
            score=severity,
        )
