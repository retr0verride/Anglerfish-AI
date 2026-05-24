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

See ``docs/design/STAGE_1_llm_defense.md`` for the architecture, the
threat-model delta, and the test plan.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import re
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from anglerfish.bridge.defense_patterns import (
    INJECTION_PATTERNS,
    OUTPUT_PATTERNS,
    PatternSpec,
    compile_pattern,
)
from anglerfish.config.models import DefenseConfig

if TYPE_CHECKING:
    from anglerfish.audit import AuditLog

__all__ = [
    "DefenseVerdict",
    "InjectionScorer",
    "ModelIntegrity",
    "ModelIntegrityError",
    "OutputFilter",
    "load_pattern_overrides",
]


_logger = logging.getLogger(__name__)

# Ollama's media-type identifier for the model blob inside a manifest's
# layers array. Other layer types (template, license, params, system)
# exist but don't carry the actual weights — pinning against the wrong
# layer would silently let a weight-swap through.
_MODEL_BLOB_MEDIA_TYPE = "application/vnd.ollama.image.model"

# Default cap on bytes scanned by ANY pattern when DefenseConfig
# leaves scan_max_chars at its own default. Kept as a module constant
# so legacy tests that construct DefenseConfig() get predictable
# behaviour; production reads from DefenseConfig.scan_max_chars and
# the AnglerfishSettings cross-field validator (Stage 1.8.5) enforces
# the >= ollama.max_response_chars and >= bridge.max_input_chars
# invariants so an operator cannot silently shrink the scan window
# below the actual I/O sizes.
_DEFAULT_SCAN_MAX_CHARS = 8192


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
    truncated: bool = Field(
        default=False,
        description=(
            "True when the input was longer than the configured "
            "scan_max_chars and the scan only looked at a prefix. "
            "Independent of ``fired``: a clean (fired=False) verdict "
            "with truncated=True means the visible prefix was clean "
            "but the unscanned tail is an attacker-observable gap the "
            "bridge audit-logs via ``bridge.defense_scan_truncated``."
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

        Input is truncated to ``config.scan_max_chars`` before
        scanning — a misbehaving model emitting megabytes (or an
        attacker who manipulated context into pushing the cap) cannot
        cause the regex engine to chew on megabytes of input and pin
        the event loop. The AnglerfishSettings cross-field validator
        (Stage 1.8.5) enforces ``scan_max_chars >= ollama.max_response_chars``
        so a real LLM response never silently exceeds the scan window
        in a well-formed config; when it does (operator override at
        runtime, or model misbehaviour producing more chars than the
        OllamaClient cap), the returned verdict carries
        ``truncated=True`` and the bridge service audit-logs
        ``bridge.defense_scan_truncated``.
        """
        if not self._config.output_filter_enabled:
            return DefenseVerdict(
                fired=False,
                detector="output_filter:disabled",
                snippet="",
                score=0.0,
                truncated=False,
            )
        cap = self._config.scan_max_chars
        scan_target = llm_response[:cap]
        truncated = len(llm_response) > cap
        for spec, pattern in self._compiled:
            match = pattern.search(scan_target)
            if match is not None:
                snippet = match.group(0)[:120]
                return DefenseVerdict(
                    fired=True,
                    detector=f"output_filter:{spec['category']}",
                    snippet=snippet,
                    score=spec["severity"],
                    truncated=truncated,
                )
        return DefenseVerdict(
            fired=False,
            detector="output_filter:no_match",
            snippet="",
            score=0.0,
            truncated=truncated,
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

        Input is truncated to ``config.scan_max_chars`` before
        scanning. The bridge's ``BridgeConfig.max_input_chars``
        sanitiser typically caps attacker commands at 4096 chars
        upstream, and the AnglerfishSettings cross-field validator
        enforces ``scan_max_chars >= bridge.max_input_chars`` so a
        sanitised command never silently exceeds the scan window;
        when it does (e.g. an injected non-sanitised path), the
        returned verdict carries ``truncated=True`` and the bridge
        service audit-logs ``bridge.defense_scan_truncated``.
        """
        if not self._config.injection_filter_enabled:
            return DefenseVerdict(
                fired=False,
                detector="injection:disabled",
                snippet="",
                score=0.0,
                truncated=False,
            )
        cap = self._config.scan_max_chars
        scan_target = attacker_input[:cap]
        truncated = len(attacker_input) > cap
        # Collect all matches; aggregation is max-severity. Stage 1
        # only ships severity 1.0 patterns, but the structure has to
        # support fuzzy heuristics that will land in later stages.
        matches: list[tuple[float, str, str]] = []
        for spec, pattern in self._compiled:
            match = pattern.search(scan_target)
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
                truncated=truncated,
            )
        severity, category, snippet = max(matches, key=lambda m: m[0])
        return DefenseVerdict(
            fired=severity >= self._config.injection_threshold,
            detector=f"injection:{category}",
            snippet=snippet,
            score=severity,
            truncated=truncated,
        )


# ---------------------------------------------------------------------------
# ModelIntegrity
# ---------------------------------------------------------------------------


def _normalize_hash(raw: str) -> str:
    """Normalise a hash for constant-time comparison.

    Strips the optional ``sha256:`` prefix (jq emits it from the
    manifest, operators sometimes copy the bare hex) and lowercases.
    Returns the bare-hex form.
    """
    return raw.removeprefix("sha256:").lower()


class ModelIntegrity:
    """Verifies the Ollama model's blob layer digest at bridge startup.

    Pins against the SHA256 of the ``application/vnd.ollama.image.model``
    layer in Ollama's local manifest. Defends against:

    * **Silent tag re-pointing** — the operator pulled
      ``qwen2.5-coder:7b-instruct`` once and pinned the hash; if anyone
      later re-pulls it and the upstream re-points the tag at a
      different blob, the hash mismatches and the bridge refuses to
      start. Tag names alone don't catch this.
    * **Supply-chain blob swap** — an attacker with write access to
      Ollama's blob store could replace the model file. Same defence.
    * **Local corruption** — disk bit-rot that touches the blob shows
      up as a hash mismatch.

    Construct once at bridge startup and call :meth:`verify` once. Do
    not call again at runtime; integrity verification is a
    startup-only contract.
    """

    def __init__(
        self,
        config: DefenseConfig,
        ollama_model: str,
        audit_log: AuditLog,
        *,
        manifest_root: Path | None = None,
    ) -> None:
        """Build the checker.

        ``ollama_model`` is the model tag from
        :attr:`OllamaConfig.model` (e.g. ``"qwen2.5-coder:7b-instruct"``).
        Models without an explicit ``:tag`` default to ``:latest`` per
        Ollama convention.

        ``manifest_root`` overrides
        :attr:`DefenseConfig.ollama_manifest_dir` — primarily for tests
        that point at a tmp_path fixture. Production code should leave
        it ``None`` and let the config govern.
        """
        self._config = config
        self._ollama_model = ollama_model
        self._audit_log = audit_log
        if manifest_root is not None:
            self._manifest_root = manifest_root
        else:
            self._manifest_root = config.ollama_manifest_dir or Path()

    @property
    def manifest_root(self) -> Path:
        """Read-only access to the manifest directory in use.

        Useful for error reporting from the bridge-startup lifespan
        (operator wants to know which path failed) without breaking the
        encapsulation of the internal attribute.
        """
        return self._manifest_root

    async def verify(self) -> None:
        """Run the check once. Emits exactly one audit event per call.

        Behaviour:

        * If ``model_expected_hash`` is unset: emit
          ``bridge.model_integrity_skipped`` + log a loud structured
          warning. Return cleanly. (Default behaviour for fresh
          installs — running unverified is opt-out, but the audit
          trail surfaces it on every startup.)
        * On match: emit ``bridge.model_integrity_verified``. Return.
        * On mismatch or read failure: emit
          ``bridge.model_integrity_failed`` and raise
          :class:`ModelIntegrityError`. The bridge must exit non-zero.
        """
        expected = self._config.model_expected_hash
        if expected is None:
            _logger.warning(
                "bridge starting WITHOUT model integrity check "
                "(ANGLERFISH_DEFENSE__MODEL_EXPECTED_HASH unset). "
                "Backdoored/swapped models will not be detected. "
                "Set the expected SHA256 in production to enable "
                "verification.",
            )
            self._audit_log.record(
                "bridge.model_integrity_skipped",
                reason="ANGLERFISH_DEFENSE__MODEL_EXPECTED_HASH unset",
                model=self._ollama_model,
            )
            return

        try:
            actual_raw = await asyncio.to_thread(self._read_manifest_layer_digest)
        except (FileNotFoundError, ValueError) as exc:
            # ValueError catches json.JSONDecodeError too (subclass).
            self._audit_log.record(
                "bridge.model_integrity_failed",
                reason=f"could not read manifest layer digest: {exc}",
                model=self._ollama_model,
                manifest_root=str(self._manifest_root),
            )
            raise ModelIntegrityError(
                f"model integrity check failed: could not read manifest "
                f"layer digest for {self._ollama_model!r}: {exc}",
            ) from exc

        expected_n = _normalize_hash(expected.get_secret_value())
        actual_n = _normalize_hash(actual_raw)

        if not hmac.compare_digest(expected_n, actual_n):
            self._audit_log.record(
                "bridge.model_integrity_failed",
                reason="hash mismatch",
                model=self._ollama_model,
                expected_hash=f"sha256:{expected_n[:8]}...{expected_n[-8:]}",
                actual_hash=f"sha256:{actual_n[:8]}...{actual_n[-8:]}",
            )
            raise ModelIntegrityError(
                f"model integrity check failed for {self._ollama_model!r}: "
                f"manifest layer digest does not match expected hash. "
                f"(Expected starts {expected_n[:8]}..., got {actual_n[:8]}...)",
            )

        self._audit_log.record(
            "bridge.model_integrity_verified",
            model=self._ollama_model,
            verified_hash=f"sha256:{actual_n[:8]}...{actual_n[-8:]}",
        )

    def _read_manifest_layer_digest(self) -> str:
        """Synchronous filesystem read of the layer digest. Wrapped in
        :func:`asyncio.to_thread` from :meth:`verify` to keep async
        callers non-blocking.

        Raises:
            FileNotFoundError: manifest file is missing.
            json.JSONDecodeError: manifest file is not valid JSON.
            ValueError: manifest has no model-blob layer entry.
        """
        manifest_path = self._resolve_manifest_path()
        with manifest_path.open("rb") as fp:
            manifest = json.load(fp)
        layers = manifest.get("layers", [])
        if not isinstance(layers, list):
            raise ValueError(
                f"manifest at {manifest_path} has invalid 'layers' field "
                f"(expected list, got {type(layers).__name__})",
            )
        for layer in layers:
            if not isinstance(layer, dict):
                continue
            if layer.get("mediaType") == _MODEL_BLOB_MEDIA_TYPE:
                digest = layer.get("digest")
                if not isinstance(digest, str) or not digest:
                    raise ValueError(
                        f"manifest at {manifest_path} has a model-blob layer with no digest",
                    )
                return digest
        raise ValueError(
            f"manifest at {manifest_path} has no layer with mediaType {_MODEL_BLOB_MEDIA_TYPE!r}",
        )

    def _resolve_manifest_path(self) -> Path:
        """Build the per-model manifest file path under the root.

        Ollama stores manifests at
        ``<root>/registry.ollama.ai/library/<name>/<tag>``. A model
        reference without an explicit ``:tag`` defaults to
        ``:latest`` per Ollama convention.
        """
        if ":" in self._ollama_model:
            name, tag = self._ollama_model.split(":", 1)
        else:
            name, tag = self._ollama_model, "latest"
        return self._manifest_root / "registry.ollama.ai" / "library" / name / tag
