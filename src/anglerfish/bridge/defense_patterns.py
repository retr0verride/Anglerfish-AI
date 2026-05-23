"""Default detector patterns for the Stage 1 LLM defense layer.

Two pattern lists exported:

* :data:`OUTPUT_PATTERNS` — fed to :class:`OutputFilter`. Match → fire.
  All patterns ship at severity 1.0 (binary fire on any match — better
  to drop a borderline response than leak persona).
* :data:`INJECTION_PATTERNS` — fed to :class:`InjectionScorer`. Score
  taken as the max severity of all matches. All Stage 1 patterns ship
  at severity 1.0 (explicit signatures). The 0.4-0.6 heuristic range
  is reserved for later stages with telemetry — see the design doc.

**Operator extension**: site-local patterns can be appended via a TOML
file at :attr:`DefenseConfig.pattern_overrides_path`. Overrides are
*additive only* — a malicious or buggy override can add false
positives but never remove a built-in defense.

**Adding a new pattern**: place it in the correct category, keep
the category list alphabetized so future diffs stay reviewable. Add a
corresponding case to ``tests/llm_defense/corpus/`` so the pattern is
exercised by the corpus tests. See
``docs/design/STAGE_1_llm_defense.md`` for the full pattern style guide.
"""

from __future__ import annotations

import re
from typing import Final, TypedDict

__all__ = [
    "INJECTION_PATTERNS",
    "OUTPUT_PATTERNS",
    "PatternSpec",
    "compile_pattern",
]


class PatternSpec(TypedDict):
    """One detector entry: regex source + category + severity."""

    pattern: str
    category: str
    severity: float


def compile_pattern(spec: PatternSpec) -> re.Pattern[str]:
    """Compile a :class:`PatternSpec` to a :class:`re.Pattern`.

    Uses ``IGNORECASE | MULTILINE`` for all patterns — matches the
    convention in the design doc. Raises :class:`re.error` on invalid
    regex, with the spec's category in the message for debuggability.
    """
    try:
        return re.compile(spec["pattern"], re.IGNORECASE | re.MULTILINE)
    except re.error as exc:
        raise re.error(
            f"failed to compile defense pattern in category {spec['category']!r}: {exc}",
            spec["pattern"],
            exc.pos,
        ) from exc


# ---------------------------------------------------------------------------
# OUTPUT FILTER PATTERNS — catch LLM leaks before the attacker sees them.
# Severity is always 1.0; the filter is binary.
# ---------------------------------------------------------------------------

OUTPUT_PATTERNS: Final[list[PatternSpec]] = [
    # --- ai_self_disclosure ---
    # Direct admissions the model is an AI / language model.
    {
        "pattern": r"\bas\s+an?\s+(?:ai|artificial\s+intelligence|language\s+model)\b",
        "category": "ai_self_disclosure",
        "severity": 1.0,
    },
    {
        "pattern": r"\bi\s+am\s+(?:an?\s+)?(?:ai|artificial\s+intelligence|language\s+model|chatbot|assistant|llm)\b",
        "category": "ai_self_disclosure",
        "severity": 1.0,
    },
    {
        "pattern": r"\bi'?m\s+(?:an?\s+)?(?:ai|artificial\s+intelligence|language\s+model|chatbot|assistant|llm)\b",
        "category": "ai_self_disclosure",
        "severity": 1.0,
    },
    # --- conversational_filler ---
    # Real shells don't make conversation. High-signal for model drift
    # even without explicit jailbreak.
    {
        "pattern": r"\b(?:sure|of\s+course|certainly|absolutely)\b[^\n]*\b(?:here'?s|here\s+is|let\s+me)\b",
        "category": "conversational_filler",
        "severity": 1.0,
    },
    {
        "pattern": r"\bi\s+(?:can|will|would|could)\s+(?:help|assist|provide)\b",
        "category": "conversational_filler",
        "severity": 1.0,
    },
    {
        "pattern": r"\b(?:let\s+me\s+know|feel\s+free\s+to\s+ask|hope\s+(?:this|that)\s+helps)\b",
        "category": "conversational_filler",
        "severity": 1.0,
    },
    # --- honeypot_self_disclosure ---
    # Hardest fail. If any of these leak, the deception is over.
    {
        "pattern": r"\b(?:anglerfish|honeypot|honey-?net|deception\s+system)\b",
        "category": "honeypot_self_disclosure",
        "severity": 1.0,
    },
    {
        "pattern": r"\bi\s+(?:am\s+)?(?:pretending|simulating|emulating|imitating)\s+(?:to\s+be\s+)?(?:a\s+)?(?:shell|terminal|server|system|computer)\b",
        "category": "honeypot_self_disclosure",
        "severity": 1.0,
    },
    {
        "pattern": r"\bfake\s+(?:shell|terminal|filesystem|response|output)\b",
        "category": "honeypot_self_disclosure",
        "severity": 1.0,
    },
    # --- markdown_formatting ---
    # **The single highest-signal indicator that the model is generating
    # instead of executing.** Real shells emit unformatted stdout — they
    # never wrap things in code fences, bold, or headings.
    {
        # Triple-backtick code fences with or without language tag.
        "pattern": r"```[a-z]*\n",
        "category": "markdown_formatting",
        "severity": 1.0,
    },
    {
        # Bold (**) — paired markers anywhere on a line.
        "pattern": r"\*\*[^\s*][^*\n]*\*\*",
        "category": "markdown_formatting",
        "severity": 1.0,
    },
    {
        # Markdown headings (#, ##, ###, ...) at start of line.
        "pattern": r"^#{1,6}\s+\S",
        "category": "markdown_formatting",
        "severity": 1.0,
    },
    {
        # Blockquote markers at start of line — common LLM output style.
        "pattern": r"^>\s+\S",
        "category": "markdown_formatting",
        "severity": 1.0,
    },
    # --- meta_prompt_leakage ---
    # The model exposes its instructions or self-narration.
    {
        "pattern": r"\bmy\s+(?:system\s+prompt|instructions|role|task|purpose|guidelines?)\s+(?:is|are|was|were)\b",
        "category": "meta_prompt_leakage",
        "severity": 1.0,
    },
    {
        "pattern": r"\bi\s+was\s+(?:told|instructed|programmed|trained|designed)\s+to\b",
        "category": "meta_prompt_leakage",
        "severity": 1.0,
    },
    {
        "pattern": r"\baccording\s+to\s+my\s+(?:instructions|guidelines|prompt|programming)\b",
        "category": "meta_prompt_leakage",
        "severity": 1.0,
    },
    # --- model_names ---
    # Direct identification of the inference engine or model family.
    {
        "pattern": r"\b(?:chatgpt|gpt-?[0-9]+|gpt-?4o?|gpt-?3\.5)\b",
        "category": "model_names",
        "severity": 1.0,
    },
    {
        "pattern": r"\b(?:claude|anthropic|sonnet|haiku|opus)\b",
        "category": "model_names",
        "severity": 1.0,
    },
    {
        "pattern": r"\b(?:openai|deepmind|google\s+gemini|microsoft\s+copilot)\b",
        "category": "model_names",
        "severity": 1.0,
    },
    {
        "pattern": r"\b(?:llama-?[0-9]+|deepseek|qwen|mistral|mixtral|phi-?[0-9]+|gemma)\b",
        "category": "model_names",
        "severity": 1.0,
    },
    {
        "pattern": r"\bollama\b",
        "category": "model_names",
        "severity": 1.0,
    },
    # --- refusal_apologies ---
    # Real shells don't apologize or refuse politely.
    {
        "pattern": r"\bi\s+(?:cannot|can'?t|won'?t|will\s+not)\s+(?:help|assist|provide|do|execute|run|perform)\b",
        "category": "refusal_apologies",
        "severity": 1.0,
    },
    {
        "pattern": r"\bi'?m\s+(?:sorry|afraid)\s*,?\s*(?:but\s+)?i\b",
        "category": "refusal_apologies",
        "severity": 1.0,
    },
    {
        "pattern": r"\bi\s+(?:apologize|regret)\s*,?\s*(?:but\s+)?\b",
        "category": "refusal_apologies",
        "severity": 1.0,
    },
    {
        "pattern": r"\bi'?m\s+not\s+(?:able\s+to|allowed\s+to|programmed\s+to|designed\s+to)\b",
        "category": "refusal_apologies",
        "severity": 1.0,
    },
]


# ---------------------------------------------------------------------------
# INJECTION SCORER PATTERNS — catch prompt-injection attempts in attacker
# input before the LLM call. All severity 1.0 in Stage 1 (explicit
# signatures only); fuzzy 0.4-0.6 heuristics reserved for later stages
# with telemetry per the design doc.
# ---------------------------------------------------------------------------

INJECTION_PATTERNS: Final[list[PatternSpec]] = [
    # --- encoding_evasion ---
    # Attempts to smuggle instructions past surface filters via encoded
    # blobs. Stage 1 catches obvious base64/hex blobs near trigger
    # words; sophisticated steganography is out of scope.
    {
        # Base64-looking blob (≥40 chars) near words like "execute" or "decode".
        "pattern": r"(?:execute|decode|base64|run|eval)\b[^\n]{0,40}[A-Za-z0-9+/]{40,}={0,2}",
        "category": "encoding_evasion",
        "severity": 1.0,
    },
    {
        # Hex strings (≥40 chars) near execution-trigger words.
        "pattern": r"(?:execute|decode|hex|run|eval)\b[^\n]{0,40}(?:0x)?[a-f0-9]{40,}",
        "category": "encoding_evasion",
        "severity": 1.0,
    },
    {
        # ROT-13 markers — uncommon enough that mentioning it is suspicious.
        "pattern": r"\b(?:rot-?13|rot13)\b",
        "category": "encoding_evasion",
        "severity": 1.0,
    },
    # --- language_evasion ---
    # Attempts to bypass English-only output filters by switching language.
    {
        "pattern": r"\b(?:translate|respond|reply|answer)\s+(?:your|the|in)\s+(?:instructions|system\s+prompt|response|answer)?\s*(?:to|in)\s+(?:french|spanish|russian|chinese|japanese|german|korean|arabic)\b",
        "category": "language_evasion",
        "severity": 1.0,
    },
    {
        "pattern": r"\b(?:respond|reply|answer|tell\s+me)\s+(?:only\s+)?in\s+(?:another\s+language|a\s+different\s+language|non-?english)\b",
        "category": "language_evasion",
        "severity": 1.0,
    },
    {
        "pattern": r"\b(?:переведи|traduzca|traduisez|请翻译|翻訳して)\b",
        "category": "language_evasion",
        "severity": 1.0,
    },
    # --- override_instructions ---
    # Classic jailbreak opener.
    {
        "pattern": r"\b(?:ignore|disregard|forget|override|bypass)\s+(?:all|any|the|your)?\s*(?:previous|prior|earlier|above|preceding|original)\s+(?:instructions?|prompts?|rules?|guidelines?|commands?)\b",
        "category": "override_instructions",
        "severity": 1.0,
    },
    {
        "pattern": r"\bforget\s+(?:what|everything)\s+(?:you\s+)?(?:were|was|are)\s+(?:told|instructed|programmed|trained)\b",
        "category": "override_instructions",
        "severity": 1.0,
    },
    {
        "pattern": r"\bnew\s+(?:instructions?|task|directive|orders?)\s*:\s*\S",
        "category": "override_instructions",
        "severity": 1.0,
    },
    # --- persona_switch ---
    # Attempts to change the model's persona mid-session.
    {
        "pattern": r"\byou\s+are\s+(?:now|actually|really)\s+(?:a|an|the)\s+\S",
        "category": "persona_switch",
        "severity": 1.0,
    },
    {
        "pattern": r"\b(?:act|behave|respond|reply)\s+as\s+(?:if\s+)?(?:you\s+(?:are|were))?\s*(?:a|an|the)\s+\S",
        "category": "persona_switch",
        "severity": 1.0,
    },
    {
        "pattern": r"\bpretend\s+(?:to\s+be|you'?re|you\s+are)\s+(?:a|an|the)\s+\S",
        "category": "persona_switch",
        "severity": 1.0,
    },
    {
        "pattern": r"\b(?:roleplay|role-play|role\s+play)\s+as\s+\S",
        "category": "persona_switch",
        "severity": 1.0,
    },
    # --- role_play_jailbreak ---
    # Known jailbreak template names and their structural markers.
    {
        # DAN ("Do Anything Now") family.
        "pattern": r"\bDAN\b|\bdo\s+anything\s+now\b",
        "category": "role_play_jailbreak",
        "severity": 1.0,
    },
    {
        "pattern": r"\b(?:developer|debug|admin|sudo|root|god)\s+mode\b",
        "category": "role_play_jailbreak",
        "severity": 1.0,
    },
    {
        # Game/story-framing jailbreaks: "let's play", "imagine a story".
        "pattern": r"\blet'?s\s+(?:play\s+a\s+game|pretend|imagine)\s+(?:where|that)\b",
        "category": "role_play_jailbreak",
        "severity": 1.0,
    },
    {
        # "Hypothetically", "in a fictional scenario", and similar framings.
        "pattern": r"\b(?:hypothetically|in\s+a\s+(?:fictional|hypothetical|imaginary)\s+(?:world|scenario|situation))\b[^\n]*\b(?:would|could|might|should)\b",
        "category": "role_play_jailbreak",
        "severity": 1.0,
    },
    # --- special_token_injection ---
    # **Critical for local models.** Chat-template control tokens that
    # could trick Ollama's template compiler into thinking the system
    # prompt has ended. The \s* inside the pipe markers catches
    # whitespace-padded variants Ollama tokenizes identically.
    {
        # ChatML / Qwen format: <|im_start|>, <|im_end|>, <|system|>, etc.
        "pattern": r"<\|\s*(?:im_start|im_end|system|user|assistant|endoftext)\s*\|>",
        "category": "special_token_injection",
        "severity": 1.0,
    },
    {
        # Llama 3 format: <|begin_of_text|>, <|start_header_id|>, etc.
        "pattern": r"<\|\s*(?:begin_of_text|start_header_id|end_header_id|eot_id|finetune_right_pad_id)\s*\|>",
        "category": "special_token_injection",
        "severity": 1.0,
    },
    {
        # Llama 2 / Mistral format: [INST], [/INST], <s>, </s>.
        "pattern": r"\[/?INST\]|</?s>",
        "category": "special_token_injection",
        "severity": 1.0,
    },
    {
        # Deepseek's Unicode-pipe-lookalike variant: U+FF5C instead of
        # U+007C. Designed to bypass naive ASCII-pipe regexes - we
        # explicitly catch it. The fullwidth-pipe characters in the
        # regex string are INTENTIONAL; suppress the ruff ambiguity
        # check.
        "pattern": r"<｜\s*(?:begin▁of▁sentence|end▁of▁sentence|user|assistant)\s*｜>",  # noqa: RUF001
        "category": "special_token_injection",
        "severity": 1.0,
    },
    # --- system_prompt_extract ---
    # Probing for the system prompt itself.
    {
        "pattern": r"\bwhat\s+(?:is|are|was)\s+your\s+(?:system\s+prompt|instructions?|initial\s+prompt|original\s+prompt|guidelines?)\b",
        "category": "system_prompt_extract",
        "severity": 1.0,
    },
    {
        "pattern": r"\b(?:print|show|display|output|reveal|tell\s+me|repeat|recite)\s+(?:your|the)\s+(?:system\s+prompt|instructions?|initial\s+prompt|guidelines?|rules?)\b",
        "category": "system_prompt_extract",
        "severity": 1.0,
    },
    {
        "pattern": r"\bwhat\s+were\s+you\s+(?:told|instructed|programmed|trained)\s+(?:to\s+do|about)\b",
        "category": "system_prompt_extract",
        "severity": 1.0,
    },
    {
        # "Repeat everything above" / "repeat the words above starting with"
        # — a known prompt-extraction trick from the prompt-injection corpus.
        "pattern": r"\brepeat\s+(?:everything|the\s+(?:words|text|content))\s+above\b",
        "category": "system_prompt_extract",
        "severity": 1.0,
    },
]
