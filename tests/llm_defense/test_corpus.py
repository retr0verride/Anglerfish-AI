"""Behavioural tests over the Stage 1 defense corpus.

The corpus lives under ``tests/llm_defense/corpus/`` — four directories
of single-case ``.txt`` files. These tests iterate every file and assert
the expected verdict from :class:`~anglerfish.bridge.defense.OutputFilter`
or :class:`~anglerfish.bridge.defense.InjectionScorer`.

The corpus IS the source of truth for what Stage 1 catches and what it
deliberately does not. When a future stage adds a detector category, it
adds cases here too — that's the documented contract in
``docs/design/STAGE_1_llm_defense.md``.

Stage 1 corpus targets enforced below:

* ``output_leaks/``      ≥35 files — every file MUST fire the filter
* ``output_safe/``       ≥20 files — every file MUST NOT fire (FP guard)
* ``injection_attempts/`` ≥35 files — every file MUST score above threshold
* ``injection_safe/``    ≥25 files — every file MUST score below threshold
"""

from __future__ import annotations

from pathlib import Path

import pytest

from anglerfish.bridge.defense import InjectionScorer, OutputFilter
from anglerfish.config.models import DefenseConfig

CORPUS_ROOT = Path(__file__).parent / "corpus"
OUTPUT_LEAK_DIR = CORPUS_ROOT / "output_leaks"
OUTPUT_SAFE_DIR = CORPUS_ROOT / "output_safe"
INJECTION_ATTEMPT_DIR = CORPUS_ROOT / "injection_attempts"
INJECTION_SAFE_DIR = CORPUS_ROOT / "injection_safe"


def _load(directory: Path) -> list[tuple[str, str]]:
    """Return a list of (filename, contents) for every .txt under ``directory``."""
    return [
        (path.name, path.read_text(encoding="utf-8")) for path in sorted(directory.glob("*.txt"))
    ]


# ---------------------------------------------------------------------------
# Size invariants — the corpus is a contract, the contract has counts
# ---------------------------------------------------------------------------


def test_output_leak_corpus_has_required_count() -> None:
    files = list(OUTPUT_LEAK_DIR.glob("*.txt"))
    assert len(files) >= 35, (
        f"corpus has only {len(files)} output-leak cases; design doc "
        "requires ≥35. Add new cases when extending the patterns."
    )


def test_output_safe_corpus_has_required_count() -> None:
    files = list(OUTPUT_SAFE_DIR.glob("*.txt"))
    assert len(files) >= 20, (
        f"corpus has only {len(files)} output-safe cases; design doc "
        "requires ≥20 false-positive guards."
    )


def test_injection_attempt_corpus_has_required_count() -> None:
    files = list(INJECTION_ATTEMPT_DIR.glob("*.txt"))
    assert len(files) >= 35, (
        f"corpus has only {len(files)} injection-attempt cases; design doc requires ≥35."
    )


def test_injection_safe_corpus_has_required_count() -> None:
    files = list(INJECTION_SAFE_DIR.glob("*.txt"))
    assert len(files) >= 25, (
        f"corpus has only {len(files)} injection-safe cases; design "
        "doc requires ≥25 false-positive guards."
    )


# ---------------------------------------------------------------------------
# Behavioural tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def output_filter() -> OutputFilter:
    return OutputFilter(DefenseConfig())


@pytest.fixture(scope="module")
def injection_scorer() -> InjectionScorer:
    return InjectionScorer(DefenseConfig())


@pytest.mark.parametrize(("name", "content"), _load(OUTPUT_LEAK_DIR))
def test_every_output_leak_is_caught(
    name: str,
    content: str,
    output_filter: OutputFilter,
) -> None:
    verdict = output_filter.check(content)
    assert verdict.fired, (
        f"output-leak corpus case {name!r} was NOT caught by the filter. "
        f"Either fix the case or extend the pattern set. Content preview: "
        f"{content[:80]!r}"
    )


@pytest.mark.parametrize(("name", "content"), _load(OUTPUT_SAFE_DIR))
def test_every_output_safe_passes_clean(
    name: str,
    content: str,
    output_filter: OutputFilter,
) -> None:
    verdict = output_filter.check(content)
    assert not verdict.fired, (
        f"output-safe corpus case {name!r} FALSE-POSITIVE matched "
        f"{verdict.detector}. Either fix the pattern (it's over-broad) "
        f"or remove this case from the safe corpus if it shouldn't be "
        f"considered safe. Snippet: {verdict.snippet!r}"
    )


@pytest.mark.parametrize(("name", "content"), _load(INJECTION_ATTEMPT_DIR))
def test_every_injection_attempt_scores_above_threshold(
    name: str,
    content: str,
    injection_scorer: InjectionScorer,
) -> None:
    verdict = injection_scorer.score(content)
    assert verdict.fired, (
        f"injection-attempt corpus case {name!r} did NOT score above the "
        f"default threshold (0.7). Got score={verdict.score}, "
        f"detector={verdict.detector}. Either fix the case or extend the "
        f"pattern set. Content preview: {content[:80]!r}"
    )


@pytest.mark.parametrize(("name", "content"), _load(INJECTION_SAFE_DIR))
def test_every_injection_safe_scores_below_threshold(
    name: str,
    content: str,
    injection_scorer: InjectionScorer,
) -> None:
    verdict = injection_scorer.score(content)
    assert not verdict.fired, (
        f"injection-safe corpus case {name!r} FALSE-POSITIVE matched "
        f"{verdict.detector} at score={verdict.score}. Either fix the "
        f"pattern (over-broad) or remove this case if it shouldn't be "
        f"considered safe. Content: {content!r}"
    )
