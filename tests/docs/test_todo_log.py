"""Lint check on ``docs/TODO.md``.

Stage 2A introduces ``docs/TODO.md`` as the source of truth for every
``TODO-N`` referenced from source code or other docs. This test
greps the repo for ``TODO-\\d+`` mentions and fails if any of them
point at a number not declared in the log.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TODO_PATH = REPO_ROOT / "docs" / "TODO.md"

# Source directories that may legitimately reference TODO-N.
_SCAN_DIRS = (
    REPO_ROOT / "src",
    REPO_ROOT / "tests",
    REPO_ROOT / "docs",
)

_TODO_REF = re.compile(r"\bTODO-(\d+)\b")
_TODO_HEADING = re.compile(r"^## TODO-(\d+):", re.MULTILINE)


def _todo_log_numbers() -> set[int]:
    text = TODO_PATH.read_text(encoding="utf-8")
    return {int(m.group(1)) for m in _TODO_HEADING.finditer(text)}


def _referenced_numbers() -> set[int]:
    refs: set[int] = set()
    for root in _SCAN_DIRS:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in {".py", ".md", ".toml", ".cfg"}:
                continue
            # Skip the log itself; it contains the canonical headings.
            if path == TODO_PATH:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for match in _TODO_REF.finditer(text):
                refs.add(int(match.group(1)))
    # Also exclude the regex literal in this test file from the set
    # since it would match itself.
    refs.discard(0)
    return refs


def test_todo_log_file_exists() -> None:
    assert TODO_PATH.is_file()


def test_todo_log_has_at_least_one_entry() -> None:
    assert len(_todo_log_numbers()) >= 1


def test_todo_log_has_no_duplicate_numbers() -> None:
    text = TODO_PATH.read_text(encoding="utf-8")
    numbers = [int(m.group(1)) for m in _TODO_HEADING.finditer(text)]
    assert len(numbers) == len(set(numbers))


def test_every_todo_reference_resolves_in_the_log() -> None:
    declared = _todo_log_numbers()
    referenced = _referenced_numbers()
    missing = referenced - declared
    assert not missing, (
        f"TODO-{sorted(missing)} referenced in source but not declared in "
        f"docs/TODO.md (declared: {sorted(declared)})"
    )


def test_todo_1_reserved_for_http_lure() -> None:
    text = TODO_PATH.read_text(encoding="utf-8")
    assert "## TODO-1: HTTP/HTTPS lure listener" in text


def test_http_stub_references_todo_1() -> None:
    stub = (REPO_ROOT / "src" / "anglerfish" / "lure" / "http.py").read_text(
        encoding="utf-8",
    )
    assert "TODO-1" in stub
