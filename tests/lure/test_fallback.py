"""Tests for :mod:`anglerfish.lure.fallback`."""

from __future__ import annotations

from anglerfish.lure.fallback import fallback_with_default


def test_falls_back_to_command_not_found_when_unknown() -> None:
    assert (
        fallback_with_default(
            "totally-not-a-real-command --weird-flag",
            hostname="h",
            username="u",
            cwd="/tmp",
        )
        == "bash: totally-not-a-real-command: command not found"
    )


def test_returns_canned_response_for_known_command() -> None:
    # `whoami` has a scripted fallback in bridge.fallback.
    out = fallback_with_default("whoami", hostname="h", username="alice", cwd="/")
    assert "alice" in out


def test_empty_command_returns_empty_string() -> None:
    assert fallback_with_default("", hostname="h", username="u", cwd="/") == ""


def test_whitespace_only_command_returns_empty_string() -> None:
    assert fallback_with_default("   \t  ", hostname="h", username="u", cwd="/") == ""
