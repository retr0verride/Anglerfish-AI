"""Tests for :mod:`anglerfish.bridge.sanitize`."""

from __future__ import annotations

import pytest

from anglerfish.bridge.sanitize import TRUNCATION_MARKER, cap_output, sanitize_command


class TestSanitizeCommand:
    def test_plain_text_unchanged(self) -> None:
        assert sanitize_command("ls -la /etc", max_chars=4096) == "ls -la /etc"

    def test_preserves_tab_and_newline(self) -> None:
        assert sanitize_command("a\tb\nc", max_chars=4096) == "a\tb\nc"

    def test_normalises_crlf(self) -> None:
        assert sanitize_command("a\r\nb\rc", max_chars=4096) == "a\nb\nc"

    def test_strips_control_chars(self) -> None:
        raw = "ls\x01\x02\x03 -\x7fla"
        assert sanitize_command(raw, max_chars=4096) == "ls -la"

    def test_strips_ansi_escape_bytes(self) -> None:
        # ESC (0x1B) is a C0 control char and must be stripped.
        raw = "ls\x1b[31m -la"
        out = sanitize_command(raw, max_chars=4096)
        assert "\x1b" not in out
        assert out == "ls[31m -la"

    def test_unicode_preserved(self) -> None:
        assert sanitize_command("cat → file", max_chars=4096) == "cat → file"

    def test_truncates_to_max_chars(self) -> None:
        out = sanitize_command("x" * 100, max_chars=10)
        assert out.startswith("x" * 10)
        assert out.endswith(TRUNCATION_MARKER)
        assert len(out) == 10 + len(TRUNCATION_MARKER)

    def test_at_limit_not_truncated(self) -> None:
        out = sanitize_command("x" * 10, max_chars=10)
        assert out == "x" * 10
        assert TRUNCATION_MARKER not in out

    def test_rejects_non_string(self) -> None:
        with pytest.raises(TypeError):
            sanitize_command(b"bytes", max_chars=4096)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            sanitize_command(None, max_chars=4096)  # type: ignore[arg-type]

    def test_rejects_non_positive_max(self) -> None:
        with pytest.raises(ValueError):
            sanitize_command("x", max_chars=0)
        with pytest.raises(ValueError):
            sanitize_command("x", max_chars=-1)


class TestCapOutput:
    def test_passes_through_short_output(self) -> None:
        assert cap_output("hello\n", max_chars=100) == "hello"

    def test_truncates_silently(self) -> None:
        out = cap_output("x" * 100, max_chars=10)
        assert out == "x" * 10
        assert TRUNCATION_MARKER not in out  # silent — no marker

    def test_strips_trailing_whitespace(self) -> None:
        assert cap_output("hello  \n\t  ", max_chars=100) == "hello"

    def test_rejects_non_string(self) -> None:
        with pytest.raises(TypeError):
            cap_output(123, max_chars=10)  # type: ignore[arg-type]

    def test_rejects_non_positive_max(self) -> None:
        with pytest.raises(ValueError):
            cap_output("x", max_chars=0)
