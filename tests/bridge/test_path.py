"""Tests for :func:`anglerfish.bridge.path.normalise_path`."""

from __future__ import annotations

import pytest

from anglerfish.bridge.path import normalise_path


@pytest.mark.parametrize(
    ("inp", "out"),
    [
        ("/etc", "/etc"),
        ("/etc/", "/etc"),
        ("/etc/./foo", "/etc/foo"),
        ("/etc/../var", "/var"),
        ("/etc/foo/../bar", "/etc/bar"),
        ("relative", "/relative"),
        ("/", "/"),
        ("/..", "/"),
    ],
)
def test_normalise_path(inp: str, out: str) -> None:
    assert normalise_path(inp) == out


def test_normalise_path_drops_trailing_slash() -> None:
    assert normalise_path("/var/log/") == "/var/log"


def test_normalise_path_collapses_multiple_dotdot() -> None:
    assert normalise_path("/a/b/../../c") == "/c"


def test_normalise_path_root_dotdot_is_root() -> None:
    assert normalise_path("/../../..") == "/"


def test_normalise_path_empty_input_is_root() -> None:
    assert normalise_path("") == "/"
