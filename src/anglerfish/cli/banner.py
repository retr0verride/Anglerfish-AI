"""CLI banner for Anglerfish AI.

The banner is a small text block printed by ``anglerfish banner`` and
at the top of the first-boot wizard. It deliberately does NOT include
ASCII fish art — operators see this on tty1 during install and at the
top of every interactive CLI invocation, where character-art renders
inconsistently across terminals (mono-spaced vs. proportional fonts,
unicode-block-glyph fallbacks, low-contrast themes). Plain text with
a single accent colour reads cleanly on every terminal.

Two entrypoints:

* :func:`render_banner` returns the banner as a string, optionally
  with an ANSI cyan accent on the project name.
* :func:`write_banner` writes the banner to a stream, autodetecting
  whether colour is appropriate from the stream's ``isatty``.
"""

from __future__ import annotations

import sys
from typing import TextIO

__all__ = ["BANNER", "BANNER_LINES", "render_banner", "write_banner"]


_ANSI_CYAN = "\x1b[1;36m"
_ANSI_RESET = "\x1b[0m"
_ACCENT_WORDMARK = "Anglerfish AI"


BANNER: str = (
    """
  Anglerfish AI
  AI-powered SSH honeypot · Deep-sea threat intelligence
""".lstrip("\n").rstrip()
    + "\n"
)


BANNER_LINES: tuple[str, ...] = tuple(BANNER.splitlines())


def render_banner(*, color: bool = True) -> str:
    """Return the banner string.

    When ``color`` is true the project name is wrapped in cyan ANSI
    escapes. When false, the banner is returned as plain text suitable
    for log files.
    """
    if not color:
        return BANNER
    return BANNER.replace(
        _ACCENT_WORDMARK,
        f"{_ANSI_CYAN}{_ACCENT_WORDMARK}{_ANSI_RESET}",
        1,
    )


def write_banner(stream: TextIO | None = None, *, color: bool | None = None) -> None:
    """Write the banner to ``stream`` (default :data:`sys.stdout`).

    When ``color`` is :data:`None`, autodetect from the stream's
    ``isatty`` method.
    """
    target = stream if stream is not None else sys.stdout
    if color is None:
        isatty = getattr(target, "isatty", None)
        color = bool(isatty()) if callable(isatty) else False
    target.write(render_banner(color=color))
