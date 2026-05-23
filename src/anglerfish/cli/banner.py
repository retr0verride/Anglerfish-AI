"""ASCII banner for the Anglerfish AI CLI.

The banner is shipped as a string constant so it travels with the
wheel and is available regardless of working directory or installation
method. Two entrypoints are exposed:

* :func:`render_banner` returns the banner as a string, optionally
  with an ANSI cyan glow on the bioluminescent lure.
* :func:`write_banner` writes the banner to a stream, autodetecting
  whether colour is appropriate from the stream's ``isatty``.
"""

from __future__ import annotations

import sys
from typing import TextIO

__all__ = ["BANNER", "BANNER_LINES", "render_banner", "write_banner"]


_ANSI_CYAN = "\x1b[1;36m"
_ANSI_RESET = "\x1b[0m"
_LURE_GLYPH = "●"


BANNER: str = (
    r"""
                          .
                         /
                        /
                       *
                      / |    .-"""
    """""-.
                     /  |  .'            '.
                    .   | /                \
                    |   |/      O           |
                    |   /                   |
                     \\  |    ___        ___/
                      \\  '--'   '-.__.-'
                       '-.________________.-'
                                /\\/\\/\
                                 \\/\\/

           █▀█ █▄░█ █▀▀ █░░ █▀▀ █▀█ █▀▀ █ █▀ █░█   ▄▀█ █
           █▀█ █░▀█ █▄█ █▄▄ ██▄ █▀▄ █▀░ █ ▄█ █▀█   █▀█ █

              AI-powered SSH honeypot · Deep-sea intel
""".lstrip("\n").rstrip()
    + "\n"
)


BANNER_LINES: tuple[str, ...] = tuple(BANNER.splitlines())


def render_banner(*, color: bool = True) -> str:
    """Return the banner string.

    When ``color`` is true the bioluminescent lure (the standalone
    period on the first non-empty line) is replaced with a cyan glyph
    using ANSI escape codes. When false, the banner is returned as
    plain ASCII suitable for log files.
    """
    if not color:
        return BANNER
    lines = list(BANNER_LINES)
    for i, line in enumerate(lines):
        if line.strip() == ".":
            lines[i] = line.replace(
                ".",
                f"{_ANSI_CYAN}{_LURE_GLYPH}{_ANSI_RESET}",
                1,
            )
            break
    return "\n".join(lines) + "\n"


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
