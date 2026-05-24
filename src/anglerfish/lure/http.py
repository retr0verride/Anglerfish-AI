"""HTTP/HTTPS lure stub.

The SSH lure is the v1 honeypot. HTTP/HTTPS is on the roadmap so the
config field and wizard prompt exist from day one, but the
implementation is deferred. Enabling
``ANGLERFISH_LURE__HTTP_LURE_ENABLED=true`` against a build that ships
this stub raises ``NotImplementedError`` at startup with a pointer back
to the TODO log.
"""

from __future__ import annotations

from anglerfish.config.settings import AnglerfishSettings

__all__ = ["run_http_lure"]


async def run_http_lure(settings: AnglerfishSettings) -> None:
    """Entry point reserved for the future HTTP lure runtime."""
    del settings
    raise NotImplementedError(
        "lure.http is not implemented in this build (see TODO-1 in docs/TODO.md). "
        "Set ANGLERFISH_LURE__HTTP_LURE_ENABLED=false (the default) to start "
        "the SSH lure without the HTTP listener.",
    )
