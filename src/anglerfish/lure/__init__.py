"""Native asyncssh-based SSH honeypot frontend.

The sole attacker-facing SSH listener. See
``docs/design/STAGE_2_lure_subsystem.md`` for the full design. The
HTTP/HTTPS lure stays a ``NotImplementedError`` stub; see TODO-1 in
``docs/TODO.md``.

This package's ``__init__`` is intentionally empty (no eager
re-exports). Eager re-exports would pull in submodules that depend
on ``anglerfish.bridge``, which depends on ``anglerfish.config``,
which loads this package transitively, producing a circular import.
Callers import directly from submodules:

    from anglerfish.lure.config import LureConfig
    from anglerfish.lure.session import LureSessionContext
    from anglerfish.lure.banner import debian_banner
"""

from __future__ import annotations

__all__: list[str] = []
