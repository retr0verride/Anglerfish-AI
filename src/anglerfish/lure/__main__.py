"""``python -m anglerfish.lure`` entry point.

Mirrors what the ``anglerfish lure serve`` typer command does but
without the CLI wrapper, so systemd units can invoke the module
directly if the operator prefers.
"""

from __future__ import annotations

import asyncio
import logging
import sys

from anglerfish.config.settings import load_settings
from anglerfish.lure.runner import BaitNicError, run_lure


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    settings = load_settings()
    try:
        asyncio.run(run_lure(settings))
    except BaitNicError as exc:
        logging.error("lure: bait-NIC validation failed: %s", exc)
        return 2
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":  # pragma: no cover - entry point
    sys.exit(main())
