"""Time-wasting strategies the bridge consults per command.

Stage 6 introduces three strategies the operator picks between via
the dashboard control plane (Stage 3 already shipped the knob):

* ``off`` - passthrough; behaviour identical to Stage 5.
* ``light`` - small inter-chunk delays + occasional pre-messages.
* ``aggressive`` - larger delays, more pre-messages, occasional
  clarification injections that force the attacker to send a
  follow-up command.

Each strategy implements :class:`WastingStrategyBase`. The bridge
calls :func:`get_strategy` per command with the operator's current
selection (read from the dashboard-published runtime overrides
JSON via :class:`anglerfish.bridge.overrides_reader.BridgeOverridesReader`)
and applies the returned instance's ``pre_command`` /
``between_chunks`` hooks.

Slice 6.1 ships only the ``off`` implementation; ``light`` and
``aggressive`` return the off strategy until slices 6.2 / 6.3 land.
"""

from __future__ import annotations

import logging

from anglerfish.bridge.strategies.base import (
    StrategyContext,
    StrategyPreEffect,
    WastingStrategyBase,
)
from anglerfish.bridge.strategies.off import OffStrategy

__all__ = [
    "OffStrategy",
    "StrategyContext",
    "StrategyPreEffect",
    "WastingStrategyBase",
    "get_strategy",
]


_logger = logging.getLogger(__name__)


def get_strategy(name: str) -> WastingStrategyBase:
    """Return a strategy instance for ``name``.

    Slice 6.1 ships only :class:`OffStrategy`. The names ``light``
    and ``aggressive`` are accepted (so dashboard-driven changes do
    not 500 the bridge) but resolve to :class:`OffStrategy` until
    slices 6.2 / 6.3 land. Unknown names raise :class:`ValueError`;
    the caller treats this as a misconfiguration and falls back to
    the bridge's static config.
    """
    if name == "off":
        return OffStrategy()
    if name in ("light", "aggressive"):
        # Stage 6 slice 1: real implementations land in 6.2 / 6.3.
        # Falling back to OffStrategy keeps the cross-process channel
        # exercisable end-to-end without behaviour change yet.
        _logger.debug("wasting_strategy=%s requested; slice 6.1 routes to off", name)
        return OffStrategy()
    raise ValueError(f"unknown wasting strategy: {name!r}")
