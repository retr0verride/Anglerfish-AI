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
from anglerfish.bridge.strategies.light import LightStrategy
from anglerfish.bridge.strategies.off import OffStrategy

__all__ = [
    "LightStrategy",
    "OffStrategy",
    "StrategyContext",
    "StrategyPreEffect",
    "WastingStrategyBase",
    "get_strategy",
]


_logger = logging.getLogger(__name__)


def get_strategy(name: str) -> WastingStrategyBase:
    """Return a strategy instance for ``name``.

    Slice 6.2 added :class:`LightStrategy`; ``aggressive`` is still
    routed to :class:`OffStrategy` until slice 6.3 lands. Unknown
    names raise :class:`ValueError`; the caller treats this as a
    misconfiguration and falls back to the bridge's static config.
    """
    if name == "off":
        return OffStrategy()
    if name == "light":
        return LightStrategy()
    if name == "aggressive":
        # Stage 6 slice 2: real implementation lands in slice 6.3.
        # Falling back to OffStrategy keeps the cross-process channel
        # exercisable end-to-end without behaviour change yet.
        _logger.debug("wasting_strategy=aggressive requested; slice 6.2 routes to off")
        return OffStrategy()
    raise ValueError(f"unknown wasting strategy: {name!r}")
