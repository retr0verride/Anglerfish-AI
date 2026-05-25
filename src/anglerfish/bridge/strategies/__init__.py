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

from anglerfish.bridge.strategies.aggressive import AggressiveStrategy
from anglerfish.bridge.strategies.base import (
    StrategyContext,
    StrategyPreEffect,
    WastingStrategyBase,
)
from anglerfish.bridge.strategies.light import LightStrategy
from anglerfish.bridge.strategies.off import OffStrategy

__all__ = [
    "AggressiveStrategy",
    "LightStrategy",
    "OffStrategy",
    "StrategyContext",
    "StrategyPreEffect",
    "WastingStrategyBase",
    "get_strategy",
]


def get_strategy(name: str) -> WastingStrategyBase:
    """Return a strategy instance for ``name``.

    All three documented strategies are now wired. Slice 6.3 added
    :class:`AggressiveStrategy` (delays only; the clarification
    injection mode the design doc describes lands in slice 6.4).
    Unknown names raise :class:`ValueError`; the caller treats this
    as a misconfiguration and falls back to the bridge's static
    config.
    """
    if name == "off":
        return OffStrategy()
    if name == "light":
        return LightStrategy()
    if name == "aggressive":
        return AggressiveStrategy()
    raise ValueError(f"unknown wasting strategy: {name!r}")
