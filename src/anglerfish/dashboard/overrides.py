"""In-process runtime overrides the dashboard exposes to operators.

The dashboard and the bridge run as separate processes. Stage 3
ships dashboard-process-only mutation: a settings POST updates the
overrides held on ``app.state.runtime_overrides``, and the response
makes that boundary explicit. Cross-process propagation (so the
bridge actually honours, for example, a new wasting strategy) lands
in Stage 6 when the first capability stage needs it.

The dataclasses below intentionally mirror the *shape* of
:class:`anglerfish.config.models.BridgeConfig` and the future
feature-flag fields without using Pydantic. Pydantic models are
``frozen=True`` across the codebase; the override layer needs
mutation. Using a plain dataclass is cleaner than fighting Pydantic's
immutability for a process-local mutable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from anglerfish.config.settings import AnglerfishSettings

__all__ = [
    "BridgeRuntimeOverrides",
    "FeatureFlagOverrides",
    "RuntimeOverrides",
    "WastingStrategy",
    "build_runtime_overrides",
]


WastingStrategy = Literal["off", "light", "aggressive"]


@dataclass
class BridgeRuntimeOverrides:
    """Mutable per-process snapshot of the bridge knobs the dashboard exposes.

    Initialised from ``settings.rate_limit`` at app startup; the
    ``wasting_strategy`` is dashboard-only until Stage 6 adds the
    matching ``BridgeConfig.wasting_strategy`` field and the bridge
    learns to consume it.
    """

    max_concurrent_requests: int
    requests_per_session_per_minute: int
    wasting_strategy: WastingStrategy = "off"


@dataclass
class FeatureFlagOverrides:
    """Opt-in capability toggles. All default False.

    Each flag corresponds to a future capability stage and stays
    inert in Stage 3. The dashboard surfaces the toggle so operators
    can flip it ahead of the runtime implementation; the audit log
    records the toggle even when the bridge does not yet honour it.
    """

    time_wasting: bool = False
    engaged_persistence: bool = False
    decoy_poisoning: bool = False
    counter_deception: bool = False


@dataclass
class RuntimeOverrides:
    """Top-level holder attached to ``app.state.runtime_overrides``."""

    bridge: BridgeRuntimeOverrides
    features: FeatureFlagOverrides = field(default_factory=FeatureFlagOverrides)
    applied_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))

    def snapshot(self) -> dict[str, Any]:
        """Render the current state for the GET /api/settings response.

        Stable shape: nested dicts of `bridge` and `features`, plus
        the provenance fields the API contract promises. Callers do
        not mutate the result.
        """
        return {
            "bridge": {
                "max_concurrent_requests": self.bridge.max_concurrent_requests,
                "requests_per_session_per_minute": (self.bridge.requests_per_session_per_minute),
                "wasting_strategy": self.bridge.wasting_strategy,
            },
            "features": {
                "time_wasting": self.features.time_wasting,
                "engaged_persistence": self.features.engaged_persistence,
                "decoy_poisoning": self.features.decoy_poisoning,
                "counter_deception": self.features.counter_deception,
            },
            "applied_at": self.applied_at.isoformat(),
            "applies_to": "dashboard_process",
            "note": (
                "Service restart reverts to env-file values. "
                "Bridge-side propagation lands in a later stage."
            ),
        }

    def apply_bridge(
        self,
        *,
        max_concurrent_requests: int | None = None,
        requests_per_session_per_minute: int | None = None,
        wasting_strategy: WastingStrategy | None = None,
    ) -> dict[str, tuple[Any, Any]]:
        """Mutate the bridge overrides; return a per-field diff.

        Absent kwargs keep the current value. The diff (``{"field":
        (old, new)}``) lets the audit-log entry record exactly what
        changed without dumping the full before/after snapshot.
        """
        diff: dict[str, tuple[Any, Any]] = {}
        if (
            max_concurrent_requests is not None
            and max_concurrent_requests != self.bridge.max_concurrent_requests
        ):
            diff["max_concurrent_requests"] = (
                self.bridge.max_concurrent_requests,
                max_concurrent_requests,
            )
            self.bridge.max_concurrent_requests = max_concurrent_requests
        if (
            requests_per_session_per_minute is not None
            and requests_per_session_per_minute != self.bridge.requests_per_session_per_minute
        ):
            diff["requests_per_session_per_minute"] = (
                self.bridge.requests_per_session_per_minute,
                requests_per_session_per_minute,
            )
            self.bridge.requests_per_session_per_minute = requests_per_session_per_minute
        if wasting_strategy is not None and wasting_strategy != self.bridge.wasting_strategy:
            diff["wasting_strategy"] = (
                self.bridge.wasting_strategy,
                wasting_strategy,
            )
            self.bridge.wasting_strategy = wasting_strategy
        if diff:
            self.applied_at = datetime.now(tz=UTC)
        return diff

    def apply_features(
        self,
        *,
        time_wasting: bool | None = None,
        engaged_persistence: bool | None = None,
        decoy_poisoning: bool | None = None,
        counter_deception: bool | None = None,
    ) -> dict[str, tuple[bool, bool]]:
        """Mutate feature flags; return a per-flag diff."""
        diff: dict[str, tuple[bool, bool]] = {}
        if time_wasting is not None and time_wasting != self.features.time_wasting:
            diff["time_wasting"] = (self.features.time_wasting, time_wasting)
            self.features.time_wasting = time_wasting
        if (
            engaged_persistence is not None
            and engaged_persistence != self.features.engaged_persistence
        ):
            diff["engaged_persistence"] = (
                self.features.engaged_persistence,
                engaged_persistence,
            )
            self.features.engaged_persistence = engaged_persistence
        if decoy_poisoning is not None and decoy_poisoning != self.features.decoy_poisoning:
            diff["decoy_poisoning"] = (
                self.features.decoy_poisoning,
                decoy_poisoning,
            )
            self.features.decoy_poisoning = decoy_poisoning
        if counter_deception is not None and counter_deception != self.features.counter_deception:
            diff["counter_deception"] = (
                self.features.counter_deception,
                counter_deception,
            )
            self.features.counter_deception = counter_deception
        if diff:
            self.applied_at = datetime.now(tz=UTC)
        return diff


def build_runtime_overrides(settings: AnglerfishSettings) -> RuntimeOverrides:
    """Construct the initial overrides from a loaded settings object.

    Called once at dashboard startup. A restart re-runs this so the
    overrides revert to the env-file values, matching the API
    contract that promises ``"note": "Service restart reverts to
    env-file values."``.

    The override object is a singleton per dashboard process by
    design. Forking via :func:`dataclasses.replace` would let
    callers carry around their own copy, which is exactly the
    cross-process drift problem Stage 3 is scoped to avoid.
    """
    return RuntimeOverrides(
        bridge=BridgeRuntimeOverrides(
            max_concurrent_requests=settings.rate_limit.max_concurrent_requests,
            requests_per_session_per_minute=(settings.rate_limit.requests_per_session_per_minute),
            wasting_strategy="off",
        ),
        features=FeatureFlagOverrides(),
    )
