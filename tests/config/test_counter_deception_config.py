"""Tests for CounterDeceptionConfig (Stage 12 slice 1)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from anglerfish.config.models import CounterDeceptionConfig, CounterDeceptionMode


def test_defaults_parse_cleanly() -> None:
    config = CounterDeceptionConfig()
    assert config.enabled is False
    assert config.mode is CounterDeceptionMode.BOTH
    assert config.engagement_threshold == 70
    assert config.timebomb_cold_to_mild == 6
    assert config.timebomb_mild_to_severe == 16
    assert "/root/.ssh/id_rsa" in config.garble_paths
    assert "/root/.aws/credentials" in config.garble_paths


def test_enabled_true_with_no_other_overrides_works() -> None:
    """Stage 12's master switch is independent of the other knobs; an
    operator who flips enabled=True with no other env vars set still
    gets a valid config (BOTH mode + default garble paths + default
    time-bomb thresholds)."""
    config = CounterDeceptionConfig(enabled=True)
    assert config.enabled is True
    assert config.mode is CounterDeceptionMode.BOTH


def test_engagement_threshold_boundary_values_accepted() -> None:
    """0 and 100 are both valid threshold values (engage on every
    session vs effectively never)."""
    low = CounterDeceptionConfig(engagement_threshold=0)
    high = CounterDeceptionConfig(engagement_threshold=100)
    assert low.engagement_threshold == 0
    assert high.engagement_threshold == 100


def test_engagement_threshold_out_of_range_rejected() -> None:
    """101 and -1 are both rejected; the field is bounded [0, 100]
    matching the threat scorer's range."""
    with pytest.raises(ValidationError):
        CounterDeceptionConfig(engagement_threshold=101)
    with pytest.raises(ValidationError):
        CounterDeceptionConfig(engagement_threshold=-1)


def test_timebomb_mild_to_severe_must_be_strictly_greater_than_cold_to_mild() -> None:
    """The two thresholds collapse if mild_to_severe <= cold_to_mild;
    post-init validator rejects (the severe instruction would fire
    before mild had effect)."""
    with pytest.raises(ValidationError):
        CounterDeceptionConfig(
            timebomb_cold_to_mild=10,
            timebomb_mild_to_severe=10,  # equal: rejected
        )
    with pytest.raises(ValidationError):
        CounterDeceptionConfig(
            timebomb_cold_to_mild=10,
            timebomb_mild_to_severe=5,  # less: rejected
        )


def test_invalid_mode_string_rejected_with_enum_error() -> None:
    """A typo in the mode name (env-var pasted wrong) fails at
    settings load."""
    with pytest.raises(ValidationError):
        CounterDeceptionConfig(mode="aggressive")  # type: ignore[arg-type]


def test_mode_accepts_lowercase_string_per_strenum() -> None:
    """Pydantic accepts the StrEnum's string value at construct."""
    config = CounterDeceptionConfig(mode="timebomb")  # type: ignore[arg-type]
    assert config.mode is CounterDeceptionMode.TIMEBOMB


def test_empty_garble_paths_accepted() -> None:
    """Operators who want time-bomb only without any garbling can set
    mode=TIMEBOMB; an empty garble_paths tuple is also legal (defensive
    posture: even mode=GARBLE with empty paths is a degenerate no-op
    rather than an error)."""
    config = CounterDeceptionConfig(
        mode=CounterDeceptionMode.GARBLE,
        garble_paths=(),
    )
    assert config.garble_paths == ()
