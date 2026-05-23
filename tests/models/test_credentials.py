"""Tests for :mod:`anglerfish.models.credentials`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from anglerfish.models.credentials import CredentialRecord, CredentialStats


def test_record_minimum_count() -> None:
    with pytest.raises(ValidationError):
        CredentialRecord(
            source_ip="1.1.1.1",
            username="x",
            password="y",
            first_seen=datetime(2026, 1, 1, tzinfo=UTC),
            last_seen=datetime(2026, 1, 1, tzinfo=UTC),
            attempt_count=0,
        )


def test_stats_fields_default_to_zero_safe() -> None:
    s = CredentialStats(
        total_attempts=0,
        unique_combinations=0,
        unique_usernames=0,
        unique_passwords=0,
        unique_source_ips=0,
    )
    assert s.total_attempts == 0


def test_stats_rejects_negative_values() -> None:
    with pytest.raises(ValidationError):
        CredentialStats(
            total_attempts=-1,
            unique_combinations=0,
            unique_usernames=0,
            unique_passwords=0,
            unique_source_ips=0,
        )
