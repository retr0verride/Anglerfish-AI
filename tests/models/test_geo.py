"""Tests for :mod:`anglerfish.models.geo`."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from anglerfish.models.geo import GeoRecord


def test_record_bounds_latitude() -> None:
    with pytest.raises(ValidationError):
        GeoRecord(ip="1.2.3.4", latitude=99.0)


def test_record_bounds_longitude() -> None:
    with pytest.raises(ValidationError):
        GeoRecord(ip="1.2.3.4", longitude=-181.0)


def test_record_bounds_asn() -> None:
    with pytest.raises(ValidationError):
        GeoRecord(ip="1.2.3.4", asn=-1)


def test_record_minimal() -> None:
    record = GeoRecord(ip="1.2.3.4")
    assert record.looked_up is True
    assert record.country is None
