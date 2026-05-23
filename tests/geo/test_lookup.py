"""Tests for :class:`anglerfish.geo.GeoLookup`."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from anglerfish.config.models import GeoConfig
from anglerfish.geo import GeoLookup


class _StubReader:
    def __init__(self, data: dict[str, dict[str, Any] | None]) -> None:
        self.data = data
        self.closed = False

    def get(self, ip: str) -> Any:
        return self.data.get(ip)

    def close(self) -> None:
        self.closed = True


def _city_payload() -> dict[str, Any]:
    return {
        "country": {"iso_code": "GB", "names": {"en": "United Kingdom"}},
        "city": {"names": {"en": "London"}},
        "location": {
            "latitude": 51.5074,
            "longitude": -0.1278,
            "time_zone": "Europe/London",
        },
    }


def _asn_payload() -> dict[str, Any]:
    return {
        "autonomous_system_number": 16276,
        "autonomous_system_organization": "OVH SAS",
    }


async def test_lookup_disabled_returns_unenriched_record() -> None:
    cfg = GeoConfig()
    lookup = GeoLookup(cfg)
    record = await lookup.lookup("8.8.8.8")
    assert record.looked_up is False
    assert record.country is None
    assert lookup.enabled is False


async def test_lookup_with_both_readers() -> None:
    cfg = GeoConfig(city_db_path=Path("/x.mmdb"), asn_db_path=Path("/y.mmdb"))
    city = _StubReader({"203.0.113.7": _city_payload()})
    asn = _StubReader({"203.0.113.7": _asn_payload()})
    lookup = GeoLookup(cfg, city_reader=city, asn_reader=asn)
    record = await lookup.lookup("203.0.113.7")
    assert record.country == "GB"
    assert record.country_name == "United Kingdom"
    assert record.city == "London"
    assert record.latitude == pytest.approx(51.5074)
    assert record.timezone == "Europe/London"
    assert record.asn == 16276
    assert record.asn_organization == "OVH SAS"
    await lookup.aclose()


async def test_lookup_missing_ip_returns_nones() -> None:
    city = _StubReader({})
    asn = _StubReader({})
    lookup = GeoLookup(
        GeoConfig(city_db_path=Path("/x.mmdb"), asn_db_path=Path("/y.mmdb")),
        city_reader=city,
        asn_reader=asn,
    )
    record = await lookup.lookup("1.2.3.4")
    assert record.looked_up is True
    assert record.country is None
    assert record.asn is None
    await lookup.aclose()


async def test_lookup_partial_payload() -> None:
    city = _StubReader(
        {
            "1.2.3.4": {
                "country": {"iso_code": "US"},
                "location": {"latitude": 37.7, "longitude": -122.4},
            },
        },
    )
    lookup = GeoLookup(
        GeoConfig(city_db_path=Path("/x.mmdb")),
        city_reader=city,
    )
    record = await lookup.lookup("1.2.3.4")
    assert record.country == "US"
    assert record.country_name is None
    assert record.city is None
    assert record.latitude == pytest.approx(37.7)
    assert record.asn is None
    await lookup.aclose()


async def test_lookup_swallows_reader_errors() -> None:
    class _ExplodingReader:
        def get(self, _ip: str) -> Any:
            raise ValueError("malformed ip")

        def close(self) -> None: ...

    lookup = GeoLookup(
        GeoConfig(city_db_path=Path("/x.mmdb")),
        city_reader=_ExplodingReader(),
    )
    record = await lookup.lookup("not-an-ip")
    assert record.country is None
    assert record.looked_up is True
    await lookup.aclose()


async def test_lookup_non_dict_payload_is_ignored() -> None:
    city = _StubReader({"1.2.3.4": "unexpected"})  # type: ignore[dict-item]
    lookup = GeoLookup(
        GeoConfig(city_db_path=Path("/x.mmdb")),
        city_reader=city,
    )
    record = await lookup.lookup("1.2.3.4")
    assert record.country is None
    await lookup.aclose()


async def test_aclose_only_closes_owned_readers() -> None:
    city = _StubReader({})
    asn = _StubReader({})
    lookup = GeoLookup(
        GeoConfig(city_db_path=Path("/x.mmdb"), asn_db_path=Path("/y.mmdb")),
        city_reader=city,
        asn_reader=asn,
    )
    await lookup.aclose()
    # We passed both readers, so we keep ownership.
    assert city.closed is False
    assert asn.closed is False


async def test_async_context_manager() -> None:
    city = _StubReader({"1.2.3.4": _city_payload()})
    async with GeoLookup(
        GeoConfig(city_db_path=Path("/x.mmdb")),
        city_reader=city,
    ) as lookup:
        record = await lookup.lookup("1.2.3.4")
    assert record.country == "GB"
