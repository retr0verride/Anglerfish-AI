"""Async wrapper around the MaxMind GeoLite2 City and ASN databases.

The underlying ``maxminddb`` library is synchronous; we keep the
honeypot's event loop responsive by dispatching the lookups onto
:func:`asyncio.to_thread`. Both databases are optional — if neither
path is configured, :meth:`GeoLookup.lookup` returns a record with
``looked_up=False`` and all enrichment fields as :data:`None`.

The two database readers are injectable for tests so the test suite
does not need to ship real MMDB files. Any object satisfying the
:class:`_GeoReader` :class:`~typing.Protocol` will do.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Protocol, Self

from anglerfish.config.models import GeoConfig
from anglerfish.models.geo import GeoRecord

__all__ = ["GeoLookup"]


class _GeoReader(Protocol):
    def get(self, ip: str) -> Any: ...

    def close(self) -> None: ...


def _open_reader(path: Path) -> _GeoReader:
    """Open a MaxMind MMDB reader. Lazy-imports the optional dependency."""
    import maxminddb

    return maxminddb.open_database(str(path))


class GeoLookup:
    """Geographic + ASN enrichment for IP addresses."""

    def __init__(
        self,
        config: GeoConfig,
        *,
        city_reader: _GeoReader | None = None,
        asn_reader: _GeoReader | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._config = config
        self._logger = logger if logger is not None else logging.getLogger(__name__)
        if city_reader is not None:
            self._city_reader: _GeoReader | None = city_reader
            self._owns_city = False
        elif config.city_db_path is not None:
            self._city_reader = _open_reader(config.city_db_path)
            self._owns_city = True
        else:
            self._city_reader = None
            self._owns_city = False
        if asn_reader is not None:
            self._asn_reader: _GeoReader | None = asn_reader
            self._owns_asn = False
        elif config.asn_db_path is not None:
            self._asn_reader = _open_reader(config.asn_db_path)
            self._owns_asn = True
        else:
            self._asn_reader = None
            self._owns_asn = False

    @property
    def config(self) -> GeoConfig:
        return self._config

    @property
    def enabled(self) -> bool:
        return self._city_reader is not None or self._asn_reader is not None

    async def lookup(self, ip: str) -> GeoRecord:
        """Look up ``ip`` in the configured databases.

        Never raises — a missing IP, a malformed result, or a reader
        exception all degrade to fields that are :data:`None` in the
        returned :class:`GeoRecord`.
        """
        if not self.enabled:
            return GeoRecord(ip=ip, looked_up=False)

        city_payload, asn_payload = await asyncio.gather(
            self._lookup_one(self._city_reader, ip),
            self._lookup_one(self._asn_reader, ip),
        )
        return self._build_record(ip, city_payload, asn_payload)

    async def _lookup_one(
        self,
        reader: _GeoReader | None,
        ip: str,
    ) -> dict[str, Any] | None:
        if reader is None:
            return None
        try:
            result = await asyncio.to_thread(reader.get, ip)
        except (ValueError, OSError) as exc:
            self._logger.warning(
                "geo.lookup_failed ip=%s error=%s",
                ip,
                exc,
            )
            return None
        if isinstance(result, dict):
            return result
        return None

    @staticmethod
    def _build_record(
        ip: str,
        city: dict[str, Any] | None,
        asn: dict[str, Any] | None,
    ) -> GeoRecord:
        country: str | None = None
        country_name: str | None = None
        city_name: str | None = None
        latitude: float | None = None
        longitude: float | None = None
        timezone: str | None = None
        asn_number: int | None = None
        asn_organization: str | None = None

        if city is not None:
            country_block = city.get("country")
            if isinstance(country_block, dict):
                code = country_block.get("iso_code")
                if isinstance(code, str):
                    country = code
                names = country_block.get("names")
                if isinstance(names, dict):
                    name = names.get("en")
                    if isinstance(name, str):
                        country_name = name
            city_block = city.get("city")
            if isinstance(city_block, dict):
                names = city_block.get("names")
                if isinstance(names, dict):
                    name = names.get("en")
                    if isinstance(name, str):
                        city_name = name
            location_block = city.get("location")
            if isinstance(location_block, dict):
                lat = location_block.get("latitude")
                if isinstance(lat, (int, float)):
                    latitude = float(lat)
                lon = location_block.get("longitude")
                if isinstance(lon, (int, float)):
                    longitude = float(lon)
                tz = location_block.get("time_zone")
                if isinstance(tz, str):
                    timezone = tz

        if asn is not None:
            n = asn.get("autonomous_system_number")
            if isinstance(n, int):
                asn_number = n
            org = asn.get("autonomous_system_organization")
            if isinstance(org, str):
                asn_organization = org

        return GeoRecord(
            ip=ip,
            looked_up=True,
            country=country,
            country_name=country_name,
            city=city_name,
            latitude=latitude,
            longitude=longitude,
            timezone=timezone,
            asn=asn_number,
            asn_organization=asn_organization,
        )

    async def aclose(self) -> None:
        if self._city_reader is not None and self._owns_city:
            await asyncio.to_thread(self._city_reader.close)
        if self._asn_reader is not None and self._owns_asn:
            await asyncio.to_thread(self._asn_reader.close)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
