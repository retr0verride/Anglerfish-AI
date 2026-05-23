"""Shared data model for geographic and ASN enrichment."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["GeoRecord"]


class GeoRecord(BaseModel):
    """Geographic and ASN lookup result for one IP address.

    All fields except ``ip`` and ``looked_up`` may be :data:`None`
    when the IP is not present in the corresponding database (the
    GeoLite2 databases do not cover every IP).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ip: str
    looked_up: bool = Field(
        default=True,
        description="False when no GeoLite2 database is configured at all.",
    )
    country: str | None = Field(default=None, max_length=8)
    country_name: str | None = Field(default=None, max_length=128)
    city: str | None = Field(default=None, max_length=128)
    latitude: float | None = Field(default=None, ge=-90.0, le=90.0)
    longitude: float | None = Field(default=None, ge=-180.0, le=180.0)
    timezone: str | None = Field(default=None, max_length=64)
    asn: int | None = Field(default=None, ge=0, le=4_294_967_295)
    asn_organization: str | None = Field(default=None, max_length=255)
