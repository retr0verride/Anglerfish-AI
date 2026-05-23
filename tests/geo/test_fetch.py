"""Tests for the MaxMind GeoLite2 fetcher."""

from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from anglerfish.config.models import GeoConfig
from anglerfish.geo.fetch import FetchError, fetch_geolite_databases


def _build_archive(edition: str, mmdb_bytes: bytes) -> bytes:
    """Build an in-memory tar.gz matching MaxMind's layout."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=f"{edition}_20260520/{edition}.mmdb")
        info.size = len(mmdb_bytes)
        tar.addfile(info, io.BytesIO(mmdb_bytes))
    return buf.getvalue()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _config(tmp_path: Path, *, key: str | None = "licensekey1234") -> GeoConfig:
    return GeoConfig(
        city_db_path=tmp_path / "city.mmdb",
        asn_db_path=tmp_path / "asn.mmdb",
        maxmind_license_key=SecretStr(key) if key else None,
    )


def _mock_client(routes: dict[str, tuple[int, bytes]]) -> httpx.Client:
    def _handler(request: httpx.Request) -> httpx.Response:
        for needle, (code, body) in routes.items():
            if needle in str(request.url):
                return httpx.Response(status_code=code, content=body)
        return httpx.Response(404, content=b"not found")

    return httpx.Client(
        transport=httpx.MockTransport(_handler),
        base_url="https://example.invalid",
    )


def test_fetch_no_key_is_noop(tmp_path: Path) -> None:
    cfg = _config(tmp_path, key=None)
    results = fetch_geolite_databases(cfg, http_client=_mock_client({}))
    assert results == []


def test_fetch_downloads_and_installs_both_editions(tmp_path: Path) -> None:
    city_mmdb = b"\x00\xab" * 64
    asn_mmdb = b"\x00\xcd" * 64
    city_archive = _build_archive("GeoLite2-City", city_mmdb)
    asn_archive = _build_archive("GeoLite2-ASN", asn_mmdb)

    client = _mock_client(
        {
            "GeoLite2-City&license_key=licensekey1234&suffix=tar.gz.sha256": (
                200,
                f"{_sha256(city_archive)}  GeoLite2-City.tar.gz".encode(),
            ),
            "GeoLite2-ASN&license_key=licensekey1234&suffix=tar.gz.sha256": (
                200,
                f"{_sha256(asn_archive)}  GeoLite2-ASN.tar.gz".encode(),
            ),
            "edition_id=GeoLite2-City&license_key=licensekey1234&suffix=tar.gz": (
                200,
                city_archive,
            ),
            "edition_id=GeoLite2-ASN&license_key=licensekey1234&suffix=tar.gz": (
                200,
                asn_archive,
            ),
        },
    )
    cfg = _config(tmp_path)
    results = fetch_geolite_databases(cfg, http_client=client)
    assert {r.edition for r in results} == {"GeoLite2-City", "GeoLite2-ASN"}
    assert (tmp_path / "city.mmdb").read_bytes() == city_mmdb
    assert (tmp_path / "asn.mmdb").read_bytes() == asn_mmdb


def test_fetch_refuses_sha_mismatch(tmp_path: Path) -> None:
    archive = _build_archive("GeoLite2-City", b"\x00" * 16)
    client = _mock_client(
        {
            ".sha256": (200, ("a" * 64 + "  whatever").encode()),
            "edition_id=GeoLite2-City&license_key=licensekey1234&suffix=tar.gz": (
                200,
                archive,
            ),
        },
    )
    cfg = GeoConfig(
        city_db_path=tmp_path / "city.mmdb",
        maxmind_license_key=SecretStr("licensekey1234"),
    )
    with pytest.raises(FetchError, match="sha256 mismatch"):
        fetch_geolite_databases(cfg, http_client=client)
    # Destination must NOT be created on mismatch.
    assert not (tmp_path / "city.mmdb").exists()


def test_fetch_rejects_malformed_sha_manifest(tmp_path: Path) -> None:
    client = _mock_client({".sha256": (200, b"this-is-not-a-hash  blah")})
    cfg = GeoConfig(
        city_db_path=tmp_path / "city.mmdb",
        maxmind_license_key=SecretStr("licensekey1234"),
    )
    with pytest.raises(FetchError, match="malformed sha256"):
        fetch_geolite_databases(cfg, http_client=client)


def test_fetch_rejects_path_traversal_in_archive(tmp_path: Path) -> None:
    payload = b"\x00\x01"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="../escape/GeoLite2-City.mmdb")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    archive = buf.getvalue()

    client = _mock_client(
        {
            ".sha256": (200, f"{_sha256(archive)}  x".encode()),
            "edition_id=GeoLite2-City&license_key=licensekey1234&suffix=tar.gz": (
                200,
                archive,
            ),
        },
    )
    cfg = GeoConfig(
        city_db_path=tmp_path / "city.mmdb",
        maxmind_license_key=SecretStr("licensekey1234"),
    )
    with pytest.raises(FetchError, match="unsafe path"):
        fetch_geolite_databases(cfg, http_client=client)


def test_fetch_rejects_archive_without_mmdb(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="GeoLite2-City_20260520/COPYRIGHT.txt")
        body = b"no mmdb here"
        info.size = len(body)
        tar.addfile(info, io.BytesIO(body))
    archive = buf.getvalue()

    client = _mock_client(
        {
            ".sha256": (200, f"{_sha256(archive)}  x".encode()),
            "edition_id=GeoLite2-City&license_key=licensekey1234&suffix=tar.gz": (
                200,
                archive,
            ),
        },
    )
    cfg = GeoConfig(
        city_db_path=tmp_path / "city.mmdb",
        maxmind_license_key=SecretStr("licensekey1234"),
    )
    with pytest.raises(FetchError, match=r"did not contain a \.mmdb"):
        fetch_geolite_databases(cfg, http_client=client)
