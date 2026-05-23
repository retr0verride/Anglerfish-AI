"""Tests for ``anglerfish geo update``."""

from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from anglerfish.audit import AuditLog
from anglerfish.cli.__main__ import app
from anglerfish.geo import fetch_geolite_databases


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _build_archive(edition: str, mmdb_bytes: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=f"{edition}_20260520/{edition}.mmdb")
        info.size = len(mmdb_bytes)
        tar.addfile(info, io.BytesIO(mmdb_bytes))
    return buf.getvalue()


def _stage_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    license_key: str | None,
) -> Path:
    geo_dir = tmp_path / "geo"
    geo_dir.mkdir()
    city_path = geo_dir / "city.mmdb"
    asn_path = geo_dir / "asn.mmdb"

    monkeypatch.setenv("ANGLERFISH_DASHBOARD__SESSION_SECRET", "x" * 40)
    monkeypatch.setenv(
        "ANGLERFISH_CREDENTIALS__ENCRYPTION_KEY",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    monkeypatch.setenv("ANGLERFISH_GEO__CITY_DB_PATH", str(city_path))
    monkeypatch.setenv("ANGLERFISH_GEO__ASN_DB_PATH", str(asn_path))
    if license_key is not None:
        monkeypatch.setenv("ANGLERFISH_GEO__MAXMIND_LICENSE_KEY", license_key)

    monkeypatch.setattr(
        "anglerfish.cli.__main__.AuditLog",
        lambda *_a, **_kw: AuditLog(tmp_path / "audit.jsonl"),
    )
    return geo_dir


def test_geo_update_no_key_is_noop(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stage_env(monkeypatch, tmp_path, license_key=None)
    result = runner.invoke(app, ["geo", "update"])
    assert result.exit_code == 0
    assert "not configured" in result.output.lower()


def test_geo_update_downloads_and_writes(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    geo_dir = _stage_env(monkeypatch, tmp_path, license_key="testkey123")
    city_mmdb = b"\x00C" * 32
    asn_mmdb = b"\x00A" * 32
    city_archive = _build_archive("GeoLite2-City", city_mmdb)
    asn_archive = _build_archive("GeoLite2-ASN", asn_mmdb)

    def _handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "GeoLite2-City" in url and "sha256" in url:
            return httpx.Response(
                200,
                content=f"{hashlib.sha256(city_archive).hexdigest()}  x".encode(),
            )
        if "GeoLite2-ASN" in url and "sha256" in url:
            return httpx.Response(
                200,
                content=f"{hashlib.sha256(asn_archive).hexdigest()}  x".encode(),
            )
        if "edition_id=GeoLite2-City" in url:
            return httpx.Response(200, content=city_archive)
        if "edition_id=GeoLite2-ASN" in url:
            return httpx.Response(200, content=asn_archive)
        return httpx.Response(404, content=b"not found")

    def _wrapped(cfg, **kwargs):  # type: ignore[no-untyped-def]
        client = httpx.Client(
            transport=httpx.MockTransport(_handler),
            base_url="https://example.invalid",
        )
        return fetch_geolite_databases(cfg, http_client=client, **kwargs)

    monkeypatch.setattr("anglerfish.geo.fetch_geolite_databases", _wrapped)
    monkeypatch.setattr("anglerfish.geo.fetch.fetch_geolite_databases", _wrapped)

    result = runner.invoke(app, ["geo", "update"])
    assert result.exit_code == 0, result.output
    assert (geo_dir / "city.mmdb").read_bytes() == city_mmdb
    assert (geo_dir / "asn.mmdb").read_bytes() == asn_mmdb
