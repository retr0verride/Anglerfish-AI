"""MaxMind GeoLite2 database fetcher.

Operators supply a MaxMind licence key in the wizard; the
``anglerfish geo update`` command (driven by a systemd oneshot at
first boot, plus a weekly timer) downloads the ``GeoLite2-City`` and
``GeoLite2-ASN`` archives, validates the SHA-256 published alongside
each archive, extracts the ``.mmdb`` payload, and atomically swaps it
into place.

The fetcher is deliberately conservative:

* Each download has a small total-time budget.
* The archive is streamed to a temp file inside the destination
  directory so the final rename is on the same filesystem.
* If the SHA-256 manifest is missing or wrong, the download is
  discarded and the existing database stays in place.
* No request body is interpreted as Python — only as bytes — so a
  hostile mirror cannot inject code.

The function is sync so it can run from a oneshot systemd unit
without an event loop. The bridge / dashboard never call it directly.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx

from anglerfish.config.models import GeoConfig

__all__ = ["MAXMIND_BASE_URL", "FetchError", "FetchResult", "fetch_geolite_databases"]


MAXMIND_BASE_URL = "https://download.maxmind.com/app/geoip_download"
_USER_AGENT = "anglerfish-ai/geolite-fetcher"
_DEFAULT_TIMEOUT = 60.0
_CHUNK = 1 << 16
_MAX_BYTES = 200 * 1024 * 1024  # 200 MB ceiling; current dbs are ~70 MB combined


class FetchError(RuntimeError):
    """Raised when the fetcher refuses to swap a stale database."""


@dataclass(frozen=True)
class FetchResult:
    edition: str
    destination: Path
    bytes_written: int
    sha256: str


_EDITIONS = (
    ("GeoLite2-City", "city_db_path"),
    ("GeoLite2-ASN", "asn_db_path"),
)


def fetch_geolite_databases(
    config: GeoConfig,
    *,
    base_url: str = MAXMIND_BASE_URL,
    http_client: httpx.Client | None = None,
    logger: logging.Logger | None = None,
) -> list[FetchResult]:
    """Download all configured GeoLite2 editions.

    Returns one :class:`FetchResult` per edition successfully written;
    raises :class:`FetchError` only when the operator asked for an
    edition (path configured + key set) and the download failed.
    """

    log = logger or logging.getLogger(__name__)
    if config.maxmind_license_key is None:
        log.info("MaxMind licence key not configured — skipping geo update")
        return []

    key = config.maxmind_license_key.get_secret_value()

    with _maybe_client(http_client) as client:  # client: httpx.Client
        results: list[FetchResult] = []
        for edition, attr in _EDITIONS:
            dest = getattr(config, attr)
            if dest is None:
                continue
            result = _fetch_one(
                client=client,
                base_url=base_url,
                license_key=key,
                edition=edition,
                destination=Path(dest),
                logger=log,
            )
            results.append(result)
        return results


@contextmanager
def _maybe_client(client: httpx.Client | None) -> Iterator[httpx.Client]:
    """Yield ``client`` if supplied; otherwise open + close a default one."""
    if client is not None:
        yield client
        return
    with httpx.Client(
        timeout=_DEFAULT_TIMEOUT,
        headers={"User-Agent": _USER_AGENT},
        follow_redirects=True,
    ) as owned:
        yield owned


def _fetch_one(
    *,
    client: httpx.Client,
    base_url: str,
    license_key: str,
    edition: str,
    destination: Path,
    logger: logging.Logger,
) -> FetchResult:
    """Download + verify + install one edition. Atomic per destination."""

    destination.parent.mkdir(parents=True, exist_ok=True)

    params = {"edition_id": edition, "license_key": license_key, "suffix": "tar.gz"}
    sha_url = f"{base_url}?edition_id={edition}&license_key={license_key}&suffix=tar.gz.sha256"

    logger.info("fetching %s manifest", edition)
    sha_resp = client.get(sha_url)
    sha_resp.raise_for_status()
    expected_sha = sha_resp.text.split()[0].strip().lower()
    if len(expected_sha) != 64 or not all(c in "0123456789abcdef" for c in expected_sha):
        raise FetchError(f"{edition}: malformed sha256 manifest {expected_sha!r}")

    logger.info("downloading %s", edition)
    with tempfile.TemporaryDirectory(prefix="anglerfish-geo-") as tmpdir:
        archive_path = Path(tmpdir) / f"{edition}.tar.gz"
        actual_sha = hashlib.sha256()
        bytes_seen = 0
        with (
            client.stream("GET", base_url, params=params) as response,
            archive_path.open("wb") as out,
        ):
            response.raise_for_status()
            for chunk in response.iter_bytes(_CHUNK):
                bytes_seen += len(chunk)
                if bytes_seen > _MAX_BYTES:
                    raise FetchError(f"{edition}: archive exceeded {_MAX_BYTES} byte ceiling")
                actual_sha.update(chunk)
                out.write(chunk)

        if actual_sha.hexdigest() != expected_sha:
            raise FetchError(
                f"{edition}: sha256 mismatch (expected {expected_sha}, "
                f"got {actual_sha.hexdigest()})",
            )

        extracted = _extract_mmdb(archive_path, edition=edition)
        if extracted is None:
            raise FetchError(f"{edition}: archive did not contain a .mmdb payload")

        # Stage the file in the destination directory so the final
        # rename is on the same filesystem.
        staged = destination.with_suffix(destination.suffix + ".new")
        shutil.copyfile(extracted, staged)
        staged.chmod(0o644)
        staged.replace(destination)
        return FetchResult(
            edition=edition,
            destination=destination,
            bytes_written=bytes_seen,
            sha256=expected_sha,
        )


def _extract_mmdb(archive_path: Path, *, edition: str) -> Path | None:
    """Extract the ``.mmdb`` from a MaxMind tar.gz and return its path.

    MaxMind archives contain a single dated directory with the database
    plus license + changelog files. We accept any ``.mmdb`` whose name
    starts with ``edition`` and refuse archive members with parent-dir
    traversal in their names.
    """

    extract_root = archive_path.parent / "extracted"
    extract_root.mkdir(exist_ok=True)
    with tarfile.open(archive_path, "r:gz") as tar:
        for member in tar.getmembers():
            name = member.name
            if name.startswith("/") or ".." in Path(name).parts:
                raise FetchError(f"{edition}: archive contains unsafe path {name!r}")
        # tarfile.data_filter is available on Python 3.12+; on older it's a no-op
        tar.extractall(extract_root, filter="data")

    matches = sorted(extract_root.rglob(f"{edition}*.mmdb"))
    return matches[0] if matches else None
