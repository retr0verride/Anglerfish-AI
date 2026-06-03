"""Off-box audit-log shipper (TODO-12)."""

from __future__ import annotations

from pathlib import Path

import httpx
from pydantic import HttpUrl, SecretStr

from anglerfish.audit_shipper import AuditShipper
from anglerfish.config.models import AuditShipperConfig


def _write_log(path: Path, *records: str) -> None:
    with path.open("ab") as fp:
        for rec in records:
            fp.write((rec + "\n").encode("utf-8"))


def _make_shipper(
    tmp_path: Path,
    *,
    url: str | None = "https://collector.example/ingest",
    token: str | None = None,
    batch: int = 200,
    statuses: list[int] | None = None,
) -> tuple[AuditShipper, list[httpx.Request]]:
    requests: list[httpx.Request] = []
    status_iter = iter(statuses or [])

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        try:
            code = next(status_iter)
        except StopIteration:
            code = 200
        return httpx.Response(code)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    config = AuditShipperConfig(
        url=HttpUrl(url) if url is not None else None,
        token=SecretStr(token) if token is not None else None,
        batch_max_records=batch,
        offset_path=tmp_path / "offset.json",
    )
    shipper = AuditShipper(config, log_path=tmp_path / "audit.jsonl", http_client=client)
    return shipper, requests


async def test_disabled_when_no_url(tmp_path: Path) -> None:
    shipper, requests = _make_shipper(tmp_path, url=None)
    _write_log(tmp_path / "audit.jsonl", '{"event_type":"x"}')
    assert shipper.enabled is False
    assert await shipper.ship_pending() == 0
    assert requests == []


async def test_ships_new_records_as_ndjson(tmp_path: Path) -> None:
    shipper, requests = _make_shipper(tmp_path)
    _write_log(
        tmp_path / "audit.jsonl",
        '{"event_type":"a"}',
        '{"event_type":"b"}',
    )
    assert await shipper.ship_pending() == 2
    assert len(requests) == 1
    body = requests[0].content
    assert body == b'{"event_type":"a"}\n{"event_type":"b"}\n'
    assert requests[0].headers["content-type"] == "application/x-ndjson"


async def test_only_new_records_ship_on_second_call(tmp_path: Path) -> None:
    shipper, requests = _make_shipper(tmp_path)
    log = tmp_path / "audit.jsonl"
    _write_log(log, '{"event_type":"a"}')
    assert await shipper.ship_pending() == 1
    # No new records -> no POST.
    assert await shipper.ship_pending() == 0
    assert len(requests) == 1
    # Append one more -> only it ships.
    _write_log(log, '{"event_type":"b"}')
    assert await shipper.ship_pending() == 1
    assert requests[-1].content == b'{"event_type":"b"}\n'


async def test_batches_respect_max(tmp_path: Path) -> None:
    shipper, requests = _make_shipper(tmp_path, batch=2)
    _write_log(tmp_path / "audit.jsonl", *[f'{{"n":{i}}}' for i in range(5)])
    assert await shipper.ship_pending() == 5
    assert [r.content.count(b"\n") for r in requests] == [2, 2, 1]


async def test_bearer_token_header(tmp_path: Path) -> None:
    shipper, requests = _make_shipper(tmp_path, token="s3cr3t")
    _write_log(tmp_path / "audit.jsonl", '{"event_type":"a"}')
    await shipper.ship_pending()
    assert requests[0].headers["authorization"] == "Bearer s3cr3t"


async def test_offset_not_advanced_on_collector_failure(tmp_path: Path) -> None:
    # First POST 500s; nothing should be marked shipped, and a later run
    # (collector healthy) re-ships the same records.
    shipper, requests = _make_shipper(tmp_path, statuses=[500])
    _write_log(tmp_path / "audit.jsonl", '{"event_type":"a"}')
    assert await shipper.ship_pending() == 0
    assert len(requests) == 1
    # Collector recovers (handler now returns 200): same record ships.
    assert await shipper.ship_pending() == 1
    assert len(requests) == 2


async def test_partial_trailing_line_not_shipped(tmp_path: Path) -> None:
    shipper, requests = _make_shipper(tmp_path)
    log = tmp_path / "audit.jsonl"
    # Two complete records and a half-written third (no trailing newline).
    with log.open("ab") as fp:
        fp.write(b'{"event_type":"a"}\n{"event_type":"b"}\n{"event_type":"par')
    assert await shipper.ship_pending() == 2
    assert requests[-1].content == b'{"event_type":"a"}\n{"event_type":"b"}\n'
    # Completing the record makes it shippable.
    with log.open("ab") as fp:
        fp.write(b'tial"}\n')
    assert await shipper.ship_pending() == 1
    assert requests[-1].content == b'{"event_type":"partial"}\n'


async def test_rotation_resumes_from_fresh_file(tmp_path: Path) -> None:
    shipper, requests = _make_shipper(tmp_path)
    log = tmp_path / "audit.jsonl"
    _write_log(log, '{"event_type":"old"}')
    assert await shipper.ship_pending() == 1
    # Simulate logrotate: replace the path with a brand-new inode.
    fresh = tmp_path / "audit.jsonl.new"
    _write_log(fresh, '{"event_type":"new"}')
    fresh.replace(log)
    assert await shipper.ship_pending() == 1
    assert requests[-1].content == b'{"event_type":"new"}\n'
