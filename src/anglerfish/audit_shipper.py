"""Off-box shipping of the append-only audit log (TODO-12).

The on-box ``audit.jsonl`` is the only tamper-evidence surface: an attacker
who roots the box can alter it before anyone reads it. :class:`AuditShipper`
tails the log from a persisted byte offset and POSTs new records as
``application/x-ndjson`` to an operator-run HTTPS collector, so a durable
copy lands off-box as events happen.

Delivery is at-least-once: the offset advances only after the collector acks
a batch, so a collector outage backs up against the durable on-disk log
rather than dropping records (the next run resumes where it left off). The
writer is untouched: shipping reads the file, it does not change the
fsync-per-record tamper-evidence contract of :class:`anglerfish.audit.AuditLog`.

Default-off: with no ``url`` configured the shipper is a no-op.

Rotation: when ``logrotate`` renames the log, the shipper detects the inode
change and resumes from the start of the fresh file. The unshipped tail of
the rotated file (at most one ``flush_interval_s`` of records) is not chased
into ``audit.jsonl.1``; it remains on disk. This bounded gap is the one
tradeoff for keeping the tailer simple.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Self

import httpx

from anglerfish.config.models import AuditShipperConfig

__all__ = ["AuditShipper"]

_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Offset:
    """Where shipping last got to. ``inode`` detects rotation."""

    inode: int | None
    pos: int


def _batches(items: list[bytes], size: int) -> list[list[bytes]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


class AuditShipper:
    """Tail the audit log and POST new records to an HTTPS collector."""

    def __init__(
        self,
        config: AuditShipperConfig,
        *,
        log_path: Path,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._config = config
        self._log_path = log_path
        self._owns_client = http_client is None
        self._client = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(
                config.timeout_s,
                connect=min(config.timeout_s, 5.0),
            ),
        )

    @property
    def enabled(self) -> bool:
        return self._config.url is not None

    # -- offset persistence -----------------------------------------------

    def _load_offset(self) -> _Offset:
        try:
            raw = json.loads(self._config.offset_path.read_text(encoding="utf-8"))
            return _Offset(inode=raw.get("inode"), pos=int(raw.get("pos", 0)))
        except (OSError, ValueError, TypeError):
            return _Offset(inode=None, pos=0)

    def _save_offset(self, offset: _Offset) -> None:
        path = self._config.offset_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(
                json.dumps({"inode": offset.inode, "pos": offset.pos}),
                encoding="utf-8",
            )
            os.replace(tmp, path)
        except OSError as exc:
            _logger.warning("audit_shipper: could not persist offset: %s", exc)

    # -- shipping ----------------------------------------------------------

    @staticmethod
    def _read_complete_lines(path: Path, start: int) -> tuple[list[bytes], int]:
        """Read complete (newline-terminated) lines from ``start``.

        Returns the non-empty lines and the byte offset just past the last
        newline. A trailing partial line (a record mid-write) is left for the
        next read so a half-written record is never shipped.
        """
        with path.open("rb") as fp:
            fp.seek(start)
            data = fp.read()
        last_nl = data.rfind(b"\n")
        if last_nl == -1:
            return [], start
        complete = data[: last_nl + 1]
        lines = [line for line in complete.split(b"\n") if line]
        return lines, start + len(complete)

    async def _post(self, batch: list[bytes]) -> bool:
        body = b"\n".join(batch) + b"\n"
        headers = {"Content-Type": "application/x-ndjson"}
        token = self._config.token
        if token is not None:
            headers["Authorization"] = f"Bearer {token.get_secret_value()}"
        try:
            resp = await self._client.post(str(self._config.url), content=body, headers=headers)
        except httpx.HTTPError as exc:
            _logger.warning("audit_shipper: POST failed: %s", exc)
            return False
        if not 200 <= resp.status_code < 300:
            _logger.warning("audit_shipper: collector returned HTTP %s", resp.status_code)
            return False
        return True

    async def ship_pending(self) -> int:
        """Ship any unshipped records. Returns the number shipped."""
        if self._config.url is None or not self._log_path.exists():
            return 0

        st = self._log_path.stat()
        saved = self._load_offset()
        # Resume from the saved offset only when it is the same file and not
        # truncated; otherwise (first run, rotation, truncation) start at the
        # beginning of the current file.
        resume = saved.inode == st.st_ino and st.st_size >= saved.pos
        start = saved.pos if resume else 0

        lines, _ = self._read_complete_lines(self._log_path, start)
        if not lines:
            # Persist the current inode so a later rotation is still detected.
            self._save_offset(_Offset(inode=st.st_ino, pos=start))
            return 0

        shipped = 0
        pos = start
        for batch in _batches(lines, self._config.batch_max_records):
            if not await self._post(batch):
                # Stop without advancing; the next run retries this batch.
                break
            pos += sum(len(line) + 1 for line in batch)
            shipped += len(batch)
            self._save_offset(_Offset(inode=st.st_ino, pos=pos))
        return shipped

    async def run_forever(self) -> None:
        """Ship on the configured interval until cancelled."""
        if not self.enabled:
            _logger.info("audit_shipper: no url configured; shipping disabled")
            return
        _logger.info("audit_shipper: shipping %s to the collector", self._log_path)
        try:
            while True:
                try:
                    count = await self.ship_pending()
                    if count:
                        _logger.debug("audit_shipper: shipped %d record(s)", count)
                except Exception:
                    _logger.exception("audit_shipper: ship cycle failed")
                await asyncio.sleep(self._config.flush_interval_s)
        finally:
            if self._owns_client:
                await self._client.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
