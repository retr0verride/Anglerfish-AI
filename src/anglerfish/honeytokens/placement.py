"""Bridge-side honeytoken placement (Stage 11 slice 11.3).

The bridge's :meth:`AIBridgeService.record_threat_assessment` hook
(Stage 1.5 plumbing) calls
:meth:`HoneytokenPlacementService.schedule_placement` whenever a
threat score crosses ``settings.honeytokens.placement_threshold``.
The placement runs fire-and-forget (mirrors Stage 7 intent
extraction + Stage 8 embedding generation): generate one AWS +
one SSH token for the source IP, audit each as
``bridge.honeytoken_placed``, return. The dashboard tailer
(slice 11.2) registers each into the ``honeytokens`` table.

The placement service holds no persistent state. Per-source-IP
deduplication is intentional: if the same source IP crosses the
threshold twice in two sessions, two pairs of tokens get
generated. Operators see the attacker's iteration history;
older tokens stay valid for callback receivers.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from uuid import UUID

from anglerfish.audit import AuditLog
from anglerfish.honeytokens.generators import HoneytokenGenerator
from anglerfish.honeytokens.schema import Honeytoken

__all__ = ["HoneytokenPlacementService"]


_logger = logging.getLogger(__name__)


class HoneytokenPlacementService:
    """Generate + audit honeytokens when the threat scorer trips.

    Stateless; safe to share across asyncio tasks. The
    ``_tasks`` set keeps spawned tasks alive across the
    asyncio loop's GC (mirrors the Stage 7 / 8 intent +
    embedding task patterns).
    """

    def __init__(
        self,
        *,
        generator: HoneytokenGenerator,
        audit_log: AuditLog,
    ) -> None:
        self._generator = generator
        self._audit_log = audit_log
        self._tasks: set[asyncio.Task[None]] = set()

    def schedule_placement(
        self,
        *,
        source_ip: str,
        session_id: UUID,
    ) -> asyncio.Task[None]:
        """Spawn the fire-and-forget placement task.

        Returns the task so callers can await it in tests; the
        production HTTP path discards the return. Tasks add
        themselves to ``_tasks`` and self-discard via
        ``done_callback`` so the set never accumulates finished
        tasks.
        """
        task = asyncio.create_task(
            self._run_placement(source_ip=source_ip, session_id=session_id),
            name=f"honeytoken-placement-{session_id}",
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def _run_placement(
        self,
        *,
        source_ip: str,
        session_id: UUID,
    ) -> None:
        """Generate + audit one AWS + one SSH token per call.

        Never raises - any per-generator exception lands in
        ``bridge.honeytoken_placement_error`` so the
        record_threat_assessment caller doesn't have to handle
        a failure shape from a fire-and-forget task.
        """
        try:
            aws_token = self._generator.generate_aws(
                source_ip=source_ip,
                session_id=session_id,
            )
            self._audit_placed(aws_token)
        except Exception as exc:  # noqa: BLE001 - fire-and-forget; audit + swallow
            self._audit_placement_error(
                source_ip=source_ip,
                session_id=session_id,
                kind="aws",
                error=exc,
            )

        try:
            ssh_token = self._generator.generate_ssh(
                source_ip=source_ip,
                session_id=session_id,
            )
            self._audit_placed(ssh_token)
        except Exception as exc:  # noqa: BLE001
            self._audit_placement_error(
                source_ip=source_ip,
                session_id=session_id,
                kind="ssh_key",
                error=exc,
            )

    def _audit_placed(self, token: Honeytoken) -> None:
        """Emit one bridge.honeytoken_placed event matching the slice 11.2 parser shape."""
        self._audit_log.record(
            "bridge.honeytoken_placed",
            token_id=token.id,
            kind=token.kind,
            payload=token.payload,
            placed_at=token.placed_at,
            callback_url=token.callback_url,
            source_ip=token.source_ip,
            session_id=str(token.session_id) if token.session_id is not None else None,
            created_at=token.created_at.isoformat(),
        )

    def _audit_placement_error(
        self,
        *,
        source_ip: str,
        session_id: UUID,
        kind: str,
        error: BaseException,
    ) -> None:
        self._audit_log.record(
            "bridge.honeytoken_placement_error",
            source_ip=source_ip,
            session_id=str(session_id),
            kind=kind,
            error_type=type(error).__name__,
            error=str(error),
            audited_at=datetime.now(tz=UTC).isoformat(),
        )
