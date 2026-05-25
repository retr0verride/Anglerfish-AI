"""Background model warm-pool for the LLM layer.

A honeypot's plausibility window starts the moment the attacker hits
ENTER on the first command. If Ollama just paged the model out of
GPU memory, the bridge spends 5-15 seconds loading it back in
before producing the first token. That delay is uncharacteristic of
a real shell and is the kind of signal scanners record.

:class:`WarmPool` mitigates by issuing a no-op
``POST /api/generate`` with ``keep_alive=-1`` against every
configured role at bridge startup and again on a refresh interval
(default :attr:`OllamaConfig.warmup_refresh_seconds`). Ollama pins
the model in memory between requests, so the first real attacker
command lands on an already-resident model.

Failure is best-effort: warmup errors are logged + audit-recorded
but never raised. The first real request to that role then pays
the cold-start cost. The dashboard surfaces last-warmed timestamps
per role via the audit log so operators can spot a persistently-
unwarmable model.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Self

from anglerfish.audit import AuditLog
from anglerfish.config.models import OllamaConfig
from anglerfish.llm.client import LLMClient
from anglerfish.llm.errors import LLMError
from anglerfish.llm.roles import LLMRole

__all__ = ["WarmPool", "WarmStatus"]


_Clock = Callable[[], float]


@dataclass(frozen=True)
class WarmStatus:
    """Last-known warm-up state for one role.

    ``warmed_at`` is monotonic seconds (from the injected clock); the
    audit log carries wall-clock timestamps for the dashboard.
    """

    role: LLMRole
    warmed_at: float | None = None
    last_error: str | None = None
    refresh_count: int = field(default=0)


class WarmPool:
    """Periodically pings every configured LLM role to keep it resident."""

    def __init__(
        self,
        *,
        client: LLMClient,
        config: OllamaConfig,
        audit_log: AuditLog,
        roles: tuple[LLMRole, ...] = (LLMRole.FAST, LLMRole.DEEP),
        logger: logging.Logger | None = None,
        clock: _Clock | None = None,
    ) -> None:
        self._client = client
        self._config = config
        self._audit_log = audit_log
        self._roles = roles
        self._logger = logger if logger is not None else logging.getLogger(__name__)
        self._clock: _Clock = clock if clock is not None else time.monotonic
        self._status: dict[LLMRole, WarmStatus] = {r: WarmStatus(role=r) for r in roles}
        self._tasks: dict[LLMRole, asyncio.Task[None]] = {}
        self._started = False
        self._stopped = False

    @property
    def roles(self) -> tuple[LLMRole, ...]:
        return self._roles

    def status(self) -> dict[LLMRole, WarmStatus]:
        """Return a snapshot of per-role warm status."""
        return dict(self._status)

    async def start(self) -> None:
        """Spawn one background task per configured role.

        Each task performs an immediate warm-up call and then sleeps for
        ``config.warmup_refresh_seconds`` between subsequent calls. Call
        :meth:`stop` (or use the async context manager) to cancel.
        """
        if self._started:
            raise RuntimeError("WarmPool already started")
        if self._stopped:
            raise RuntimeError("WarmPool already stopped; construct a new instance")
        self._started = True
        for role in self._roles:
            self._tasks[role] = asyncio.create_task(
                self._loop(role),
                name=f"llm-warmup-{role.value}",
            )

    async def stop(self) -> None:
        """Cancel every background task and wait for it to exit."""
        if not self._started or self._stopped:
            return
        self._stopped = True
        for task in self._tasks.values():
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        self._tasks.clear()

    async def warm_once(self, role: LLMRole) -> WarmStatus:
        """Run a single warm-up cycle for ``role`` and return the new status.

        Always returns; warm-up failures are logged + audited but never
        raised. The returned :class:`WarmStatus` reflects success or the
        latest error string.
        """
        try:
            await self._client.warm(role)
        except LLMError as exc:
            self._record_failure(role, exc)
        else:
            self._record_success(role)
        return self._status[role]

    async def _loop(self, role: LLMRole) -> None:
        interval = self._config.warmup_refresh_seconds
        while True:
            await self.warm_once(role)
            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                return

    def _record_success(self, role: LLMRole) -> None:
        prior = self._status[role]
        new_status = WarmStatus(
            role=role,
            warmed_at=self._clock(),
            last_error=None,
            refresh_count=prior.refresh_count + 1,
        )
        self._status[role] = new_status
        self._audit_log.record(
            "llm.warmup_succeeded",
            role=role.value,
            model=self._client.model_for(role),
            refresh_count=new_status.refresh_count,
        )

    def _record_failure(self, role: LLMRole, exc: LLMError) -> None:
        message = f"{type(exc).__name__}: {exc}"
        prior = self._status[role]
        self._status[role] = WarmStatus(
            role=role,
            warmed_at=prior.warmed_at,
            last_error=message,
            refresh_count=prior.refresh_count + 1,
        )
        self._logger.warning(
            "llm.warmup_failed role=%s model=%s error=%s",
            role.value,
            self._client.model_for(role),
            message,
        )
        self._audit_log.record(
            "llm.warmup_failed",
            role=role.value,
            model=self._client.model_for(role),
            error=message,
        )

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.stop()
