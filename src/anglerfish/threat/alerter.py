"""Webhook alerter for high-severity threat assessments.

Posts a structured JSON payload to the configured webhook URL when a
:class:`ThreatAssessment` either crosses the configured score
threshold or flips ``persistence_attempted``. Network failures are
swallowed and logged — the alerter is a best-effort sidecar, never
load-bearing for the bridge.
"""

from __future__ import annotations

import logging
from typing import Any, Self

import httpx

from anglerfish.config.models import ThreatConfig
from anglerfish.models.threat import ThreatAssessment

__all__ = ["ThreatAlerter"]


class ThreatAlerter:
    """POSTs threat assessments to an operator-defined webhook."""

    def __init__(
        self,
        config: ThreatConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._config = config
        self._logger = logger if logger is not None else logging.getLogger(__name__)
        if http_client is None:
            self._client: httpx.AsyncClient | None = (
                httpx.AsyncClient(
                    timeout=httpx.Timeout(
                        config.alert_webhook_timeout_s,
                        connect=min(config.alert_webhook_timeout_s, 5.0),
                    ),
                    headers={
                        "User-Agent": "anglerfish-ai/0.1.0",
                        "Content-Type": "application/json",
                    },
                )
                if config.alert_webhook_url is not None
                else None
            )
            self._owns_client = self._client is not None
        else:
            self._client = http_client
            self._owns_client = False

    @property
    def config(self) -> ThreatConfig:
        return self._config

    def should_alert(self, assessment: ThreatAssessment) -> bool:
        if self._config.alert_webhook_url is None:
            return False
        if assessment.persistence_attempted:
            return True
        return assessment.score >= self._config.alert_threshold

    async def maybe_alert(self, assessment: ThreatAssessment) -> bool:
        """Send the alert if appropriate. Returns True iff sent successfully."""
        if not self.should_alert(assessment) or self._client is None:
            return False

        webhook_url = self._config.alert_webhook_url
        if webhook_url is None:
            return False

        payload: dict[str, Any] = {
            "session_id": str(assessment.session_id),
            "score": assessment.score,
            "high_severity": assessment.high_severity,
            "persistence_attempted": assessment.persistence_attempted,
            "techniques": [
                {"id": t.id, "name": t.name, "matches": list(t.matches)}
                for t in assessment.techniques
            ],
            "notes": list(assessment.notes),
        }

        try:
            response = await self._client.post(str(webhook_url), json=payload)
        except httpx.HTTPError as exc:
            self._logger.warning(
                "threat.alert_failed transport=%s error=%s",
                type(exc).__name__,
                exc,
            )
            return False
        if response.status_code >= 400:
            self._logger.warning(
                "threat.alert_rejected status=%d body=%s",
                response.status_code,
                response.text[:200],
            )
            return False
        return True

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
