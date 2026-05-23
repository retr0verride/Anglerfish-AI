"""Threat engine — the integration point between the bridge and alerting.

:class:`ThreatEngine` combines :func:`score_session` with the
:class:`ThreatAlerter` so that a single ``process`` call performs
scoring, optional alerting, and returns the assessment for storage or
forwarding.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Self

from anglerfish.config.settings import AnglerfishSettings
from anglerfish.models.session import SessionSnapshot
from anglerfish.models.threat import ThreatAssessment
from anglerfish.threat.alerter import ThreatAlerter
from anglerfish.threat.scorer import score_session
from anglerfish.threat.techniques import TECHNIQUES, TechniqueRule

__all__ = ["ThreatEngine"]


class ThreatEngine:
    """Combines scoring with alerting."""

    def __init__(
        self,
        settings: AnglerfishSettings,
        *,
        alerter: ThreatAlerter | None = None,
        rules: Sequence[TechniqueRule] = TECHNIQUES,
        logger: logging.Logger | None = None,
    ) -> None:
        self._settings = settings
        self._rules = tuple(rules)
        self._alerter = alerter if alerter is not None else ThreatAlerter(settings.threat)
        self._logger = logger if logger is not None else logging.getLogger(__name__)

    @property
    def settings(self) -> AnglerfishSettings:
        return self._settings

    @property
    def alerter(self) -> ThreatAlerter:
        return self._alerter

    @property
    def rules(self) -> tuple[TechniqueRule, ...]:
        return self._rules

    def assess(self, snapshot: SessionSnapshot) -> ThreatAssessment:
        """Score the snapshot without performing any IO."""
        return score_session(snapshot, rules=self._rules)

    async def process(self, snapshot: SessionSnapshot) -> ThreatAssessment:
        """Score the snapshot and dispatch an alert if appropriate."""
        assessment = self.assess(snapshot)
        if self._alerter.should_alert(assessment):
            self._logger.info(
                "threat.alerting session=%s score=%d techniques=%d",
                assessment.session_id,
                assessment.score,
                len(assessment.techniques),
            )
            await self._alerter.maybe_alert(assessment)
        return assessment

    async def aclose(self) -> None:
        await self._alerter.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
