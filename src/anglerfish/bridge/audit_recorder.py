"""Audit-event emission for the bridge, extracted from AIBridgeService.

Every ``bridge.*`` audit event the service emits per command is built and
written here. The service holds one :class:`BridgeAuditRecorder` and
delegates to it. Pulling these formatters out of the orchestrator keeps
the "what does this event look like" logic in one focused, separately
testable place.

The recorder depends only on the :class:`AuditLog` (and its own logger).
The handful of events that need a value the service computes (a budget
snapshot, the scan cap) take it as an explicit argument rather than
reaching back into service state.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from anglerfish.audit import AuditLog
    from anglerfish.bridge.defense import DefenseVerdict
    from anglerfish.bridge.session import SessionContext
    from anglerfish.bridge.strategies.counter_deception import CounterDeceptionState
    from anglerfish.llm.budget import BudgetExhaustedError
    from anglerfish.models.embedding import SessionEmbedding
    from anglerfish.models.intent import IntentSummary
    from anglerfish.models.persistence import PersistenceEvent
    from anglerfish.models.session import SessionSnapshot

_logger = logging.getLogger(__name__)


class BridgeAuditRecorder:
    """Build and write the bridge's per-command audit events."""

    def __init__(self, audit_log: AuditLog) -> None:
        self._audit_log = audit_log

    # ------------------------------------------------------------------
    # Counter-deception (Stage 12)
    # ------------------------------------------------------------------

    def record_counter_deception_engaged(
        self,
        *,
        session_id: UUID,
        source_ip: str | None,
        state: CounterDeceptionState,
        trigger: str,
        threat_score: int | None,
    ) -> None:
        """Audit a single bridge.counter_deception_engaged event.

        ``trigger`` is "threat" (score crossed the threshold) or "pin"
        (operator forced it). ``threat_score`` is the crossing score for
        the threat path, None for a pin. ``garble_paths`` rides as a
        count (not the full list) to bound the audit-log payload; the
        dashboard reads the live config for the path list.
        """
        self._audit_log.record(
            "bridge.counter_deception_engaged",
            session_id=str(session_id),
            attacker_ip=source_ip,
            mode=state.mode.value,
            trigger=trigger,
            garble_paths_count=len(state.garble_paths),
            timebomb_thresholds=list(state.timebomb_thresholds),
            threat_score=threat_score,
        )

    def record_counter_deception_timebomb_applied(
        self,
        *,
        session_id: UUID,
        command_count: int,
        intensity: str,
    ) -> None:
        """Audit a per-command time-bomb prompt amendment (mild | severe)."""
        self._audit_log.record(
            "bridge.counter_deception_timebomb_applied",
            session_id=str(session_id),
            command_count=command_count,
            intensity=intensity,
        )

    # ------------------------------------------------------------------
    # Persistence (Stage 10)
    # ------------------------------------------------------------------

    def record_persistence_attempt(
        self,
        *,
        session: SessionContext,
        event: PersistenceEvent,
    ) -> None:
        """Audit a single bridge.persistence_attempt event.

        The dashboard audit-tailer (slice 10.2) reads this and
        upserts into fake_persistence_state via the COALESCE-
        based UNIQUE INDEX so replay is idempotent.
        """
        self._audit_log.record(
            "bridge.persistence_attempt",
            session_id=str(session.session_id),
            source_ip=session.source_ip,
            kind=event.kind,
            sub_key=event.sub_key,
            payload=event.payload,
            source=event.source,
            created_at=datetime.now(tz=UTC).isoformat(),
        )

    def record_persistence_classifier_error(
        self,
        *,
        session: SessionContext,
        error: str,
    ) -> None:
        """Audit a persistence-classifier failure."""
        self._audit_log.record(
            "bridge.persistence_classifier_error",
            session_id=str(session.session_id),
            source_ip=session.source_ip,
            error=error,
        )

    # ------------------------------------------------------------------
    # Defense (Stage 1)
    # ------------------------------------------------------------------

    def record_defense_fire(
        self,
        session: SessionContext,
        verdict: DefenseVerdict,
    ) -> None:
        """Record a ``bridge.defense_fired`` audit event for ``verdict``."""
        self._audit_log.record(
            "bridge.defense_fired",
            detector=verdict.detector,
            score=verdict.score,
            snippet=verdict.snippet,
            session_id=str(session.session_id),
            attacker_ip=session.source_ip,
        )

    def record_scan_truncated(
        self,
        session: SessionContext,
        *,
        kind: str,
        input_length: int,
        verdict: DefenseVerdict,
        scan_max_chars: int,
    ) -> None:
        """Audit-log a defense scan that truncated its input.

        Stage 1.8.5 closes the silent-bypass gap: when scan_max_chars
        is smaller than the actual input, the regex only sees a prefix.
        The AnglerfishSettings cross-field validator prevents the
        common shape of this bug (operator misconfiguration), but
        runtime occurrences (an LLM response longer than expected, an
        attacker payload that bypassed sanitisation upstream) still
        warrant a signal. Operators reviewing audit logs can see
        exactly how far over the cap the input ran.
        """
        self._audit_log.record(
            "bridge.defense_scan_truncated",
            kind=kind,
            scan_max_chars=scan_max_chars,
            input_length=input_length,
            detector=verdict.detector,
            session_id=str(session.session_id),
            attacker_ip=session.source_ip,
        )

    # ------------------------------------------------------------------
    # Intent extraction (Stage 5+)
    # ------------------------------------------------------------------

    def record_intent_extracted(self, summary: IntentSummary) -> None:
        """Audit a successful intent extraction."""
        self._audit_log.record(
            "bridge.intent_extracted",
            session_id=str(summary.session_id),
            actor_profile=summary.actor_profile,
            confidence=summary.confidence,
            intent=summary.intent,
            why=summary.why,
            matched_techniques=list(summary.matched_techniques),
            summary=summary.summary,
            extracted_at=summary.extracted_at.isoformat(),
        )

    def record_intent_extraction_failed(
        self,
        *,
        snapshot: SessionSnapshot,
        error_type: str,
        error: str,
    ) -> None:
        """Audit a failed intent-extraction attempt."""
        self._audit_log.record(
            "bridge.intent_extraction_failed",
            session_id=str(snapshot.session_id),
            attacker_ip=snapshot.source_ip,
            error_type=error_type,
            error=error,
        )

    # ------------------------------------------------------------------
    # Embeddings (Stage 8)
    # ------------------------------------------------------------------

    def record_embedding_generated(self, embedding: SessionEmbedding) -> None:
        """Audit a successful Stage 8 embedding generation.

        The full vector rides as a tuple of floats so the dashboard
        tailer can reconstruct + persist without a separate read.
        ~2 KB per 768-dim vector at JSON-serialised float precision.
        """
        self._audit_log.record(
            "bridge.embedding_generated",
            session_id=str(embedding.session_id),
            dimension=embedding.dimension,
            model=embedding.model,
            vector=list(embedding.vector),
            generated_at=embedding.generated_at.isoformat(),
        )

    def record_embedding_failed(
        self,
        *,
        snapshot: SessionSnapshot,
        error_type: str,
        error: str,
    ) -> None:
        """Audit a failed embedding-generation attempt."""
        self._audit_log.record(
            "bridge.embedding_failed",
            session_id=str(snapshot.session_id),
            attacker_ip=snapshot.source_ip,
            error_type=error_type,
            error=error,
        )

    def record_embedding_skipped(self, snapshot: SessionSnapshot) -> None:
        """Audit a below-min-commands skip (generator returned None)."""
        self._audit_log.record(
            "bridge.embedding_skipped",
            session_id=str(snapshot.session_id),
            attacker_ip=snapshot.source_ip,
            reason="below_min_commands",
        )

    # ------------------------------------------------------------------
    # Wasting strategy + budget (Stage 3 / 5)
    # ------------------------------------------------------------------

    def record_wasting_applied(
        self,
        *,
        session: SessionContext,
        strategy_name: str,
        wasted_ms: int,
        pre_message: bool,
        clarification_injected: bool = False,
    ) -> None:
        """Audit a per-command wasting-strategy effect.

        Fires once per command that the strategy touched in any way
        (pre-message, inter-chunk delay, clarification injection, or
        a combination). The `off` strategy never reaches this path
        because ``wasted_ms`` stays at zero and clarification is
        aggressive-only.
        """
        self._audit_log.record(
            "bridge.wasting_applied",
            session_id=str(session.session_id),
            attacker_ip=session.source_ip,
            strategy=strategy_name,
            wasted_ms=wasted_ms,
            pre_message=pre_message,
            clarification_injected=clarification_injected,
        )

    def record_budget_exhausted(
        self,
        session: SessionContext,
        exc: BudgetExhaustedError,
        *,
        budget_snapshot: dict[str, dict[str, int]],
    ) -> None:
        """Audit a per-session token-budget exhaustion.

        ``budget_snapshot`` is the service's per-session budget state
        (empty dict when the session has no budget recorded).
        """
        self._audit_log.record(
            "bridge.budget_exhausted",
            session_id=str(session.session_id),
            attacker_ip=session.source_ip,
            error=str(exc),
            budget=budget_snapshot,
        )

    # ------------------------------------------------------------------
    # Handler-guard errors (M6)
    # ------------------------------------------------------------------

    def record_handler_error(self, session: SessionContext, exc: Exception) -> None:
        """Audit an unexpected error caught by a command handler's guard (M6)."""
        _logger.exception(
            "bridge.handler_error session=%s",
            session.session_id,
        )
        self._audit_log.record(
            "bridge.handler_error",
            session_id=str(session.session_id),
            attacker_ip=session.source_ip,
            error=f"{type(exc).__name__}: {exc}",
        )
