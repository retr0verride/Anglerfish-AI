"""High-level AI bridge service.

:class:`AIBridgeService` is the orchestrator the lure's command
handler talks to. Given a session and a command, it returns the
response to print to the attacker's terminal. It wires together:

* :mod:`anglerfish.bridge.sanitize` (input cap + control-char strip)
* the deterministic ``cd`` shortcut so cwd never depends on the LLM
* :mod:`anglerfish.bridge.rate_limit` (global + per-session caps)
* :mod:`anglerfish.bridge.prompts` (prompt construction)
* :mod:`anglerfish.llm` (Ollama HTTP call via :class:`LLMClient`)
* :mod:`anglerfish.bridge.fallback` (scripted responses on failure)
* :mod:`anglerfish.bridge.session` (per-attacker state recording)

The service catches every bridge-level error and degrades to a
fallback response so that the lure always gets a non-empty result
and the attacker is never shown an exception.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
import time
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from typing import Self
from uuid import UUID

from anglerfish.audit import AuditLog
from anglerfish.bridge.defense import (
    DefenseVerdict,
    InjectionScorer,
    OutputFilter,
)
from anglerfish.bridge.errors import (
    GlobalQueueTimeoutError,
    InjectionDetectedError,
    OllamaResponseError,
    OllamaUnavailableError,
    OutputFilterFiredError,
    SessionRateLimitedError,
)
from anglerfish.bridge.fallback import fallback_response
from anglerfish.bridge.overrides_reader import BridgeOverridesReader
from anglerfish.bridge.path import normalise_path
from anglerfish.bridge.prompts import build_clarification_messages, build_messages
from anglerfish.bridge.rate_limit import BridgeRateLimiter
from anglerfish.bridge.sanitize import cap_output, sanitize_command
from anglerfish.bridge.session import SessionContext
from anglerfish.bridge.strategies import (
    StrategyContext,
    StrategyPreEffect,
    WastingStrategyBase,
    get_strategy,
)
from anglerfish.config.settings import AnglerfishSettings
from anglerfish.honeytokens import Honeytoken, HoneytokenPlacementService
from anglerfish.intel import EmbeddingGenerator, IntentExtractor
from anglerfish.llm import LLMClient, TokenBudget
from anglerfish.llm.budget import BudgetExhaustedError
from anglerfish.llm.errors import LLMError
from anglerfish.models.embedding import SessionEmbedding
from anglerfish.models.intent import IntentSummary
from anglerfish.models.persistence import PersistenceEvent
from anglerfish.models.session import (
    BridgeChunk,
    BridgeResponse,
    ResponseSource,
    SessionSnapshot,
)
from anglerfish.models.threat import ThreatAssessment
from anglerfish.persistence import PersistenceClassifier
from anglerfish.persistence.classifier import PersistenceClassifierError
from anglerfish.persona import PersonaSelector, SelectionResult
from anglerfish.sessions.reader import SessionStoreReader

__all__ = ["AIBridgeService"]


class AIBridgeService:
    """Lure-facing orchestrator.

    Construct once at startup; share across all sessions.
    """

    def __init__(
        self,
        settings: AnglerfishSettings,
        *,
        client: LLMClient,
        limiter: BridgeRateLimiter | None = None,
        audit_log: AuditLog | None = None,
        output_filter: OutputFilter | None = None,
        injection_scorer: InjectionScorer | None = None,
        overrides_reader: BridgeOverridesReader | None = None,
        intent_extractor: IntentExtractor | None = None,
        embedding_generator: EmbeddingGenerator | None = None,
        persona_selector: PersonaSelector | None = None,
        persistence_classifier: PersistenceClassifier | None = None,
        honeytoken_placement: HoneytokenPlacementService | None = None,
        session_store_reader: SessionStoreReader | None = None,
        sleep: Callable[[float], asyncio.Future[None]] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        logger: logging.Logger | None = None,
    ) -> None:
        self._settings = settings
        self._client = client
        self._limiter = limiter if limiter is not None else BridgeRateLimiter(settings.rate_limit)
        # The defense layer is constructed here from settings.defense by
        # default so simple call-sites (CLI, tests) don't have to know
        # about its existence. Production code may pass explicit
        # instances to share them across services or pre-load operator
        # overrides at startup.
        self._audit_log = audit_log if audit_log is not None else AuditLog(settings.audit.log_path)
        self._output_filter = (
            output_filter if output_filter is not None else OutputFilter(settings.defense)
        )
        self._injection_scorer = (
            injection_scorer if injection_scorer is not None else InjectionScorer(settings.defense)
        )
        self._monotonic = monotonic
        self._logger = logger if logger is not None else logging.getLogger(__name__)
        # Per-session token budgets. Created lazily on first command in a
        # session and dropped via end_session_budget() from the HTTP DELETE
        # path so the dict does not grow unbounded.
        self._budgets: dict[UUID, TokenBudget] = {}
        # Per-session record of the command_count at which a clarification
        # was last injected (slice 6.4 aggressive strategy). Used by the
        # strategy to enforce the one-clarification-per-chain rule.
        # Dropped by end_session_budget alongside the budget entry.
        self._last_clarification: dict[UUID, int] = {}
        # Per-session running total of milliseconds the wasting strategy
        # has added (slice 6.5). When it crosses
        # settings.bridge.session_wasted_ms_cap, the session is forced
        # to "off" for the rest of its lifetime regardless of the
        # operator-selected strategy. Dropped by end_session_budget.
        self._wasted_ms: dict[UUID, int] = {}
        # Set of session_ids that have already emitted the budget-
        # exhausted audit; gates the one-per-session emission.
        self._wasted_exhausted: set[UUID] = set()
        # Stage 7: optional end-of-session intent extractor. None in
        # tests + dev loops where no deep model is available; real in
        # production via the CLI. When set + intent_extraction_enabled,
        # schedule_intent_extraction() spawns a fire-and-forget task on
        # session close that audits the result.
        self._intent_extractor = intent_extractor
        # Tracks the per-session ThreatAssessment so the intent
        # extractor can feed it as prompt context. Populated by the
        # threat-engine integration hook (Stage 1.5); read by
        # schedule_intent_extraction. Dropped via end_session_budget.
        self._latest_threat: dict[UUID, ThreatAssessment] = {}
        # Outstanding intent-extraction tasks kept alive so the
        # asyncio loop does not cancel them on garbage collection.
        # Tasks self-remove via discard in their done-callback.
        self._intent_tasks: set[asyncio.Task[None]] = set()
        # Stage 8: optional end-of-session embedding generator. Same
        # lifecycle pattern as the intent extractor; spawned via
        # schedule_embedding_generation() on the bridge HTTP DELETE
        # endpoint alongside the intent task.
        self._embedding_generator = embedding_generator
        self._embedding_tasks: set[asyncio.Task[None]] = set()
        # Stage 9: optional persona selector. The HTTP server's
        # POST /api/v1/session endpoint calls
        # self.select_persona(source_ip) which returns either a
        # SelectionResult (selector wired + enabled) or None
        # (selector absent or settings.persona.enabled=False) so
        # SessionContext falls back to BridgeConfig.fake_* values.
        self._persona_selector = persona_selector
        # Stage 10: optional persistence classifier + session-store
        # reader. classify_command runs the classifier pre-LLM on
        # every command; on hit, the event is recorded on the
        # SessionContext (so subsequent prompt builds reflect it)
        # AND audited as bridge.persistence_attempt for the
        # dashboard tailer to persist. load_persistence_for_source_ip
        # uses the reader at session-open to seed
        # SessionContext.persistence_events from prior cross-session
        # installs.
        self._persistence_classifier = persistence_classifier
        # Stage 11: optional honeytoken placement service. Triggered
        # from record_threat_assessment when threat.score crosses
        # settings.honeytokens.placement_threshold. Spawns a fire-
        # and-forget task that audits bridge.honeytoken_placed; the
        # dashboard tailer (slice 11.2) persists into the registry.
        # Per-session tokens become visible to the attacker on the
        # NEXT session from the same source IP (the lure overlay is
        # set at session-open from the registry, mirroring Stage 10's
        # cross-session pattern).
        self._honeytoken_placement = honeytoken_placement
        # Set tracking source IPs we have already triggered placement
        # for; placement service de-dupes per session, this set
        # bounds duplicate audits within a single bridge process
        # lifetime when the threat scorer fires repeatedly for the
        # same session above the threshold.
        self._honeytoken_placed_for: set[UUID] = set()
        # Stage 11: parallel map of session_id -> source_ip the HTTP
        # server populates at session-open via
        # record_session_source_ip. Cleaner than reaching into
        # bridge.server's sessions dict (would create a circular
        # import) and avoids tying the threshold-hook to the HTTP
        # process topology.
        self._source_ip_by_session: dict[UUID, str] = {}
        # Pre-deploy sweep TODO-8: per-session monotonic last-activity
        # timestamps. Updated by record_session_activity (every
        # session_open + every per-session HTTP request); read by
        # evict_idle_sessions which the server invokes piggybacked on
        # every per-session call so eviction is amortised without a
        # background task. Cutoff is settings.bridge.session_idle_eviction_s.
        self._session_last_activity: dict[UUID, float] = {}
        self._session_store_reader = session_store_reader
        # Stage 6: reader for dashboard-published runtime overrides. None
        # in tests + dev loops where no dashboard process is running;
        # _current_strategy() falls back to settings.bridge.wasting_strategy.
        self._overrides_reader = overrides_reader
        # Injected for tests so strategy delays do not park real wall-clock
        # time during the suite. Defaults to asyncio.sleep at construct.
        # The type-ignore exists because asyncio.sleep returns a Coroutine
        # that is structurally compatible with the Future-returning
        # callable our other paths require, but mypy cannot prove the
        # equivalence without wrapping every call in ensure_future.
        self._sleep: Callable[[float], asyncio.Future[None]] = (
            sleep if sleep is not None else asyncio.sleep  # type: ignore[assignment]
        )

    @property
    def settings(self) -> AnglerfishSettings:
        return self._settings

    @property
    def client(self) -> LLMClient:
        return self._client

    @property
    def limiter(self) -> BridgeRateLimiter:
        return self._limiter

    async def _apply_pre_effect(
        self,
        pre_effect: StrategyPreEffect,
        accumulated: list[str],
    ) -> AsyncIterator[BridgeChunk]:
        """Yield the strategy's pre-message chunk (if any) and apply delays."""
        if pre_effect.pre_message is not None:
            if pre_effect.pre_message_delay_ms > 0:
                await self._sleep(pre_effect.pre_message_delay_ms / 1000.0)
            accumulated.append(pre_effect.pre_message)
            yield BridgeChunk(
                delta=pre_effect.pre_message,
                source=ResponseSource.AI,
                done=False,
            )
        if pre_effect.pre_delay_ms > 0:
            await self._sleep(pre_effect.pre_delay_ms / 1000.0)

    def _current_strategy(self, session_id: UUID) -> WastingStrategyBase:
        """Resolve the active wasting strategy for this command.

        Sessions that have hit the per-session wasted-ms cap (slice
        6.5) always get :class:`OffStrategy` regardless of the
        operator selection. Otherwise the dashboard-published runtime
        overrides JSON wins (slice 6.1 / 6.2 / 6.3); missing or
        invalid values fall back to ``settings.bridge.wasting_strategy``.
        """
        if session_id in self._wasted_exhausted:
            return get_strategy("off")
        if self._overrides_reader is not None:
            try:
                name = self._overrides_reader.current_wasting_strategy()
            except ValueError:
                name = self._settings.bridge.wasting_strategy
        else:
            name = self._settings.bridge.wasting_strategy
        try:
            return get_strategy(name)
        except ValueError:
            return get_strategy("off")

    def budget_for(self, session_id: UUID) -> TokenBudget:
        """Return (creating if needed) the per-session :class:`TokenBudget`."""
        budget = self._budgets.get(session_id)
        if budget is None:
            budget = TokenBudget(
                fast_token_cap=self._settings.ollama.session_fast_token_cap,
                deep_token_cap=self._settings.ollama.session_deep_token_cap,
                embed_token_cap=self._settings.ollama.session_embed_token_cap,
            )
            self._budgets[session_id] = budget
        return budget

    def end_session_budget(self, session_id: UUID) -> None:
        """Drop per-session state. Safe to call for unknown ids."""
        self._budgets.pop(session_id, None)
        self._last_clarification.pop(session_id, None)
        self._wasted_ms.pop(session_id, None)
        self._wasted_exhausted.discard(session_id)
        self._latest_threat.pop(session_id, None)
        # Stage 11 per-session state cleanup.
        self._honeytoken_placed_for.discard(session_id)
        self._source_ip_by_session.pop(session_id, None)
        # Pre-deploy sweep TODO-8: drop the activity timestamp last
        # so a racing evict_idle_sessions() call cannot see this id
        # as both stale + still tracked.
        self._session_last_activity.pop(session_id, None)

    def record_session_activity(self, session_id: UUID) -> None:
        """Mark ``session_id`` as live as of now (pre-deploy sweep TODO-8).

        Called by the HTTP server on every per-session request
        (session_open + command POST) so :meth:`evict_idle_sessions`
        sees an accurate liveness signal. Safe for unknown ids
        (creates a fresh entry).
        """
        self._session_last_activity[session_id] = self._monotonic()

    def evict_idle_sessions(self) -> list[UUID]:
        """Drop per-session state for sessions idle past the cutoff.

        Returns the list of evicted session ids so the HTTP server
        can drop its own SessionContext map entries in lock-step.
        Cutoff is ``settings.bridge.session_idle_eviction_s``.

        Mirrors :class:`BridgeRateLimiter._evict_idle_locked`'s
        piggyback pattern: callers invoke this on every per-session
        access so eviction is amortised across normal traffic
        without spinning up a background task. Closed via
        pre-deploy sweep TODO-8.
        """
        cutoff = self._monotonic() - self._settings.bridge.session_idle_eviction_s
        stale = [sid for sid, last in self._session_last_activity.items() if last < cutoff]
        for sid in stale:
            self.end_session_budget(sid)
        return stale

    def record_threat_assessment(
        self,
        session_id: UUID,
        threat: ThreatAssessment,
    ) -> None:
        """Cache the most recent threat assessment for ``session_id``.

        Intent extraction (Stage 7) feeds the cached assessment as
        prompt context when the session closes. The threat engine
        calls this after each scoring pass; only the latest result
        per session is retained.

        Stage 11: when honeytoken placement is wired AND
        ``settings.honeytokens.enabled`` AND threat.score crosses
        ``settings.honeytokens.placement_threshold``, schedule a
        fire-and-forget placement task for this session's source
        IP. Per-source-IP de-dup via ``_honeytoken_placed_for``
        bounds the audit-log noise when the scorer fires
        repeatedly above the threshold for the same session.
        """
        self._latest_threat[session_id] = threat
        self._maybe_schedule_honeytoken_placement(session_id, threat)

    def _maybe_schedule_honeytoken_placement(
        self,
        session_id: UUID,
        threat: ThreatAssessment,
    ) -> None:
        """Trigger one honeytoken-placement task per session above threshold."""
        if not self._settings.honeytokens.enabled:
            return
        if self._honeytoken_placement is None:
            return
        if threat.score < self._settings.honeytokens.placement_threshold:
            return
        if session_id in self._honeytoken_placed_for:
            return
        # Look up the source IP for this session. We pull it from
        # the latest snapshot the bridge has in memory - if the
        # session is not in the sessions dict, we silently skip
        # (the bridge process is in tear-down or the threat-engine
        # is firing for a stranger session_id). Don't surface that
        # as an error - record_threat_assessment is fire-and-
        # forget for the caller.
        source_ip = self._source_ip_for(session_id)
        if source_ip is None:
            return
        self._honeytoken_placed_for.add(session_id)
        self._honeytoken_placement.schedule_placement(
            source_ip=source_ip,
            session_id=session_id,
        )

    def _source_ip_for(self, session_id: UUID) -> str | None:
        """Best-effort source-IP lookup for an active session.

        Returns :data:`None` when the session is unknown. The
        bridge process holds active sessions in
        :class:`anglerfish.bridge.server`'s ``sessions`` dict,
        which is not visible from this module; rely on the
        latest-threat cache being populated alongside the
        session itself (the threat engine pulls source IP from
        the same snapshot it scores). For Stage 11 we read from
        the cached ``_latest_threat`` plus a parallel
        ``_source_ip_by_session`` set the threat engine
        populates - which it doesn't yet. Workaround: take
        source_ip directly via a setter on this service.
        """
        # Stage 11 v1 takes source_ip from the threat-engine
        # caller via a separate setter (record_session_source_ip)
        # so this service doesn't reach into bridge.server's
        # state. See the docstring on record_session_source_ip.
        return self._source_ip_by_session.get(session_id)

    def record_session_source_ip(
        self,
        session_id: UUID,
        source_ip: str,
    ) -> None:
        """Stash source IP for cross-method lookups.

        The bridge HTTP server's POST /api/v1/session calls this
        once at session-open. Stage 11's threshold hook then has
        a way to map session_id -> source_ip without reaching
        into bridge.server.sessions (which would create a
        circular import).
        """
        self._source_ip_by_session[session_id] = source_ip

    async def select_persona(self, source_ip: str) -> SelectionResult | None:
        """Pick a persona for ``source_ip`` via the configured selector.

        Returns ``None`` when no selector is wired or persona support
        is disabled via ``settings.persona.enabled=False``; callers
        fall back to the BridgeConfig.fake_* defaults in that case
        and SessionContext is constructed without a Persona object.

        On the happy path, returns a :class:`SelectionResult` so the
        caller can audit the selection_reason and pass the persona
        through to SessionContext.
        """
        if not self._settings.persona.enabled or self._persona_selector is None:
            return None
        return await self._persona_selector.select(source_ip)

    def record_persona_selected(
        self,
        *,
        session_id: UUID,
        source_ip: str,
        result: SelectionResult,
    ) -> None:
        """Audit a persona pick. Called by the HTTP server post-select."""
        self._audit_log.record(
            "bridge.persona_selected",
            session_id=str(session_id),
            source_ip=source_ip,
            persona=result.persona.name,
            selection_reason=result.reason,
        )

    # ------------------------------------------------------------------
    # Stage 10 persistence classification + audit
    # ------------------------------------------------------------------

    async def load_persistence_for_source_ip(
        self,
        source_ip: str,
    ) -> list[PersistenceEvent]:
        """Return prior-session persistence events for ``source_ip``.

        Used by the bridge HTTP server at session-open to seed
        ``SessionContext.persistence_events`` so subsequent
        commands in the new session render with the attacker's
        previously-installed state in fs_context. Returns an
        empty list when engaged_persistence is disabled, no
        reader is wired, or the source IP has no prior installs.
        """
        if not self._settings.bridge.engaged_persistence:
            return []
        if self._session_store_reader is None:
            return []
        return await self._session_store_reader.list_persistence_for_source_ip(
            source_ip,
        )

    async def load_honeytokens_for_source_ip(
        self,
        source_ip: str,
    ) -> list[Honeytoken]:
        """Return honeytokens to merge into this session's fakefs_overlay.

        Combines static-base tokens (visible to every session)
        with per-source-IP tokens previously generated for this
        IP. Returns an empty list when honeytokens are disabled
        or no reader is wired. Used by the bridge HTTP server at
        session-open to seed the lure ``SessionStartResponse``
        with the AWS/SSH bait payloads at their configured
        ``placed_at`` paths.
        """
        if not self._settings.honeytokens.enabled:
            return []
        if self._session_store_reader is None:
            return []
        static = await self._session_store_reader.list_static_honeytokens()
        per_ip = await self._session_store_reader.list_honeytokens_for_source_ip(
            source_ip,
        )
        return [*static, *per_ip]

    async def classify_command(
        self,
        command: str,
        *,
        session: SessionContext,
    ) -> PersistenceEvent | None:
        """Run the persistence classifier on one attacker command.

        Pre-LLM hook called from the bridge command handler. On a
        regex or LLM hit, records the event on the session +
        audits ``bridge.persistence_attempt`` so the dashboard
        tailer persists it to fake_persistence_state.

        Returns the classified event (caller may use it to
        short-circuit some downstream behaviour) or :data:`None`
        on miss / disabled / classifier error.

        Classifier errors are caught + audited as
        ``bridge.persistence_classifier_error``; they never raise
        to the caller (the engagement degrades to "no fake state
        recorded for this command" rather than blocking the
        attacker's session).
        """
        if not self._settings.bridge.engaged_persistence or self._persistence_classifier is None:
            return None
        try:
            event = await self._persistence_classifier.classify(
                command,
                cwd=session.cwd,
            )
        except PersistenceClassifierError as exc:
            self._record_persistence_classifier_error(
                session=session,
                error=str(exc),
            )
            return None
        if event is None:
            return None
        session.record_persistence_event(event)
        self._record_persistence_attempt(
            session=session,
            event=event,
        )
        return event

    def _record_persistence_attempt(
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

    def _record_persistence_classifier_error(
        self,
        *,
        session: SessionContext,
        error: str,
    ) -> None:
        self._audit_log.record(
            "bridge.persistence_classifier_error",
            session_id=str(session.session_id),
            source_ip=session.source_ip,
            error=error,
        )

    def schedule_intent_extraction(
        self,
        snapshot: SessionSnapshot,
    ) -> asyncio.Task[None] | None:
        """Spawn a fire-and-forget intent-extraction task for ``snapshot``.

        Returns the spawned :class:`asyncio.Task` (None when intent
        extraction is disabled or no extractor was wired). The task
        runs the extractor under
        ``settings.bridge.intent_extraction_timeout_s`` and audits the
        result (``bridge.intent_extracted`` on success,
        ``bridge.intent_extraction_failed`` on every failure shape).
        The caller does not await the task; the bridge HTTP DELETE
        endpoint returns 204 immediately.
        """
        if not self._settings.bridge.intent_extraction_enabled or self._intent_extractor is None:
            return None
        threat = self._latest_threat.get(snapshot.session_id)
        task = asyncio.create_task(
            self._run_intent_extraction(snapshot, threat),
            name=f"intent-extract-{snapshot.session_id}",
        )
        self._intent_tasks.add(task)
        task.add_done_callback(self._intent_tasks.discard)
        return task

    async def _run_intent_extraction(
        self,
        snapshot: SessionSnapshot,
        threat: ThreatAssessment | None,
    ) -> None:
        """Run the extractor under timeout + audit the outcome.

        Never raises - every failure path lands in
        bridge.intent_extraction_failed. The DELETE HTTP response
        has already returned 204 by the time this runs, so a raise
        here would only be visible in the bridge process logs.
        """
        if self._intent_extractor is None:  # pragma: no cover - guarded above
            return
        timeout_s = self._settings.bridge.intent_extraction_timeout_s
        try:
            summary = await asyncio.wait_for(
                self._intent_extractor.extract(snapshot, threat),
                timeout=timeout_s,
            )
        except TimeoutError:
            self._record_intent_extraction_failed(
                snapshot=snapshot,
                error_type="TimeoutError",
                error=f"intent extraction exceeded {timeout_s}s",
            )
            return
        except Exception as exc:  # noqa: BLE001 - audit + swallow on background task
            self._record_intent_extraction_failed(
                snapshot=snapshot,
                error_type=type(exc).__name__,
                error=str(exc),
            )
            return
        self._record_intent_extracted(summary)

    def schedule_embedding_generation(
        self,
        snapshot: SessionSnapshot,
    ) -> asyncio.Task[None] | None:
        """Spawn a fire-and-forget embedding-generation task for ``snapshot``.

        Returns the spawned :class:`asyncio.Task` (None when embedding
        is disabled or no generator was wired). The task runs the
        generator under ``settings.bridge.embedding_timeout_s`` and
        audits the result (``bridge.embedding_generated`` on success,
        ``bridge.embedding_failed`` on every failure shape). The
        caller does not await the task; the DELETE endpoint returns
        204 immediately. Sessions below the generator's min-commands
        threshold produce a ``None`` embedding and emit
        ``bridge.embedding_skipped`` so the operator can see why no
        cluster_match could fire.
        """
        if not self._settings.bridge.embedding_enabled or self._embedding_generator is None:
            return None
        task = asyncio.create_task(
            self._run_embedding_generation(snapshot),
            name=f"embed-{snapshot.session_id}",
        )
        self._embedding_tasks.add(task)
        task.add_done_callback(self._embedding_tasks.discard)
        return task

    async def _run_embedding_generation(self, snapshot: SessionSnapshot) -> None:
        """Run the generator under timeout + audit the outcome.

        Never raises - every failure path lands in
        bridge.embedding_failed. The DELETE HTTP response has already
        returned 204 by the time this runs.
        """
        if self._embedding_generator is None:  # pragma: no cover - guarded above
            return
        timeout_s = self._settings.bridge.embedding_timeout_s
        try:
            embedding = await asyncio.wait_for(
                self._embedding_generator.generate(snapshot),
                timeout=timeout_s,
            )
        except TimeoutError:
            self._record_embedding_failed(
                snapshot=snapshot,
                error_type="TimeoutError",
                error=f"embedding generation exceeded {timeout_s}s",
            )
            return
        except Exception as exc:  # noqa: BLE001 - audit + swallow on background task
            self._record_embedding_failed(
                snapshot=snapshot,
                error_type=type(exc).__name__,
                error=str(exc),
            )
            return
        if embedding is None:
            self._record_embedding_skipped(snapshot)
            return
        self._record_embedding_generated(embedding)

    def wasting_stats(self) -> dict[str, int]:
        """Return a snapshot of per-process wasting counters.

        Operator-facing: the dashboard runs in a separate process
        and reads its dashboard health view from the audit log, so
        this method is for in-process consumers (CLI tools, tests,
        future Stage 7+ analytics that share the bridge process).
        """
        return {
            "active_sessions_with_wasting": len(self._wasted_ms),
            "sessions_at_budget_cap": len(self._wasted_exhausted),
            "total_wasted_ms": sum(self._wasted_ms.values()),
        }

    async def handle_command(
        self,
        session: SessionContext,
        command: str,
    ) -> BridgeResponse:
        """Return the shell response to display for ``command``.

        Always returns a :class:`BridgeResponse` — never raises.
        Bridge-level failures degrade to scripted fallback content;
        when fallbacks are disabled in configuration, the response text
        is empty and ``source`` is :attr:`ResponseSource.REJECTED`.
        """
        sanitised = sanitize_command(
            command,
            max_chars=self._settings.bridge.max_input_chars,
        )

        # Empty command — bash just shows the next prompt.
        if not sanitised.strip():
            session.record(
                sanitised,
                "",
                source=ResponseSource.AI,
                latency_ms=0.0,
            )
            return BridgeResponse(text="", source=ResponseSource.AI, latency_ms=0.0)

        # Defense layer (Stage 1): injection scorer on sanitised input.
        # Runs before the `cd` shortcut because an injection attempt
        # disguised as `cd <attack>` still warrants the audit signal.
        # When fired, skip Ollama entirely and use a scripted fallback
        # so the attacker can't tell defense triggered.
        injection_verdict = self._injection_scorer.score(sanitised)
        # Stage 1.8.5: surface the scan-cap-truncated signal independently
        # of fired. A clean verdict on a truncated scan means the tail
        # wasn't inspected — operator-visible gap.
        if injection_verdict.truncated:
            self._record_scan_truncated(
                session,
                kind="injection",
                input_length=len(sanitised),
                verdict=injection_verdict,
            )
        if injection_verdict.fired:
            start = self._monotonic()
            self._record_defense_fire(session, injection_verdict)
            text, source = self._fallback(
                session,
                sanitised,
                reason=InjectionDetectedError(
                    f"{injection_verdict.detector} fired (score={injection_verdict.score})",
                ),
            )
            latency_ms = (self._monotonic() - start) * 1000.0
            session.record(sanitised, text, source=source, latency_ms=latency_ms)
            return BridgeResponse(text=text, source=source, latency_ms=latency_ms)

        # `cd` is handled deterministically so cwd never depends on the LLM.
        if self._handle_cd(session, sanitised):
            session.record(
                sanitised,
                "",
                source=ResponseSource.AI,
                latency_ms=0.0,
            )
            return BridgeResponse(text="", source=ResponseSource.AI, latency_ms=0.0)

        start = self._monotonic()
        budget = self.budget_for(session.session_id)
        try:
            async with self._limiter.slot(session.session_id):
                messages = build_messages(
                    sanitised,
                    config=self._settings.bridge,
                    cwd=session.cwd,
                    history=session.history(),
                    persona=session.persona,
                    persistence_events=session.persistence_events,
                )
                result = await self._client.chat(messages, budget=budget)
                # Defense layer (Stage 1): cap FIRST, then scan. Capping
                # before the filter prevents a misbehaving model (or an
                # attacker-influenced context) from forcing the regex
                # engine to iterate over multi-MB responses. cap_output
                # also normalises trailing whitespace which gives the
                # filter cleaner input.
                text = cap_output(
                    result.content,
                    max_chars=self._settings.ollama.max_response_chars,
                )
                output_verdict = self._output_filter.check(text)
                # Stage 1.8.5: surface scan-cap truncation on the output
                # path too. Most LLM responses sit well under the cap;
                # one that exceeds it means either model misbehaviour
                # or an attacker steering toward a long response to
                # smuggle a leak past the scan window.
                if output_verdict.truncated:
                    self._record_scan_truncated(
                        session,
                        kind="output",
                        input_length=len(text),
                        verdict=output_verdict,
                    )
                if output_verdict.fired:
                    self._record_defense_fire(session, output_verdict)
                    raise OutputFilterFiredError(
                        f"{output_verdict.detector} fired (score={output_verdict.score})",
                    )
                source = ResponseSource.AI
        except BudgetExhaustedError as exc:
            self._record_budget_exhausted(session, exc)
            text, source = self._fallback(session, sanitised, reason=exc)
        except (
            OllamaUnavailableError,
            OllamaResponseError,
            OutputFilterFiredError,
            SessionRateLimitedError,
            GlobalQueueTimeoutError,
        ) as exc:
            text, source = self._fallback(session, sanitised, reason=exc)

        latency_ms = (self._monotonic() - start) * 1000.0
        session.record(sanitised, text, source=source, latency_ms=latency_ms)
        return BridgeResponse(text=text, source=source, latency_ms=latency_ms)

    async def handle_command_stream(
        self,
        session: SessionContext,
        command: str,
    ) -> AsyncIterator[BridgeChunk]:
        """Stream the shell response for ``command`` as :class:`BridgeChunk`s.

        Mirrors :meth:`handle_command` but yields chunks progressively
        for the lure to write to the attacker's terminal as they
        arrive. The terminal chunk carries ``done=True`` and
        ``latency_ms``; intermediate chunks have ``done=False`` and
        ``latency_ms=None``.

        Per the Stage 5 design, the OutputFilter runs once on the
        assembled string after the stream completes. If it fires, the
        defense audit event records the leak (the detection signal is
        the value) but no rollback of already-emitted chunks is
        attempted; doing so would just paint a more obvious tell.

        Bridge-level failures degrade to a single fallback chunk if
        no AI content was streamed yet, or close the stream cleanly
        with what was already shipped otherwise.
        """
        sanitised = sanitize_command(
            command,
            max_chars=self._settings.bridge.max_input_chars,
        )

        if not sanitised.strip():
            session.record(sanitised, "", source=ResponseSource.AI, latency_ms=0.0)
            yield BridgeChunk(
                delta="",
                source=ResponseSource.AI,
                done=True,
                latency_ms=0.0,
            )
            return

        injection_verdict = self._injection_scorer.score(sanitised)
        if injection_verdict.truncated:
            self._record_scan_truncated(
                session,
                kind="injection",
                input_length=len(sanitised),
                verdict=injection_verdict,
            )
        if injection_verdict.fired:
            start = self._monotonic()
            self._record_defense_fire(session, injection_verdict)
            text, source = self._fallback(
                session,
                sanitised,
                reason=InjectionDetectedError(
                    f"{injection_verdict.detector} fired (score={injection_verdict.score})",
                ),
            )
            latency_ms = (self._monotonic() - start) * 1000.0
            session.record(sanitised, text, source=source, latency_ms=latency_ms)
            yield BridgeChunk(
                delta=text,
                source=source,
                done=True,
                latency_ms=latency_ms,
            )
            return

        if self._handle_cd(session, sanitised):
            session.record(sanitised, "", source=ResponseSource.AI, latency_ms=0.0)
            yield BridgeChunk(
                delta="",
                source=ResponseSource.AI,
                done=True,
                latency_ms=0.0,
            )
            return

        start = self._monotonic()
        accumulated: list[str] = []
        error: LLMError | None = None
        budget = self.budget_for(session.session_id)
        strategy = self._current_strategy(session.session_id)
        strategy_ctx = StrategyContext(
            session_id=session.session_id,
            command=sanitised,
            command_count=session.command_count,
            wasted_ms_so_far=self._wasted_ms.get(session.session_id, 0),
            bridge_config=self._settings.bridge,
            last_clarification_command_count=self._last_clarification.get(
                session.session_id,
            ),
        )
        pre_effect = await strategy.pre_command(strategy_ctx)
        wasted_ms = pre_effect.total_added_ms
        async for pre_chunk in self._apply_pre_effect(pre_effect, accumulated):
            yield pre_chunk

        # Slice 6.4: when the strategy signals a clarification, swap in
        # the alternate prompt template and remember the command_count
        # so the strategy honours its one-per-chain invariant on the
        # next command. The LLM call shape is otherwise identical.
        if pre_effect.inject_clarification:
            self._last_clarification[session.session_id] = session.command_count
            messages_builder = build_clarification_messages
        else:
            messages_builder = build_messages

        try:
            async with self._limiter.slot(session.session_id):
                messages = messages_builder(
                    sanitised,
                    config=self._settings.bridge,
                    cwd=session.cwd,
                    history=session.history(),
                    persona=session.persona,
                    persistence_events=session.persistence_events,
                )
                # Pre-deploy sweep TODO-9: bound the accumulator so a
                # flood of small chunks cannot push lure memory past
                # the documented whole-stream cap. The per-chunk cap
                # in LLMClient catches one pathological chunk; this
                # catches N small ones whose sum exceeds the
                # max_response_chars contract. The projected total
                # is checked BEFORE append/yield so the over-cap
                # chunk never reflects to the lure and the session
                # record matches what shipped.
                response_cap = self._settings.ollama.max_response_chars
                accumulated_chars = 0
                try:
                    async for chunk in self._client.stream_chat(messages, budget=budget):
                        if chunk.delta:
                            if accumulated_chars + len(chunk.delta) > response_cap:
                                error = OllamaUnavailableError(
                                    f"Ollama stream exceeded max_response_chars cap "
                                    f"({accumulated_chars + len(chunk.delta)} > "
                                    f"{response_cap}); aborting",
                                )
                                break
                            accumulated.append(chunk.delta)
                            accumulated_chars += len(chunk.delta)
                            bridge_chunk = BridgeChunk(
                                delta=chunk.delta,
                                source=ResponseSource.AI,
                                done=False,
                            )
                            yield bridge_chunk
                            delay = await strategy.between_chunks(strategy_ctx, bridge_chunk)
                            if delay > 0:
                                wasted_ms += int(delay * 1000.0)
                                await self._sleep(delay)
                except BudgetExhaustedError as exc:
                    self._record_budget_exhausted(session, exc)
                    error = exc
                except (OllamaUnavailableError, OllamaResponseError) as exc:
                    error = exc
        except (SessionRateLimitedError, GlobalQueueTimeoutError) as exc:
            error = exc

        latency_ms = (self._monotonic() - start) * 1000.0

        if wasted_ms > 0 or pre_effect.inject_clarification:
            self._record_wasting_applied(
                session=session,
                strategy_name=strategy.name,
                wasted_ms=wasted_ms,
                pre_message=pre_effect.pre_message is not None,
                clarification_injected=pre_effect.inject_clarification,
            )
        self._accumulate_wasted_ms(session, wasted_ms)

        if error is None:
            # Post-stream defense filter. Detection only; the chunks
            # already left the bridge so we cannot redact them. The
            # audit event is the operator signal.
            full_text = cap_output(
                "".join(accumulated),
                max_chars=self._settings.ollama.max_response_chars,
            )
            output_verdict = self._output_filter.check(full_text)
            if output_verdict.truncated:
                self._record_scan_truncated(
                    session,
                    kind="output",
                    input_length=len(full_text),
                    verdict=output_verdict,
                )
            if output_verdict.fired:
                self._record_defense_fire(session, output_verdict)
            session.record(
                sanitised,
                full_text,
                source=ResponseSource.AI,
                latency_ms=latency_ms,
            )
            yield BridgeChunk(
                delta="",
                source=ResponseSource.AI,
                done=True,
                latency_ms=latency_ms,
            )
            return

        # Errored. If we already streamed AI content, close cleanly
        # and let the partial reply stand. Otherwise serve the
        # scripted fallback as a single chunk.
        if accumulated:
            full_text = "".join(accumulated)
            session.record(
                sanitised,
                full_text,
                source=ResponseSource.AI,
                latency_ms=latency_ms,
            )
            yield BridgeChunk(
                delta="",
                source=ResponseSource.AI,
                done=True,
                latency_ms=latency_ms,
            )
            return

        text, source = self._fallback(session, sanitised, reason=error)
        session.record(sanitised, text, source=source, latency_ms=latency_ms)
        yield BridgeChunk(
            delta=text,
            source=source,
            done=True,
            latency_ms=latency_ms,
        )

    def _record_defense_fire(
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

    def _record_intent_extracted(self, summary: IntentSummary) -> None:
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

    def _record_intent_extraction_failed(
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

    def _record_embedding_generated(self, embedding: SessionEmbedding) -> None:
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

    def _record_embedding_failed(
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

    def _record_embedding_skipped(self, snapshot: SessionSnapshot) -> None:
        """Audit a below-min-commands skip (generator returned None)."""
        self._audit_log.record(
            "bridge.embedding_skipped",
            session_id=str(snapshot.session_id),
            attacker_ip=snapshot.source_ip,
            reason="below_min_commands",
        )

    def _accumulate_wasted_ms(
        self,
        session: SessionContext,
        wasted_ms: int,
    ) -> None:
        """Update the per-session wasted-ms total and fire the cap audit.

        ``wasted_ms`` is the contribution from the just-completed
        command. Adds it to the running per-session total; if the
        total crosses ``settings.bridge.session_wasted_ms_cap`` for
        the first time, emits ``bridge.wasting_budget_exhausted`` once
        and marks the session so subsequent commands route through
        the off strategy via :meth:`_current_strategy`. cap=0 disables
        enforcement.
        """
        if wasted_ms <= 0:
            return
        session_id = session.session_id
        new_total = self._wasted_ms.get(session_id, 0) + wasted_ms
        self._wasted_ms[session_id] = new_total
        cap = self._settings.bridge.session_wasted_ms_cap
        if cap <= 0:
            return  # disabled by operator
        if session_id in self._wasted_exhausted:
            return
        if new_total >= cap:
            self._wasted_exhausted.add(session_id)
            self._audit_log.record(
                "bridge.wasting_budget_exhausted",
                session_id=str(session_id),
                attacker_ip=session.source_ip,
                wasted_ms=new_total,
                cap_ms=cap,
            )

    def _record_wasting_applied(
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

    def _record_budget_exhausted(
        self,
        session: SessionContext,
        exc: BudgetExhaustedError,
    ) -> None:
        """Audit a per-session token-budget exhaustion."""
        budget = self._budgets.get(session.session_id)
        budget_snapshot = budget.as_dict() if budget is not None else {}
        self._audit_log.record(
            "bridge.budget_exhausted",
            session_id=str(session.session_id),
            attacker_ip=session.source_ip,
            error=str(exc),
            budget=budget_snapshot,
        )

    def _record_scan_truncated(
        self,
        session: SessionContext,
        *,
        kind: str,
        input_length: int,
        verdict: DefenseVerdict,
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
            scan_max_chars=self._settings.defense.scan_max_chars,
            input_length=input_length,
            detector=verdict.detector,
            session_id=str(session.session_id),
            attacker_ip=session.source_ip,
        )

    def _fallback(
        self,
        session: SessionContext,
        command: str,
        *,
        reason: LLMError,
    ) -> tuple[str, ResponseSource]:
        self._logger.warning(
            "bridge.fallback session=%s reason=%s message=%s",
            session.session_id,
            type(reason).__name__,
            reason,
        )
        if not self._settings.bridge.enable_fallback:
            return ("", ResponseSource.REJECTED)
        scripted = fallback_response(
            command,
            hostname=session.fake_hostname,
            username=session.fake_username,
            cwd=session.cwd,
        )
        if scripted is None:
            head = self._first_token(command)
            scripted = f"bash: {head}: command not found" if head else ""
        return (scripted, ResponseSource.FALLBACK)

    def _handle_cd(self, session: SessionContext, command: str) -> bool:
        stripped = command.strip()
        if not stripped:
            return False
        try:
            tokens = shlex.split(stripped, posix=True)
        except ValueError:
            return False
        if not tokens or tokens[0] != "cd":
            return False

        if len(tokens) == 1 or tokens[1] == "~":
            target = (
                f"/home/{session.fake_username}" if session.fake_username != "root" else "/root"
            )
        elif tokens[1].startswith("/"):
            target = tokens[1]
        else:
            base = session.cwd.rstrip("/") or "/"
            target = f"{base}/{tokens[1]}"
        session.update_cwd(normalise_path(target))
        return True

    @staticmethod
    def _first_token(command: str) -> str:
        stripped = command.strip()
        if not stripped:
            return ""
        try:
            tokens = shlex.split(stripped, posix=True)
        except ValueError:
            return stripped.split()[0]
        return tokens[0] if tokens else ""

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
