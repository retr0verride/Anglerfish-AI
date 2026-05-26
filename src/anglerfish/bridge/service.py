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
from anglerfish.llm import LLMClient, TokenBudget
from anglerfish.llm.budget import BudgetExhaustedError
from anglerfish.llm.errors import LLMError
from anglerfish.models.session import BridgeChunk, BridgeResponse, ResponseSource

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
        # Stage 6: reader for dashboard-published runtime overrides. None
        # in tests + dev loops where no dashboard process is running;
        # _current_strategy() falls back to settings.bridge.wasting_strategy.
        self._overrides_reader = overrides_reader
        # Injected for tests so strategy delays do not park real wall-clock
        # time during the suite. Defaults to asyncio.sleep at construct.
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

    def _current_strategy(self) -> WastingStrategyBase:
        """Resolve the active wasting strategy for this command.

        Reads the dashboard-published runtime overrides JSON if a
        reader was wired in; otherwise falls back to the static
        ``settings.bridge.wasting_strategy`` value. Unknown names from
        the reader fall through to the static config too (the reader
        already audits the failure).
        """
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
            )
            self._budgets[session_id] = budget
        return budget

    def end_session_budget(self, session_id: UUID) -> None:
        """Drop per-session state. Safe to call for unknown ids."""
        self._budgets.pop(session_id, None)
        self._last_clarification.pop(session_id, None)

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
        strategy = self._current_strategy()
        strategy_ctx = StrategyContext(
            session_id=session.session_id,
            command=sanitised,
            command_count=session.command_count,
            wasted_ms_so_far=0,  # slice 6.5 wires the per-session cap
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
                )
                try:
                    async for chunk in self._client.stream_chat(messages, budget=budget):
                        if chunk.delta:
                            accumulated.append(chunk.delta)
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
