"""High-level AI bridge service.

:class:`AIBridgeService` is the orchestrator that Cowrie's command
handler talks to. Given a session and a command, it returns the
response to print to the attacker's terminal. It wires together:

* :mod:`anglerfish.bridge.sanitize` (input cap + control-char strip)
* the deterministic ``cd`` shortcut so cwd never depends on the LLM
* :mod:`anglerfish.bridge.rate_limit` (global + per-session caps)
* :mod:`anglerfish.bridge.prompts` (prompt construction)
* :mod:`anglerfish.bridge.client` (Ollama HTTP call)
* :mod:`anglerfish.bridge.fallback` (scripted responses on failure)
* :mod:`anglerfish.bridge.session` (per-attacker state recording)

The service catches every bridge-level error and degrades to a
fallback response so that Cowrie always gets a non-empty result and
the attacker is never shown an exception.
"""

from __future__ import annotations

import logging
import shlex
import time
from collections.abc import Callable
from typing import Self

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
from anglerfish.bridge.path import normalise_path
from anglerfish.bridge.prompts import build_messages
from anglerfish.bridge.rate_limit import BridgeRateLimiter
from anglerfish.bridge.sanitize import cap_output, sanitize_command
from anglerfish.bridge.session import SessionContext
from anglerfish.config.settings import AnglerfishSettings
from anglerfish.llm import LLMClient
from anglerfish.llm.errors import LLMError
from anglerfish.models.session import BridgeResponse, ResponseSource

__all__ = ["AIBridgeService"]


class AIBridgeService:
    """Cowrie-facing orchestrator.

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

    @property
    def settings(self) -> AnglerfishSettings:
        return self._settings

    @property
    def client(self) -> LLMClient:
        return self._client

    @property
    def limiter(self) -> BridgeRateLimiter:
        return self._limiter

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
        # Note: `text` and `source` types are inferred from both branches
        # (try / except). The explicit annotations that used to live here
        # are no longer necessary since the injection branch above
        # establishes the types via destructuring assignment.
        try:
            async with self._limiter.slot(session.session_id):
                messages = build_messages(
                    sanitised,
                    config=self._settings.bridge,
                    cwd=session.cwd,
                    history=session.history(),
                )
                result = await self._client.chat(messages)
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

    def _record_defense_fire(
        self,
        session: SessionContext,
        verdict: DefenseVerdict,
    ) -> None:
        """Audit-log a defense trigger. Asymmetric observability: we
        always know defense fired, the attacker never does."""
        self._audit_log.record(
            "bridge.defense_fired",
            detector=verdict.detector,
            score=verdict.score,
            snippet=verdict.snippet,
            session_id=str(session.session_id),
            attacker_ip=session.source_ip,
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
