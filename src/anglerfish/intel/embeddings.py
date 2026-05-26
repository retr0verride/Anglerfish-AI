"""Per-session behavioural embedding producer (Stage 8 slice 2).

The bridge process calls :meth:`EmbeddingGenerator.generate` after
a session closes. It joins the attacker's commands into a single
text, truncates to ``max_command_chars``, calls
:meth:`anglerfish.llm.LLMClient.embed` against the embed model,
and returns a populated :class:`anglerfish.models.SessionEmbedding`.

Two short-circuits keep inference cost bounded:

* Sessions with fewer than ``min_commands`` recorded turns return
  :data:`None` (no embedding row gets persisted). One-shot
  scanners dominate attacker traffic; clustering them adds no
  signal.
* The joined command text is truncated to ``max_command_chars``
  with oldest commands dropped first (the embed model's context
  window is the hard ceiling; the cap keeps us well under it
  while preserving the most recent behaviour).

An independent :class:`anglerfish.llm.TokenBudget` is constructed
per call (embed tier only) so embedding generation never consumes
the per-session command budget Stage 5 slice 5 introduced.
Responses are intentionally excluded from the embed input - they
are bridge-generated text and would skew the embedding toward
bridge behaviour rather than attacker behaviour.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from anglerfish.llm import LLMClient, LLMRole, TokenBudget
from anglerfish.models.embedding import SessionEmbedding
from anglerfish.models.session import CommandTurn, SessionSnapshot

__all__ = ["EmbeddingExtractionError", "EmbeddingGenerator"]


# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

_DEFAULT_MIN_COMMANDS = 3
_DEFAULT_BUDGET_TOKENS = 2000
_DEFAULT_MAX_COMMAND_CHARS = 4096


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class EmbeddingExtractionError(Exception):
    """Base class for embedding-generation failures the generator itself raises.

    Underlying LLM-layer failures (OllamaUnavailableError,
    BudgetExhaustedError) propagate unchanged so the bridge
    integration in slice 8.4 can audit them as
    ``bridge.embedding_failed`` with a precise error_type.
    """


# ---------------------------------------------------------------------------
# Public generator
# ---------------------------------------------------------------------------


class EmbeddingGenerator:
    """End-of-session behavioural embedding producer."""

    def __init__(
        self,
        client: LLMClient,
        *,
        min_commands: int = _DEFAULT_MIN_COMMANDS,
        budget_cap_tokens: int = _DEFAULT_BUDGET_TOKENS,
        max_command_chars: int = _DEFAULT_MAX_COMMAND_CHARS,
        clock: Callable[[], datetime] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        if min_commands < 0:
            raise ValueError(f"min_commands must be >= 0, got {min_commands}")
        if budget_cap_tokens < 0:
            raise ValueError(
                f"budget_cap_tokens must be >= 0, got {budget_cap_tokens}",
            )
        if max_command_chars < 1:
            raise ValueError(
                f"max_command_chars must be >= 1, got {max_command_chars}",
            )
        self._client = client
        self._min_commands = min_commands
        self._budget_cap_tokens = budget_cap_tokens
        self._max_command_chars = max_command_chars
        self._clock = clock
        self._logger = logger if logger is not None else logging.getLogger(__name__)

    async def generate(self, snapshot: SessionSnapshot) -> SessionEmbedding | None:
        """Produce a :class:`SessionEmbedding` for ``snapshot``.

        Sessions below ``min_commands`` short-circuit to :data:`None`
        (no Ollama traffic, no persisted row). Otherwise calls
        :meth:`LLMClient.embed` against the embed model with a fresh
        per-call :class:`TokenBudget` (embed tier only).

        Raises:
            BudgetExhaustedError: ``budget_cap_tokens=0`` or the
                request would push usage over.
            OllamaUnavailableError / OllamaResponseError: from the
                underlying embed call; propagate unchanged.
        """
        if len(snapshot.turns) < self._min_commands:
            return None

        text = _join_commands(snapshot.turns, cap=self._max_command_chars)
        budget = TokenBudget(
            fast_token_cap=0,  # embed tier only
            deep_token_cap=0,
            embed_token_cap=self._budget_cap_tokens,
        )
        vector = await self._client.embed(text, budget=budget)
        return SessionEmbedding(
            session_id=snapshot.session_id,
            vector=vector,
            dimension=len(vector),
            model=self._client.model_for(LLMRole.EMBED),
            generated_at=self._now(),
        )

    def _now(self) -> datetime:
        if self._clock is not None:
            return self._clock()
        return datetime.now(tz=UTC)


# ---------------------------------------------------------------------------
# Pure helpers (testable without an LLMClient)
# ---------------------------------------------------------------------------


def _join_commands(turns: Sequence[CommandTurn], *, cap: int) -> str:
    """Render the attacker-side command history as one newline-joined text.

    Truncates to ``cap`` characters by dropping the OLDEST commands
    first - the embed model's most-recent-behaviour signal is the
    operator-meaningful one when an attacker pivots mid-session.
    Bridge responses are intentionally excluded (they are LLM-
    generated and would make the embedding reflect the bridge's
    behaviour rather than the attacker's).
    """
    if cap <= 0:
        return ""
    parts: list[str] = []
    running_len = 0
    # Walk newest-first; build the joined string from the most recent
    # commands until we'd cross the cap, then reverse so the produced
    # text reads oldest-first inside the kept window.
    for turn in reversed(turns):
        candidate = turn.command + "\n"
        # +1 accounts for the separator the previous append introduced;
        # for the first kept command there is none, but the math is
        # conservative either way.
        if running_len + len(candidate) > cap:
            break
        parts.append(candidate)
        running_len += len(candidate)
    parts.reverse()
    return "".join(parts)
