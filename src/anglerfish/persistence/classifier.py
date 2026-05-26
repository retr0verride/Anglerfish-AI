"""Pre-LLM detection of attacker persistence-installation attempts.

The bridge's command-handling pipeline runs :meth:`PersistenceClassifier.classify`
before the main LLM call. A match yields a :class:`PersistenceEvent` that
the bridge:

* records on the in-memory :class:`SessionContext` so subsequent
  commands' fs_context blocks reflect the install;
* audits as ``bridge.persistence_attempt`` so the dashboard tailer
  can persist it into ``fake_persistence_state``;
* returns to the caller for any per-event side effects (none today).

A miss returns :data:`None` and the bridge proceeds with the
normal LLM call. False negatives degrade to pre-Stage-10
behaviour (no fake state); false positives over-engage but do
not violate any invariant.

Slice 10.1 ships the regex-only hot path. The LLM fast-tier
pass (for regex-silent write-shape commands) lands in slice
10.3; the constructor already accepts the wiring so the
integration tests can switch it on with one line.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from anglerfish.models.persistence import PersistenceEvent
from anglerfish.persistence.patterns import extract_event

if TYPE_CHECKING:
    from anglerfish.llm import LLMClient

__all__ = ["PersistenceClassifier"]


_logger = logging.getLogger(__name__)


class PersistenceClassifier:
    """Detect persistence-installation attempts in attacker commands.

    Constructed once at bridge startup; reused for every command.
    Stateless; safe to share across asyncio tasks.
    """

    def __init__(
        self,
        client: LLMClient | None = None,
        *,
        llm_enabled: bool = True,
        budget_cap_tokens: int = 1500,
    ) -> None:
        if budget_cap_tokens < 1:
            raise ValueError(
                f"budget_cap_tokens must be >= 1, got {budget_cap_tokens}",
            )
        self._client = client
        self._llm_enabled = llm_enabled
        self._budget_cap_tokens = budget_cap_tokens

    async def classify(
        self,
        command: str,
        *,
        cwd: str,
    ) -> PersistenceEvent | None:
        """Return a :class:`PersistenceEvent` if the command installs persistence.

        Pipeline:

        1. **Regex pass** (synchronous, microseconds): matches the
           authorized_keys / crontab / systemctl patterns +
           extracts the payload. First-match-wins across the three
           kinds.
        2. **LLM pass** (slice 10.3): triggered when regex is
           silent on a write-shape command. Returns
           :data:`None` in slice 10.1.

        Returns :data:`None` on a miss; the caller proceeds with
        the normal LLM call.
        """
        del cwd  # reserved for LLM pass in slice 10.3
        event = extract_event(command)
        if event is not None:
            return event
        # Slice 10.3 will branch here on regex misses that look
        # like write-shape commands. Today: return None.
        return None
