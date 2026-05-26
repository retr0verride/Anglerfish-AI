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
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

from anglerfish.llm import ChatMessage, LLMRole, TokenBudget
from anglerfish.llm.errors import LLMError
from anglerfish.models.persistence import PersistenceEvent, PersistenceKind
from anglerfish.persistence.patterns import extract_event, looks_write_shape

if TYPE_CHECKING:
    from anglerfish.llm import LLMClient

__all__ = ["PersistenceClassifier", "PersistenceClassifierError"]


_logger = logging.getLogger(__name__)


class PersistenceClassifierError(Exception):
    """Raised by :meth:`PersistenceClassifier.classify_via_llm` on LLM failure.

    The bridge integration in slice 10.3 catches this exception,
    audits it as ``bridge.persistence_classifier_error``, and
    proceeds with the normal LLM command call (no fake state
    recorded). Wrapping the LLM-layer ``LLMError`` shapes here
    lets the bridge distinguish "classifier failed" from "main
    LLM call failed" without parsing exception strings.
    """


# Output schema for the LLM classifier. Stripped of fields the
# classifier path supplies (source="llm"). The kind Literal is
# the same Literal alias the persisted model uses so a structured
# call returning an unknown kind already fails Pydantic
# validation inside structured_chat.
class _LLMClassifierPayload(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    is_persistence: bool
    kind: PersistenceKind | None = None
    sub_key: str | None = Field(default=None, max_length=256)
    payload: str | None = Field(default=None, min_length=1, max_length=4096)


_SYSTEM_PROMPT = """\
You are a security classifier. Examine the bash command below run by an \
attacker on a compromised Linux server.

Decide whether the command installs PERSISTENCE - a mechanism that lets \
the attacker maintain unauthorized access across reboots, logouts, or \
client rotations.

Examples of persistence:
- crontab edits (`crontab -e`, `echo '...' | crontab -`, writes to \
/etc/cron.d/ or /var/spool/cron/)
- systemd unit installs (`systemctl enable <unit>`, writes to \
/etc/systemd/system/*.service)
- SSH authorized_keys appends (`echo '<key>' >> ~/.ssh/authorized_keys`)
- /etc/profile.d/ or /etc/init.d/ drops
- ~/.bashrc / ~/.profile / ~/.bash_profile re-establishment hooks

Examples NOT persistence:
- read-only inspection (ls, cat, ps, find)
- one-shot commands without survival mechanism
- transient file writes to /tmp without a re-execution trigger
- normal admin commands (mv, cp without install path implication)

Return STRICT JSON matching the schema. When is_persistence=false, \
leave kind/sub_key/payload null. When is_persistence=true, set kind to \
exactly one of "crontab", "systemctl", "authorized_keys"; set sub_key \
to the unit name (for systemctl) or the user (for crontab / \
authorized_keys); set payload to the verbatim text the attacker installed."""


class PersistenceClassifier:
    """Detect persistence-installation attempts in attacker commands.

    Constructed once at bridge startup; reused for every command.
    Stateless; safe to share across asyncio tasks.

    The classify() pipeline is regex-first (microseconds) with an
    optional LLM second pass for regex-silent commands that
    nevertheless look write-shape. The LLM pass uses the fast tier
    + a tight token budget; failures land in
    :exc:`PersistenceClassifierError` for the caller to audit and
    swallow.
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
        2. **LLM pass**: when ``llm_enabled`` AND a client is
           wired AND the regex was silent AND
           :func:`looks_write_shape` flags the command, one
           fast-tier structured-chat call classifies. Failures
           raise :exc:`PersistenceClassifierError` for the caller
           to audit and swallow.

        Returns :data:`None` on a miss; the caller proceeds with
        the normal LLM command call.
        """
        event = extract_event(command)
        if event is not None:
            return event
        if not self._llm_enabled or self._client is None:
            return None
        if not looks_write_shape(command):
            return None
        return await self._classify_via_llm(command, cwd)

    async def _classify_via_llm(
        self,
        command: str,
        cwd: str,
    ) -> PersistenceEvent | None:
        """Run the fast-tier structured-chat classifier; map result to model."""
        messages = [
            ChatMessage(role="system", content=_SYSTEM_PROMPT),
            ChatMessage(
                role="user",
                content=(f"cwd: {cwd}\ncommand: {command}"),
            ),
        ]
        budget = TokenBudget(
            fast_token_cap=self._budget_cap_tokens,
            deep_token_cap=0,
        )
        try:
            payload = await self._client.structured_chat(  # type: ignore[union-attr]
                messages,
                _LLMClassifierPayload,
                role=LLMRole.FAST,
                budget=budget,
            )
        except (LLMError, ValueError) as exc:
            raise PersistenceClassifierError(
                f"LLM persistence classifier call failed: {exc}",
            ) from exc
        return _payload_to_event(payload)


def _payload_to_event(payload: _LLMClassifierPayload) -> PersistenceEvent | None:
    """Convert the LLM-side payload into a persisted-side event, or None.

    Returns None on three shapes:
    * ``is_persistence=False`` (the negative answer).
    * ``is_persistence=True`` without a kind or payload (the LLM
      flagged but could not extract enough to act on; safer to
      treat as a miss than to invent fields).
    """
    if not payload.is_persistence:
        return None
    if payload.kind is None or not payload.payload:
        _logger.warning(
            "PersistenceClassifier LLM returned is_persistence=true "
            "but kind=%r / payload=%r; treating as miss",
            payload.kind,
            payload.payload,
        )
        return None
    return PersistenceEvent(
        kind=payload.kind,
        sub_key=payload.sub_key,
        payload=payload.payload,
        source="llm",
    )


_LLM_KIND: Literal["llm"] = "llm"  # reserved for static-type-check ergonomics
