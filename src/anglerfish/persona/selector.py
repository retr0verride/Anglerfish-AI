"""Per-attacker persona selection (Stage 9 slice 9.2).

The bridge HTTP POST /api/v1/session endpoint calls
:meth:`PersonaSelector.select` once per attacker connection. The
selector consults three signals in order; first match wins:

1. **Operator pin** - the dashboard's persona_pins table holds
   per-source-IP pins that override every other rule. Pins are
   the test/triage knob ("force this attacker onto the
   ad-joined-workstation persona to see how the LLM responds to
   AD-themed reconnaissance").
2. **Source-IP recurrence** - the most recent prior session from
   this source_ip whose persona column is non-null. Keeps the
   persona sticky across reconnects so an attacker rotating SSH
   clients still sees a coherent box. The Stage 8 cluster signal
   feeds in here indirectly: the cluster-bias rebound updates
   the source_ip -> persona mapping after the dashboard tailer
   sees a strong neighbour match.
3. **Hash fallback** - SHA-256 of the source_ip mod registry
   size, deterministic. New attackers spread uniformly across
   the persona pool without needing any DB read to succeed.

A :class:`SelectionResult` includes the reason so the bridge can
audit it as bridge.persona_selected with selection_reason in
{pin, source_ip_recurrence, hash_fallback}.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Literal

from anglerfish.persona.registry import PersonaRegistry
from anglerfish.persona.schema import Persona
from anglerfish.sessions.reader import SessionStoreReader

__all__ = ["PersonaSelector", "SelectionReason", "SelectionResult"]


_logger = logging.getLogger(__name__)


SelectionReason = Literal["pin", "source_ip_recurrence", "hash_fallback"]
"""Why a particular persona was chosen.

Exact strings ride the bridge.persona_selected audit event;
dashboards filter on them when triaging an unexpected persona
assignment.
"""


@dataclass(frozen=True, slots=True)
class SelectionResult:
    """One persona pick + the reason it was picked."""

    persona: Persona
    reason: SelectionReason


class PersonaSelector:
    """Chooses one :class:`Persona` per attacker source IP."""

    def __init__(
        self,
        registry: PersonaRegistry,
        reader: SessionStoreReader,
    ) -> None:
        self._registry = registry
        self._reader = reader

    async def select(self, source_ip: str) -> SelectionResult:
        """Pick a persona for ``source_ip``. Total over the persona surface.

        Never raises on the happy path:

        * An operator pin that names a persona the registry has
          since dropped falls through to recurrence + hash (the
          pin is logged as stale via :meth:`PersonaRegistry.get_or_default`
          which silently returns the default; the selector
          attributes the result to its real source so the audit
          event stays honest).
        * A recurrence query whose persona column references a
          deleted name falls through the same way.
        * The hash fallback always returns a persona because the
          registry guarantees at least one entry.

        Database read failures propagate because the bridge's
        startup already verified the reader can open the DB; a
        live read failure is an operational signal that should
        surface (and the bridge has nothing useful to do with it
        on this path).
        """
        if not source_ip:
            raise ValueError("source_ip cannot be empty")
        pin = await self._reader.get_persona_pin(source_ip)
        if pin is not None and pin in self._registry:
            return SelectionResult(self._registry.get(pin), "pin")
        recurrence = await self._reader.recent_persona_for_source_ip(source_ip)
        if recurrence is not None and recurrence in self._registry:
            return SelectionResult(self._registry.get(recurrence), "source_ip_recurrence")
        return SelectionResult(self._hash_select(source_ip), "hash_fallback")

    def _hash_select(self, source_ip: str) -> Persona:
        """Pick a persona by SHA-256(source_ip) mod registry size.

        Deterministic so the same IP always lands on the same
        fallback persona between Stage 8 rebounds. SHA-256
        rather than Python's ``hash`` keeps the assignment
        stable across process restarts (CPython's
        ``PYTHONHASHSEED`` randomises ``hash(str)``).
        """
        names = self._registry.names()
        digest = hashlib.sha256(source_ip.encode("utf-8")).digest()
        # First 8 bytes as a big-endian unsigned int is plenty of
        # entropy for a four-persona ring; the modulo over
        # len(names) is unbiased for any practical persona count
        # (the worst-case bias of `2**64 mod len` is 0 below 2^32
        # which we'll never hit).
        index = int.from_bytes(digest[:8], "big") % len(names)
        return self._registry.get(names[index])
