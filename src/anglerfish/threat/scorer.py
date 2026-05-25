"""Session-level threat scoring.

The scorer is deterministic and pure: given a :class:`SessionSnapshot`
and a rule set, it returns a :class:`ThreatAssessment`. The same input
always produces the same output, which makes the scorer trivial to
test and trivial to back-fill against historical sessions.

Scoring rationale (see also the docstring on :func:`score_session`):

* Each technique contributes its declared ``weight`` to the score
  **once** per session — repeating the same technique 100 times does
  not produce a 1000-point score. Diversity of techniques is what we
  care about.
* A small volume bonus is added so that long, persistent sessions
  outscore short ones with the same technique mix.
* Sessions touching *persistence* techniques (cron, authorized_keys,
  account creation, systemd unit install) get a 20-point bonus and
  are flagged ``persistence_attempted=True``.
* Score is capped at 100. ``high_severity`` is True when the score is
  ≥ 70 or persistence was attempted.
"""

from __future__ import annotations

from collections.abc import Sequence

from anglerfish.models.session import SessionSnapshot
from anglerfish.models.threat import ThreatAssessment, ThreatTechnique
from anglerfish.threat.techniques import TECHNIQUES, TechniqueRule

__all__ = ["score_session"]


_MAX_MATCHES_PER_TECHNIQUE = 10
_VOLUME_BONUS_CAP = 15
_PERSISTENCE_BONUS = 20
_HIGH_SEVERITY_THRESHOLD = 70


def score_session(
    snapshot: SessionSnapshot,
    *,
    rules: Sequence[TechniqueRule] = TECHNIQUES,
) -> ThreatAssessment:
    """Compute a deterministic threat assessment for ``snapshot``."""

    matched: dict[str, list[str]] = {}

    for turn in snapshot.turns:
        for rule in rules:
            if rule.matches(turn.command):
                bucket = matched.setdefault(rule.id, [])
                bucket.append(turn.command)

    rule_by_id = {rule.id: rule for rule in rules}

    weight_sum = sum(rule_by_id[rid].weight for rid in matched)
    persistence = any(rule_by_id[rid].persistence for rid in matched)

    volume_bonus = min(_VOLUME_BONUS_CAP, len(snapshot.turns) // 5)
    score = min(100, weight_sum + volume_bonus)
    if persistence:
        score = min(100, score + _PERSISTENCE_BONUS)

    techniques = tuple(
        ThreatTechnique(
            id=rid,
            name=rule_by_id[rid].name,
            matches=tuple(dict.fromkeys(matched[rid]))[:_MAX_MATCHES_PER_TECHNIQUE],
        )
        for rid in sorted(matched)
    )

    notes: list[str] = []
    if persistence:
        notes.append("Persistence technique observed; investigate immediately.")
    if score >= _HIGH_SEVERITY_THRESHOLD:
        notes.append(f"Score {score} meets high-severity threshold.")
    if not techniques:
        notes.append("No MITRE ATT&CK techniques matched.")

    return ThreatAssessment(
        session_id=snapshot.session_id,
        score=score,
        techniques=techniques,
        persistence_attempted=persistence,
        high_severity=score >= _HIGH_SEVERITY_THRESHOLD or persistence,
        notes=tuple(notes),
    )
