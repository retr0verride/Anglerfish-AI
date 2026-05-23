"""Threat scoring engine with MITRE ATT&CK technique tagging.

Public surface:

* :class:`ThreatEngine` — the orchestrator; combines scoring with
  webhook alerting.
* :func:`score_session` — pure scoring function. Returns a
  :class:`anglerfish.models.threat.ThreatAssessment`.
* :data:`TECHNIQUES` — the default rule set.
* :class:`TechniqueRule` — the rule type, exported so operators can
  build custom rule sets that extend or replace the defaults.
* :class:`ThreatAlerter` — webhook poster. Best-effort, never raises.
"""

from __future__ import annotations

from anglerfish.threat.alerter import ThreatAlerter
from anglerfish.threat.scorer import score_session
from anglerfish.threat.service import ThreatEngine
from anglerfish.threat.techniques import TECHNIQUES, TechniqueRule

__all__ = [
    "TECHNIQUES",
    "TechniqueRule",
    "ThreatAlerter",
    "ThreatEngine",
    "score_session",
]
