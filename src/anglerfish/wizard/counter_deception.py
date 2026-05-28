"""Stage 12 counter-deception acknowledgement text shown by the wizard.

Mirrors :mod:`anglerfish.wizard.honeytokens` (one constant in its own
module) so the wizard orchestrator stays free of multi-paragraph prose.

This is the heaviest gate of any stage. Enabling counter-deception
makes Anglerfish deliberately produce wrong information (corrupted
"stolen" key files, factually-wrong shell output) to harm an
attacker's workflow. An honest visitor who crosses the threat
threshold receives that wrong information too. The operator
acknowledgement is the load-bearing control before the runtime
opt-in.
"""

from __future__ import annotations

__all__ = ["COUNTER_DECEPTION_TERMS"]


COUNTER_DECEPTION_TERMS: str = """\
ANGLERFISH AI: STAGE 12 ACTIVE COUNTER-DECEPTION NOTICE

Stage 12 - Active counter-deception - is OFF by default. It is the
most aggressive capability Anglerfish has. Enabling it means that, on
any session whose threat score crosses the engagement threshold
(default 70), Anglerfish will:

1. Corrupt the bytes of selected files (SSH keys, AWS credentials by
   default) the attacker reads from the fake filesystem, so attempted
   reuse fails with parse or signature errors on a file that still
   looks valid.

2. Inject prompt instructions that make the bridge LLM introduce
   small factual errors in shell-command responses once the session
   passes the command-count thresholds (wrong PIDs, wrong sizes,
   plausibly-wrong paths). The errors ramp from mild to severe.

Before enabling, you affirm each of the following:

1. You have read the "Active counter-deception" section of
   docs/THREAT_MODEL.md in full. It documents the honest-visitor
   collateral-damage risk, the LLM-falsehood guardrails (and their
   limits), and the operator-whitelist control.

2. The host this honeypot runs on is bait-only and internet-facing.
   No researcher, automated scanner, or actual user reaches it on a
   path where receiving an hour of wrong PIDs would cause real harm.
   You accept that no technical means distinguishes a real attacker
   from a researcher who tripped the threat heuristics.

3. You understand the time-bomb prompt forbids security-sensitive
   falsehoods (no fake CVEs, no fake IP addresses outside RFC 1918,
   no fake credentials), but that this guardrail is advisory: a local
   model can still hallucinate one. You review the audit log
   (bridge.counter_deception_engaged / _timebomb_applied) accordingly.

4. You know the operator whitelist exists: pinning a source IP with
   mode "off" via the dashboard suppresses counter-deception for that
   IP even above the threshold. Use it for known researchers.

If you cannot affirm every point, decline below and the wizard will
leave counter-deception disabled. You can opt in later via
ANGLERFISH_COUNTER_DECEPTION__ENABLED=true in the env file (mode and
engagement_threshold default to "both" / 70; tune them there) or via
the dashboard's POST /api/settings/features endpoint after the doc
review.
"""
