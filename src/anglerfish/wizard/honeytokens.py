"""Stage 11 honeytoken legal/ethical text displayed by the wizard.

Mirrors the shape of :mod:`anglerfish.wizard.terms` (one constant
in its own module) so the wizard's orchestrator stays free of
multi-paragraph prose.

The prompt is deliberately heavy. Enabling Stage 11 makes
Anglerfish distribute traceable beacons in the lure's fakefs;
honest visitors who exfiltrate files from a misconfigured bait
NIC could trigger callbacks from their own machine. The operator
acknowledgement is the load-bearing gate before the runtime opt-in.
"""

from __future__ import annotations

__all__ = ["HONEYTOKENS_TERMS"]


HONEYTOKENS_TERMS: str = """\
ANGLERFISH AI: STAGE 11 HONEYTOKEN DEPLOYMENT NOTICE

Stage 11 - Decoy data poisoning - is OFF by default. Enabling it
turns Anglerfish into a beacon distributor: every honeypot session
that crosses the threat-score threshold will see a fresh AWS
access-key pair and Ed25519 SSH keypair in the fake filesystem at
/root/.aws/credentials and /root/.ssh/id_rsa. Static base tokens
ship to every session.

These tokens are traceable. When the attacker tries the AWS key
against a real region (typically via `aws s3 ls`), the SDK's STS
or S3 endpoint resolution causes an HTTP request that lands on
the callback receiver you bind below. The receiver logs the hit
and you can correlate the access-key-ID back to the registered
source IP via the dashboard.

Before enabling, you affirm each of the following:

1. You have read docs/HONEYTOKENS.md in full. It documents the
   honest-visitor risk, the AWS access-key shape, and how to
   distinguish researcher traffic from attacker traffic in the
   callback audit log.

2. The host this honeypot runs on is bait-only. No production
   data lives on this machine; no real human relies on the same
   network path. If a researcher pivots a misconfigured probe
   through this host, the resulting callback is yours to triage.

3. The callback receiver URL you supply below is publicly
   reachable AND TLS-terminated. The receiver logs the
   attacker's User-Agent + source IP; a plaintext HTTP receiver
   leaks both to network observers.

4. You accept that registered tokens stay in the registry
   forever (v1 has no revocation). Callbacks remain trackable
   even after honeytokens.enabled is flipped back to False;
   that is intentional (turning off generation should not
   silently mute receivers for tokens already in the wild).

5. Determined attackers may recognise the canary-token pattern
   (AKIA prefix on an internal honeypot URL) and avoid touching
   the bait. The signal is the long-tail less-careful actor; the
   residual is documented.

If you cannot affirm every point, decline below and the wizard
will leave honeytokens disabled. You can opt in later via
ANGLERFISH_HONEYTOKENS__ENABLED=true plus
ANGLERFISH_HONEYTOKENS__CALLBACK_BASE_URL=<url> in the env file,
or via the dashboard's POST /api/settings/features endpoint after
the doc review.
"""
