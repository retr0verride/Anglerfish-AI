# Honeytokens — Stage 11 decoy data poisoning

This document is the load-bearing operator-facing notice for
Stage 11. The first-boot wizard requires you to confirm you have
read it before honeytokens can be enabled.

If you have not read this document in full, decline the wizard's
``honeytokens_enabled`` prompt and leave the feature disabled.
You can enable later by re-running the wizard with
``--reconfigure``, by setting
``ANGLERFISH_HONEYTOKENS__ENABLED=true`` plus
``ANGLERFISH_HONEYTOKENS__CALLBACK_BASE_URL=<url>`` in
``/etc/anglerfish/anglerfish.env``, or by flipping the feature
via the dashboard's ``POST /api/settings/features`` endpoint.

## What Stage 11 does

When honeytokens are enabled, Anglerfish distributes traceable
beacons in the lure's fake filesystem:

* **AWS access keys.** An INI-formatted credentials block at
  ``/root/.aws/credentials`` of the shape:

  ```ini
  [default]
  aws_access_key_id = AKIA<16-char-base32-id>
  aws_secret_access_key = <40-char-random>
  region = us-east-1
  ```

  The 16-char access-key-ID suffix is the registry lookup key.
  When an attacker tries the key against AWS (typically via
  ``aws s3 ls``), the SDK's STS / S3 endpoint resolution
  triggers HTTP requests that the operator's callback receiver
  logs. The secret value is random padding; AWS routing keys
  on the access-key-ID alone.

* **SSH keypairs.** An Ed25519 private key at
  ``/root/.ssh/id_rsa`` (OpenSSH PEM format). The public-key
  comment field carries ``honeytoken-<id>`` so an operator who
  finds the key in a Shodan dump or a paste site can grep for
  it. SSH callbacks are weaker than AWS callbacks - there is
  no equivalent of ``aws s3 ls`` for "did anyone try this key
  publicly?" - so the v1 signal for SSH is purely the
  lure-side audit ("attacker cat'd ~/.ssh/id_rsa") plus the
  operator's own grepping.

Two placement tiers ship side by side:

1. **Static-base tokens** (``honeytokens.static_base_paths``):
   visible to every session that opens against this honeypot.
   Cheap; one-time bootstrap.
2. **Per-session unique tokens** (gated by
   ``honeytokens.placement_threshold``, default 50): generated
   when the threat scorer crosses the threshold. The tokens
   become visible on the NEXT session from the same source IP
   (mirrors the Stage 10 cross-session overlay).

## The honest-visitor risk

This is the single most important risk to understand before
enabling Stage 11.

An honest visitor (a security researcher, a misconfigured
internal vulnerability scanner, a student running an SSH
fuzzer, a colleague who accidentally ran an exfil tool against
the wrong host) who exfiltrates files from your honeypot
**will trigger callbacks from their own machine** the moment
they touch the AWS key. The callback audit event will look
indistinguishable from a real attacker's exfil chain. You will
see:

* The honeypot session showed the file being read.
* The callback receiver shows the AWS key being tried hours
  or days later.
* The callback's source IP is the visitor's exfil node, not
  the original honeypot session's source IP.

Three things help triage:

1. **The callback audit event includes the User-Agent.** A
   real attacker exfil chain typically uses ``aws-cli/2.x`` or
   ``python-botocore`` or ``boto3``. A researcher poking the
   key by hand often uses ``curl`` or a browser. Neither
   signal is conclusive; both are evidence.
2. **The honeypot session's threat score is auditable.** If
   the session that placed the per-session token had a low
   threat score AND the callback arrived hours later from a
   different IP, the most likely explanation is researcher
   noise.
3. **The static-base tokens have no associated session.** The
   ``registered_source_ip`` on the callback event is
   ``null``; you cannot correlate back to a specific
   incident.

There is no technical means to distinguish "real attacker"
from "researcher who exfiltrated a file from a bait NIC they
thought was real". The operator deployment context is the only
mitigation:

* Deploy on bait NICs only. Never share a NIC with services
  honest users connect to.
* Deploy internet-facing only. An internal-network honeypot
  reachable by your own security team is a constant source of
  false positives.
* Document the deployment in your incident-response runbook
  so the on-call who sees a callback knows where to look
  before paging anyone.

## Operating the callback receiver

The receiver is a separate FastAPI app bundled in the
Anglerfish CLI. Launch it via:

```
anglerfish callback serve --host 0.0.0.0 --port 8443
```

The receiver runs unprivileged, reads the shared sessions DB
read-only, and writes its own audit log to
``settings.audit.log_path`` (the same file the bridge + dashboard
write to). Operators ship that audit log back to the main
Anglerfish host via their existing forwarder (rsync over SSH,
syslog forwarder, Splunk, the dashboard's own audit-log
export).

The receiver's public URL **must** be HTTPS-terminated. The
wizard rejects ``http://`` URLs at install time; if you
manually edit the env file to bypass that check, callback hits
and attacker User-Agents will leak to network observers.

Standard deployment topology:

* Bridge process on loopback (existing).
* Dashboard process on loopback or operator-bound (existing).
* Callback receiver on a public-reachable host (new). Front
  with a reverse proxy (nginx, Caddy, your CDN) that
  terminates TLS, rate-limits per source IP, and passes
  through to the receiver on a loopback port.

The receiver returns the same AWS-style 403 ``InvalidAccessKeyId``
XML body for every request (hits AND misses) so an attacker who
probes random token IDs cannot enumerate which IDs your registry
contains. The receiver audits every miss as well so you can see
probe traffic.

## Identifying a leaked token

The AWS access-key-ID is the lookup key. If you find a token
suspected of being yours - in a Github search, a paste site, a
Shodan dump - paste the 16-char suffix (everything after
``AKIA``) into a SQL query against the registry:

```sql
SELECT id, source_ip, session_id, placed_at, created_at
FROM honeytokens
WHERE id = '<the-16-char-id>';
```

A non-null ``source_ip`` plus ``session_id`` tells you which
honeypot session originally placed the token. Cross-reference
the session in the dashboard for command history, threat
scores, and intent extraction.

For SSH keys, grep the public key for ``honeytoken-`` and pull
the suffix; the same SQL query applies.

## Token revocation

There is no token revocation in v1. Once registered, a
honeytoken stays in the registry forever and the callback
receiver continues to log hits on it (this is intentional - if
the operator flips ``honeytokens.enabled`` back to false, that
should stop NEW poisoning but should not silently mute the
receivers for tokens already in the wild).

Operators who need a specific token to stop firing should:

1. Generate a new token via the dashboard's
   ``GET /api/honeytokens/state`` (after a new session from the
   target source IP crosses the threshold) and let the new
   token supersede the old in the lure overlay.
2. Manually delete the old row from the ``honeytokens`` table
   via SQL. The callback receiver will then return the same
   generic 403 on hits as it would for a miss.

A future stage may add a dashboard DELETE endpoint with audit
trail; v1 keeps revocation as a SQL operation to discourage
casual deletion.

## What this feature is NOT

* **NOT a way to attack the attacker.** The receiver only
  logs callbacks; it does not retaliate, scan back, or
  attempt to exploit the attacker. Stage 12 (active
  counter-deception) is where adversarial payloads land;
  Stage 11 is purely passive instrumentation.
* **NOT a substitute for incident response.** A callback is a
  signal, not an incident closure. The operator triages the
  signal, cross-references the session, decides on the
  response.
* **NOT a credential.** The AWS keys and SSH keys placed in
  the lure are random padding for the secret half; they have
  no permissions on any real system. The signal value comes
  from the access-key-ID lookup, not from any AWS API call
  the attacker can complete.

## See also

* [STAGE_11_decoy_data_poisoning.md](design/STAGE_11_decoy_data_poisoning.md) - design doc.
* [THREAT_MODEL.md](THREAT_MODEL.md) - "Decoy data poisoning" section
  enumerates the STRIDE rows.
* [RUNBOOK.md](RUNBOOK.md) - operator playbook for receiver deployment.
