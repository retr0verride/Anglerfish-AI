# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x   | Yes — current development line |
| < 0.1   | No |

After 1.0, we patch security issues in:

- The latest minor release.
- The previous minor release, for 90 days after a new minor ships.

## Reporting a vulnerability

**Do not open a public GitHub issue for suspected vulnerabilities.**

Send a report by email to **retroverride@pm.me** with:

- A clear description of the issue and its impact.
- A minimal proof-of-concept or reproduction steps.
- Your assessment of severity (low / medium / high / critical) and
  whether public exploitation is plausible.
- Any patch or mitigation suggestion you have.

You will receive an acknowledgement within 72 hours.

### Response targets

| Severity | Patch ETA |
|---|---|
| Critical | 14 days |
| High     | 30 days |
| Medium   | 60 days |
| Low      | next minor release |

### Public disclosure

We follow coordinated disclosure: a fix lands, a release goes out, and a
GHSA advisory is published. We will credit reporters by name if they
wish. We will not credit reporters who request anonymity.

## Scope

### In scope

- The Anglerfish AI Python package (`src/anglerfish/`).
- The first-boot wizard, systemd unit files, nftables ruleset, and ISO
  recipe shipped in this repository.
- Dependency vulnerabilities reported by `pip-audit` that we have not
  yet patched in a release.
- Documentation that recommends an insecure configuration.

### Out of scope (forward upstream)

- Cowrie itself — https://github.com/cowrie/cowrie
- Ollama — https://github.com/ollama/ollama
- Splunk Enterprise / Cloud
- The Linux kernel and Debian base packages
- MaxMind GeoLite2 databases

### Out of scope (intended behaviour)

- The bridge HTTP API rejects non-loopback / non-trusted-IP endpoints.
  This is enforced by configuration validation; reports about
  "configurable insecure endpoint" are not in scope.
- The fake shell sometimes makes things up — that is the design. Reports
  about "the LLM hallucinated a file path" are not security issues
  unless the hallucination leaks real host data.
- The credential intelligence database is decryptable by anyone with
  the operator-provided encryption key. Reports about "the key can
  decrypt the data" are not in scope.

## Cryptographic primitives

- AES-256-GCM for credential records (96-bit random nonces).
- HMAC-SHA-256 for credential fingerprints, under a separate
  context-bound key.
- Twisted SSH for Cowrie's bait protocol.
- TLS for outbound Splunk HEC, with `verify_tls=True` by default.

If you can break any of these primitives, please publish — that is a
much bigger story than Anglerfish.
