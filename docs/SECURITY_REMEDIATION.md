# Security remediation ledger

Tracks the findings from the 2026-05-30 full-codebase security audit
(`mythos`) through to closure. Each finding has a lane and a status so
nothing is silently dropped and every won't-fix carries a recorded
decision.

Severity is the audit severity. Reachability is the honest exploitation
context (this is a single-operator, internet-facing SSH honeypot). Lane
decides how the finding is handled.

Lanes:

- **hotfix** — remote, default-on, real impact. Fix first, on its own.
- **fix** — land test-first in the normal remediation batch.
- **feature-gated** — only reachable when an opt-in capability is
  enabled; fix before/with that feature, lower urgency.
- **spike** — fix approach is uncertain; investigate, then decide.
- **accept** — residual risk, document and do not fix. Needs operator
  sign-off (the `Decision` column records it).

## Ledger

| ID | Finding | Sev | Reachability | Lane | Status |
|----|---------|-----|--------------|------|--------|
| H1 | Per-IP limiter `_recent` map grows unbounded (memory DoS) | high | remote, unauth, **default-on** | hotfix | **closed** `f4610f0` |
| H2 | Zero-width / homoglyph bypass of the defense filters | high | remote, defense-in-depth layer | fix (zero-width+combining) / accept (homoglyph) | **closed** `da8c9cf` |
| H3 | HASSH fingerprint is a constant for every attacker | high (efficacy) | not a vuln; broken feature | spike done -> fix | **spike done, impl pending** |
| M1 | CSV formula injection in both CSV exports | medium | operator opens the file | fix | **closed** `cf8c673` |
| M2 | Per-session token-budget TOCTOU (concurrent overshoot) | medium | attacker pipelining; local GPU cost | fix-or-accept | open |
| M3 | Audit-tailer poison-pill (non-finite latency wedges sync) | medium | log replay / corruption, not live traffic | fix | **closed** `3ea0dac` |
| M4 | `X-Forwarded-For` spoofs audited `callback_source_ip` | medium | only with the public callback receiver deployed | feature-gated | open |
| M5 | Naive ISO `since` 500s three dashboard endpoints | medium | authed operator | fix | open |
| M6 | Bridge does not fail-closed on unexpected exceptions | medium | defense-in-depth robustness | fix | open |
| M7 | ReDoS in crontab persistence pattern + raw command to LLM | medium | only with `engaged_persistence` on | feature-gated | open |
| L1 | Wizard temp-file world-readable window | low | local race during first boot | fix | open |
| L2 | Username timing oracle in login | low | authed surface, rate-limited | fix | open |
| L3 | STIX pattern grammar injection | low | downstream TIP consumers | fix | open |
| L4 | Dead `truncated` audit branch on the output path | low | observability only (no leak) | fix | open |
| L5 | ReDoS in two T1059.004 technique regexes | low | scorer not on the request loop (latent) | fix | open |
| L6 | Geo archive decompression bomb | low | mirror compromise, off request path | fix | open |
| L7 | `csp-report` POST lacks `require_csrf` | low | mitigated by SameSite=Strict + caps | accept (doc) | open |
| L8 | fsync on the event loop for audit writes | low | flood on slow storage | accept-or-fix | open |

## Owner decisions required

These are not engineering calls; they need an operator sign-off and are
recorded here when made:

- **H2 homoglyph half.** NFKD + combining-mark/format stripping closes
  the zero-width, compatibility-form, combining-mark, and Latin-accent
  classes. Cross-script Cyrillic homoglyphs are not decomposable to
  Latin and need a confusables map. _Decision: accepted as a documented
  residual (THREAT_MODEL "Unicode evasion" row), closed in `da8c9cf`._
- **H3 HASSH.** Spike verdict: real data IS obtainable in asyncssh
  2.23.0 via the private `conn._client_kexinit` attribute (the raw
  KEXINIT payload), parsed with asyncssh's own `SSHPacket`; verified
  live against OpenSSH 10.0. Degrades gracefully (guarded -> no-HASSH on
  a future asyncssh change, never a crash). Effort small. _Decision
  pending: implement the private-attr fix (couples to an asyncssh
  internal) vs document HASSH unsupported and keep only `client_version`._
  The `hashes.py` separator-injection + non-ASCII-crash hardening is
  independent and should land regardless.
- **M2 budget race.** On a local single-GPU Ollama the "cost" is
  inference time, already bounded by the session rate limiter. Fix
  (reserve-then-reconcile) or accept-and-document the soft cap.
  _Decision: pending._
- **M4 callback trust.** Default `trusted_proxy_hops` and whether to
  derive the source IP from the socket peer. _Decision: pending._
- **L7 / L8.** Document-as-residual proposed for both. _Decision:
  pending._

## Process

Every fix lands as its own commit on `security/mythos-remediation`,
test-first (a regression test that fails before and passes after), green
at commit, with the AUDIT.md substage notes block. Each fix is
independently re-verified before it is marked closed. Class-level fixes
(shared CSV-escape helper, unicode normalization chokepoint, regex
timing guard) are preferred over per-instance patches so the class
cannot regress, with the bypass cases added to the permanent
`tests/llm_defense` corpus where applicable.
