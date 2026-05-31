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
| H3 | HASSH fingerprint is a constant for every attacker | high (efficacy) | not a vuln; broken feature | fix | **closed** `f2edd33` + `970c09b` |
| M1 | CSV formula injection in both CSV exports | medium | operator opens the file | fix | **closed** `cf8c673` |
| M2 | Per-session token-budget TOCTOU (concurrent overshoot) | medium | attacker pipelining; local GPU cost | fix | **closed** `63ec3d1` |
| M3 | Audit-tailer poison-pill (non-finite latency wedges sync) | medium | log replay / corruption, not live traffic | fix | **closed** `3ea0dac` |
| M4 | `X-Forwarded-For` spoofs audited `callback_source_ip` | medium | only with the public callback receiver deployed | fix | **closed** `f45f9f0` |
| M5 | Naive ISO `since` 500s three dashboard endpoints | medium | authed operator | fix | **closed** `ea6d8de` |
| M6 | Bridge does not fail-closed on unexpected exceptions | medium | defense-in-depth robustness | fix | **closed** `a1a28b4` |
| M7 | ReDoS in crontab persistence pattern + raw command to LLM | medium | only with `engaged_persistence` on | fix | **closed** `fa524e1` (+H3a `f2edd33`, H3b `970c09b`) |
| L1 | Wizard temp-file world-readable window | low | local race during first boot | fix | **closed** `ea679c4` |
| L2 | Username timing oracle in login | low | authed surface, rate-limited | fix | **closed** `f4b52eb` |
| L3 | STIX pattern grammar injection | low | downstream TIP consumers | fix | **closed** `dc3d728` |
| L4 | Dead `truncated` audit branch on the output path | low | observability only (no leak) | fix | **closed** `fc4b00d` |
| L5 | ReDoS in two T1059.004 technique regexes | low | scorer not on the request loop (latent) | fix | **closed** `525c6fe` |
| L6 | Geo archive decompression bomb | low | mirror compromise, off request path | fix | **closed** `7571398` |
| L7 | `csp-report` POST lacks `require_csrf` | low | mitigated by SameSite=Strict + caps | accept (doc) | **documented** `9eed303` |
| L8 | fsync on the event loop for audit writes | low | flood on slow storage | accept (doc) | **documented** `9eed303` |

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
- **M2 budget race.** _Decision: fixed (per-budget asyncio.Lock
  serialises the shared-budget check..consume), closed in `63ec3d1`. The
  inherent single-call boundary overshoot is out of scope._
- **M4 callback trust.** _Decision: fixed - record the connection peer,
  not the raw header; behind a proxy the operator sets uvicorn
  proxy_headers + forwarded_allow_ips. Closed in `f45f9f0`._
- **L7 csp-report CSRF.** _Decision: accepted as a documented residual.
  The browser sends CSP reports automatically and cannot attach the
  `X-Anglerfish-CSRF` header, so `require_csrf` would disable the
  tripwire. `SameSite=Strict` blocks the cross-site cookie; a forged
  same-origin POST appends only one capped, fixed-field, operator-visible
  row. Documented at the route and in THREAT_MODEL; closed in `9eed303`._
- **L8 fsync on the loop.** _Decision: accepted as a documented residual.
  Per-event durability and strict append ordering are the audit log's
  contract (the `chattr +a` tamper-evidence relies on in-order,
  un-batched writes). Audit volume is security events, not per-packet, so
  the loop stall is bounded; offloading would trade the guarantee for
  unneeded throughput. Documented at the write site and in THREAT_MODEL
  Known-limitations; closed in `9eed303`._

## Outcome

All audit findings are closed: H1-H3 and M1-M7 fixed and independently
re-verified, L1-L6 fixed test-first, L7-L8 accepted with recorded
rationale. Branch `security/mythos-remediation` (PR #9). The full suite
is green (1991 passed, 1 skipped) and coverage holds above the 90 % gate.

## Process

Every fix lands as its own commit on `security/mythos-remediation`,
test-first (a regression test that fails before and passes after), green
at commit, with the AUDIT.md substage notes block. Each fix is
independently re-verified before it is marked closed. Class-level fixes
(shared CSV-escape helper, unicode normalization chokepoint, regex
timing guard) are preferred over per-instance patches so the class
cannot regress, with the bypass cases added to the permanent
`tests/llm_defense` corpus where applicable.
