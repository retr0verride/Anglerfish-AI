## Summary

<!-- One paragraph: what changes, why. Link the related issue if any. -->

## Changes

-
-
-

## Gates (CI re-runs these — confirm they pass locally first)

- [ ] `ruff check .`
- [ ] `ruff format --check .`
- [ ] `mypy`
- [ ] `pytest` (coverage ≥ 90 %)
- [ ] `pip-audit --skip-editable --strict`
- [ ] `bandit -r src/anglerfish/ -c pyproject.toml`

## Security review

<!--
If this PR touches:
  - the bridge endpoint, prompt template, sanitiser, or rate limiter
  - the credentials encryption / fingerprinting code
  - the forwarder, HEC client, or dashboard authentication
  - the wizard's secret-generation or .env writer
  - the nftables ruleset or systemd unit hardening
…fill in the box below. Otherwise delete this section.
-->

- **What's now newly trusted?** _e.g. "the dashboard now reads from a new on-disk file"_
- **How is that trust bounded?** _e.g. "path is normalised against the data dir, file mode is 0600"_
- **Adversary thinking:** _what could a compromised honeypot do with this change that it couldn't before?_

## Tests added / updated

-
-

## Documentation

- [ ] README updated where applicable
- [ ] `docs/RUNBOOK.md` updated if operator-facing behaviour changed
- [ ] `docs/THREAT_MODEL.md` updated if trust boundaries changed
- [ ] N/A — code-only change

## Deployment impact

<!-- Does this require a config migration, key rotation, ISO rebuild, or service restart sequence? -->
