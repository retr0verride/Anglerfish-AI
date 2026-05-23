# Cowrie patches

Anglerfish AI ships **two equivalent ways** to wire the bridge into
Cowrie's shell. Pick one:

| Method | Where it lives | When it applies |
|---|---|---|
| **Runtime monkey-patch** (default) | `anglerfish.integration.cowrie_shell_adapter.install()` | Called from the Anglerfish Cowrie output plugin at Cowrie startup. No edits to Cowrie's source. Survives Cowrie upgrades. Test-friendly. |
| **Source patch** (auditable) | `0001-anglerfish-shell.patch` | Apply with `git apply` against a Cowrie checkout. Persists in Cowrie's source tree. Easier to review during a security audit. |

The ISO build applies **both**: the output plugin installs the
monkey-patch on first event; the patch is also present in `/opt/cowrie/`
so a security auditor can confirm what's running by reading Cowrie's
source.

## Verifying the patch applies cleanly

Cowrie v2.5.0 is the pinned baseline:

```bash
git clone --depth=1 --branch v2.5.0 https://github.com/cowrie/cowrie.git /tmp/cowrie
cd /tmp/cowrie
git apply --check /path/to/0001-anglerfish-shell.patch
```

If `--check` reports rejected hunks, Cowrie's `honeypot.py` has drifted.
Two options:

1. Use the runtime monkey-patch only (skip the source patch) — it works
   regardless of Cowrie's exact line numbers, because it reads
   `HoneyPotShell.lineReceived` dynamically.
2. Re-roll the patch for the new Cowrie revision and bump the pinned
   tag in `iso/config/hooks/normal/0030-install-cowrie.hook.chroot`.

## Why both?

The runtime monkey-patch is what actually wires the bridge in production.
The source patch is a transparency artefact for operators who want to
prove what's running by reading code, not by trusting our `install()`
function. Both routes call the same `_patched_line_received` function
inside `anglerfish.integration.cowrie_shell_adapter`, so behaviour is
identical.
