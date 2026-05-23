"""First-boot configuration wizard.

Public surface:

* :func:`run_wizard` — pure-function core. Takes a :class:`WizardAnswers`,
  writes every artefact (env, nftables, cowrie.cfg, systemd-networkd,
  hostname, authorized_keys, answers.json), and returns a
  :class:`WizardOutput`.
* :func:`prompt_for_answers` — builds a :class:`WizardAnswers` from
  interactive prompts. Accepts injectable prompt/confirm callables so
  the prompt surface is testable without stdin pumping.
* :class:`WizardPaths` — resolves every output path off a single base
  directory. Tests construct one rooted at ``tmp_path``.
* :class:`TermsDeclinedError` — raised when the operator declines the
  responsible-use terms.
* :class:`PreflightChecker`, :func:`check_ollama` etc. — reachability
  checks used before the wizard commits.
* :func:`save_answers`, :func:`load_answers` — JSON persistence used by
  ``anglerfish-wizard --reconfigure``.
* Render helpers (``render_env``, ``render_nftables``, etc.) for tests
  and external tooling.
"""

from __future__ import annotations

from anglerfish.wizard.answers import NetworkConfig, WizardAnswers, WizardOutput
from anglerfish.wizard.persistence import (
    DEFAULT_ANSWERS_PATH,
    load_answers,
    save_answers,
)
from anglerfish.wizard.preflight import (
    CheckResult,
    PreflightChecker,
    check_ollama,
    check_splunk_hec,
    check_webhook,
)
from anglerfish.wizard.render import (
    render_authorized_keys,
    render_cowrie_cfg,
    render_env,
    render_hostname_files,
    render_nftables,
    render_systemd_network,
)
from anglerfish.wizard.secrets import (
    generate_bridge_secret,
    generate_encryption_key,
    generate_session_secret,
)
from anglerfish.wizard.sshkey import SshPubKey, SshPubKeyError, parse_ssh_pubkey
from anglerfish.wizard.terms import TERMS
from anglerfish.wizard.wizard import (
    TermsDeclinedError,
    WizardPaths,
    prompt_for_answers,
    run_wizard,
)

__all__ = [
    "DEFAULT_ANSWERS_PATH",
    "TERMS",
    "CheckResult",
    "NetworkConfig",
    "PreflightChecker",
    "SshPubKey",
    "SshPubKeyError",
    "TermsDeclinedError",
    "WizardAnswers",
    "WizardOutput",
    "WizardPaths",
    "check_ollama",
    "check_splunk_hec",
    "check_webhook",
    "generate_bridge_secret",
    "generate_encryption_key",
    "generate_session_secret",
    "load_answers",
    "parse_ssh_pubkey",
    "prompt_for_answers",
    "render_authorized_keys",
    "render_cowrie_cfg",
    "render_env",
    "render_hostname_files",
    "render_nftables",
    "render_systemd_network",
    "run_wizard",
    "save_answers",
]
