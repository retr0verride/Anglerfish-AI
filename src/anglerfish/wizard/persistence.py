"""Save / load :class:`WizardAnswers` to disk for ``--reconfigure``.

The wizard writes ``/etc/anglerfish/wizard.json`` (mode 0600) after a
successful run. ``anglerfish-wizard --reconfigure`` reads it back and
uses the values as defaults in the interactive prompts.

The file excludes the values the wizard regenerates run-to-run:
the bridge shared secret, the dashboard session secret, and the
credentials encryption key. It does retain the dashboard
admin-password bcrypt hash and the MaxMind licence key so
``--reconfigure`` can offer "blank to keep" semantics. The file
is written 0600 (root-owned in production); see TODO-7 for the
SecretStr-vs-round-trip trade-off that prevents Pydantic
SecretStr typing here. Operators using ``--reconfigure`` should
restart the bridge, the lure, and the dashboard afterwards.
"""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path

from anglerfish.wizard.answers import WizardAnswers

__all__ = ["DEFAULT_ANSWERS_PATH", "load_answers", "save_answers"]


DEFAULT_ANSWERS_PATH = Path("/etc/anglerfish/wizard.json")


def save_answers(answers: WizardAnswers, path: Path) -> None:
    """Write ``answers`` to ``path`` atomically with mode 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = answers.model_dump(mode="json")
    serialised = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(serialised, encoding="utf-8")
    with contextlib.suppress(OSError):
        os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)


def load_answers(path: Path) -> WizardAnswers | None:
    """Return a :class:`WizardAnswers` loaded from ``path``, or :data:`None`.

    Returns :data:`None` when the file is absent. Raises :class:`ValueError`
    on malformed content so the caller can surface a clear error to the
    operator rather than silently start from scratch.
    """
    if not path.exists():
        return None
    try:
        raw = path.read_text(encoding="utf-8")
        payload = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"failed to read {path}: {exc}") from exc
    return WizardAnswers.model_validate(payload)
