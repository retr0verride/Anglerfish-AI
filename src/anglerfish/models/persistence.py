"""Shared data model for Stage 10 engaged-persistence events.

The bridge's :class:`PersistenceClassifier` produces a
:class:`PersistenceEvent` whenever an attacker command installs a
persistence mechanism (cron entry, systemd unit, SSH authorized
key). The dashboard audit-tailer reads
``bridge.persistence_attempt`` events and upserts the payload into
the ``fake_persistence_state`` table; subsequent sessions from the
same source IP see the install reflected in their fakefs overlay
and bridge fs_context.

Kept in :mod:`anglerfish.models` so the bridge classifier, the
audit-tailer parser, the SessionStore CRUD, and the dashboard
read endpoint all reference the same type.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["PersistenceEvent", "PersistenceKind", "PersistenceSource"]


PersistenceKind = Literal["crontab", "systemctl", "authorized_keys"]
"""Which persistence subsystem the attacker installed against.

* ``crontab`` - scheduled-job edits (``crontab -e``,
  ``echo ... | crontab -``, writes to ``/etc/cron.d/*``).
* ``systemctl`` - systemd unit install or enable
  (``systemctl enable <unit>``, writes to
  ``/etc/systemd/system/<unit>.service``).
* ``authorized_keys`` - SSH key appended to a user's
  ``authorized_keys`` file.

Process-list / useradd / arbitrary file persistence are
explicitly deferred to a future stage per the Stage 10 design
"Out of scope" section.
"""

PersistenceSource = Literal["regex", "llm"]
"""How the classifier reached the verdict.

Useful for the operator and the test harness to distinguish
high-confidence regex matches from LLM-classifier guesses.
"""


class PersistenceEvent(BaseModel):
    """One detected persistence-installation attempt.

    Constructed by :class:`PersistenceClassifier`; persisted via
    the audit log into ``fake_persistence_state``. The
    ``payload`` field is the verbatim text the attacker
    installed (cron line, systemd unit content, SSH public key);
    operators see it on the dashboard for triage.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: PersistenceKind
    sub_key: str | None = Field(
        default=None,
        max_length=256,
        description=(
            "Optional second-level key for the persistence event. "
            "For ``systemctl`` it is the unit name. For ``crontab`` "
            "it is the target user (None means current user). For "
            "``authorized_keys`` it is the target user's home "
            "(None means current user). Allows the operator to see "
            "multiple distinct installs of the same kind."
        ),
    )
    payload: str = Field(
        min_length=1,
        max_length=4096,
        description=(
            "Verbatim text the attacker installed. Cron line for "
            "``crontab``, unit content (or just the unit name when "
            "enabling a pre-existing unit) for ``systemctl``, the "
            "SSH key for ``authorized_keys``. 4 KB cap matches "
            "CommandRequest.fs_context's pydantic bound; the "
            "audit-tailer truncates beyond this when persisting."
        ),
    )
    source: PersistenceSource
