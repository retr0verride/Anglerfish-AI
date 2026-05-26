"""Pydantic model + YAML loader for a single :class:`Persona`.

A persona is one named environment template the bridge serves to
an attacker session. Fields map 1:1 to what slices 9.2/9.3 read
at session-open:

* :attr:`Persona.hostname` / :attr:`Persona.username` /
  :attr:`Persona.cwd` replace the bridge's ``fake_*`` defaults
  in :class:`anglerfish.bridge.session.SessionContext`.
* :attr:`Persona.prompt_block` is appended to the bridge
  system prompt's "Server facts" section.
* :attr:`Persona.fakefs_overlay` is a flat ``path -> content``
  dict the lure's fakefs consults before its static base
  table.

YAML loading uses ``yaml.safe_load`` exclusively. The full-form
``yaml.load`` (which executes ``!!python/object``) is the v1
attack-surface concern flagged in the Stage 9 threat-model
delta; a deliberate import-time check would catch a future
refactor that swaps loaders without thinking.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

__all__ = [
    "DEFAULT_PERSONA_NAME",
    "Persona",
    "PersonaLoadError",
    "load_persona_yaml",
]


DEFAULT_PERSONA_NAME = "forgotten-debian-box"
"""Persona returned by :meth:`PersonaRegistry.default` when no
operator override sets a different default. Locked to the
generic Debian box because it is the least specific of the four
bundled personas, so an attacker who lands on it before the
selector has any signal sees the same baseline every Stage 8
session saw before this stage shipped.
"""


class PersonaLoadError(Exception):
    """Raised when a YAML file cannot be parsed into a :class:`Persona`.

    Surfaces with a path-prefixed message so the operator can
    grep the audit log straight to the offending file. The
    registry catches this at startup and converts it to a clear
    fail-fast error for bundled files; override-dir failures log
    + skip the file so one bad override does not take down the
    whole registry.
    """


class Persona(BaseModel):
    """One named environment template loaded from YAML.

    Constructed by :func:`load_persona_yaml`; never instantiated
    directly outside tests. Frozen so the registry can hand the
    same instance to every session safely.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9-]+$",
        description=(
            "Registry key + audit-event value. ASCII lowercase + dash so "
            "it lands cleanly in JSON logs, URL paths, and the source-IP "
            "pin endpoint."
        ),
    )
    description: str = Field(
        min_length=1,
        max_length=512,
        description="One-line operator-facing description shown in the dashboard.",
    )
    hostname: str = Field(
        min_length=1,
        max_length=63,
        description=(
            "Replaces BridgeConfig.fake_hostname for sessions assigned "
            "this persona. RFC 1123 hostname-label cap (63 chars)."
        ),
    )
    username: str = Field(
        min_length=1,
        max_length=32,
        description="Replaces BridgeConfig.fake_username; 32-char POSIX cap.",
    )
    cwd: str = Field(
        min_length=1,
        max_length=4096,
        description="Replaces BridgeConfig.fake_cwd. Must be absolute.",
    )
    prompt_block: str = Field(
        min_length=1,
        max_length=2048,
        description=(
            "Free-text paragraph appended to the bridge system prompt's "
            "'Server facts' section. 2 KB cap keeps a runaway YAML from "
            "blowing the prompt budget."
        ),
    )
    fakefs_overlay: dict[str, str] = Field(
        default_factory=dict,
        max_length=64,
        description=(
            "Flat path -> content dict. The lure's fakefs consults this "
            "before falling through to the static base table. 64-key cap "
            "matches 'a handful of paths' - this is not a shadow "
            "filesystem; whole-tree overlays wait for Stage 13."
        ),
    )

    def model_post_init(self, _context: object) -> None:
        if not self.cwd.startswith("/"):
            raise ValueError(
                f"Persona.cwd must be absolute (starts with /), got {self.cwd!r}",
            )
        for path in self.fakefs_overlay:
            if not path.startswith("/"):
                raise ValueError(
                    f"Persona.fakefs_overlay keys must be absolute paths; got {path!r}",
                )


def load_persona_yaml(path: Path) -> Persona:
    """Parse one persona YAML file from disk.

    Raises :class:`PersonaLoadError` on any failure path:

    * file missing / unreadable;
    * YAML parse error;
    * payload is not a mapping;
    * Pydantic validation rejects a field.

    Always passes the parsed payload through ``yaml.safe_load``;
    the full-form ``yaml.load`` is explicitly never called.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PersonaLoadError(f"{path}: cannot read ({exc})") from exc
    try:
        payload = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise PersonaLoadError(f"{path}: YAML parse error ({exc})") from exc
    if not isinstance(payload, dict):
        raise PersonaLoadError(
            f"{path}: top-level YAML must be a mapping, got {type(payload).__name__}",
        )
    try:
        return Persona(**payload)
    except ValidationError as exc:
        raise PersonaLoadError(f"{path}: schema validation failed: {exc}") from exc
