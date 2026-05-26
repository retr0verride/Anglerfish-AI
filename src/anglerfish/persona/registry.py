"""In-process registry of loaded :class:`Persona` instances.

The registry is constructed at bridge startup (slice 9.2) with a
bundled-personas directory (always present, ships with the
package) and an optional operator override directory. Lookups
are O(1) and the registry is treated as immutable after
construction. Failing fast on bundled-persona errors and
logging-and-skipping override-persona errors keeps the
operator-trusted vs. operator-customised split honest.
"""

from __future__ import annotations

import logging
from pathlib import Path

from anglerfish.persona.schema import (
    DEFAULT_PERSONA_NAME,
    Persona,
    PersonaLoadError,
    load_persona_yaml,
)

__all__ = ["PersonaRegistry"]


_logger = logging.getLogger(__name__)


# Where the bundled YAML files live, resolved relative to this
# module so a wheel install + an editable install both find the
# right path. Kept as a module-level constant rather than a class
# attribute so tests can monkeypatch it if needed.
_BUNDLED_DIR_DEFAULT = Path(__file__).parent / "personas"


class PersonaRegistry:
    """Immutable name -> :class:`Persona` mapping.

    Construct via :meth:`load`; the constructor takes a fully-
    materialised dict so tests can build registries inline
    without touching the filesystem.
    """

    def __init__(
        self,
        personas: dict[str, Persona],
        *,
        default_name: str = DEFAULT_PERSONA_NAME,
    ) -> None:
        if not personas:
            raise ValueError(
                "PersonaRegistry requires at least one persona; got empty mapping",
            )
        if default_name not in personas:
            raise ValueError(
                f"default_name={default_name!r} not present in registry (have: {sorted(personas)})",
            )
        self._personas = dict(personas)
        self._default_name = default_name

    @classmethod
    def load(
        cls,
        *,
        bundled_dir: Path | None = None,
        override_dir: Path | None = None,
        default_name: str = DEFAULT_PERSONA_NAME,
    ) -> PersonaRegistry:
        """Load bundled + override directories and build the registry.

        ``bundled_dir`` defaults to the package's ``personas/``
        directory. Every YAML file inside must parse - a bundled
        failure raises :class:`PersonaLoadError`; that aborts
        bridge startup, which is correct posture for a tampered
        ship.

        ``override_dir`` is optional. A missing override dir is a
        debug log + skip; an unreadable file or invalid YAML
        inside the override dir is a warning + skip so one bad
        override does not take down the whole registry.

        Same-name YAML in the override dir replaces the bundled
        entry; new names extend the registry.
        """
        bundled = bundled_dir if bundled_dir is not None else _BUNDLED_DIR_DEFAULT
        personas: dict[str, Persona] = {}
        for path in sorted(bundled.glob("*.yaml")):
            persona = load_persona_yaml(path)
            personas[persona.name] = persona
        if not personas:
            raise PersonaLoadError(
                f"bundled persona dir {bundled} contained no YAML files; package install is broken",
            )
        if override_dir is None or not override_dir.is_dir():
            if override_dir is not None:
                _logger.debug(
                    "persona override dir %s is not a directory; skipping",
                    override_dir,
                )
            return cls(personas, default_name=default_name)
        for path in sorted(override_dir.glob("*.yaml")):
            try:
                persona = load_persona_yaml(path)
            except PersonaLoadError as exc:
                _logger.warning(
                    "persona override %s failed to load: %s; skipping",
                    path,
                    exc,
                )
                continue
            personas[persona.name] = persona
        return cls(personas, default_name=default_name)

    def get(self, name: str) -> Persona:
        """Return the persona keyed by ``name``; raise KeyError if absent."""
        return self._personas[name]

    def get_or_default(self, name: str | None) -> Persona:
        """Return ``name``'s persona, falling back to the default on miss.

        Used by the selector when a source-IP recurrence query
        returns a persona name that the operator has since
        deleted from the registry. Returning the default keeps
        the session-open path total over the persona surface.
        """
        if name is None:
            return self.default()
        return self._personas.get(name) or self.default()

    def default(self) -> Persona:
        """Return the persona used when selection has no other signal."""
        return self._personas[self._default_name]

    def names(self) -> tuple[str, ...]:
        """Sorted tuple of every registered persona name."""
        return tuple(sorted(self._personas))

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._personas

    def __len__(self) -> int:
        return len(self._personas)
