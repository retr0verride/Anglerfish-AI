"""Named environment templates served per attacker session (Stage 9).

The persona package owns the data model + loader + in-process
registry for the four bundled personas (forgotten-debian-box,
gpu-rig, ad-joined-workstation, dev-laptop) and any operator
overrides dropped into ``settings.persona.config_dir``. Selection
logic + bridge plumbing lands in slice 9.2; lure overlay in
slice 9.3; dashboard pin + cluster-bias rebound in slice 9.4.

Per the locked Stage 9 design
(``docs/design/STAGE_9_adaptive_persona.md``):

* ``yaml.safe_load`` is the parser; ``yaml.load`` is forbidden.
* Bundled personas live under ``personas/`` next to this file.
* Override dir augments + replaces by name; missing override
  dir is debug-log + skip, not an error.
* Pydantic length caps + name pattern enforce the boundary the
  threat-model delta documents (operator-trusted YAML that
  still cannot blow the prompt budget).
"""

from __future__ import annotations

from anglerfish.persona.registry import PersonaRegistry
from anglerfish.persona.schema import (
    DEFAULT_PERSONA_NAME,
    Persona,
    PersonaLoadError,
    load_persona_yaml,
)

__all__ = [
    "DEFAULT_PERSONA_NAME",
    "Persona",
    "PersonaLoadError",
    "PersonaRegistry",
    "load_persona_yaml",
]
