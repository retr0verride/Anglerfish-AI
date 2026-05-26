"""Tests for the Stage 9 slice 1 :class:`PersonaRegistry`."""

from __future__ import annotations

from pathlib import Path

import pytest

from anglerfish.persona import PersonaRegistry
from anglerfish.persona.schema import (
    DEFAULT_PERSONA_NAME,
    Persona,
    PersonaLoadError,
)


def _persona(name: str, *, hostname: str | None = None) -> Persona:
    return Persona(
        name=name,
        description=f"Persona named {name}.",
        hostname=hostname or name,
        username="root",
        cwd="/root",
        prompt_block=f"This is the {name} persona.",
    )


def _write_persona_yaml(dir_path: Path, name: str, *, hostname: str = "h") -> None:
    body = f"""\
name: {name}
description: A persona named {name}.
hostname: {hostname}
username: root
cwd: /root
prompt_block: |
  This is the {name} persona.
"""
    (dir_path / f"{name}.yaml").write_text(body, encoding="utf-8")


# ---------------------------------------------------------------------------
# Direct constructor
# ---------------------------------------------------------------------------


def test_constructor_rejects_empty_mapping() -> None:
    with pytest.raises(ValueError, match="at least one persona"):
        PersonaRegistry({})


def test_constructor_rejects_unknown_default() -> None:
    with pytest.raises(ValueError, match="not present in registry"):
        PersonaRegistry({"example": _persona("example")}, default_name="ghost")


def test_constructor_default_name_used_on_default() -> None:
    registry = PersonaRegistry(
        {"example": _persona("example"), "other": _persona("other")},
        default_name="other",
    )
    assert registry.default().name == "other"


# ---------------------------------------------------------------------------
# Bundled personas
# ---------------------------------------------------------------------------


def test_load_bundled_personas_has_four_defaults() -> None:
    registry = PersonaRegistry.load()
    names = registry.names()
    for expected in (
        "forgotten-debian-box",
        "gpu-rig",
        "ad-joined-workstation",
        "dev-laptop",
    ):
        assert expected in names


def test_bundled_default_persona_is_forgotten_debian_box() -> None:
    registry = PersonaRegistry.load()
    assert registry.default().name == DEFAULT_PERSONA_NAME


def test_load_with_empty_bundled_dir_raises(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(PersonaLoadError, match="contained no YAML files"):
        PersonaRegistry.load(bundled_dir=empty)


def test_load_with_missing_override_dir_is_non_fatal(tmp_path: Path) -> None:
    """No override dir is the common case; should not warn or error."""
    bundled = tmp_path / "bundled"
    bundled.mkdir()
    _write_persona_yaml(bundled, "forgotten-debian-box")
    registry = PersonaRegistry.load(
        bundled_dir=bundled,
        override_dir=tmp_path / "does-not-exist",
    )
    assert registry.names() == ("forgotten-debian-box",)


def test_load_override_dir_adds_new_persona(tmp_path: Path) -> None:
    bundled = tmp_path / "bundled"
    override = tmp_path / "override"
    bundled.mkdir()
    override.mkdir()
    _write_persona_yaml(bundled, "forgotten-debian-box")
    _write_persona_yaml(override, "operator-custom")
    registry = PersonaRegistry.load(
        bundled_dir=bundled,
        override_dir=override,
    )
    assert "operator-custom" in registry
    assert "forgotten-debian-box" in registry


def test_load_override_dir_replaces_bundled_by_name(tmp_path: Path) -> None:
    bundled = tmp_path / "bundled"
    override = tmp_path / "override"
    bundled.mkdir()
    override.mkdir()
    _write_persona_yaml(bundled, "forgotten-debian-box", hostname="bundled-host")
    _write_persona_yaml(override, "forgotten-debian-box", hostname="override-host")
    registry = PersonaRegistry.load(
        bundled_dir=bundled,
        override_dir=override,
    )
    assert registry.get("forgotten-debian-box").hostname == "override-host"


def test_load_skips_invalid_override_logs_warning(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    bundled = tmp_path / "bundled"
    override = tmp_path / "override"
    bundled.mkdir()
    override.mkdir()
    _write_persona_yaml(bundled, "forgotten-debian-box")
    (override / "broken.yaml").write_text("name: [unterminated", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="anglerfish.persona.registry"):
        registry = PersonaRegistry.load(
            bundled_dir=bundled,
            override_dir=override,
        )
    assert "forgotten-debian-box" in registry
    assert any("failed to load" in r.message for r in caplog.records)


def test_load_failing_bundled_raises(tmp_path: Path) -> None:
    """Bundled persona failures are not skipped; they abort the load."""
    bundled = tmp_path / "bundled"
    bundled.mkdir()
    (bundled / "broken.yaml").write_text("name: [unterminated", encoding="utf-8")
    with pytest.raises(PersonaLoadError):
        PersonaRegistry.load(bundled_dir=bundled)


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------


def test_get_returns_persona() -> None:
    registry = PersonaRegistry.load()
    persona = registry.get("gpu-rig")
    assert persona.hostname == "gpu-rig-04"


def test_get_unknown_raises_keyerror() -> None:
    registry = PersonaRegistry.load()
    with pytest.raises(KeyError):
        registry.get("does-not-exist")


def test_get_or_default_falls_back_for_unknown() -> None:
    registry = PersonaRegistry.load()
    persona = registry.get_or_default("does-not-exist")
    assert persona.name == DEFAULT_PERSONA_NAME


def test_get_or_default_falls_back_for_none() -> None:
    registry = PersonaRegistry.load()
    persona = registry.get_or_default(None)
    assert persona.name == DEFAULT_PERSONA_NAME


def test_get_or_default_returns_named_when_present() -> None:
    registry = PersonaRegistry.load()
    persona = registry.get_or_default("dev-laptop")
    assert persona.name == "dev-laptop"


def test_contains_protocol() -> None:
    registry = PersonaRegistry.load()
    assert "gpu-rig" in registry
    assert "ghost" not in registry
    assert 42 not in registry  # non-string is False, not error


def test_len() -> None:
    registry = PersonaRegistry.load()
    assert len(registry) == 4


def test_names_returns_sorted_tuple() -> None:
    registry = PersonaRegistry.load()
    names = registry.names()
    assert names == tuple(sorted(names))
