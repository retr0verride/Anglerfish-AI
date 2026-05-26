"""Tests for the Stage 9 slice 1 :class:`Persona` schema + YAML loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from anglerfish.persona.schema import (
    DEFAULT_PERSONA_NAME,
    Persona,
    PersonaLoadError,
    load_persona_yaml,
)


def _write_yaml(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def _valid_yaml() -> str:
    return """\
name: test-persona
description: A persona used in tests.
hostname: test-host
username: test
cwd: /home/test
prompt_block: |
  This is a test persona used in tests.
fakefs_overlay:
  /etc/hostname: |
    test-host
"""


# ---------------------------------------------------------------------------
# Persona model
# ---------------------------------------------------------------------------


def test_default_persona_name_is_forgotten_debian_box() -> None:
    assert DEFAULT_PERSONA_NAME == "forgotten-debian-box"


def test_persona_round_trips_minimal_fields() -> None:
    persona = Persona(
        name="example",
        description="A persona.",
        hostname="host",
        username="root",
        cwd="/root",
        prompt_block="A block.",
    )
    assert persona.name == "example"
    assert persona.fakefs_overlay == {}


def test_persona_name_rejects_uppercase() -> None:
    with pytest.raises(ValueError, match=r"string_pattern_mismatch|pattern"):
        Persona(
            name="Example",
            description="x",
            hostname="h",
            username="u",
            cwd="/r",
            prompt_block="b",
        )


def test_persona_name_rejects_spaces() -> None:
    with pytest.raises(ValueError, match="pattern"):
        Persona(
            name="bad name",
            description="x",
            hostname="h",
            username="u",
            cwd="/r",
            prompt_block="b",
        )


def test_persona_prompt_block_length_cap_enforced() -> None:
    with pytest.raises(ValueError, match="at most 2048"):
        Persona(
            name="example",
            description="x",
            hostname="h",
            username="u",
            cwd="/r",
            prompt_block="x" * 2049,
        )


def test_persona_fakefs_overlay_key_count_capped() -> None:
    overlay = {f"/path/{i}": "x" for i in range(65)}
    with pytest.raises(ValueError, match="at most 64"):
        Persona(
            name="example",
            description="x",
            hostname="h",
            username="u",
            cwd="/r",
            prompt_block="b",
            fakefs_overlay=overlay,
        )


def test_persona_cwd_must_be_absolute() -> None:
    with pytest.raises(ValueError, match="must be absolute"):
        Persona(
            name="example",
            description="x",
            hostname="h",
            username="u",
            cwd="relative/path",
            prompt_block="b",
        )


def test_persona_fakefs_overlay_keys_must_be_absolute() -> None:
    with pytest.raises(ValueError, match="must be absolute"):
        Persona(
            name="example",
            description="x",
            hostname="h",
            username="u",
            cwd="/r",
            prompt_block="b",
            fakefs_overlay={"etc/hostname": "test"},
        )


def test_persona_rejects_extra_fields() -> None:
    with pytest.raises(ValueError, match=r"extra_forbidden|not permitted|extra inputs"):
        Persona(
            name="example",
            description="x",
            hostname="h",
            username="u",
            cwd="/r",
            prompt_block="b",
            unexpected="value",  # type: ignore[call-arg]
        )


def test_persona_is_frozen() -> None:
    persona = Persona(
        name="example",
        description="x",
        hostname="h",
        username="u",
        cwd="/r",
        prompt_block="b",
    )
    with pytest.raises(ValueError, match="frozen"):
        persona.name = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# load_persona_yaml
# ---------------------------------------------------------------------------


def test_load_persona_yaml_round_trip(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path / "test.yaml", _valid_yaml())
    persona = load_persona_yaml(path)
    assert persona.name == "test-persona"
    assert "/etc/hostname" in persona.fakefs_overlay


def test_load_persona_yaml_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(PersonaLoadError, match="cannot read"):
        load_persona_yaml(tmp_path / "missing.yaml")


def test_load_persona_yaml_invalid_yaml_raises(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path / "broken.yaml", "name: [unterminated")
    with pytest.raises(PersonaLoadError, match="YAML parse error"):
        load_persona_yaml(path)


def test_load_persona_yaml_top_level_list_rejected(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path / "list.yaml", "- name: example")
    with pytest.raises(PersonaLoadError, match="must be a mapping"):
        load_persona_yaml(path)


def test_load_persona_yaml_schema_violation_raises(tmp_path: Path) -> None:
    path = _write_yaml(
        tmp_path / "bad.yaml",
        # name missing required 'description' field
        "name: example\nhostname: h\nusername: u\ncwd: /r\nprompt_block: b\n",
    )
    with pytest.raises(PersonaLoadError, match="schema validation failed"):
        load_persona_yaml(path)


def test_load_persona_yaml_does_not_execute_python_tags(tmp_path: Path) -> None:
    """yaml.safe_load must reject !!python/object tags."""
    malicious = (
        "name: !!python/object/apply:os.system ['echo pwned']\n"
        "description: x\nhostname: h\nusername: u\ncwd: /r\nprompt_block: b\n"
    )
    path = _write_yaml(tmp_path / "evil.yaml", malicious)
    with pytest.raises(PersonaLoadError):
        load_persona_yaml(path)
