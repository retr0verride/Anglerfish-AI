"""Tests for :mod:`anglerfish.wizard.persistence`."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from pydantic import HttpUrl

from anglerfish.wizard import NetworkConfig, WizardAnswers
from anglerfish.wizard.persistence import (
    DEFAULT_ANSWERS_PATH,
    load_answers,
    save_answers,
)


def _answers(**overrides: object) -> WizardAnswers:
    base: dict[str, object] = {
        "terms_acknowledged": True,
        "bait_interface": "eth0",
        "service_interface": "eth1",
        "ollama_endpoint": HttpUrl("http://127.0.0.1:11434/"),
        "ollama_model": "qwen3:14b",
        "fake_hostname": "srv-prod-01",
        "fake_username": "root",
    }
    base.update(overrides)
    return WizardAnswers(**base)  # type: ignore[arg-type]


def test_default_answers_path_constant() -> None:
    assert DEFAULT_ANSWERS_PATH.as_posix() == "/etc/anglerfish/wizard.json"


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    target = tmp_path / "wizard.json"
    original = _answers()
    save_answers(original, target)
    loaded = load_answers(target)
    assert loaded == original


def test_save_creates_parent_dirs(tmp_path: Path) -> None:
    target = tmp_path / "deep" / "nested" / "wizard.json"
    save_answers(_answers(), target)
    assert target.exists()


def test_save_writes_pretty_json(tmp_path: Path) -> None:
    target = tmp_path / "wizard.json"
    save_answers(_answers(), target)
    content = target.read_text("utf-8")
    # Indented + trailing newline.
    assert content.endswith("\n")
    parsed = json.loads(content)
    assert parsed["bait_interface"] == "eth0"


def test_load_missing_file_returns_none(tmp_path: Path) -> None:
    assert load_answers(tmp_path / "absent.json") is None


def test_load_malformed_json_raises(tmp_path: Path) -> None:
    target = tmp_path / "wizard.json"
    target.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ValueError, match="failed to read"):
        load_answers(target)


def test_load_invalid_schema_raises_validation_error(tmp_path: Path) -> None:
    from pydantic import ValidationError

    target = tmp_path / "wizard.json"
    target.write_text(json.dumps({"terms_acknowledged": True}), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_answers(target)


def test_save_preserves_network_config(tmp_path: Path) -> None:
    import ipaddress

    answers = _answers(
        bait_network=NetworkConfig(
            dhcp=False,
            address="10.0.0.5/24",
            gateway=ipaddress.ip_address("10.0.0.1"),
            dns=(ipaddress.ip_address("1.1.1.1"),),
        ),
    )
    target = tmp_path / "wizard.json"
    save_answers(answers, target)
    loaded = load_answers(target)
    assert loaded is not None
    assert loaded.bait_network.dhcp is False
    assert loaded.bait_network.address == "10.0.0.5/24"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission semantics")
def test_save_writes_with_0600(tmp_path: Path) -> None:
    target = tmp_path / "wizard.json"
    save_answers(_answers(), target)
    mode = target.stat().st_mode & 0o777
    assert mode == 0o600


def test_save_overwrites_existing(tmp_path: Path) -> None:
    target = tmp_path / "wizard.json"
    save_answers(_answers(bait_interface="eth0"), target)
    save_answers(_answers(bait_interface="ens1"), target)
    loaded = load_answers(target)
    assert loaded is not None
    assert loaded.bait_interface == "ens1"


# ---------------------------------------------------------------------------
# Pre-deploy sweep TODO-7: SecretStr round-trip + repr masking
# ---------------------------------------------------------------------------


def test_secret_fields_round_trip_plaintext_through_save_and_load(
    tmp_path: Path,
) -> None:
    """The bcrypt hash + MaxMind licence key survive save/load with their
    plaintext intact. The custom @field_serializer unwraps the SecretStr
    before JSON emit so ``--reconfigure`` reads back the actual hash, not
    pydantic's masked ``"**********"`` literal.
    """
    from pydantic import SecretStr

    bcrypt_hash = "$2b$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234"
    license_key = "ABCDEFGH12345678"  # not a real credential
    original = _answers(
        dashboard_admin_password_hash=SecretStr(bcrypt_hash),
        maxmind_license_key=SecretStr(license_key),
    )
    target = tmp_path / "wizard.json"
    save_answers(original, target)

    # Plaintext written to disk (the file is 0600 + root-owned in
    # production; this is the existing trust boundary).
    on_disk = json.loads(target.read_text("utf-8"))
    assert on_disk["dashboard_admin_password_hash"] == bcrypt_hash
    assert on_disk["maxmind_license_key"] == license_key
    # The default pydantic masked literal MUST NOT appear.
    assert "**********" not in target.read_text("utf-8")

    loaded = load_answers(target)
    assert loaded is not None
    assert loaded.dashboard_admin_password_hash is not None
    assert loaded.maxmind_license_key is not None
    assert loaded.dashboard_admin_password_hash.get_secret_value() == bcrypt_hash
    assert loaded.maxmind_license_key.get_secret_value() == license_key


def test_secret_fields_repr_is_masked() -> None:
    """SecretStr's repr/str show the masked literal so an unintended
    log/traceback never leaks the bcrypt hash or licence key.
    """
    from pydantic import SecretStr

    answers = _answers(
        dashboard_admin_password_hash=SecretStr(
            "$2b$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234",
        ),
        maxmind_license_key=SecretStr("SHHH-DO-NOT-LEAK"),
    )
    rendered = repr(answers)
    assert "SHHH-DO-NOT-LEAK" not in rendered
    assert "$2b$12" not in rendered
    assert "**********" in rendered


def test_secret_fields_length_bounds_enforced() -> None:
    """The pre-sweep ``min_length``/``max_length`` on the SecretStr
    fields are re-applied via the new ``_secret_length_bounds``
    model validator (the Field bounds do not apply through SecretStr).
    """
    from pydantic import SecretStr, ValidationError

    # MaxMind licence key must be 8..64 chars.
    with pytest.raises(ValidationError, match="maxmind_license_key length"):
        _answers(maxmind_license_key=SecretStr("short"))
    with pytest.raises(ValidationError, match="maxmind_license_key length"):
        _answers(maxmind_license_key=SecretStr("x" * 65))
    # Bcrypt hash must be 1..256 chars.
    with pytest.raises(ValidationError, match="dashboard_admin_password_hash length"):
        _answers(dashboard_admin_password_hash=SecretStr(""))
    with pytest.raises(ValidationError, match="dashboard_admin_password_hash length"):
        _answers(dashboard_admin_password_hash=SecretStr("x" * 257))
