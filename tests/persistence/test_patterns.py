"""Tests for the Stage 10 slice 1 :mod:`anglerfish.persistence.patterns`."""

from __future__ import annotations

import pytest

from anglerfish.persistence.patterns import extract_event

# ---------------------------------------------------------------------------
# authorized_keys
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "echo 'ssh-ed25519 AAAA...== attacker@x' >> ~/.ssh/authorized_keys",
        'echo "ssh-ed25519 AAAA...== attacker@x" >> /root/.ssh/authorized_keys',
        "echo ssh-ed25519 AAAA attacker >> /root/.ssh/authorized_keys",
    ],
)
def test_authorized_keys_echo_extracts_key(command: str) -> None:
    event = extract_event(command)
    assert event is not None
    assert event.kind == "authorized_keys"
    assert "ssh-ed25519" in event.payload
    assert event.source == "regex"


def test_authorized_keys_extracts_user_from_home_path() -> None:
    command = "echo 'ssh-ed25519 AAAA attacker' >> /home/alice/.ssh/authorized_keys"
    event = extract_event(command)
    assert event is not None
    assert event.kind == "authorized_keys"
    assert event.sub_key == "alice"


def test_authorized_keys_tee_append_variant_matches() -> None:
    command = "echo 'ssh-rsa AAAA attacker' | tee -a /root/.ssh/authorized_keys"
    event = extract_event(command)
    assert event is not None
    assert event.kind == "authorized_keys"


def test_authorized_keys_printf_variant_matches() -> None:
    command = "printf '%s\\n' 'ssh-ed25519 AAAA attacker' >> ~/.ssh/authorized_keys"
    event = extract_event(command)
    assert event is not None
    assert event.kind == "authorized_keys"
    assert "ssh-ed25519" in event.payload


def test_unrelated_echo_does_not_match_authorized_keys() -> None:
    command = "echo hello world"
    assert extract_event(command) is None


# ---------------------------------------------------------------------------
# crontab
# ---------------------------------------------------------------------------


def test_crontab_pipe_extracts_cron_line() -> None:
    command = "echo '0 * * * * /tmp/.x' | crontab -"
    event = extract_event(command)
    assert event is not None
    assert event.kind == "crontab"
    assert event.payload == "0 * * * * /tmp/.x"


def test_crontab_append_idiom_extracts_new_entry() -> None:
    command = "(crontab -l; echo '*/5 * * * * /tmp/.beacon') | crontab -"
    event = extract_event(command)
    assert event is not None
    assert event.kind == "crontab"
    assert event.payload == "*/5 * * * * /tmp/.beacon"


def test_crontab_interactive_edit_records_placeholder() -> None:
    command = "crontab -e"
    event = extract_event(command)
    assert event is not None
    assert event.kind == "crontab"
    assert "interactive edit" in event.payload


def test_crontab_replace_from_file_records_path() -> None:
    command = "crontab /tmp/.payload"
    event = extract_event(command)
    assert event is not None
    assert event.kind == "crontab"
    assert "/tmp/.payload" in event.payload


def test_crontab_raw_write_to_cron_d_matches() -> None:
    command = "echo '0 * * * * /tmp/.x' >> /etc/cron.d/backdoor"
    event = extract_event(command)
    assert event is not None
    assert event.kind == "crontab"
    assert event.payload == "0 * * * * /tmp/.x"


def test_crontab_raw_write_to_var_spool_matches() -> None:
    command = "echo '0 * * * * /tmp/.x' >> /var/spool/cron/crontabs/root"
    event = extract_event(command)
    assert event is not None
    assert event.kind == "crontab"


def test_crontab_listing_does_not_match() -> None:
    """`crontab -l` is read-only; must NOT register as an install."""
    assert extract_event("crontab -l") is None


# ---------------------------------------------------------------------------
# systemctl
# ---------------------------------------------------------------------------


def test_systemctl_enable_extracts_unit() -> None:
    event = extract_event("systemctl enable backdoor")
    assert event is not None
    assert event.kind == "systemctl"
    assert event.sub_key == "backdoor"


def test_systemctl_enable_with_service_suffix_strips_it() -> None:
    event = extract_event("systemctl enable backdoor.service")
    assert event is not None
    assert event.sub_key == "backdoor"


def test_systemctl_enable_now_variant_matches() -> None:
    event = extract_event("systemctl enable --now backdoor")
    assert event is not None
    assert event.kind == "systemctl"
    assert event.sub_key == "backdoor"


def test_systemctl_start_matches() -> None:
    event = extract_event("systemctl start backdoor")
    assert event is not None
    assert event.kind == "systemctl"
    assert event.sub_key == "backdoor"


def test_service_command_matches() -> None:
    event = extract_event("service nginx start")
    assert event is not None
    assert event.kind == "systemctl"
    assert event.sub_key == "nginx"


def test_systemd_unit_file_write_records_path() -> None:
    command = "echo '[Unit]\\nDescription=x' >> /etc/systemd/system/backdoor.service"
    event = extract_event(command)
    assert event is not None
    assert event.kind == "systemctl"
    assert event.sub_key == "backdoor.service"
    assert "/etc/systemd/system/backdoor.service" in event.payload


def test_systemctl_status_does_not_match() -> None:
    """`systemctl status` is read-only; must NOT register as an install."""
    assert extract_event("systemctl status backdoor") is None


def test_systemctl_disable_does_not_match() -> None:
    """`systemctl disable` is removal; not an install."""
    assert extract_event("systemctl disable backdoor") is None


# ---------------------------------------------------------------------------
# Misses + boundary
# ---------------------------------------------------------------------------


def test_empty_command_returns_none() -> None:
    assert extract_event("") is None
    assert extract_event("   ") is None


def test_unrelated_command_returns_none() -> None:
    assert extract_event("ls -la /etc") is None
    assert extract_event("cat /etc/passwd") is None
    assert extract_event("ps aux") is None


def test_first_match_wins_authorized_keys_over_crontab() -> None:
    """Pathological compound command: authorized_keys hits first."""
    command = (
        "echo 'ssh-ed25519 AAAA attacker' >> ~/.ssh/authorized_keys; "
        "echo '0 * * * * /tmp/.x' | crontab -"
    )
    event = extract_event(command)
    assert event is not None
    assert event.kind == "authorized_keys"
