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


# ---------------------------------------------------------------------------
# ReDoS hardening (audit M7)
# ---------------------------------------------------------------------------


def test_crontab_pipe_pattern_is_not_redos() -> None:
    """A crafted 'echo ...' + long space run must not pin the matcher.

    The _CRONTAB_PIPE pattern had two adjacent whitespace-matching
    quantifiers (\\s*[);\\s]*) that backtracked quadratically; ~1.1s at
    the 32 KB command cap, on the bridge event loop.
    """
    import time

    pathological = "echo 'x'" + " " * 32768
    start = time.perf_counter()
    result = extract_event(pathological)
    elapsed = time.perf_counter() - start
    assert result is None  # not a crontab install
    assert elapsed < 0.1, f"extract_event took {elapsed * 1000:.0f}ms (ReDoS)"


def test_crontab_pipe_legit_forms_still_match() -> None:
    for cmd in [
        "echo 'PAYLOAD' | crontab -",
        'echo "PAYLOAD" | crontab -',
        "(crontab -l; echo 'PAYLOAD') | crontab -",
    ]:
        event = extract_event(cmd)
        assert event is not None, cmd
        assert event.kind == "crontab"


# ---------------------------------------------------------------------------
# Robustness (audit review M4 + M5)
# ---------------------------------------------------------------------------


def test_systemctl_unit_with_hyphens_and_dots_not_truncated() -> None:
    """`my-backdoor.service` records the full unit, not the first segment (M5)."""
    event = extract_event("systemctl enable my-backdoor.service")
    assert event is not None
    assert event.sub_key == "my-backdoor"
    # A dotted (non-.service) unit keeps its name intact.
    event2 = extract_event("systemctl start foo.bar.baz")
    assert event2 is not None
    assert event2.sub_key == "foo.bar.baz"


def test_oversized_capture_is_truncated_not_raised() -> None:
    """A padded authorized_keys line must not raise ValidationError out of
    the synchronous classifier; it is recorded truncated to the model
    bound (audit review M4).
    """
    huge_key = "ssh-rsa " + "A" * 10000
    event = extract_event(f'echo "{huge_key}" >> /root/.ssh/authorized_keys')
    assert event is not None
    assert event.kind == "authorized_keys"
    assert len(event.payload) <= 4096
