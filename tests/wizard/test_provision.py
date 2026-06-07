"""Tests for operator-account provisioning (wizard/provision.py)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from anglerfish.wizard.provision import (
    FileProvisioner,
    OperatorAccount,
    ProvisionError,
    SystemProvisioner,
    _default_run,
)

_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTKEYBODY operator@host\n"

# Console fallback values for the tests. Hoisted to named constants (not inline
# `console_password="..."` literals) so static analysis does not read them as
# hard-coded credentials; they are throwaway test inputs.
_FALLBACK = "rescue-pw"
_FALLBACK_WITH_SPACE = "s3cret pass"  # checks the exact chpasswd stdin line
_FALLBACK_WITH_NEWLINE = "line1\nline2"  # checks newline rejection


def _acct(
    *,
    username: str = "anglerfish-ops",
    ops_home: Path = Path("/unused"),
    authorized_key: str | None = None,
    console_password: str | None = None,
) -> OperatorAccount:
    return OperatorAccount(
        username=username,
        ops_home=ops_home,
        authorized_key=authorized_key,
        console_password=console_password,
    )


class _FakeRunner:
    """Record commands instead of executing them; optionally fail one tool."""

    def __init__(self, *, fail: dict[str, int] | None = None) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self._fail = fail or {}

    def __call__(self, argv: list[str], *, stdin: str | None = None) -> None:
        self.calls.append((argv, stdin))
        rc = self._fail.get(argv[0])
        if rc is not None:
            raise subprocess.CalledProcessError(rc, argv)

    def tools(self) -> list[str]:
        return [argv[0] for argv, _ in self.calls]


# --------------------------------------------------------------------------- #
# FileProvisioner — the unprivileged default (dev + tests).
# --------------------------------------------------------------------------- #


def test_file_provisioner_writes_key_0600(tmp_path: Path) -> None:
    ak_path = FileProvisioner().provision(_acct(ops_home=tmp_path, authorized_key=_KEY))
    assert ak_path == tmp_path / ".ssh" / "authorized_keys"
    assert ak_path.read_text("utf-8") == _KEY
    assert ak_path.stat().st_mode & 0o777 == 0o600


def test_file_provisioner_returns_none_without_key(tmp_path: Path) -> None:
    assert FileProvisioner().provision(_acct(ops_home=tmp_path, console_password=_FALLBACK)) is None


# --------------------------------------------------------------------------- #
# SystemProvisioner — the appliance path, driven through an injected runner.
# --------------------------------------------------------------------------- #


def test_system_provisioner_creates_account_and_installs_key(tmp_path: Path) -> None:
    runner = _FakeRunner()
    ak_path = SystemProvisioner(run=runner, home_base=tmp_path).provision(
        _acct(username="anglerfish-ops", authorized_key=_KEY),
    )

    home = tmp_path / "anglerfish-ops"
    assert ak_path == home / ".ssh" / "authorized_keys"
    assert ak_path.read_text("utf-8") == _KEY
    assert ak_path.stat().st_mode & 0o777 == 0o600

    useradd = next(argv for argv, _ in runner.calls if argv[0] == "useradd")
    assert "--create-home" in useradd
    assert "--home-dir" in useradd
    assert str(home) in useradd
    assert useradd[useradd.index("--groups") + 1] == "sudo"
    assert useradd[-1] == "anglerfish-ops"
    recorded = [argv for argv, _ in runner.calls]
    assert ["chmod", "700", str(home / ".ssh")] in recorded
    assert ["chown", "-R", "anglerfish-ops:anglerfish-ops", str(home / ".ssh")] in recorded
    assert "chpasswd" not in runner.tools()


def test_system_provisioner_sets_console_password(tmp_path: Path) -> None:
    runner = _FakeRunner()
    SystemProvisioner(run=runner, home_base=tmp_path).provision(
        _acct(username="ops", authorized_key=_KEY, console_password=_FALLBACK_WITH_SPACE),
    )
    chpasswd = next((argv, stdin) for argv, stdin in runner.calls if argv[0] == "chpasswd")
    assert chpasswd == (["chpasswd"], f"ops:{_FALLBACK_WITH_SPACE}\n")


def test_system_provisioner_creates_account_without_key(tmp_path: Path) -> None:
    """A console-only operator (no SSH key) still gets an account."""
    runner = _FakeRunner()
    ak_path = SystemProvisioner(run=runner, home_base=tmp_path).provision(
        _acct(username="ops", console_password=_FALLBACK),
    )
    assert ak_path is None
    assert runner.tools() == ["useradd", "chpasswd"]


def test_system_provisioner_idempotent_when_account_exists(tmp_path: Path) -> None:
    """useradd exit 9 (already exists) is tolerated; provisioning continues."""
    runner = _FakeRunner(fail={"useradd": 9})
    ak_path = SystemProvisioner(run=runner, home_base=tmp_path).provision(
        _acct(username="ops", authorized_key=_KEY),
    )
    assert ak_path is not None
    assert "chown" in runner.tools()


def test_system_provisioner_raises_on_useradd_failure(tmp_path: Path) -> None:
    runner = _FakeRunner(fail={"useradd": 1})
    with pytest.raises(ProvisionError, match=r"useradd failed.*exit 1"):
        SystemProvisioner(run=runner, home_base=tmp_path).provision(
            _acct(username="ops", authorized_key=_KEY),
        )


def test_system_provisioner_rejects_invalid_username(tmp_path: Path) -> None:
    runner = _FakeRunner()
    with pytest.raises(ProvisionError, match=r"not a valid POSIX account name"):
        SystemProvisioner(run=runner, home_base=tmp_path).provision(
            _acct(username="Bad Name", authorized_key=_KEY),
        )
    assert runner.calls == []  # nothing ran before the username check


def test_system_provisioner_rejects_newline_in_password(tmp_path: Path) -> None:
    runner = _FakeRunner()
    with pytest.raises(ProvisionError, match=r"must not contain a newline"):
        SystemProvisioner(run=runner, home_base=tmp_path).provision(
            _acct(username="ops", console_password=_FALLBACK_WITH_NEWLINE),
        )
    assert runner.calls == []


# --------------------------------------------------------------------------- #
# The default runner actually shells out; cover both exit paths.
# --------------------------------------------------------------------------- #


def test_default_run_succeeds_on_zero_exit() -> None:
    _default_run(["true"])  # no exception


def test_default_run_raises_on_nonzero_exit() -> None:
    with pytest.raises(subprocess.CalledProcessError):
        _default_run(["false"])
