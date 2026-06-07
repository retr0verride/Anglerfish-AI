"""Provision the operator OS account at first boot.

The wizard collects the operator username, an SSH public key, and an optional
console fallback password. On the appliance (``anglerfish-wizard --provision``,
as run by ``anglerfish-firstboot.service``) the account must actually exist for
the operator to get back in: the real sshd is key-only
(``PasswordAuthentication no``) and the operator authenticates as this account,
so without it the only post-boot access is the hypervisor console. The wizard
previously wrote ``authorized_keys`` for an account that was never created,
which locked operators out of every SSH path.

Two implementations behind one :class:`WizardProvisioner` protocol:

* :class:`SystemProvisioner` creates the UNIX account (``useradd``), adds it to
  ``sudo`` so it can administer the box, sets the optional console password
  (``chpasswd``), and installs the SSH key owned by the operator. Requires
  root; used on the appliance.
* :class:`FileProvisioner` only renders the ``authorized_keys`` file under a
  given home directory. No account, no privilege. The default for local dev and
  the test suite, where creating real system users is neither wanted nor
  possible.
"""

from __future__ import annotations

import re
import subprocess  # nosec B404 - drives trusted account tools (useradd/chpasswd) with fixed argv lists, never a shell
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from anglerfish.wizard.persistence import atomic_write_private

__all__ = [
    "CommandRunner",
    "FileProvisioner",
    "OperatorAccount",
    "ProvisionError",
    "SystemProvisioner",
    "WizardProvisioner",
]

# useradd's exit status for "account already exists"; lets a --reconfigure
# re-run be idempotent instead of aborting.
_USERADD_EEXIST = 9

# POSIX-portable account name. Bounds operator_username before it reaches
# useradd as argv, so a pasted-in odd name cannot create a malformed account.
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class ProvisionError(RuntimeError):
    """Raised when operator-account provisioning fails."""


@dataclass(frozen=True)
class OperatorAccount:
    """The operator-access inputs a provisioner acts on.

    ``ops_home`` is the home directory :class:`FileProvisioner` renders the key
    under (dev/test). :class:`SystemProvisioner` ignores it and uses the
    account's real home (``/home/<username>``) instead.
    """

    username: str
    ops_home: Path
    authorized_key: str | None
    console_password: str | None


class CommandRunner(Protocol):
    """Run a command, raising on a non-zero exit. Injectable for tests."""

    def __call__(self, argv: list[str], *, stdin: str | None = None) -> None: ...


def _default_run(argv: list[str], *, stdin: str | None = None) -> None:
    """Run ``argv`` with no shell, raising on failure.

    ``capture_output`` keeps tool chatter (and any echoed input) off the
    first-boot console; a failure still surfaces via ``CalledProcessError``.
    """
    subprocess.run(  # noqa: S603  # nosec B603 B607 - fixed system tools, argv list (no shell), resolved by the firstboot unit's PATH; only the validated username/password are interpolated
        argv,
        input=stdin,
        text=True,
        check=True,
        capture_output=True,
    )


class WizardProvisioner(Protocol):
    """Places the operator's SSH key and, on the appliance, the account."""

    def provision(self, account: OperatorAccount) -> Path | None:
        """Provision access; return the ``authorized_keys`` path, or None."""
        ...


class FileProvisioner:
    """Render the ``authorized_keys`` file only (no account, no privilege).

    The default outside the appliance. Local dev and the test suite do not
    create system users, so the account's username and console password are
    left untouched here.
    """

    def provision(self, account: OperatorAccount) -> Path | None:
        if account.authorized_key is None:
            return None
        ak_path = account.ops_home / ".ssh" / "authorized_keys"
        atomic_write_private(ak_path, account.authorized_key, mode=0o600)
        return ak_path


class SystemProvisioner:
    """Create the operator UNIX account and install its key. Requires root.

    Used on the appliance via ``anglerfish-wizard --provision``. The account
    gets a home directory, a ``/bin/bash`` shell, membership in ``sudo`` so it
    can administer the box, the optional console fallback password, and
    ownership of its ``~/.ssh/authorized_keys``. sshd stays key-only, so the
    console password is usable only at the VM console, never over SSH.

    ``run`` and ``home_base`` are injectable so the suite can assert the
    command sequence and file placement without root or a real ``useradd``.
    """

    def __init__(
        self,
        *,
        run: CommandRunner = _default_run,
        home_base: Path = Path("/home"),
    ) -> None:
        self._run = run
        self._home_base = home_base

    def provision(self, account: OperatorAccount) -> Path | None:
        username = account.username
        if not _USERNAME_RE.match(username):
            raise ProvisionError(
                f"operator username {username!r} is not a valid POSIX account "
                r"name (^[a-z_][a-z0-9_-]{0,31}$)",
            )
        password = account.console_password
        if password is not None and "\n" in password:
            # chpasswd reads newline-separated user:password records; a newline
            # in the value would inject a second record.
            raise ProvisionError("console password must not contain a newline")

        home = self._home_base / username
        self._ensure_account(username, home)
        if password:
            self._run(["chpasswd"], stdin=f"{username}:{password}\n")

        if account.authorized_key is None:
            return None
        ssh_dir = home / ".ssh"
        ak_path = ssh_dir / "authorized_keys"
        # atomic_write_private creates the .ssh parent root-owned; chmod + chown
        # hand it to the operator so sshd's StrictModes accepts the key.
        atomic_write_private(ak_path, account.authorized_key, mode=0o600)
        self._run(["chmod", "700", str(ssh_dir)])
        self._run(["chown", "-R", f"{username}:{username}", str(ssh_dir)])
        return ak_path

    def _ensure_account(self, username: str, home: Path) -> None:
        argv = [
            "useradd",
            "--create-home",
            "--home-dir",
            str(home),
            "--shell",
            "/bin/bash",
            "--groups",
            "sudo",
            username,
        ]
        try:
            self._run(argv)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != _USERADD_EEXIST:
                raise ProvisionError(
                    f"useradd failed for {username!r}: exit {exc.returncode}",
                ) from exc
            # Account already exists: a --reconfigure re-run, not an error.
