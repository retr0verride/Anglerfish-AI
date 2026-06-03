"""Single source of truth for the appliance's synthetic kernel identity.

Several surfaces independently describe the fake box's kernel: the lure's
``uname`` command (``lure/commands.py``), the bridge's scripted fallback
``uname`` used during an Ollama outage (``bridge/fallback.py``),
``/proc/version`` in the fake filesystem (``lure/fakefs.py``), and the
"ground truth" facts handed to the LLM (``bridge/prompts.py``).

Before this module each hard-coded its own string and they drifted: the lure
claimed ``6.1.0-18-amd64`` while the bridge claimed ``6.1.0-26-amd64``, so an
attacker cross-checking ``uname -r``, ``cat /proc/version``, and the model's
narration saw more than one kernel (TODO-10). The fallback's ``uname -a`` also
emitted ``x86_64 x86_64 x86_64`` where stock Debian prints a single
``x86_64``. Every consumer now reads the constants below, and
``tests/test_system_identity.py`` fails if a surface drifts.

The values describe a real, plausible Debian 12 (bookworm) kernel ABI
``6.1.0-26-amd64`` (source package ``linux`` ``6.1.112-1``). This is a
persona choice, not the real ISO kernel: the lure never executes attacker
input, so the host kernel is never exposed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

#: ``uname -r`` / the ABI release string.
KERNEL_RELEASE: Final = "6.1.0-26-amd64"

#: ``uname -v`` / the build-version field.
KERNEL_BUILD: Final = "#1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)"

#: ``uname -m`` (and ``-p`` / ``-i`` when populated).
MACHINE: Final = "x86_64"

#: ``uname -o``.
OPERATING_SYSTEM: Final = "GNU/Linux"

#: The default distribution (the prompt's "Distribution:" fact).
DISTRIBUTION: Final = "Debian GNU/Linux 12 (bookworm)"

# The compiler + linker toolchain line is identical across bookworm kernels.
_BUILDER: Final = (
    "(debian-kernel@lists.debian.org) "
    "(gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40)"
)

#: The full ``/proc/version`` line, trailing newline included.
PROC_VERSION: Final = f"Linux version {KERNEL_RELEASE} {_BUILDER} {KERNEL_BUILD}\n"


@dataclass(frozen=True)
class KernelIdentity:
    """A coherent ``uname`` release + build-version pair."""

    release: str
    build: str

    def uname_a(self, hostname: str) -> str:
        return f"Linux {hostname} {self.release} {self.build} {MACHINE} {OPERATING_SYSTEM}"


_DEFAULT_KERNEL: Final = KernelIdentity(release=KERNEL_RELEASE, build=KERNEL_BUILD)


def kernel_for(proc_version: str | None) -> KernelIdentity:
    """Kernel identity matching a persona's ``/proc/version`` overlay (TODO-10).

    A persona that overrides ``/proc/version`` (e.g. an Ubuntu box) must report
    a matching ``uname`` or ``uname -r`` contradicts ``cat /proc/version``.
    Parse the release and build-version out of the overlay; fall back to the
    default Debian identity when there is no overlay or it does not parse.
    """
    if not proc_version:
        return _DEFAULT_KERNEL
    tokens = proc_version.split()
    if len(tokens) < 3 or tokens[0] != "Linux" or tokens[1] != "version":
        return _DEFAULT_KERNEL
    release = tokens[2]
    hash_idx = proc_version.find("#")
    build = proc_version[hash_idx:].strip() if hash_idx != -1 else KERNEL_BUILD
    return KernelIdentity(release=release, build=build)


def distribution_for(os_release: str | None) -> str:
    """The ``PRETTY_NAME`` from a persona's ``/etc/os-release`` overlay.

    Falls back to the default :data:`DISTRIBUTION` when absent so the prompt's
    "Distribution:" fact matches the persona's OS instead of always claiming
    Debian.
    """
    if os_release:
        for line in os_release.splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    return DISTRIBUTION


def id_line(username: str) -> str:
    """Render ``id`` output for ``username`` (no trailing newline).

    The non-root session user is a sudoer (gid 27): the fake ``/etc/group``
    lists ``sudo:x:27:<user>`` and ``/var/log/auth.log`` shows the user
    running ``sudo``, so the group must appear here too or ``id`` contradicts
    them.
    """
    if username == "root":
        return "uid=0(root) gid=0(root) groups=0(root)"
    return f"uid=1000({username}) gid=1000({username}) groups=1000({username}),27(sudo)"


def uname_a(hostname: str) -> str:
    """Render ``uname -a`` for ``hostname`` (no trailing newline).

    Matches stock Debian's layout: kernel-name, nodename, release, version,
    machine, operating-system. The processor / hardware-platform fields are
    "unknown" on Debian and therefore suppressed, so a single ``x86_64``
    precedes ``GNU/Linux`` (not three).
    """
    return f"Linux {hostname} {KERNEL_RELEASE} {KERNEL_BUILD} {MACHINE} {OPERATING_SYSTEM}"
