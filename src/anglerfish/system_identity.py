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

from typing import Final

#: ``uname -r`` / the ABI release string.
KERNEL_RELEASE: Final = "6.1.0-26-amd64"

#: ``uname -v`` / the build-version field.
KERNEL_BUILD: Final = "#1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)"

#: ``uname -m`` (and ``-p`` / ``-i`` when populated).
MACHINE: Final = "x86_64"

#: ``uname -o``.
OPERATING_SYSTEM: Final = "GNU/Linux"

# The compiler + linker toolchain line is identical across bookworm kernels.
_BUILDER: Final = (
    "(debian-kernel@lists.debian.org) "
    "(gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40)"
)

#: The full ``/proc/version`` line, trailing newline included.
PROC_VERSION: Final = f"Linux version {KERNEL_RELEASE} {_BUILDER} {KERNEL_BUILD}\n"


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
