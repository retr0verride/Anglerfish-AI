"""Network interface enumeration for the wizard.

Reads :file:`/sys/class/net/` on Linux. Returns an empty list on
non-Linux hosts; the wizard falls back to whatever the operator types
in. The lookup is deliberately stdlib-only so the wizard runs inside a
minimal Debian ISO chroot.
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["list_interfaces"]


_SYS_CLASS_NET = Path("/sys/class/net")
_VIRTUAL_PREFIXES = ("lo", "veth", "docker", "br-", "virbr", "vmnet", "vnet")


def list_interfaces(*, root: Path | None = None) -> list[str]:
    """Return the non-loopback, non-virtual interfaces visible to the host.

    Loopback (``lo``) and common virtual interfaces (Docker, libvirt,
    VMware bridges) are excluded so the operator is not asked to pick
    between two dozen meaningless options. The wizard accepts any
    string the operator types, so this list is only ever a suggestion.
    """
    base = root if root is not None else _SYS_CLASS_NET
    if not base.is_dir():
        return []
    names: list[str] = []
    for entry in sorted(base.iterdir()):
        name = entry.name
        if any(name.startswith(prefix) for prefix in _VIRTUAL_PREFIXES):
            continue
        names.append(name)
    return names
