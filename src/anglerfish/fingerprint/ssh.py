"""SSH client identification string parser (RFC 4253 §4.2).

The banner has the form::

    SSH-<protoversion>-<softwareversion>[ <comments>]

Examples:

    SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
    SSH-2.0-libssh2_1.10.0
    SSH-2.0-PUTTY_Release_0.74

``softwareversion`` itself often encodes the implementation name and a
version separated by an underscore. We split on the first underscore
so ``OpenSSH_8.9p1`` becomes ``("OpenSSH", "8.9p1")``.
"""

from __future__ import annotations

from anglerfish.models.fingerprint import SshBannerInfo

__all__ = ["parse_ssh_banner"]


_MAX_BANNER_LEN = 255


def parse_ssh_banner(raw: str) -> SshBannerInfo:
    """Parse an SSH banner string into a :class:`SshBannerInfo`.

    Always returns an :class:`SshBannerInfo` — malformed banners
    populate :attr:`SshBannerInfo.raw` and leave the structured
    fields as :data:`None`. Length is capped at 255 characters
    (per RFC 4253).
    """
    if not isinstance(raw, str):
        raise TypeError(f"parse_ssh_banner expected str, got {type(raw).__name__}")

    trimmed = raw.rstrip("\r\n")[:_MAX_BANNER_LEN]

    if not trimmed.startswith("SSH-"):
        return SshBannerInfo(raw=trimmed)

    body = trimmed[len("SSH-") :]
    parts = body.split("-", 1)
    if len(parts) != 2:
        return SshBannerInfo(raw=trimmed, protocol=body or None)
    protocol, rest = parts
    if not rest:
        return SshBannerInfo(raw=trimmed, protocol=protocol)

    software_block, _, comments = rest.partition(" ")
    software = software_block or None
    software_name: str | None = None
    software_version: str | None = None
    if software is not None:
        name, sep, version = software.partition("_")
        if sep:
            software_name = name or None
            software_version = version or None
        else:
            software_name = name or None

    return SshBannerInfo(
        raw=trimmed,
        protocol=protocol or None,
        software=software,
        software_name=software_name,
        software_version=software_version,
        comments=comments or None,
    )
