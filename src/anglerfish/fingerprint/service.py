"""Fingerprinter — composes banner parsing, hash storage, and Tor lookup."""

from __future__ import annotations

import re
from typing import Self

from anglerfish.config.settings import AnglerfishSettings
from anglerfish.fingerprint.ssh import parse_ssh_banner
from anglerfish.fingerprint.tor import TorExitList
from anglerfish.models.fingerprint import SessionFingerprint

__all__ = ["Fingerprinter"]


_HEX_HASH_RE = re.compile(r"^[0-9a-f]{32}$")


class Fingerprinter:
    """Builds :class:`SessionFingerprint` records for incoming sessions."""

    def __init__(
        self,
        settings: AnglerfishSettings,
        *,
        tor_exit_list: TorExitList | None = None,
    ) -> None:
        self._settings = settings
        if tor_exit_list is not None:
            self._tor_exit_list = tor_exit_list
        else:
            self._tor_exit_list = TorExitList(
                settings.fingerprint.tor_exit_list_path,
                refresh_interval_s=settings.fingerprint.tor_exit_refresh_interval_s,
            )

    @property
    def settings(self) -> AnglerfishSettings:
        return self._settings

    @property
    def tor_exit_list(self) -> TorExitList:
        return self._tor_exit_list

    async def fingerprint(
        self,
        *,
        source_ip: str,
        ssh_banner: str | None = None,
        hassh: str | None = None,
        ja3: str | None = None,
    ) -> SessionFingerprint:
        """Compose a fingerprint for a session.

        ``hassh`` and ``ja3`` must be lowercase 32-character hex MD5
        digests if supplied. Mis-shaped values are rejected so that
        downstream consumers can rely on the format. Use the helpers in
        :mod:`anglerfish.fingerprint.hashes` to compute them from raw
        protocol fields.
        """
        if hassh is not None:
            hassh = self._validate_hash("hassh", hassh)
        if ja3 is not None:
            ja3 = self._validate_hash("ja3", ja3)

        banner_info = parse_ssh_banner(ssh_banner) if ssh_banner is not None else None
        is_tor_exit = await self._tor_exit_list.contains(source_ip)

        return SessionFingerprint(
            source_ip=source_ip,
            ssh_banner=banner_info,
            hassh=hassh,
            ja3=ja3,
            is_tor_exit=is_tor_exit,
        )

    @staticmethod
    def _validate_hash(field: str, value: str) -> str:
        normalised = value.lower().strip()
        if not _HEX_HASH_RE.match(normalised):
            raise ValueError(
                f"{field} must be a 32-character lowercase hex MD5, got {value!r}",
            )
        return normalised

    async def aclose(self) -> None:
        del self  # no resources to release today; keeps the API uniform

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
