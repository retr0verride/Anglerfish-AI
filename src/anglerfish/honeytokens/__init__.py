"""Honeytoken generation + registry for Stage 11 decoy data poisoning.

Stage 11 distributes traceable beacons (AWS access keys, SSH
keypairs) in the lure's fakefs so an attacker who exfiltrates
``/root/.aws/credentials`` or ``~/.ssh/id_rsa`` leaks the
source-session correlation when they try the AWS key against a
sinkhole or paste the SSH public key publicly.

This package provides the in-process pieces:

* :class:`Honeytoken` - the shared frozen data model.
* :class:`HoneytokenGenerator` - AWS + SSH generators.
* :class:`HoneytokenPlacementService` - the threat-threshold hook
  that schedules per-session placement.

The SQLite schema + SessionStore CRUD + audit-tailer dispatch live
in :mod:`anglerfish.sessions`, the bridge wiring in
:mod:`anglerfish.bridge.service`, and the public callback receiver in
:mod:`anglerfish.callback`.
"""

from __future__ import annotations

from anglerfish.honeytokens.generators import HoneytokenGenerator
from anglerfish.honeytokens.placement import HoneytokenPlacementService
from anglerfish.honeytokens.schema import (
    Honeytoken,
    HoneytokenKind,
    new_lookup_id,
)

__all__ = [
    "Honeytoken",
    "HoneytokenGenerator",
    "HoneytokenKind",
    "HoneytokenPlacementService",
    "new_lookup_id",
]
