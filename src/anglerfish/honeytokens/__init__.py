"""Honeytoken generation + registry for Stage 11 decoy data poisoning.

Stage 11 distributes traceable beacons (AWS access keys, SSH
keypairs) in the lure's fakefs so an attacker who exfiltrates
``/root/.aws/credentials`` or ``~/.ssh/id_rsa`` leaks the
source-session correlation when they try the AWS key against a
sinkhole or paste the SSH public key publicly.

Slice 11.1 ships the in-process pieces only:

* :class:`Honeytoken` - the shared frozen data model.
* :class:`HoneytokenGenerator` - AWS + SSH generators.

Slice 11.2 adds the SQLite schema + SessionStore CRUD + the
audit-tailer dispatch. Slice 11.3 wires the bridge integration
(threat-scorer threshold hook + fakefs_overlay merge). Slice
11.4 ships the bundled callback receiver + the wizard prompt +
the THREAT_MODEL update.
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
