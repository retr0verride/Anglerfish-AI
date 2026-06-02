"""Shared honeytokens-row rehydration for the store + reader facades.

The :class:`~anglerfish.sessions.store.SessionStore` writer and the
:class:`~anglerfish.sessions.reader.SessionStoreReader` both SELECT the
honeytokens columns in the same order. This is the single rehydration
helper they share so the two facades cannot drift (they previously kept
byte-divergent copies, one with extra str-coercion).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from anglerfish.honeytokens.schema import Honeytoken


def row_to_honeytoken(row: Sequence[Any]) -> Honeytoken:
    """Rehydrate one honeytokens row into a :class:`Honeytoken`.

    Column order: ``id, kind, payload, callback_url, placed_at,
    source_ip, session_id, created_at`` (the order both facades SELECT).
    """
    session_id_raw = row[6]
    return Honeytoken(
        id=row[0],
        kind=row[1],
        payload=row[2],
        callback_url=row[3],
        placed_at=row[4],
        source_ip=row[5],
        session_id=UUID(session_id_raw) if session_id_raw is not None else None,
        created_at=datetime.fromisoformat(row[7]),
    )
