"""Tests for the Stage 8 embeddings table and SessionStore methods."""

from __future__ import annotations

import sqlite3
import struct
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from anglerfish.config.models import SessionStoreConfig
from anglerfish.models import (
    CommandTurn,
    ResponseSource,
    SessionEmbedding,
    SessionSnapshot,
)
from anglerfish.sessions import SessionStore
from anglerfish.sessions.schema import CURRENT_SCHEMA_VERSION, run_migrations
from anglerfish.sessions.store import (
    _cosine_similarity,
    _pack_vector,
    _row_to_embedding,
    _unpack_vector,
)


def _snapshot(*, session_id=None) -> SessionSnapshot:
    now = datetime(2026, 5, 26, 12, 0, tzinfo=UTC)
    return SessionSnapshot(
        session_id=session_id or uuid4(),
        source_ip="203.0.113.7",
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=now,
        last_activity_at=now,
        turns=(
            CommandTurn(
                command="ls",
                response="",
                source=ResponseSource.AI,
                timestamp=now,
                latency_ms=1.0,
            ),
        ),
    )


def _embedding_for(
    session_id,
    *,
    vector=None,
    model="embed-test",
) -> SessionEmbedding:
    vec = tuple(vector) if vector is not None else tuple(0.01 * i for i in range(64))
    return SessionEmbedding(
        session_id=session_id,
        vector=vec,
        dimension=len(vec),
        model=model,
        generated_at=datetime(2026, 5, 26, 12, 30, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# Schema migration
# ---------------------------------------------------------------------------


def test_current_schema_version_is_three() -> None:
    assert CURRENT_SCHEMA_VERSION == 3


def test_migration_creates_embeddings_table(tmp_path: Path) -> None:
    db = tmp_path / "schema.db"
    conn = sqlite3.connect(db)
    try:
        run_migrations(conn)
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='embeddings'"
        ).fetchall()
        assert rows == [("embeddings",)]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Pack/unpack helpers
# ---------------------------------------------------------------------------


def test_pack_vector_round_trip() -> None:
    original = tuple(0.1 * i for i in range(64))
    blob = _pack_vector(original)
    assert len(blob) == 64 * 4  # float32 = 4 bytes per element
    unpacked = _unpack_vector(blob, 64)
    # float32 precision means small rounding; compare with tolerance.
    for orig, back in zip(original, unpacked, strict=True):
        assert abs(orig - back) < 1e-5


def test_unpack_vector_rejects_truncated_blob() -> None:
    short_blob = struct.pack("<3f", 0.1, 0.2, 0.3)
    with pytest.raises(ValueError, match="does not match dimension"):
        _unpack_vector(short_blob, 64)


def test_row_to_embedding_assembles_correctly() -> None:
    sid = uuid4()
    vector = tuple(0.5 for _ in range(64))
    blob = _pack_vector(vector)
    row = (blob, 64, "embed-test", "2026-05-26T12:30:00+00:00")
    embedding = _row_to_embedding(sid, row)
    assert embedding.session_id == sid
    assert embedding.dimension == 64
    assert embedding.model == "embed-test"


# ---------------------------------------------------------------------------
# Cosine similarity
# ---------------------------------------------------------------------------


def test_cosine_similarity_identical_vectors_is_one() -> None:
    vec = tuple(1.0 for _ in range(8))
    assert abs(_cosine_similarity(vec, vec) - 1.0) < 1e-9


def test_cosine_similarity_orthogonal_vectors_is_zero() -> None:
    a = (1.0, 0.0, 0.0)
    b = (0.0, 1.0, 0.0)
    assert abs(_cosine_similarity(a, b)) < 1e-9


def test_cosine_similarity_opposite_vectors_is_minus_one() -> None:
    a = (1.0, 0.0)
    b = (-1.0, 0.0)
    assert abs(_cosine_similarity(a, b) + 1.0) < 1e-9


def test_cosine_similarity_zero_vector_returns_zero() -> None:
    a = (0.0, 0.0, 0.0)
    b = (1.0, 2.0, 3.0)
    assert _cosine_similarity(a, b) == 0.0
    assert _cosine_similarity(b, a) == 0.0


def test_cosine_similarity_length_mismatch_raises() -> None:
    with pytest.raises(ValueError, match="equal-length"):
        _cosine_similarity((1.0, 2.0), (1.0, 2.0, 3.0))


# ---------------------------------------------------------------------------
# upsert_embedding / get_embedding round-trip
# ---------------------------------------------------------------------------


async def test_upsert_and_get_embedding_round_trip(tmp_path: Path) -> None:
    snapshot = _snapshot()
    embedding = _embedding_for(snapshot.session_id)
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        await store.upsert_session(snapshot)
        await store.upsert_embedding(embedding)
        loaded = await store.get_embedding(snapshot.session_id)
    assert loaded is not None
    assert loaded.session_id == embedding.session_id
    assert loaded.dimension == 64
    assert loaded.model == "embed-test"
    # float32 precision tolerance.
    for orig, back in zip(embedding.vector, loaded.vector, strict=True):
        assert abs(orig - back) < 1e-5


async def test_get_embedding_returns_none_for_unknown_session(
    tmp_path: Path,
) -> None:
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        assert await store.get_embedding(uuid4()) is None


async def test_upsert_embedding_overwrites_existing(tmp_path: Path) -> None:
    snapshot = _snapshot()
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    first = _embedding_for(snapshot.session_id, vector=[0.1] * 64)
    second = _embedding_for(snapshot.session_id, vector=[0.9] * 64)
    async with SessionStore(config) as store:
        await store.upsert_session(snapshot)
        await store.upsert_embedding(first)
        await store.upsert_embedding(second)
        loaded = await store.get_embedding(snapshot.session_id)
    assert loaded is not None
    for v in loaded.vector:
        assert abs(v - 0.9) < 1e-5


async def test_upsert_embedding_without_session_fk_raises(tmp_path: Path) -> None:
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        with pytest.raises(sqlite3.IntegrityError):
            await store.upsert_embedding(_embedding_for(uuid4()))


async def test_session_delete_cascades_embedding(tmp_path: Path) -> None:
    snapshot = _snapshot()
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        await store.upsert_session(snapshot)
        await store.upsert_embedding(_embedding_for(snapshot.session_id))
        assert await store.get_embedding(snapshot.session_id) is not None
        async with store._lock:
            store._conn.execute(  # type: ignore[union-attr]
                "DELETE FROM sessions WHERE session_id = ?",
                (str(snapshot.session_id),),
            )
        assert await store.get_embedding(snapshot.session_id) is None


# ---------------------------------------------------------------------------
# find_similar
# ---------------------------------------------------------------------------


async def test_find_similar_returns_empty_for_unknown_session(
    tmp_path: Path,
) -> None:
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        assert await store.find_similar(uuid4()) == []


async def test_find_similar_excludes_self_and_orders_by_score(
    tmp_path: Path,
) -> None:
    """Query vector matches more strongly with closer neighbours."""
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    query_vec = tuple(1.0 if i == 0 else 0.0 for i in range(64))
    close_vec = tuple(0.99 if i == 0 else 0.001 for i in range(64))
    far_vec = tuple(0.0 if i == 0 else 1.0 / 63 for i in range(64))

    async with SessionStore(config) as store:
        query_snap = _snapshot()
        close_snap = _snapshot()
        far_snap = _snapshot()
        for snap in (query_snap, close_snap, far_snap):
            await store.upsert_session(snap)
        await store.upsert_embedding(
            _embedding_for(query_snap.session_id, vector=query_vec),
        )
        await store.upsert_embedding(
            _embedding_for(close_snap.session_id, vector=close_vec),
        )
        await store.upsert_embedding(
            _embedding_for(far_snap.session_id, vector=far_vec),
        )
        results = await store.find_similar(
            query_snap.session_id,
            k=10,
            min_similarity=0.0,
        )
    sids = [r[0].session_id for r in results]
    assert query_snap.session_id not in sids  # self excluded
    # close vector should rank first
    assert sids[0] == close_snap.session_id
    # close-vector similarity should beat far-vector similarity
    assert results[0][1] > results[1][1]


async def test_find_similar_respects_min_similarity_threshold(
    tmp_path: Path,
) -> None:
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    query_vec = tuple(1.0 if i == 0 else 0.0 for i in range(64))
    # Orthogonal-ish neighbour: cosine ~= 0.
    distant_vec = tuple(0.0 if i == 0 else 1.0 / 63 for i in range(64))
    async with SessionStore(config) as store:
        query_snap = _snapshot()
        distant_snap = _snapshot()
        for snap in (query_snap, distant_snap):
            await store.upsert_session(snap)
        await store.upsert_embedding(
            _embedding_for(query_snap.session_id, vector=query_vec),
        )
        await store.upsert_embedding(
            _embedding_for(distant_snap.session_id, vector=distant_vec),
        )
        # Strict threshold should produce no matches.
        results = await store.find_similar(
            query_snap.session_id,
            k=10,
            min_similarity=0.8,
        )
    assert results == []


async def test_find_similar_excludes_cross_model_neighbours(
    tmp_path: Path,
) -> None:
    """Different embed-model tags must not produce neighbour matches."""
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    same_model_vec = tuple(1.0 if i == 0 else 0.0 for i in range(64))
    cross_model_vec = tuple(1.0 if i == 0 else 0.0 for i in range(64))
    async with SessionStore(config) as store:
        query_snap = _snapshot()
        same_snap = _snapshot()
        cross_snap = _snapshot()
        for snap in (query_snap, same_snap, cross_snap):
            await store.upsert_session(snap)
        await store.upsert_embedding(
            _embedding_for(query_snap.session_id, vector=same_model_vec, model="A"),
        )
        await store.upsert_embedding(
            _embedding_for(same_snap.session_id, vector=same_model_vec, model="A"),
        )
        await store.upsert_embedding(
            _embedding_for(cross_snap.session_id, vector=cross_model_vec, model="B"),
        )
        results = await store.find_similar(
            query_snap.session_id,
            k=10,
            min_similarity=0.0,
        )
    sids = [r[0].session_id for r in results]
    assert same_snap.session_id in sids
    assert cross_snap.session_id not in sids


async def test_find_similar_rejects_invalid_args(tmp_path: Path) -> None:
    config = SessionStoreConfig(database_path=tmp_path / "store.db")
    async with SessionStore(config) as store:
        with pytest.raises(ValueError, match="k must be positive"):
            await store.find_similar(uuid4(), k=0)
        with pytest.raises(ValueError, match="min_similarity"):
            await store.find_similar(uuid4(), min_similarity=1.5)
