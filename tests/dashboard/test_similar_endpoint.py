"""Tests for the Stage 8 slice 5 :code:`GET /api/sessions/{id}/similar` route."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from anglerfish.audit import AuditLog
from anglerfish.config import AnglerfishSettings
from anglerfish.dashboard import create_app
from anglerfish.dashboard.state import DashboardState
from anglerfish.models import (
    CommandTurn,
    ResponseSource,
    SessionSnapshot,
)
from anglerfish.models.embedding import SessionEmbedding


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture
def client(
    settings: AnglerfishSettings,
    audit_path: Path,
    dashboard_state: DashboardState,
) -> Iterator[TestClient]:
    audit = AuditLog(audit_path)
    app = create_app(settings, state=dashboard_state, audit=audit)
    with TestClient(app) as c:
        yield c


def _snapshot() -> SessionSnapshot:
    now = datetime(2026, 5, 26, 12, 0, tzinfo=UTC)
    return SessionSnapshot(
        session_id=uuid4(),
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


def _embedding(
    session_id,
    *,
    vector,
    model: str = "embed-test",
) -> SessionEmbedding:
    vec = tuple(vector)
    return SessionEmbedding(
        session_id=session_id,
        vector=vec,
        dimension=len(vec),
        model=model,
        generated_at=datetime(2026, 5, 26, 12, 30, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# 404 / missing-embedding paths
# ---------------------------------------------------------------------------


def test_similar_404_when_session_unknown(client: TestClient) -> None:
    r = client.get(f"/api/sessions/{uuid4()}/similar")
    assert r.status_code == 404


async def test_similar_404_when_session_has_no_embedding(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    snap = _snapshot()
    await dashboard_state.update_session(snap)
    r = client.get(f"/api/sessions/{snap.session_id}/similar")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_similar_returns_neighbours_ranked_by_similarity(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    """Two neighbours; closer one ranks first."""
    query_snap = _snapshot()
    close_snap = _snapshot()
    far_snap = _snapshot()
    for snap in (query_snap, close_snap, far_snap):
        await dashboard_state.update_session(snap)

    query_vec = tuple(1.0 if i == 0 else 0.0 for i in range(64))
    close_vec = tuple(0.99 if i == 0 else 0.001 for i in range(64))
    far_vec = tuple(0.0 if i == 0 else 1.0 / 63 for i in range(64))

    await dashboard_state.upsert_embedding(
        _embedding(query_snap.session_id, vector=query_vec),
    )
    await dashboard_state.upsert_embedding(
        _embedding(close_snap.session_id, vector=close_vec),
    )
    await dashboard_state.upsert_embedding(
        _embedding(far_snap.session_id, vector=far_vec),
    )

    r = client.get(
        f"/api/sessions/{query_snap.session_id}/similar?min_similarity=0.0",
    )
    assert r.status_code == 200
    body = r.json()
    assert body["session_id"] == str(query_snap.session_id)
    assert body["count"] == 2
    items = body["items"]
    # Closer neighbour first.
    assert items[0]["session_id"] == str(close_snap.session_id)
    assert items[1]["session_id"] == str(far_snap.session_id)
    assert items[0]["similarity"] > items[1]["similarity"]
    # Each item includes basic session metadata.
    assert items[0]["session"]["source_ip"] == "203.0.113.7"
    assert items[0]["model"] == "embed-test"


async def test_similar_default_threshold_comes_from_settings(
    client: TestClient,
    dashboard_state: DashboardState,
    settings: AnglerfishSettings,
) -> None:
    """No ``min_similarity`` query param -> falls back to settings default."""
    query_snap = _snapshot()
    await dashboard_state.update_session(query_snap)
    await dashboard_state.upsert_embedding(
        _embedding(
            query_snap.session_id,
            vector=tuple(1.0 if i == 0 else 0.0 for i in range(64)),
        ),
    )
    r = client.get(f"/api/sessions/{query_snap.session_id}/similar")
    assert r.status_code == 200
    body = r.json()
    assert body["min_similarity"] == settings.bridge.cluster_similarity_threshold


async def test_similar_respects_k_query_param(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    query_snap = _snapshot()
    await dashboard_state.update_session(query_snap)
    await dashboard_state.upsert_embedding(
        _embedding(
            query_snap.session_id,
            vector=tuple(1.0 if i == 0 else 0.0 for i in range(64)),
        ),
    )
    for _ in range(5):
        snap = _snapshot()
        await dashboard_state.update_session(snap)
        await dashboard_state.upsert_embedding(
            _embedding(
                snap.session_id,
                vector=tuple(0.99 if i == 0 else 0.001 for i in range(64)),
            ),
        )
    body = client.get(
        f"/api/sessions/{query_snap.session_id}/similar?k=2&min_similarity=0.0",
    ).json()
    assert body["k"] == 2
    assert body["count"] == 2


async def test_similar_strict_threshold_returns_empty_items(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    query_snap = _snapshot()
    distant_snap = _snapshot()
    for snap in (query_snap, distant_snap):
        await dashboard_state.update_session(snap)
    await dashboard_state.upsert_embedding(
        _embedding(
            query_snap.session_id,
            vector=tuple(1.0 if i == 0 else 0.0 for i in range(64)),
        ),
    )
    await dashboard_state.upsert_embedding(
        _embedding(
            distant_snap.session_id,
            vector=tuple(0.0 if i == 0 else 1.0 / 63 for i in range(64)),
        ),
    )
    body = client.get(
        f"/api/sessions/{query_snap.session_id}/similar?min_similarity=0.99",
    ).json()
    assert body["items"] == []
    assert body["count"] == 0


async def test_similar_cross_model_neighbours_excluded(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    """Vectors from a different embed model are not comparable."""
    query_snap = _snapshot()
    cross_snap = _snapshot()
    for snap in (query_snap, cross_snap):
        await dashboard_state.update_session(snap)
    vec = tuple(1.0 if i == 0 else 0.0 for i in range(64))
    await dashboard_state.upsert_embedding(
        _embedding(query_snap.session_id, vector=vec, model="A"),
    )
    await dashboard_state.upsert_embedding(
        _embedding(cross_snap.session_id, vector=vec, model="B"),
    )
    body = client.get(
        f"/api/sessions/{query_snap.session_id}/similar?min_similarity=0.0",
    ).json()
    assert body["count"] == 0


def test_similar_rejects_out_of_range_k(client: TestClient) -> None:
    r = client.get(f"/api/sessions/{uuid4()}/similar?k=0")
    assert r.status_code == 422
    r = client.get(f"/api/sessions/{uuid4()}/similar?k=21")
    assert r.status_code == 422


def test_similar_rejects_out_of_range_min_similarity(client: TestClient) -> None:
    r = client.get(f"/api/sessions/{uuid4()}/similar?min_similarity=1.5")
    assert r.status_code == 422
    r = client.get(f"/api/sessions/{uuid4()}/similar?min_similarity=-0.1")
    assert r.status_code == 422
