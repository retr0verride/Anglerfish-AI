"""Stage 13 slice 13.2: GET /api/clusters cross-session similarity graph.

Edges are same-model cosine similarities over the Stage 8 embeddings,
thresholded and symmetric-deduped; nodes are the newest ``limit``
embeddings enriched with session/threat/intent context.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from anglerfish.audit import AuditLog
from anglerfish.config import AnglerfishSettings
from anglerfish.dashboard import create_app
from anglerfish.dashboard.state import DashboardState
from anglerfish.models import CommandTurn, ResponseSource, SessionSnapshot
from anglerfish.models.embedding import SessionEmbedding
from anglerfish.models.intent import IntentSummary
from anglerfish.models.threat import ThreatAssessment

_BASE = datetime(2026, 5, 28, 12, 0, tzinfo=UTC)


@pytest.fixture
def client(
    settings: AnglerfishSettings,
    tmp_path: Path,
    dashboard_state: DashboardState,
) -> Iterator[TestClient]:
    audit = AuditLog(tmp_path / "audit.jsonl")
    app = create_app(settings, state=dashboard_state, audit=audit)
    with TestClient(app) as c:
        yield c


def _snapshot(
    *,
    session_id: UUID | None = None,
    source_ip: str = "203.0.113.7",
    persona: str | None = None,
) -> SessionSnapshot:
    return SessionSnapshot(
        session_id=session_id or uuid4(),
        source_ip=source_ip,
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=_BASE,
        last_activity_at=_BASE,
        turns=(
            CommandTurn(
                command="ls",
                response="",
                source=ResponseSource.AI,
                timestamp=_BASE,
                latency_ms=1.0,
            ),
        ),
        persona_name=persona,
    )


def _vec(lead: float, *, dim: int = 0) -> tuple[float, ...]:
    """64-dim vector with ``lead`` at ``dim`` and a small floor elsewhere."""
    return tuple(lead if i == dim else 0.001 for i in range(64))


def _embedding(
    session_id: UUID,
    *,
    vector: tuple[float, ...],
    model: str = "embed-test",
    at: datetime = _BASE,
) -> SessionEmbedding:
    return SessionEmbedding(
        session_id=session_id,
        vector=vector,
        dimension=len(vector),
        model=model,
        generated_at=at,
    )


async def _add(
    state: DashboardState,
    *,
    vector: tuple[float, ...],
    model: str = "embed-test",
    at: datetime = _BASE,
    persona: str | None = None,
) -> UUID:
    """Persist a session + its embedding; return the session id."""
    snap = _snapshot(persona=persona)
    await state.update_session(snap)
    await state.upsert_embedding(
        _embedding(snap.session_id, vector=vector, model=model, at=at),
    )
    return snap.session_id


# ---------------------------------------------------------------------------
# Empty graph
# ---------------------------------------------------------------------------


def test_clusters_empty_when_no_embeddings(client: TestClient) -> None:
    r = client.get("/api/clusters")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["nodes"] == []
    assert body["edges"] == []


# ---------------------------------------------------------------------------
# Thresholded, symmetric-deduped edge set
# ---------------------------------------------------------------------------


async def test_clusters_edges_thresholded_and_deduped(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    a = await _add(dashboard_state, vector=_vec(1.0))
    b = await _add(dashboard_state, vector=_vec(0.99))  # ~1.0 cosine with a
    far = await _add(dashboard_state, vector=_vec(1.0, dim=1))  # orthogonal-ish

    r = client.get("/api/clusters?min_similarity=0.85")
    assert r.status_code == 200, r.text
    edges = r.json()["edges"]

    # Exactly one edge, between a and b, emitted once (not a-b and b-a).
    assert len(edges) == 1
    pair = {edges[0]["a"], edges[0]["b"]}
    assert pair == {str(a), str(b)}
    assert str(far) not in pair
    assert edges[0]["similarity"] >= 0.85
    # All three sessions are still nodes even though `far` has no edge.
    assert len(r.json()["nodes"]) == 3


# ---------------------------------------------------------------------------
# Node cap drops oldest-first
# ---------------------------------------------------------------------------


async def test_clusters_node_cap_drops_oldest_first(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    oldest = await _add(dashboard_state, vector=_vec(1.0), at=_BASE)
    mid = await _add(dashboard_state, vector=_vec(1.0), at=_BASE + timedelta(minutes=1))
    newest = await _add(
        dashboard_state,
        vector=_vec(1.0),
        at=_BASE + timedelta(minutes=2),
    )

    r = client.get("/api/clusters?limit=2")
    assert r.status_code == 200, r.text
    ids = {n["session_id"] for n in r.json()["nodes"]}

    assert ids == {str(mid), str(newest)}
    assert str(oldest) not in ids


# ---------------------------------------------------------------------------
# since filter
# ---------------------------------------------------------------------------


async def test_clusters_since_filter_excludes_older(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    old = await _add(dashboard_state, vector=_vec(1.0), at=_BASE)
    recent = await _add(
        dashboard_state,
        vector=_vec(1.0),
        at=_BASE + timedelta(hours=2),
    )
    cutoff = (_BASE + timedelta(hours=1)).isoformat()

    r = client.get("/api/clusters", params={"since": cutoff})
    assert r.status_code == 200, r.text
    ids = {n["session_id"] for n in r.json()["nodes"]}

    assert ids == {str(recent)}
    assert str(old) not in ids


def test_clusters_rejects_bad_since(client: TestClient) -> None:
    r = client.get("/api/clusters?since=not-a-timestamp")
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Cross-model vectors are never compared
# ---------------------------------------------------------------------------


async def test_clusters_cross_model_not_compared(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    await _add(dashboard_state, vector=_vec(1.0), model="model-a")
    await _add(dashboard_state, vector=_vec(0.99), model="model-b")

    r = client.get("/api/clusters?min_similarity=0.85")
    assert r.status_code == 200, r.text
    # Identical vectors, different embedding spaces: no edge.
    assert r.json()["edges"] == []
    assert len(r.json()["nodes"]) == 2


# ---------------------------------------------------------------------------
# Node enrichment
# ---------------------------------------------------------------------------


async def test_clusters_nodes_enriched(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    snap = _snapshot(source_ip="198.51.100.9", persona="gpu-rig")
    await dashboard_state.update_session(snap)
    await dashboard_state.upsert_embedding(
        _embedding(snap.session_id, vector=_vec(1.0)),
    )
    await dashboard_state.record_threat(
        ThreatAssessment(session_id=snap.session_id, score=77),
    )
    await dashboard_state.upsert_intent(
        IntentSummary(
            session_id=snap.session_id,
            actor_profile="opportunistic",
            intent="cryptojacking",
            why="deployed a miner",
            matched_techniques=("T1496",),
            confidence="high",
            summary="Opportunistic cryptojacking.",
            extracted_at=_BASE,
        ),
    )

    r = client.get("/api/clusters")
    assert r.status_code == 200, r.text
    nodes = r.json()["nodes"]
    assert len(nodes) == 1
    node = nodes[0]
    assert node["session_id"] == str(snap.session_id)
    assert node["source_ip"] == "198.51.100.9"
    assert node["persona"] == "gpu-rig"
    assert node["threat_score"] == 77
    assert node["intent_label"] == "cryptojacking"
