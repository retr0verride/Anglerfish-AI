"""Stage 13 slice 13.1: GET /api/sessions/{id}/detail aggregate endpoint.

The detail handler composes store reads (session, turns, intent, persona,
honeytokens, cluster neighbours) with two facts that live only in the
audit log (time_wasted_ms, counter_deception). These tests populate the
shared store via :class:`DashboardState` and seed audit events directly.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from anglerfish.audit import AuditLog
from anglerfish.config import AnglerfishSettings
from anglerfish.dashboard import create_app
from anglerfish.dashboard.state import DashboardState
from anglerfish.honeytokens.schema import Honeytoken
from anglerfish.models import CommandTurn, ResponseSource, SessionSnapshot
from anglerfish.models.embedding import SessionEmbedding
from anglerfish.models.intent import IntentSummary

_SOURCE_IP = "203.0.113.7"
_HONEYTOKEN_ID = "MFRGGZDFMZTWQ2LK"


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture
def client(
    settings: AnglerfishSettings,
    audit: AuditLog,
    dashboard_state: DashboardState,
) -> Iterator[TestClient]:
    app = create_app(settings, state=dashboard_state, audit=audit)
    with TestClient(app) as c:
        yield c


def _turn(command: str, *, at: datetime) -> CommandTurn:
    return CommandTurn(
        command=command,
        response="ok",
        source=ResponseSource.AI,
        timestamp=at,
        latency_ms=1.0,
    )


def _snapshot(
    *,
    session_id: UUID | None = None,
    persona: str | None = None,
    turns: Sequence[CommandTurn] = (),
) -> SessionSnapshot:
    now = datetime(2026, 5, 28, 12, 0, tzinfo=UTC)
    return SessionSnapshot(
        session_id=session_id or uuid4(),
        source_ip=_SOURCE_IP,
        username="root",
        fake_hostname="srv-prod-01",
        fake_username="root",
        fake_cwd="/root",
        started_at=now,
        last_activity_at=now,
        turns=tuple(turns),
        persona_name=persona,
    )


def _embedding(session_id: UUID, *, lead: float) -> SessionEmbedding:
    vec = tuple(lead if i == 0 else 0.001 for i in range(64))
    return SessionEmbedding(
        session_id=session_id,
        vector=vec,
        dimension=len(vec),
        model="embed-test",
        generated_at=datetime(2026, 5, 28, 12, 30, tzinfo=UTC),
    )


def _honeytoken(session_id: UUID) -> Honeytoken:
    return Honeytoken(
        id=_HONEYTOKEN_ID,
        kind="aws",
        payload="AKIAEXAMPLE",
        callback_url="https://cb.example/ht-aws-1",
        placed_at="/root/.aws/credentials",
        source_ip=_SOURCE_IP,
        session_id=session_id,
        created_at=datetime(2026, 5, 28, 12, 5, tzinfo=UTC),
    )


def _intent(session_id: UUID) -> IntentSummary:
    return IntentSummary(
        session_id=session_id,
        actor_profile="opportunistic",
        intent="cryptojacking",
        why="deployed a miner pointed at an external pool",
        matched_techniques=("T1496", "T1078"),
        confidence="high",
        summary="Opportunistic cryptojacking.",
        extracted_at=datetime(2026, 5, 28, 12, 20, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# 404
# ---------------------------------------------------------------------------


def test_detail_404_when_session_unknown(client: TestClient) -> None:
    r = client.get(f"/api/sessions/{uuid4()}/detail")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Bare session: capability sections are null/empty, not errors.
# ---------------------------------------------------------------------------


async def test_detail_null_sections_when_capabilities_absent(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    snap = _snapshot()
    await dashboard_state.update_session(snap)

    r = client.get(f"/api/sessions/{snap.session_id}/detail")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["session"]["session_id"] == str(snap.session_id)
    assert body["persona"] is None
    assert body["intent"] is None
    assert body["counter_deception"] is None
    assert body["honeytokens"] == []
    assert body["similar"] == []
    assert body["time_wasted_ms"] == 0


# ---------------------------------------------------------------------------
# Turns preserve insertion order.
# ---------------------------------------------------------------------------


async def test_detail_returns_turns_in_order(
    client: TestClient,
    dashboard_state: DashboardState,
) -> None:
    base = datetime(2026, 5, 28, 12, 0, tzinfo=UTC)
    snap = _snapshot(
        turns=(
            _turn("first", at=base),
            _turn("second", at=base.replace(second=1)),
            _turn("third", at=base.replace(second=2)),
        ),
    )
    await dashboard_state.update_session(snap)

    r = client.get(f"/api/sessions/{snap.session_id}/detail")

    assert r.status_code == 200, r.text
    assert [t["command"] for t in r.json()["turns"]] == ["first", "second", "third"]


# ---------------------------------------------------------------------------
# time_wasted_ms sums this session's wasting_applied deltas only.
# ---------------------------------------------------------------------------


async def test_detail_time_wasted_sums_this_session_only(
    client: TestClient,
    dashboard_state: DashboardState,
    audit: AuditLog,
) -> None:
    snap = _snapshot()
    other = _snapshot()
    await dashboard_state.update_session(snap)
    await dashboard_state.update_session(other)
    for ms in (1200, 800):
        audit.record(
            "bridge.wasting_applied",
            session_id=str(snap.session_id),
            attacker_ip=_SOURCE_IP,
            strategy="molasses",
            wasted_ms=ms,
        )
    # A different session's wasting must not bleed into the total.
    audit.record(
        "bridge.wasting_applied",
        session_id=str(other.session_id),
        attacker_ip=_SOURCE_IP,
        strategy="molasses",
        wasted_ms=5000,
    )

    r = client.get(f"/api/sessions/{snap.session_id}/detail")

    assert r.status_code == 200, r.text
    assert r.json()["time_wasted_ms"] == 2000


# ---------------------------------------------------------------------------
# counter_deception is built from the engaged event; no timebomb_intensity.
# ---------------------------------------------------------------------------


async def test_detail_counter_deception_from_engaged_event(
    client: TestClient,
    dashboard_state: DashboardState,
    audit: AuditLog,
) -> None:
    snap = _snapshot()
    await dashboard_state.update_session(snap)
    audit.record(
        "bridge.counter_deception_engaged",
        session_id=str(snap.session_id),
        attacker_ip=_SOURCE_IP,
        mode="both",
        trigger="threshold",
        garble_paths_count=2,
        timebomb_thresholds=[5, 12],
        threat_score=80,
    )

    r = client.get(f"/api/sessions/{snap.session_id}/detail")

    assert r.status_code == 200, r.text
    cd = r.json()["counter_deception"]
    assert cd is not None
    assert cd["mode"] == "both"
    assert cd["garble_paths_count"] == 2
    assert cd["engaged_at"]  # ISO timestamp string is present
    # Time-bomb intensity is escalating in-process state, never persisted.
    assert "timebomb_intensity" not in cd


# ---------------------------------------------------------------------------
# Malformed audit fields degrade gracefully rather than 500.
# ---------------------------------------------------------------------------


async def test_detail_tolerates_malformed_audit_fields(
    client: TestClient,
    dashboard_state: DashboardState,
    audit: AuditLog,
) -> None:
    snap = _snapshot()
    await dashboard_state.update_session(snap)
    # wasted_ms is not an int: skipped, not summed.
    audit.record(
        "bridge.wasting_applied",
        session_id=str(snap.session_id),
        attacker_ip=_SOURCE_IP,
        strategy="molasses",
        wasted_ms="not-a-number",
    )
    # engaged event without garble_paths_count: surfaced as None.
    audit.record(
        "bridge.counter_deception_engaged",
        session_id=str(snap.session_id),
        attacker_ip=_SOURCE_IP,
        mode="garble",
        trigger="pin",
    )

    r = client.get(f"/api/sessions/{snap.session_id}/detail")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["time_wasted_ms"] == 0
    assert body["counter_deception"]["mode"] == "garble"
    assert body["counter_deception"]["garble_paths_count"] is None


# ---------------------------------------------------------------------------
# Full composition: every section populated from a single fetch.
# ---------------------------------------------------------------------------


async def test_detail_composes_all_sections(
    client: TestClient,
    dashboard_state: DashboardState,
    audit: AuditLog,
) -> None:
    base = datetime(2026, 5, 28, 12, 0, tzinfo=UTC)
    snap = _snapshot(persona="gpu-rig", turns=(_turn("whoami", at=base),))
    neighbour = _snapshot()
    await dashboard_state.update_session(snap)
    await dashboard_state.update_session(neighbour)
    await dashboard_state.upsert_embedding(_embedding(snap.session_id, lead=1.0))
    await dashboard_state.upsert_embedding(_embedding(neighbour.session_id, lead=0.99))
    await dashboard_state.upsert_intent(_intent(snap.session_id))
    assert await dashboard_state.register_honeytoken(_honeytoken(snap.session_id))
    audit.record(
        "bridge.wasting_applied",
        session_id=str(snap.session_id),
        attacker_ip=_SOURCE_IP,
        strategy="molasses",
        wasted_ms=4200,
    )
    audit.record(
        "bridge.counter_deception_engaged",
        session_id=str(snap.session_id),
        attacker_ip=_SOURCE_IP,
        mode="both",
        trigger="threshold",
        garble_paths_count=2,
        timebomb_thresholds=[5, 12],
        threat_score=80,
    )

    r = client.get(f"/api/sessions/{snap.session_id}/detail")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["session"]["session_id"] == str(snap.session_id)
    assert body["persona"] == "gpu-rig"
    assert [t["command"] for t in body["turns"]] == ["whoami"]
    assert body["intent"]["intent"] == "cryptojacking"
    assert body["intent"]["matched_techniques"] == ["T1496", "T1078"]
    assert body["time_wasted_ms"] == 4200
    assert len(body["honeytokens"]) == 1
    assert body["honeytokens"][0]["id"] == _HONEYTOKEN_ID
    assert body["counter_deception"]["mode"] == "both"
    assert [n["session_id"] for n in body["similar"]] == [str(neighbour.session_id)]
