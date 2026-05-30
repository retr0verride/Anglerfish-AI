"""Stage 13 slice 13.4: MISP Event exporter."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

from anglerfish.dashboard.exporters import build_misp_event
from anglerfish.honeytokens.schema import Honeytoken
from anglerfish.models import CommandTurn, ResponseSource, SessionSnapshot
from anglerfish.models.intent import IntentSummary

_START = datetime(2026, 5, 28, 12, 0, tzinfo=UTC)
_END = datetime(2026, 5, 29, 12, 0, tzinfo=UTC)
_PAYLOAD = "SUPERSECRETtokenPAYLOAD"
_TOKEN_ID = "MFRGGZDFMZTWQ2LK"


def _session(source_ip: str = "203.0.113.7") -> SessionSnapshot:
    return SessionSnapshot(
        session_id=uuid4(),
        source_ip=source_ip,
        username="root",
        fake_hostname="srv",
        fake_username="root",
        fake_cwd="/root",
        started_at=_START,
        last_activity_at=_END,
        turns=(
            CommandTurn(
                command="ls",
                response="",
                source=ResponseSource.AI,
                timestamp=_START,
                latency_ms=1.0,
            ),
        ),
    )


def _intent(sid: UUID, *, techniques: tuple[str, ...] = ("T1496", "T1078")) -> IntentSummary:
    return IntentSummary(
        session_id=sid,
        actor_profile="opportunistic",
        intent="cryptojacking",
        why="deployed a miner",
        matched_techniques=techniques,
        confidence="high",
        summary="Opportunistic cryptojacking.",
        extracted_at=_START,
    )


def _honeytoken(sid: UUID) -> Honeytoken:
    return Honeytoken(
        id=_TOKEN_ID,
        kind="aws",
        payload=_PAYLOAD,
        callback_url="https://cb.example/h1",
        placed_at="/root/.aws/credentials",
        source_ip="203.0.113.7",
        session_id=sid,
        created_at=_START,
    )


def test_misp_empty_window() -> None:
    event = build_misp_event([], {}, [], start=_START, end=_END)["Event"]
    assert event["Attribute"] == []
    assert event["Tag"] == []
    assert event["uuid"]
    assert event["published"] is False


def test_misp_source_ip_attributes_deduped() -> None:
    sessions = [_session("203.0.113.7"), _session("203.0.113.7"), _session("198.51.100.9")]
    event = build_misp_event(sessions, {}, [], start=_START, end=_END)["Event"]
    ips = sorted(a["value"] for a in event["Attribute"] if a["type"] == "ip-src")
    assert ips == ["198.51.100.9", "203.0.113.7"]


def test_misp_honeytoken_identifier_attr_payload_absent() -> None:
    s = _session()
    event = build_misp_event([s], {}, [_honeytoken(s.session_id)], start=_START, end=_END)
    attrs = event["Event"]["Attribute"]
    assert any(a["type"] == "text" and a["value"] == _TOKEN_ID for a in attrs)
    assert any(a["type"] == "url" and "cb.example" in a["value"] for a in attrs)
    assert _PAYLOAD not in json.dumps(event)


def test_misp_techniques_as_galaxy_tags() -> None:
    s = _session()
    intents = {str(s.session_id): _intent(s.session_id, techniques=("T1496", "T1078"))}
    event = build_misp_event([s], intents, [], start=_START, end=_END)["Event"]
    tags = sorted(t["name"] for t in event["Tag"])
    assert tags == [
        'misp-galaxy:mitre-attack-pattern="T1078"',
        'misp-galaxy:mitre-attack-pattern="T1496"',
    ]


def test_misp_event_uuid_deterministic() -> None:
    e1 = build_misp_event([], {}, [], start=_START, end=_END)["Event"]
    e2 = build_misp_event([], {}, [], start=_START, end=_END)["Event"]
    assert e1["uuid"] == e2["uuid"]
