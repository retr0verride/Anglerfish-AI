"""Stage 13 slice 13.4: STIX 2.1 bundle exporter."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from anglerfish.dashboard.exporters import build_stix_bundle
from anglerfish.honeytokens.schema import Honeytoken
from anglerfish.models import CommandTurn, ResponseSource, SessionSnapshot
from anglerfish.models.intent import IntentSummary

_NOW = datetime(2026, 5, 29, 12, 0, tzinfo=UTC)
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
        started_at=_NOW,
        last_activity_at=_NOW,
        turns=(
            CommandTurn(
                command="ls",
                response="",
                source=ResponseSource.AI,
                timestamp=_NOW,
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
        extracted_at=_NOW,
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
        created_at=_NOW,
    )


def _by_type(bundle: dict[str, Any], stix_type: str) -> list[dict[str, Any]]:
    return [o for o in bundle["objects"] if o["type"] == stix_type]


def test_stix_empty_window_is_identity_only() -> None:
    b = build_stix_bundle([], {}, [], generated=_NOW)
    assert b["type"] == "bundle"
    assert b["id"].startswith("bundle--")
    assert len(b["objects"]) == 1
    assert b["objects"][0]["type"] == "identity"


def test_stix_session_yields_observed_data_and_ip() -> None:
    s = _session()
    b = build_stix_bundle([s], {}, [], generated=_NOW)
    obs = _by_type(b, "observed-data")
    ips = _by_type(b, "ipv4-addr")
    assert len(obs) == 1
    assert len(ips) == 1
    assert ips[0]["value"] == "203.0.113.7"
    assert obs[0]["object_refs"] == [ips[0]["id"]]
    assert obs[0]["spec_version"] == "2.1"


def test_stix_one_indicator_per_technique() -> None:
    s = _session()
    intents = {str(s.session_id): _intent(s.session_id, techniques=("T1496", "T1078", "T1059"))}
    b = build_stix_bundle([s], intents, [], generated=_NOW)
    inds = _by_type(b, "indicator")
    ext_ids = sorted(ref["external_id"] for ind in inds for ref in ind["external_references"])
    assert ext_ids == ["T1059", "T1078", "T1496"]


def test_stix_intent_becomes_note() -> None:
    s = _session()
    b = build_stix_bundle([s], {str(s.session_id): _intent(s.session_id)}, [], generated=_NOW)
    notes = _by_type(b, "note")
    assert len(notes) == 1
    assert notes[0]["content"] == "Opportunistic cryptojacking."
    assert notes[0]["object_refs"] == [_by_type(b, "observed-data")[0]["id"]]


def test_stix_honeytoken_identifier_present_payload_absent() -> None:
    s = _session()
    b = build_stix_bundle([s], {}, [_honeytoken(s.session_id)], generated=_NOW)
    ht = [
        ind
        for ind in _by_type(b, "indicator")
        if any(r["source_name"] == "anglerfish-honeytoken" for r in ind["external_references"])
    ]
    assert len(ht) == 1
    assert ht[0]["external_references"][0]["external_id"] == _TOKEN_ID
    # The live decoy secret must never travel in a shareable bundle.
    assert _PAYLOAD not in json.dumps(b)


def test_stix_ids_are_deterministic() -> None:
    s = _session()
    b1 = build_stix_bundle([s], {}, [], generated=_NOW)
    b2 = build_stix_bundle([s], {}, [], generated=_NOW)
    assert _by_type(b1, "observed-data")[0]["id"] == _by_type(b2, "observed-data")[0]["id"]
