"""Hand-built STIX 2.1 bundle exporter (Stage 13 slice 13.4).

No ``stix2`` library dependency: the bundle is assembled as plain dicts
against the 2.1 JSON shape. Each session becomes an ``observed-data``
object referencing an ``ipv4-addr`` SCO for the attacker IP; each
matched MITRE technique and each honeytoken becomes an ``indicator``;
the intent summary becomes a ``note``. Honeytoken payloads (the live
decoy secrets) are never emitted: only the token identifier and the
callback URL travel, so a bundle shared with a feed cannot leak a
working beacon. Object IDs are deterministic (UUIDv5) so re-exporting
the same data yields a stable, dedupe-able bundle.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid5

if TYPE_CHECKING:
    from anglerfish.honeytokens.schema import Honeytoken
    from anglerfish.models.intent import IntentSummary
    from anglerfish.models.session import SessionSnapshot

__all__ = ["build_stix_bundle"]

# Fixed namespace so identical input produces identical object IDs.
_NAMESPACE = UUID("1b671a64-40d5-491e-99b0-da01ff1f3341")
_IDENTITY_ID = f"identity--{uuid5(_NAMESPACE, 'anglerfish-honeypot')}"


def _ts(value: datetime) -> str:
    """STIX 2.1 timestamp: RFC3339, UTC, millisecond precision, Z suffix."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _oid(stix_type: str, name: str) -> str:
    """Deterministic ``type--uuid`` STIX id for ``name``."""
    return f"{stix_type}--{uuid5(_NAMESPACE, name)}"


def _technique_indicator(
    session: SessionSnapshot,
    tech: str,
    now: str,
) -> dict[str, Any]:
    """An indicator tying a matched ATT&CK technique to the attacker IP."""
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _oid("indicator", f"tech:{session.session_id}:{tech}"),
        "created": now,
        "modified": now,
        "created_by_ref": _IDENTITY_ID,
        "name": f"ATT&CK {tech} observed from {session.source_ip}",
        "indicator_types": ["malicious-activity"],
        "pattern": f"[ipv4-addr:value = '{session.source_ip}']",
        "pattern_type": "stix",
        "valid_from": _ts(session.started_at),
        "external_references": [
            {"source_name": "mitre-attack", "external_id": tech},
        ],
    }


def _honeytoken_indicator(token: Honeytoken, now: str) -> dict[str, Any]:
    """An indicator for a honeytoken: identifier and callback only, no payload."""
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _oid("indicator", f"honeytoken:{token.id}"),
        "created": now,
        "modified": now,
        "created_by_ref": _IDENTITY_ID,
        "name": f"Honeytoken {token.id} ({token.kind})",
        "indicator_types": ["attribution"],
        "pattern": f"[url:value = '{token.callback_url}']",
        "pattern_type": "stix",
        "valid_from": _ts(token.created_at),
        "external_references": [
            {"source_name": "anglerfish-honeytoken", "external_id": token.id},
        ],
    }


def build_stix_bundle(
    sessions: list[SessionSnapshot],
    intents_by_session: dict[str, IntentSummary],
    honeytokens: list[Honeytoken],
    *,
    generated: datetime,
) -> dict[str, Any]:
    """Assemble a STIX 2.1 bundle from a window's sessions and intel."""
    now = _ts(generated)
    identity: dict[str, Any] = {
        "type": "identity",
        "spec_version": "2.1",
        "id": _IDENTITY_ID,
        "created": now,
        "modified": now,
        "name": "Anglerfish AI Honeypot",
        "identity_class": "system",
    }
    objects: list[dict[str, Any]] = [identity]
    seen_ip_scos: set[str] = set()

    for session in sessions:
        sid = str(session.session_id)
        ip_id = _oid("ipv4-addr", f"ip:{session.source_ip}")
        if ip_id not in seen_ip_scos:
            seen_ip_scos.add(ip_id)
            objects.append(
                {
                    "type": "ipv4-addr",
                    "spec_version": "2.1",
                    "id": ip_id,
                    "value": session.source_ip,
                },
            )
        observed_id = _oid("observed-data", f"session:{sid}")
        objects.append(
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": observed_id,
                "created": now,
                "modified": now,
                "created_by_ref": _IDENTITY_ID,
                "first_observed": _ts(session.started_at),
                "last_observed": _ts(session.last_activity_at),
                "number_observed": max(1, len(session.turns)),
                "object_refs": [ip_id],
            },
        )
        intent = intents_by_session.get(sid)
        if intent is None:
            continue
        objects.append(
            {
                "type": "note",
                "spec_version": "2.1",
                "id": _oid("note", f"intent:{sid}"),
                "created": now,
                "modified": now,
                "created_by_ref": _IDENTITY_ID,
                "abstract": f"Intent: {intent.intent}",
                "content": intent.summary,
                "object_refs": [observed_id],
            },
        )
        objects.extend(
            _technique_indicator(session, tech, now) for tech in intent.matched_techniques
        )

    objects.extend(_honeytoken_indicator(token, now) for token in honeytokens)

    return {
        "type": "bundle",
        "id": _oid("bundle", f"export:{now}"),
        "objects": objects,
    }
