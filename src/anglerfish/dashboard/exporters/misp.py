"""Hand-built MISP Event-JSON exporter (Stage 13 slice 13.4).

No ``pymisp`` dependency: the Event is assembled as plain dicts against
the MISP JSON shape. Source IPs become ``ip-src`` attributes, honeytoken
identifiers and callback URLs become attributes, and matched MITRE
techniques become MISP galaxy cluster tags. Honeytoken payloads are
never emitted; only the token identifier and callback URL travel.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid5

if TYPE_CHECKING:
    from anglerfish.honeytokens.schema import Honeytoken
    from anglerfish.models.intent import IntentSummary
    from anglerfish.models.session import SessionSnapshot

__all__ = ["build_misp_event"]

_NAMESPACE = UUID("1b671a64-40d5-491e-99b0-da01ff1f3341")


def build_misp_event(
    sessions: list[SessionSnapshot],
    intents_by_session: dict[str, IntentSummary],
    honeytokens: list[Honeytoken],
    *,
    start: datetime,
    end: datetime,
) -> dict[str, Any]:
    """Assemble one MISP Event for the export window."""
    attributes: list[dict[str, Any]] = []
    seen_ips: set[str] = set()
    for session in sessions:
        if session.source_ip in seen_ips:
            continue
        seen_ips.add(session.source_ip)
        attributes.append(
            {
                "type": "ip-src",
                "category": "Network activity",
                "value": session.source_ip,
                "to_ids": True,
                "comment": "honeypot attacker source",
            },
        )
    for token in honeytokens:
        attributes.append(
            {
                "type": "text",
                "category": "Internal reference",
                "value": token.id,
                "to_ids": False,
                "comment": f"honeytoken {token.kind} (identifier only; payload withheld)",
            },
        )
        attributes.append(
            {
                "type": "url",
                "category": "Network activity",
                "value": token.callback_url,
                "to_ids": True,
                "comment": f"honeytoken {token.id} callback",
            },
        )

    techniques: set[str] = set()
    for intent in intents_by_session.values():
        techniques.update(intent.matched_techniques)
    tags = [{"name": f'misp-galaxy:mitre-attack-pattern="{tech}"'} for tech in sorted(techniques)]

    event_uuid = str(uuid5(_NAMESPACE, f"misp:{start.isoformat()}:{end.isoformat()}"))
    return {
        "Event": {
            "uuid": event_uuid,
            "info": f"Anglerfish honeypot export {start.date()} to {end.date()}",
            "date": end.strftime("%Y-%m-%d"),
            "threat_level_id": "2",
            "analysis": "2",
            "published": False,
            "Attribute": attributes,
            "Tag": tags,
        },
    }
