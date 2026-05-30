"""Stage 13 slice 13.4: per-session PDF report builder."""

from __future__ import annotations

from typing import Any

from anglerfish.dashboard.exporters import build_pdf_report


def _detail(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "session": {
            "session_id": "7f3aSESSIONID",
            "source_ip": "192.0.2.10",
            "started_at": "2026-05-29T12:00:00Z",
            "last_activity_at": "2026-05-29T12:21:00Z",
        },
        "turns": [{"command": "whoami", "response": "root"}],
        "intent": {
            "confidence": "high",
            "summary": "OpportunisticCRYPTOJACK",
            "matched_techniques": ["T1496", "T1078"],
        },
        "persona": "gpu-rig",
        "time_wasted_ms": 252000,
        "honeytokens": [{"id": "MFRGGZDFMZTWQ2LK", "kind": "aws", "payload": "SECRETPAYLOAD"}],
        "counter_deception": {"mode": "both", "engaged_at": "x", "garble_paths_count": 2},
        "similar": [{"session_id": "3a1fNEIGHBOUR", "similarity": 0.94}],
    }
    base.update(overrides)
    return base


def test_starts_with_pdf_magic() -> None:
    pdf = build_pdf_report(_detail())
    assert pdf[:4] == b"%PDF"


def test_rendered_text_contains_session_facts() -> None:
    # Page compression is off, so rendered runs are inspectable in the bytes.
    pdf = build_pdf_report(_detail())
    assert b"7f3aSESSIONID" in pdf
    assert b"OpportunisticCRYPTOJACK" in pdf
    assert b"gpu-rig" in pdf
    assert b"both" in pdf  # counter-deception mode
    assert b"T1496" in pdf  # matched technique
    assert b"3a1fNEIGHBOUR" in pdf  # similar session


def test_honeytoken_payload_never_rendered() -> None:
    pdf = build_pdf_report(_detail())
    assert b"MFRGGZDFMZTWQ2LK" in pdf  # identifier shown
    assert b"SECRETPAYLOAD" not in pdf  # secret payload withheld


def test_attacker_markup_is_escaped_not_interpreted() -> None:
    # Without escaping, reportlab's Paragraph parser would choke on the
    # tag-shaped text; escaping makes it render as literal data instead.
    detail = _detail(
        turns=[{"command": "cat <script>evil()</script> && id", "response": "<b>x</b> & y"}],
    )
    pdf = build_pdf_report(detail)
    assert pdf[:4] == b"%PDF"
    assert b"script" in pdf
    assert b"evil" in pdf


def test_turn_and_text_caps_applied() -> None:
    # More turns than _MAX_TURNS and a turn longer than _TURN_TEXT_CAP
    # both render without blowing up; the overflow notice appears.
    turns = [{"command": f"cmd{i}", "response": ""} for i in range(205)]
    turns[0] = {"command": "A" * 3000, "response": ""}
    pdf = build_pdf_report(_detail(turns=turns))
    assert pdf[:4] == b"%PDF"
    assert b"omitted" in pdf  # the >_MAX_TURNS overflow notice


def test_null_sections_omitted() -> None:
    detail = _detail(intent=None, counter_deception=None, honeytokens=[], similar=[], turns=[])
    pdf = build_pdf_report(detail)
    assert pdf[:4] == b"%PDF"
    assert b"no commands recorded" in pdf
    # Section headings for the omitted capabilities are absent.
    assert b"Counter-deception" not in pdf
    assert b"Honeytokens served" not in pdf
