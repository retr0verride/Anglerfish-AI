"""Per-session PDF report builder (Stage 13 slice 13.4).

Renders one session's detail view (the same aggregate the
``/api/sessions/{id}/detail`` endpoint serves) to a PDF for sharing with
a SOC: header, intent summary, counter-deception state, honeytokens
served, command turns, and cluster neighbours.

``reportlab`` is imported lazily inside :func:`build_pdf_report` so the
exporters package stays importable without it (it is a dashboard-only
optional dependency) and the dependency is confined to this one code
path. Attacker-controlled text (commands, responses) is XML-escaped
before it reaches a reportlab ``Paragraph``, whose markup mini-language
would otherwise interpret ``<`` / ``&``; escaped text renders as a plain
run. Honeytoken secret payloads are never rendered: a PDF may be shared,
so only identifiers travel, matching the STIX/MISP default.
"""

from __future__ import annotations

import io
from typing import Any
from xml.sax.saxutils import escape

__all__ = ["build_pdf_report"]

# Bound the per-turn text rendered into the PDF. The session store
# already caps command/response length; this is a second, report-local
# guard so a maxed-out turn cannot blow up a single table cell.
_TURN_TEXT_CAP = 2000
_MAX_TURNS = 200


def build_pdf_report(detail: dict[str, Any]) -> bytes:
    """Render a session-detail aggregate to PDF bytes.

    ``detail`` is the dict shape returned by the ``/detail`` endpoint:
    ``session``, ``turns``, ``intent``, ``persona``, ``time_wasted_ms``,
    ``honeytokens``, ``counter_deception``, ``similar``.
    """
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.pdfgen.canvas import Canvas
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    styles = getSampleStyleSheet()
    mono = ParagraphStyle(
        "Turn",
        parent=styles["Code"],
        alignment=TA_LEFT,
        spaceAfter=4,
    )

    session = detail["session"]
    flow: list[Any] = []

    flow.append(Paragraph(f"Session {_esc(session.get('session_id'))}", styles["Title"]))
    flow.append(Paragraph(_session_header_line(detail), styles["Normal"]))
    flow.append(Spacer(1, 12))

    _append_intent(flow, detail.get("intent"), styles)
    _append_counter_deception(flow, detail.get("counter_deception"), styles)
    _append_honeytokens(flow, detail.get("honeytokens", []), styles)
    _append_turns(flow, detail.get("turns", []), styles, mono)
    _append_similar(flow, detail.get("similar", []), styles)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, title="Anglerfish session report")

    # Page compression off: the rendered text streams stay inspectable
    # (the security properties - no honeytoken payload, attacker markup
    # shown as literal data - are asserted against the bytes) and the
    # output is deterministic. Session reports are small; the size cost
    # is negligible.
    def _uncompressed_canvas(*args: Any, **kwargs: Any) -> Any:
        kwargs["pageCompression"] = 0
        return Canvas(*args, **kwargs)

    doc.build(flow, canvasmaker=_uncompressed_canvas)
    return buffer.getvalue()


def _session_header_line(detail: dict[str, Any]) -> str:
    session = detail["session"]
    persona = detail.get("persona") or "none"
    wasted_s = round(detail.get("time_wasted_ms", 0) / 1000, 1)
    return (
        f"source {_esc(session.get('source_ip'))} | "
        f"persona {_esc(persona)} | "
        f"started {_esc(session.get('started_at'))} | "
        f"last activity {_esc(session.get('last_activity_at'))} | "
        f"time-wasted {wasted_s}s"
    )


def _append_intent(flow: list[Any], intent: Any, styles: Any) -> None:
    from reportlab.platypus import Paragraph, Spacer

    if not intent:
        return
    flow.append(
        Paragraph(f"Intent (confidence: {_esc(intent.get('confidence'))})", styles["Heading2"])
    )
    flow.append(Paragraph(_esc(intent.get("summary")), styles["Normal"]))
    techniques = ", ".join(intent.get("matched_techniques", []))
    if techniques:
        flow.append(Paragraph(f"Matched techniques: {_esc(techniques)}", styles["Normal"]))
    flow.append(Spacer(1, 10))


def _append_counter_deception(flow: list[Any], cd: Any, styles: Any) -> None:
    from reportlab.platypus import Paragraph, Spacer

    if not cd:
        return
    flow.append(Paragraph("Counter-deception", styles["Heading2"]))
    flow.append(
        Paragraph(
            f"mode {_esc(cd.get('mode'))} | "
            f"engaged {_esc(cd.get('engaged_at'))} | "
            f"garbled {cd.get('garble_paths_count', 0)} file(s)",
            styles["Normal"],
        ),
    )
    flow.append(Spacer(1, 10))


def _append_honeytokens(flow: list[Any], tokens: list[dict[str, Any]], styles: Any) -> None:
    from reportlab.platypus import Paragraph, Spacer

    if not tokens:
        return
    flow.append(Paragraph("Honeytokens served", styles["Heading2"]))
    # Identifiers and kinds only; the secret payload is never rendered.
    flow.extend(
        Paragraph(f"{_esc(token.get('id'))} ({_esc(token.get('kind'))})", styles["Normal"])
        for token in tokens
    )
    flow.append(Spacer(1, 10))


def _append_turns(
    flow: list[Any],
    turns: list[dict[str, Any]],
    styles: Any,
    mono: Any,
) -> None:
    from reportlab.platypus import Paragraph, Spacer

    flow.append(Paragraph("Turns", styles["Heading2"]))
    if not turns:
        flow.append(Paragraph("(no commands recorded)", styles["Normal"]))
        return
    for turn in turns[:_MAX_TURNS]:
        command = _esc(_clip(turn.get("command")))
        response = _esc(_clip(turn.get("response")))
        flow.append(Paragraph(f"$ {command}", mono))
        if response:
            flow.append(Paragraph(response, mono))
    if len(turns) > _MAX_TURNS:
        flow.append(
            Paragraph(f"... {len(turns) - _MAX_TURNS} more turn(s) omitted", styles["Italic"])
        )
    flow.append(Spacer(1, 10))


def _append_similar(flow: list[Any], similar: list[dict[str, Any]], styles: Any) -> None:
    from reportlab.platypus import Paragraph

    if not similar:
        return
    flow.append(Paragraph("Similar sessions", styles["Heading2"]))
    flow.extend(
        Paragraph(
            f"{_esc(neighbour.get('session_id'))} (similarity {neighbour.get('similarity')})",
            styles["Normal"],
        )
        for neighbour in similar
    )


def _clip(value: Any) -> str:
    text = "" if value is None else str(value)
    if len(text) > _TURN_TEXT_CAP:
        return text[:_TURN_TEXT_CAP] + " ..."
    return text


def _esc(value: Any) -> str:
    """XML-escape a value for safe rendering inside a reportlab Paragraph."""
    return escape("" if value is None else str(value))
