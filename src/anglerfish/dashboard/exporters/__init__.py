"""Threat-intel export format builders (Stage 13).

Each builder is a pure transform: gathered session/intent/honeytoken
data in, format bytes/dict out. No attacker-facing behaviour.

Honeytoken secret payloads never leave the shareable feed formats (STIX
2.1, MISP), which emit identifiers and callback URLs only. The one
exception is :func:`build_honeytoken_report_rows`, the operator-only
registry CSV (slice 13.3): it is an authenticated file download that
deliberately carries the payload as the canonical operator record, never
pushed to a third party. See its module docstring and THREAT_MODEL.md.
"""

from anglerfish.dashboard.exporters.honeytoken_report import (
    HONEYTOKEN_REPORT_COLUMNS,
    build_honeytoken_report_rows,
)
from anglerfish.dashboard.exporters.misp import build_misp_event
from anglerfish.dashboard.exporters.report import build_pdf_report
from anglerfish.dashboard.exporters.stix import build_stix_bundle

__all__ = [
    "HONEYTOKEN_REPORT_COLUMNS",
    "build_honeytoken_report_rows",
    "build_misp_event",
    "build_pdf_report",
    "build_stix_bundle",
]
