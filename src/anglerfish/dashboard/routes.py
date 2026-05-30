"""REST routes for the dashboard.

Each route is a thin shim over :class:`DashboardState` plus the
optional :class:`CredentialStore`. The auth dependency
(:func:`anglerfish.dashboard.auth.require_auth`) is applied at router
level so every endpoint requires authentication — except
``/`` (renders the login-aware SPA), ``/api/health`` (used by load
balancers and service probes), and ``/api/login``/``/api/logout``
(wired separately by :func:`build_auth_router`).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field

from anglerfish import __version__
from anglerfish.audit import AuditLog
from anglerfish.config.models import CounterDeceptionMode
from anglerfish.dashboard.alerts import ALERT_KINDS, ALERT_STUBS, list_alerts
from anglerfish.dashboard.audit_reader import iter_events_in_range, parse_event_timestamp
from anglerfish.dashboard.auth import is_open_mode, require_auth
from anglerfish.dashboard.csrf import require_csrf
from anglerfish.dashboard.export import (
    ExportRangeError,
    audit_export_payload,
    intent_export_payload,
    parse_range,
    session_csv_rows,
    session_export_payload,
)
from anglerfish.dashboard.exporters import build_misp_event, build_stix_bundle
from anglerfish.dashboard.health import (
    ollama_health,
    sessions_health,
)
from anglerfish.dashboard.overrides import RuntimeOverrides, WastingStrategy
from anglerfish.dashboard.state import DashboardState
from anglerfish.honeytokens.schema import Honeytoken
from anglerfish.models.credentials import CredentialRecord, CredentialStats
from anglerfish.models.intent import IntentSummary
from anglerfish.models.session import SessionSnapshot
from anglerfish.models.threat import ThreatAssessment

__all__ = ["build_router"]

# A CSP violation report is a small JSON object. Cap the body so the
# auth-gated endpoint cannot be used to write large blobs into the audit
# log, and truncate each recorded field for the same reason.
_CSP_REPORT_MAX_BYTES = 8192
_CSP_REPORT_FIELD_MAX = 512


def _get_state(request: Request) -> DashboardState:
    state = getattr(request.app.state, "dashboard_state", None)
    if state is None:  # pragma: no cover - guarded at startup
        raise RuntimeError("DashboardState not attached to app.state")
    return cast("DashboardState", state)


def _get_credential_store(request: Request) -> Any | None:
    return getattr(request.app.state, "credential_store", None)


def _get_overrides(request: Request) -> RuntimeOverrides:
    overrides = getattr(request.app.state, "runtime_overrides", None)
    if overrides is None:  # pragma: no cover - attached in create_app
        raise RuntimeError("runtime_overrides not attached to app.state")
    return cast("RuntimeOverrides", overrides)


def _get_audit(request: Request) -> AuditLog:
    audit = getattr(request.app.state, "audit", None)
    if audit is None:  # pragma: no cover - attached in create_app
        raise RuntimeError("audit log not attached to app.state")
    return cast("AuditLog", audit)


def _get_persona_registry(request: Request) -> Any | None:
    """Return the persona registry attached at startup, or None.

    The persona pin endpoints raise 503 when this is None (Stage 9
    disabled via ``settings.persona.enabled=False``) so the SPA can
    grey-disable the pin controls cleanly rather than getting a 422
    for every persona name it tries.
    """
    return getattr(request.app.state, "persona_registry", None)


def _get_overrides_publisher(request: Request) -> Any:
    """Return the runtime-overrides publisher, or None if not attached.

    Older test fixtures construct create_app paths that omit the
    publisher; the routes degrade to in-process-only override updates
    in that case so existing tests continue to pass.
    """
    return getattr(request.app.state, "overrides_publisher", None)


# Default neighbour count for the aggregate detail view's similar
# section; mirrors the /api/sessions/{id}/similar k default.
_DETAIL_SIMILAR_K = 5

# Cluster graph endpoint caps. The node default bounds what a busy
# honeypot ships to the browser; the max is the hard ceiling a caller
# may request. _CLUSTER_THREAT_SCAN bounds the recent-threats window
# scanned to enrich node threat scores.
_CLUSTER_NODE_DEFAULT = 200
_CLUSTER_NODE_MAX = 1000
_CLUSTER_THREAT_SCAN = 200


async def _build_similar_items(
    state: DashboardState,
    session_id: UUID,
    *,
    k: int,
    min_similarity: float,
) -> list[dict[str, Any]]:
    """Map ``find_similar`` neighbours to the REST item shape.

    Shared by ``/api/sessions/{id}/similar`` and the aggregate
    ``/api/sessions/{id}/detail`` so both surface identical neighbour
    rows from one code path.
    """
    neighbours = await state.find_similar(
        session_id,
        k=k,
        min_similarity=min_similarity,
    )
    items: list[dict[str, Any]] = []
    for embedding, similarity in neighbours:
        session = await state.get_session(embedding.session_id)
        items.append(
            {
                "session_id": str(embedding.session_id),
                "similarity": round(similarity, 6),
                "model": embedding.model,
                "generated_at": embedding.generated_at.isoformat(),
                "session": session.model_dump(mode="json") if session else None,
            },
        )
    return items


def _read_session_audit_facts(
    audit_path: Path,
    session_id: UUID,
) -> tuple[int, dict[str, Any] | None]:
    """Derive ``(time_wasted_ms, counter_deception)`` from the audit log.

    Neither fact is in the session store: the bridge keeps per-session
    wasted-ms and counter-deception engagement state in its own
    process and emits them only to the audit log. One pass over the
    log, scoped to ``session_id``:

    * ``time_wasted_ms`` sums the per-command ``wasted_ms`` deltas on
      ``bridge.wasting_applied`` events (the same field health.py
      reads).
    * ``counter_deception`` is built from the session's single
      ``bridge.counter_deception_engaged`` event (mode, engaged_at,
      garble_paths_count); ``None`` when never engaged. Time-bomb
      intensity is escalating in-process bridge state, never
      persisted, so it is not surfaced here.
    """
    sid = str(session_id)
    time_wasted_ms = 0
    counter_deception: dict[str, Any] | None = None
    start = datetime.fromtimestamp(0, tz=UTC)
    end = datetime.now(tz=UTC)
    for event in iter_events_in_range(audit_path, start=start, end=end):
        if event.get("session_id") != sid:
            continue
        event_type = event.get("event_type")
        if event_type == "bridge.wasting_applied":
            wasted = event.get("wasted_ms")
            if isinstance(wasted, int):
                time_wasted_ms += wasted
        elif event_type == "bridge.counter_deception_engaged" and counter_deception is None:
            count = event.get("garble_paths_count")
            counter_deception = {
                "mode": event.get("mode"),
                "engaged_at": event.get("ts"),
                "garble_paths_count": count if isinstance(count, int) else None,
            }
    return time_wasted_ms, counter_deception


async def _gather_export_window(
    state: DashboardState,
    *,
    start: datetime,
    end: datetime,
) -> tuple[list[SessionSnapshot], dict[str, IntentSummary], list[Honeytoken]]:
    """Collect a window's sessions, intents, and honeytokens for export.

    Shared by the STIX and MISP endpoints so both summarise the same
    data. Honeytokens are gathered per unique source IP and de-duplicated
    by token id.
    """
    sessions = await state.store.get_sessions_in_range(start=start, end=end)
    intents = await state.get_intents_in_range(start=start, end=end)
    intents_by_session = {str(item.session_id): item for item in intents}
    honeytokens: list[Honeytoken] = []
    seen_tokens: set[str] = set()
    seen_ips: set[str] = set()
    for session in sessions:
        if session.source_ip in seen_ips:
            continue
        seen_ips.add(session.source_ip)
        for token in await state.list_honeytokens_for_source_ip(session.source_ip):
            if token.id not in seen_tokens:
                seen_tokens.add(token.id)
                honeytokens.append(token)
    return sessions, intents_by_session, honeytokens


# ---------------------------------------------------------------------------
# Stage 3 request bodies for the settings POSTs. Kept here rather than in
# overrides.py because they are HTTP-layer schemas (Pydantic + bounds);
# overrides.py is the in-process mutation API.
# ---------------------------------------------------------------------------


class _BridgeSettingsUpdate(BaseModel):
    """POST /api/settings/bridge request body. All fields optional."""

    model_config = ConfigDict(extra="forbid")

    max_concurrent_requests: int | None = Field(default=None, ge=1, le=128)
    requests_per_session_per_minute: int | None = Field(default=None, ge=1, le=600)
    wasting_strategy: WastingStrategy | None = None


class _FeatureFlagsUpdate(BaseModel):
    """POST /api/settings/features request body. All fields optional."""

    model_config = ConfigDict(extra="forbid")

    time_wasting: bool | None = None
    engaged_persistence: bool | None = None
    decoy_poisoning: bool | None = None
    counter_deception: bool | None = None


class _PersonaPinRequest(BaseModel):
    """POST /api/persona/pin request body."""

    model_config = ConfigDict(extra="forbid")

    source_ip: str = Field(min_length=1, max_length=64)
    persona: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9-]+$",
        description="Persona name; validated against the loaded PersonaRegistry.",
    )


class _CounterDeceptionPinRequest(BaseModel):
    """POST /api/counter_deception/pin request body (Stage 12)."""

    model_config = ConfigDict(extra="forbid")

    source_ip: str = Field(min_length=1, max_length=64)
    mode: CounterDeceptionMode = Field(
        description=(
            "Forced mode for this source IP. 'off' whitelists the IP "
            "(no counter-deception even above the threat threshold); "
            "garble / timebomb / both force-engage with that mode."
        ),
    )


def build_router(*, templates: Jinja2Templates) -> APIRouter:
    """Return a router wired to the configured templates directory."""
    router = APIRouter()

    @router.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        config = request.app.state.settings.dashboard
        return cast(
            "HTMLResponse",
            templates.TemplateResponse(
                request,
                "index.html",
                {
                    "version": __version__,
                    "open_mode": is_open_mode(config),
                    "admin_username": config.admin_username,
                },
            ),
        )

    @router.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @router.get("/api/stats", dependencies=[Depends(require_auth)])
    async def stats(
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> dict[str, Any]:
        snap = await state.get_stats()
        return snap.model_dump(mode="json")

    @router.get("/api/sessions", dependencies=[Depends(require_auth)])
    async def list_sessions(
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> list[dict[str, Any]]:
        sessions: list[SessionSnapshot] = await state.get_active_sessions()
        return [s.model_dump(mode="json") for s in sessions]

    @router.get(
        "/api/sessions/{session_id}",
        dependencies=[Depends(require_auth)],
    )
    async def get_session(
        session_id: UUID,
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> dict[str, Any]:
        session = await state.get_session(session_id)
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        return session.model_dump(mode="json")

    @router.get(
        "/api/sessions/{session_id}/intent",
        dependencies=[Depends(require_auth)],
    )
    async def get_session_intent(
        session_id: UUID,
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> dict[str, Any]:
        """Return the persisted IntentSummary or 404 if not extracted yet."""
        intent = await state.get_intent(session_id)
        if intent is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        return intent.model_dump(mode="json")

    @router.get(
        "/api/sessions/{session_id}/similar",
        dependencies=[Depends(require_auth)],
    )
    async def get_session_similar(
        session_id: UUID,
        request: Request,
        k: int = Query(default=5, ge=1, le=20),
        min_similarity: float | None = Query(default=None, ge=0.0, le=1.0),
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> dict[str, Any]:
        """Return up to ``k`` neighbour sessions ranked by cosine similarity.

        404 when the query session has no persisted embedding (the
        bridge has not run :class:`EmbeddingGenerator` for it yet, or
        the session closed below the min-commands threshold).
        ``min_similarity`` defaults to
        ``settings.bridge.cluster_similarity_threshold`` so the
        endpoint surfaces the same neighbour set the alerts panel
        sees by default; callers can lower the threshold to
        explore looser clusters without affecting alert noise.
        """
        if await state.get_embedding(session_id) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        threshold = (
            min_similarity
            if min_similarity is not None
            else request.app.state.settings.bridge.cluster_similarity_threshold
        )
        items = await _build_similar_items(
            state,
            session_id,
            k=k,
            min_similarity=threshold,
        )
        return {
            "session_id": str(session_id),
            "k": k,
            "min_similarity": threshold,
            "count": len(items),
            "items": items,
        }

    @router.get(
        "/api/sessions/{session_id}/detail",
        dependencies=[Depends(require_auth)],
    )
    async def get_session_detail(
        session_id: UUID,
        request: Request,
        state: DashboardState = Depends(_get_state),  # noqa: B008
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> dict[str, Any]:
        """Aggregate every per-session read behind a single fetch.

        Composes the session snapshot and its ordered turns, the Stage 7
        intent summary, the assigned persona, honeytokens placed for the
        session's source IP, the Stage 12 counter-deception engagement,
        and the Stage 8 cluster neighbours. ``time_wasted_ms`` and
        ``counter_deception`` come from the audit log (the bridge keeps
        both in-process; neither is in the session store), the same read
        path the engagements and health endpoints use. Returns 404 for an
        unknown session id. No LLM call.
        """
        session = await state.get_session(session_id)
        if session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        intent = await state.get_intent(session_id)
        honeytokens = await state.list_honeytokens_for_source_ip(session.source_ip)

        # Cluster neighbours render empty (not 404) when the session has
        # no embedding yet, so the panel still opens for fresh sessions.
        similar: list[dict[str, Any]] = []
        if await state.get_embedding(session_id) is not None:
            threshold = request.app.state.settings.bridge.cluster_similarity_threshold
            similar = await _build_similar_items(
                state,
                session_id,
                k=_DETAIL_SIMILAR_K,
                min_similarity=threshold,
            )

        time_wasted_ms, counter_deception = _read_session_audit_facts(
            audit.path,
            session_id,
        )

        return {
            "session": session.model_dump(mode="json"),
            "turns": [turn.model_dump(mode="json") for turn in session.turns],
            "intent": intent.model_dump(mode="json") if intent else None,
            "persona": session.persona_name,
            "time_wasted_ms": time_wasted_ms,
            "honeytokens": [token.model_dump(mode="json") for token in honeytokens],
            "counter_deception": counter_deception,
            "similar": similar,
        }

    @router.get("/api/clusters", dependencies=[Depends(require_auth)])
    async def get_clusters(
        request: Request,
        since: str | None = Query(default=None, max_length=64),
        min_similarity: float | None = Query(default=None, ge=0.0, le=1.0),
        limit: int = Query(default=_CLUSTER_NODE_DEFAULT, ge=1, le=_CLUSTER_NODE_MAX),
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> dict[str, Any]:
        """Cross-session similarity graph for the cluster view.

        Nodes are the newest ``limit`` embeddings with ``generated_at``
        since ``since`` (default the epoch, i.e. the newest ``limit``
        overall), each enriched with the session's source IP, persona,
        threat score, and intent label. Edges are same-model cosine
        similarities >= ``min_similarity`` (default
        ``bridge.cluster_similarity_threshold``), each unordered pair
        emitted once. Nodes beyond the cap drop oldest-first.
        """
        try:
            start = (
                datetime.fromisoformat(since)
                if since is not None
                else datetime.fromtimestamp(0, tz=UTC)
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid since timestamp: {since!r}",
            ) from exc
        end = datetime.now(tz=UTC)
        threshold = (
            min_similarity
            if min_similarity is not None
            else request.app.state.settings.bridge.cluster_similarity_threshold
        )
        embeddings, raw_edges = await state.get_cluster_graph(
            start=start,
            end=end,
            min_similarity=threshold,
            limit=limit,
        )
        # Best-effort threat enrichment: newest score per session from the
        # recent-threats window. Sessions with no recent assessment score 0.
        threats = await state.get_recent_threats(limit=_CLUSTER_THREAT_SCAN)
        threat_by_session: dict[str, int] = {}
        for assessment in threats:
            threat_by_session.setdefault(str(assessment.session_id), assessment.score)
        nodes: list[dict[str, Any]] = []
        for embedding in embeddings:
            sid = embedding.session_id
            session = await state.get_session(sid)
            intent = await state.get_intent(sid)
            nodes.append(
                {
                    "session_id": str(sid),
                    "source_ip": session.source_ip if session else None,
                    "persona": session.persona_name if session else None,
                    "threat_score": threat_by_session.get(str(sid), 0),
                    "intent_label": intent.intent if intent else None,
                },
            )
        edges = [{"a": str(a), "b": str(b), "similarity": round(sim, 6)} for a, b, sim in raw_edges]
        return {
            "generated_at": end.isoformat(),
            "since": start.isoformat(),
            "min_similarity": threshold,
            "nodes": nodes,
            "edges": edges,
        }

    # Stage 9 slice 9.4: operator persona pins. The selector consults
    # these before the source-IP recurrence query. Auth + CSRF gates
    # match the existing settings + features POST surface.

    @router.post(
        "/api/persona/pin",
        dependencies=[Depends(require_auth), Depends(require_csrf)],
    )
    async def upsert_persona_pin(
        request: Request,
        body: _PersonaPinRequest = Body(...),  # noqa: B008
        state: DashboardState = Depends(_get_state),  # noqa: B008
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
        registry: Any = Depends(_get_persona_registry),  # noqa: B008
    ) -> dict[str, Any]:
        if registry is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="persona registry not loaded; set ANGLERFISH_PERSONA__ENABLED=true",
            )
        if body.persona not in registry:
            raise HTTPException(
                status_code=422,
                detail=f"unknown persona {body.persona!r}; registered: {list(registry.names())}",
            )
        actor = _actor(request)
        pin = await state.upsert_persona_pin(
            source_ip=body.source_ip,
            persona=body.persona,
            created_by=actor,
        )
        audit.record(
            "dashboard.persona_pinned",
            source_ip=pin.source_ip,
            persona=pin.persona,
            operator=actor,
        )
        return pin.model_dump(mode="json")

    @router.get("/api/persona/pin", dependencies=[Depends(require_auth)])
    async def list_persona_pins(
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> dict[str, Any]:
        pins = await state.list_persona_pins()
        return {
            "count": len(pins),
            "items": [pin.model_dump(mode="json") for pin in pins],
        }

    @router.post("/api/csp-report", dependencies=[Depends(require_auth)])
    async def csp_report(
        request: Request,
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> Response:
        """Record a Content-Security-Policy violation as a tripwire.

        The CSP ``report-uri`` points here. A violation while the operator
        views attacker-controlled data signals that something reached the
        DOM in a way the policy had to block - a candidate output-encoding
        gap. Auth-gated: the same-origin report carries the session cookie,
        so this is not an unauthenticated write path into the audit log.
        The body is size-capped and only a fixed set of fields is recorded,
        each truncated, so a violation cannot bloat or inject the log.
        """
        raw = await request.body()
        if len(raw) > _CSP_REPORT_MAX_BYTES:
            raise HTTPException(status_code=413, detail="CSP report too large")
        try:
            payload = json.loads(raw)
            report = payload["csp-report"]
        except (json.JSONDecodeError, TypeError, KeyError):
            raise HTTPException(status_code=400, detail="malformed CSP report") from None
        if not isinstance(report, dict):
            raise HTTPException(status_code=400, detail="malformed CSP report")

        def _field(name: str) -> str:
            return str(report.get(name, ""))[:_CSP_REPORT_FIELD_MAX]

        audit.record(
            "dashboard.csp_violation",
            operator=_actor(request),
            violated_directive=(_field("violated-directive") or _field("effective-directive")),
            blocked_uri=_field("blocked-uri"),
            document_uri=_field("document-uri"),
            source_file=_field("source-file"),
            line_number=_field("line-number"),
        )
        return Response(status_code=204)

    @router.delete(
        "/api/persona/pin/{source_ip}",
        status_code=status.HTTP_204_NO_CONTENT,
        dependencies=[Depends(require_auth), Depends(require_csrf)],
    )
    async def delete_persona_pin(
        source_ip: str,
        request: Request,
        state: DashboardState = Depends(_get_state),  # noqa: B008
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> None:
        deleted = await state.delete_persona_pin(source_ip)
        if not deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        audit.record(
            "dashboard.persona_unpinned",
            source_ip=source_ip,
            operator=_actor(request),
        )

    # Stage 10 slice 10.4: read-only view of the fake-persistence
    # state an attacker has installed via a particular source IP.
    # The SPA's session-detail view uses this alongside the existing
    # alerts panel's persistence_attempt kind. No write endpoint:
    # operators clear an attacker's state via SQL in v1 (a future
    # stage may add a DELETE route).

    @router.get(
        "/api/persistence/state",
        dependencies=[Depends(require_auth)],
    )
    async def get_persistence_state(
        source_ip: str = Query(min_length=1, max_length=64),
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> dict[str, Any]:
        events = await state.list_persistence_events_for_source_ip(source_ip)
        return {
            "source_ip": source_ip,
            "count": len(events),
            "items": [event.model_dump(mode="json") for event in events],
        }

    # Stage 11 slice 11.4: honeytoken registry + callback views.
    # /state mirrors the slice 10.4 persistence/state shape (source-
    # IP-scoped registry rows, oldest first). /callbacks reads the
    # audit log directly so the operator-shipped callback-receiver
    # lines surface here without an SQL store round-trip.

    @router.get(
        "/api/honeytokens/state",
        dependencies=[Depends(require_auth)],
    )
    async def get_honeytokens_state(
        source_ip: str = Query(min_length=1, max_length=64),
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> dict[str, Any]:
        tokens = await state.list_honeytokens_for_source_ip(source_ip)
        return {
            "source_ip": source_ip,
            "count": len(tokens),
            "items": [t.model_dump(mode="json") for t in tokens],
        }

    @router.get(
        "/api/honeytokens/callbacks",
        dependencies=[Depends(require_auth)],
    )
    async def get_honeytokens_callbacks(
        since: str | None = Query(default=None, max_length=64),
        limit: int = Query(default=100, ge=1, le=1000),
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> dict[str, Any]:
        """Return recent bridge.honeytoken_callback events, newest first.

        ``since`` is an ISO-8601 timestamp; defaults to the unix
        epoch (returns the full callback history capped at
        ``limit``). The callback receiver writes its own audit log;
        operators ship that file back into the main audit log via
        their existing forwarder, so this endpoint reads whichever
        events have actually landed on disk.
        """
        try:
            start = (
                datetime.fromisoformat(since)
                if since is not None
                else datetime.fromtimestamp(0, tz=UTC)
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid since timestamp: {since!r}",
            ) from exc
        end = datetime.now(tz=UTC)
        items: list[dict[str, Any]] = []
        for event in iter_events_in_range(audit.path, start=start, end=end):
            if event.get("event_type") != "bridge.honeytoken_callback":
                continue
            ts = parse_event_timestamp(event)
            items.append(
                {
                    "ts": event.get("ts"),
                    "ts_ms": int(ts.timestamp() * 1000) if ts is not None else None,
                    "token_id": event.get("token_id"),
                    "kind": event.get("kind"),
                    "registered_source_ip": event.get("registered_source_ip"),
                    "callback_source_ip": event.get("callback_source_ip"),
                    "user_agent": event.get("user_agent"),
                    "request_path": event.get("request_path"),
                },
            )
            if len(items) >= limit:
                break
        return {
            "since": start.isoformat(),
            "count": len(items),
            "items": items,
        }

    # Stage 12 slice 12.4: active counter-deception surface.

    @router.get(
        "/api/counter_deception/state",
        dependencies=[Depends(require_auth)],
    )
    async def get_counter_deception_state(
        request: Request,
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> dict[str, Any]:
        """Return the counter-deception config snapshot + active pin count.

        The config (mode, threshold, paths, time-bomb bands) comes from
        the loaded settings. A live "currently-engaged sessions" count is
        not available cross-process (engagement state lives in the bridge
        process); recent engagements are surfaced via
        ``/api/counter_deception/engagements`` instead. The active-pin
        count comes from the shared session store.
        """
        cfg = request.app.state.settings.counter_deception
        pins = await state.list_counter_deception_pins()
        return {
            "config": {
                "enabled": cfg.enabled,
                "mode": cfg.mode.value,
                "engagement_threshold": cfg.engagement_threshold,
                "garble_paths": list(cfg.garble_paths),
                "timebomb_cold_to_mild": cfg.timebomb_cold_to_mild,
                "timebomb_mild_to_severe": cfg.timebomb_mild_to_severe,
            },
            "active_pins": len(pins),
        }

    @router.get(
        "/api/counter_deception/engagements",
        dependencies=[Depends(require_auth)],
    )
    async def get_counter_deception_engagements(
        since: str | None = Query(default=None, max_length=64),
        limit: int = Query(default=100, ge=1, le=1000),
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> dict[str, Any]:
        """Return recent bridge.counter_deception_engaged events, newest first.

        Reads the audit log directly (the tailer does not persist these;
        there is no engagement table). ``since`` is an ISO-8601 timestamp
        defaulting to the unix epoch.
        """
        try:
            start = (
                datetime.fromisoformat(since)
                if since is not None
                else datetime.fromtimestamp(0, tz=UTC)
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid since timestamp: {since!r}",
            ) from exc
        end = datetime.now(tz=UTC)
        items: list[dict[str, Any]] = []
        for event in iter_events_in_range(audit.path, start=start, end=end):
            if event.get("event_type") != "bridge.counter_deception_engaged":
                continue
            ts = parse_event_timestamp(event)
            items.append(
                {
                    "ts": event.get("ts"),
                    "ts_ms": int(ts.timestamp() * 1000) if ts is not None else None,
                    "session_id": event.get("session_id"),
                    "attacker_ip": event.get("attacker_ip"),
                    "mode": event.get("mode"),
                    "trigger": event.get("trigger"),
                    "threat_score": event.get("threat_score"),
                },
            )
            if len(items) >= limit:
                break
        return {
            "since": start.isoformat(),
            "count": len(items),
            "items": items,
        }

    @router.post(
        "/api/counter_deception/pin",
        dependencies=[Depends(require_auth), Depends(require_csrf)],
    )
    async def upsert_counter_deception_pin(
        request: Request,
        body: _CounterDeceptionPinRequest = Body(...),  # noqa: B008
        state: DashboardState = Depends(_get_state),  # noqa: B008
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> dict[str, Any]:
        actor = _actor(request)
        pin = await state.upsert_counter_deception_pin(
            source_ip=body.source_ip,
            mode=body.mode,
            created_by=actor,
        )
        audit.record(
            "dashboard.counter_deception_pinned",
            source_ip=pin.source_ip,
            mode=pin.mode.value,
            actor=actor,
        )
        return pin.model_dump(mode="json")

    @router.get(
        "/api/counter_deception/pin",
        dependencies=[Depends(require_auth)],
    )
    async def list_counter_deception_pins(
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> dict[str, Any]:
        pins = await state.list_counter_deception_pins()
        return {
            "count": len(pins),
            "items": [p.model_dump(mode="json") for p in pins],
        }

    @router.delete(
        "/api/counter_deception/pin/{source_ip}",
        dependencies=[Depends(require_auth), Depends(require_csrf)],
    )
    async def delete_counter_deception_pin(
        request: Request,
        source_ip: str,
        state: DashboardState = Depends(_get_state),  # noqa: B008
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> dict[str, Any]:
        deleted = await state.delete_counter_deception_pin(source_ip)
        if not deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        audit.record(
            "dashboard.counter_deception_unpinned",
            source_ip=source_ip,
            actor=_actor(request),
        )
        return {"deleted": True, "source_ip": source_ip}

    @router.get("/api/commands", dependencies=[Depends(require_auth)])
    async def recent_commands(
        limit: int = Query(default=100, ge=1, le=1000),
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> list[dict[str, Any]]:
        return await state.get_recent_commands(limit=limit)

    @router.get("/api/threats", dependencies=[Depends(require_auth)])
    async def recent_threats(
        limit: int = Query(default=50, ge=1, le=500),
        state: DashboardState = Depends(_get_state),  # noqa: B008
    ) -> list[dict[str, Any]]:
        threats: list[ThreatAssessment] = await state.get_recent_threats(limit=limit)
        return [t.model_dump(mode="json") for t in threats]

    @router.get("/api/credentials", dependencies=[Depends(require_auth)])
    async def list_credentials(
        limit: int = Query(default=100, ge=1, le=1000),
        offset: int = Query(default=0, ge=0, le=100_000),
        source_ip: str | None = Query(default=None, max_length=64),
        store: Any | None = Depends(_get_credential_store),  # noqa: B008
    ) -> dict[str, Any]:
        if store is None:
            return {"records": [], "configured": False}
        records: list[CredentialRecord] = await store.query(
            limit=limit,
            offset=offset,
            source_ip=source_ip,
        )
        return {
            "records": [r.model_dump(mode="json") for r in records],
            "configured": True,
        }

    @router.get(
        "/api/credentials/stats",
        dependencies=[Depends(require_auth)],
    )
    async def credential_stats(
        store: Any | None = Depends(_get_credential_store),  # noqa: B008
    ) -> dict[str, Any]:
        if store is None:
            return {"configured": False}
        stats: CredentialStats = await store.stats()
        return {**stats.model_dump(mode="json"), "configured": True}

    # -----------------------------------------------------------------
    # Stage 3: settings control plane
    # -----------------------------------------------------------------

    @router.get("/api/settings", dependencies=[Depends(require_auth)])
    async def get_settings(
        overrides: RuntimeOverrides = Depends(_get_overrides),  # noqa: B008
    ) -> dict[str, Any]:
        return overrides.snapshot()

    @router.post(
        "/api/settings/bridge",
        dependencies=[Depends(require_auth), Depends(require_csrf)],
    )
    async def update_bridge_settings(
        request: Request,
        body: _BridgeSettingsUpdate = Body(...),  # noqa: B008
        overrides: RuntimeOverrides = Depends(_get_overrides),  # noqa: B008
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
        publisher: Any = Depends(_get_overrides_publisher),  # noqa: B008
    ) -> dict[str, Any]:
        diff = overrides.apply_bridge(
            max_concurrent_requests=body.max_concurrent_requests,
            requests_per_session_per_minute=body.requests_per_session_per_minute,
            wasting_strategy=body.wasting_strategy,
        )
        if diff:
            audit.record(
                "dashboard.settings_changed",
                section="bridge",
                diff={k: {"old": v[0], "new": v[1]} for k, v in diff.items()},
                actor=_actor(request),
            )
            if publisher is not None:
                publisher.publish(overrides)
        snapshot = overrides.snapshot()
        snapshot["changed_fields"] = sorted(diff.keys())
        return snapshot

    @router.post(
        "/api/settings/features",
        dependencies=[Depends(require_auth), Depends(require_csrf)],
    )
    async def update_feature_flags(
        request: Request,
        body: _FeatureFlagsUpdate = Body(...),  # noqa: B008
        overrides: RuntimeOverrides = Depends(_get_overrides),  # noqa: B008
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
        publisher: Any = Depends(_get_overrides_publisher),  # noqa: B008
    ) -> dict[str, Any]:
        diff = overrides.apply_features(
            time_wasting=body.time_wasting,
            engaged_persistence=body.engaged_persistence,
            decoy_poisoning=body.decoy_poisoning,
            counter_deception=body.counter_deception,
        )
        for flag, (old, new) in diff.items():
            audit.record(
                "dashboard.feature_toggled",
                flag=flag,
                old=old,
                new=new,
                actor=_actor(request),
            )
        if diff and publisher is not None:
            publisher.publish(overrides)
        snapshot = overrides.snapshot()
        snapshot["changed_fields"] = sorted(diff.keys())
        return snapshot

    # -----------------------------------------------------------------
    # Stage 3: system health
    # -----------------------------------------------------------------

    @router.get("/api/health/ollama", dependencies=[Depends(require_auth)])
    async def health_ollama(
        request: Request,
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> dict[str, Any]:
        return await ollama_health(request.app.state.settings, audit)

    @router.get("/api/health/sessions", dependencies=[Depends(require_auth)])
    async def health_sessions(
        request: Request,
        state: DashboardState = Depends(_get_state),  # noqa: B008
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> dict[str, Any]:
        return await sessions_health(request.app.state.settings, state, audit)

    # -----------------------------------------------------------------
    # Stage 3: alerts
    # -----------------------------------------------------------------

    @router.get("/api/alerts", dependencies=[Depends(require_auth)])
    async def get_alerts(
        request: Request,
        limit: int = Query(default=50, ge=1, le=200),
        cursor: str | None = Query(default=None, max_length=128),
        kind: str | None = Query(default=None, max_length=64),
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> dict[str, Any]:
        if kind is not None and kind not in ALERT_KINDS:
            # Unknown kind yields an empty page rather than 422 so
            # the SPA can chip-filter on a kind not yet observed.
            # Guarded here (not inside list_alerts) so unknown-kind
            # requests don't generate a dashboard.audit_read row.
            return {"items": [], "next_cursor": None, "stubs": ALERT_STUBS}
        audit.record(
            "dashboard.audit_read",
            cursor=cursor,
            kind=kind,
            limit=limit,
            actor=_actor(request),
        )
        return list_alerts(audit.path, limit=limit, cursor=cursor, kind=kind)

    # -----------------------------------------------------------------
    # Stage 3: export
    # -----------------------------------------------------------------

    @router.get("/api/export/sessions", dependencies=[Depends(require_auth)])
    async def export_sessions(
        request: Request,
        export_format: Literal["json", "csv"] = Query(default="json", alias="format"),
        from_: str | None = Query(default=None, alias="from"),
        to: str | None = Query(default=None),
        state: DashboardState = Depends(_get_state),  # noqa: B008
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> Any:
        try:
            start, end = parse_range(from_=from_, to_=to)
        except ExportRangeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        audit.record(
            "dashboard.export_served",
            kind="sessions",
            export_format=export_format,
            from_=start.isoformat(),
            to=end.isoformat(),
            actor=_actor(request),
        )
        if export_format == "csv":
            filename = f"sessions-{start.date()}-to-{end.date()}.csv"
            return StreamingResponse(
                session_csv_rows(state, start=start, end=end),
                media_type="text/csv; charset=utf-8",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                },
            )
        return await session_export_payload(state, start=start, end=end)

    @router.get("/api/export/stix", dependencies=[Depends(require_auth)])
    async def export_stix(
        request: Request,
        from_: str | None = Query(default=None, alias="from"),
        to: str | None = Query(default=None),
        state: DashboardState = Depends(_get_state),  # noqa: B008
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> dict[str, Any]:
        """Export the window as a hand-built STIX 2.1 bundle."""
        try:
            start, end = parse_range(from_=from_, to_=to)
        except ExportRangeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        sessions, intents_by_session, honeytokens = await _gather_export_window(
            state,
            start=start,
            end=end,
        )
        audit.record(
            "dashboard.export_served",
            kind="stix",
            export_format="stix2",
            from_=start.isoformat(),
            to=end.isoformat(),
            item_count=len(sessions),
            actor=_actor(request),
        )
        return build_stix_bundle(
            sessions,
            intents_by_session,
            honeytokens,
            generated=end,
        )

    @router.get("/api/export/misp", dependencies=[Depends(require_auth)])
    async def export_misp(
        request: Request,
        from_: str | None = Query(default=None, alias="from"),
        to: str | None = Query(default=None),
        state: DashboardState = Depends(_get_state),  # noqa: B008
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> dict[str, Any]:
        """Export the window as a hand-built MISP Event."""
        try:
            start, end = parse_range(from_=from_, to_=to)
        except ExportRangeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        sessions, intents_by_session, honeytokens = await _gather_export_window(
            state,
            start=start,
            end=end,
        )
        audit.record(
            "dashboard.export_served",
            kind="misp",
            export_format="misp_json",
            from_=start.isoformat(),
            to=end.isoformat(),
            item_count=len(sessions),
            actor=_actor(request),
        )
        return build_misp_event(
            sessions,
            intents_by_session,
            honeytokens,
            start=start,
            end=end,
        )

    @router.get("/api/export/audit", dependencies=[Depends(require_auth)])
    async def export_audit(
        request: Request,
        from_: str | None = Query(default=None, alias="from"),
        to: str | None = Query(default=None),
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> dict[str, Any]:
        try:
            start, end = parse_range(from_=from_, to_=to)
        except ExportRangeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        payload = audit_export_payload(audit.path, start=start, end=end)
        audit.record(
            "dashboard.export_served",
            kind="audit",
            export_format="json",
            from_=start.isoformat(),
            to=end.isoformat(),
            item_count=payload["count"],
            actor=_actor(request),
        )
        return payload

    @router.get("/api/export/intents", dependencies=[Depends(require_auth)])
    async def export_intents(
        request: Request,
        from_: str | None = Query(default=None, alias="from"),
        to: str | None = Query(default=None),
        state: DashboardState = Depends(_get_state),  # noqa: B008
        audit: AuditLog = Depends(_get_audit),  # noqa: B008
    ) -> dict[str, Any]:
        """Export persisted Stage 7 IntentSummaries in a date range."""
        try:
            start, end = parse_range(from_=from_, to_=to)
        except ExportRangeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        payload = await intent_export_payload(state, start=start, end=end)
        audit.record(
            "dashboard.export_served",
            kind="intents",
            export_format="json",
            from_=start.isoformat(),
            to=end.isoformat(),
            item_count=payload["count"],
            actor=_actor(request),
        )
        return payload

    return router


def _actor(request: Request) -> str:
    """Best-effort principal identifier for audit-event ``actor`` fields.

    The session cookie sets ``authenticated`` plus the admin username
    when login succeeds; Basic-auth requests carry the username in the
    Authorization header. In open mode (no admin password) we record
    ``"open_mode"`` so the audit trail still distinguishes runs.
    """
    session = request.session
    if session.get("authenticated") and session.get("username"):
        return str(session["username"])
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        return "basic_auth"
    return "open_mode"
