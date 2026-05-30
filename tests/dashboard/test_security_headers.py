"""Dashboard security response headers (CSP + companions)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from anglerfish.config import AnglerfishSettings
from anglerfish.dashboard import create_app


@pytest.fixture
def client(settings: AnglerfishSettings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as c:
        yield c


def test_csp_blocks_inline_script(client: TestClient) -> None:
    csp = client.get("/").headers.get("content-security-policy")
    assert csp is not None
    # script-src 'self' with no 'unsafe-inline' is the XSS backstop:
    # an injected inline <script> or event handler cannot execute.
    script_src = csp.split("script-src", 1)[1].split(";", 1)[0]
    assert script_src.strip() == "'self'"
    assert "frame-ancestors 'none'" in csp
    # No directive carries 'unsafe-inline': script never did, and the
    # score-bar width is set via the CSSOM rather than an inline style.
    assert "unsafe-inline" not in csp
    # Violations report to the auth-gated tripwire endpoint.
    assert "report-uri /api/csp-report" in csp


def test_companion_security_headers(client: TestClient) -> None:
    headers = client.get("/").headers
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("referrer-policy") == "no-referrer"


def test_hsts_is_deliberately_absent(client: TestClient) -> None:
    # The dashboard may run over plain HTTP on an isolated net, so HSTS is
    # not set here; a TLS-fronted deployment adds it at the reverse proxy.
    # See the rationale in headers.py.
    assert "strict-transport-security" not in client.get("/").headers


def test_csp_rides_every_response(client: TestClient) -> None:
    # Not just the HTML route; the policy is on API responses too.
    assert "content-security-policy" in client.get("/api/stats").headers
