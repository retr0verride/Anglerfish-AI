"""Pre-flight reachability checks executed before the wizard commits.

Two services may need a sanity check:

* **Ollama** — ``GET <base_url>/api/version`` (no auth).
* **Threat-alert webhook** — best-effort ``HEAD <url>``; we accept
  anything < 500 because many webhook receivers reject HEAD/OPTIONS
  while still accepting POST.

Each check has a hard timeout (default 5 s). Failures are advisory:
the wizard logs the result and continues. Operators get a final
"continue anyway?" prompt if anything failed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal

import httpx

__all__ = [
    "CheckResult",
    "PreflightChecker",
    "check_ollama",
    "check_webhook",
]


_logger = logging.getLogger(__name__)
_DEFAULT_TIMEOUT_S = 5.0


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one pre-flight check."""

    service: str
    success: bool
    detail: str

    @property
    def status(self) -> Literal["ok", "fail"]:
        return "ok" if self.success else "fail"

    def render(self) -> str:
        """Render this result as ``[OK|FAIL] service: detail`` for the wizard log."""
        return f"[{self.status.upper()}] {self.service}: {self.detail}"


def check_ollama(base_url: str, *, timeout: float = _DEFAULT_TIMEOUT_S) -> CheckResult:
    """Hit Ollama's ``/api/version`` endpoint."""
    target = _join(base_url, "/api/version")
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get(target)
    except httpx.HTTPError as exc:
        return CheckResult("ollama", False, f"{type(exc).__name__}: {exc}")

    if response.status_code != 200:
        return CheckResult(
            "ollama",
            False,
            f"unexpected status {response.status_code}",
        )
    try:
        version = response.json().get("version", "unknown")
    except ValueError:
        version = "unknown"
    return CheckResult("ollama", True, f"version {version}")


def check_webhook(
    webhook_url: str,
    *,
    timeout: float = _DEFAULT_TIMEOUT_S,
) -> CheckResult:
    """Best-effort liveness probe on the threat-alert webhook URL."""
    try:
        with httpx.Client(timeout=timeout) as client:
            # HEAD is cheaper but many webhooks 405 it. Treat <500 as alive.
            response = client.head(webhook_url)
    except httpx.HTTPError as exc:
        return CheckResult("webhook", False, f"{type(exc).__name__}: {exc}")

    if response.status_code >= 500:
        return CheckResult(
            "webhook",
            False,
            f"server error {response.status_code}",
        )
    return CheckResult(
        "webhook",
        True,
        f"reachable (status {response.status_code})",
    )


def _join(base: str, path: str) -> str:
    """Concatenate a base URL with a fixed path, stripping a duplicate slash."""
    if base.endswith("/") and path.startswith("/"):
        return base + path[1:]
    if not base.endswith("/") and not path.startswith("/"):
        return f"{base}/{path}"
    return base + path


class PreflightChecker:
    """Run all configured reachability checks and report results."""

    def __init__(self, *, timeout: float = _DEFAULT_TIMEOUT_S) -> None:
        if timeout <= 0:
            raise ValueError(f"timeout must be positive, got {timeout}")
        self._timeout = timeout

    @property
    def timeout(self) -> float:
        return self._timeout

    def run(
        self,
        *,
        ollama_url: str | None,
        webhook_url: str | None,
    ) -> list[CheckResult]:
        """Execute each non-``None`` check in turn and return the results."""
        results: list[CheckResult] = []
        if ollama_url is not None:
            results.append(check_ollama(ollama_url, timeout=self._timeout))
        if webhook_url is not None:
            results.append(check_webhook(webhook_url, timeout=self._timeout))
        for r in results:
            _logger.info("preflight %s", r.render())
        return results
