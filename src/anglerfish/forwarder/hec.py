"""Splunk HEC (HTTP Event Collector) client.

Submits one event per request to the configured ``hec_url``. The URL is
taken as the **full** HEC endpoint (including
``/services/collector/event``) so the operator can choose between the
``event``, ``raw``, or ``ack`` endpoints by configuration alone.
"""

from __future__ import annotations

from typing import Any, Self

import httpx

from anglerfish.config.models import SplunkConfig
from anglerfish.forwarder.errors import HECResponseError, HECUnavailableError
from anglerfish.forwarder.event import ForwarderEvent

__all__ = ["SplunkHECClient"]


_USER_AGENT = "anglerfish-ai/0.1.0"


class SplunkHECClient:
    """Async HEC client.

    Construct once at service startup and reuse across submissions —
    the underlying :class:`httpx.AsyncClient` pools connections.
    """

    def __init__(
        self,
        config: SplunkConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not config.enabled:
            raise ValueError(
                "SplunkHECClient requires SplunkConfig.enabled = True",
            )
        if config.hec_url is None or config.hec_token is None:
            raise ValueError(
                "SplunkHECClient requires hec_url and hec_token to be set",
            )
        self._config = config
        self._endpoint = str(config.hec_url)
        if http_client is None:
            timeout = httpx.Timeout(config.timeout_s, connect=min(config.timeout_s, 5.0))
            self._client = httpx.AsyncClient(
                timeout=timeout,
                verify=config.verify_tls,
                headers={
                    "Authorization": f"Splunk {config.hec_token.get_secret_value()}",
                    "User-Agent": _USER_AGENT,
                    "Content-Type": "application/json",
                },
            )
            self._owns_client = True
        else:
            self._client = http_client
            self._owns_client = False

    @property
    def config(self) -> SplunkConfig:
        return self._config

    @property
    def endpoint(self) -> str:
        return self._endpoint

    async def submit(self, event: ForwarderEvent) -> None:
        """Submit one event to Splunk HEC.

        Raises:
            HECUnavailableError: network failure or 5xx response.
            HECResponseError: 4xx response or a Splunk-reported error code.
        """
        payload: dict[str, Any] = {
            "event": event.event,
            "sourcetype": event.sourcetype or self._config.sourcetype,
            "index": event.index or self._config.index,
        }
        if event.time is not None:
            payload["time"] = event.time.timestamp()

        try:
            response = await self._client.post(self._endpoint, json=payload)
        except httpx.HTTPError as exc:
            raise HECUnavailableError(
                f"HEC POST failed: {type(exc).__name__}: {exc}",
            ) from exc

        if 500 <= response.status_code < 600:
            raise HECUnavailableError(
                f"HEC returned server error {response.status_code}",
            )
        if response.status_code >= 400:
            raise HECResponseError(
                f"HEC returned client error {response.status_code}: {response.text[:200]!r}",
            )

        try:
            body = response.json()
        except ValueError:
            return
        if not isinstance(body, dict):
            return
        code = body.get("code")
        if isinstance(code, int) and code != 0:
            text = body.get("text", "unknown HEC error")
            raise HECResponseError(f"HEC reported error code {code}: {text}")

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
