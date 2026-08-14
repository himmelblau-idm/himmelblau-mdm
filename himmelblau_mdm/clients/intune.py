from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from ..config import Settings
from ..constants import EXPECTED_SERVICE_PATHS
from ..errors import UpstreamError
from .graph import GraphClient
from .http import MicrosoftHttpClient


@dataclass
class EndpointCache:
    values: dict[str, str]
    expires_at: float


class IntuneClient:
    def __init__(self, settings: Settings, graph: GraphClient, http: MicrosoftHttpClient) -> None:
        self.settings = settings
        self.graph = graph
        self.http = http
        self._cache: EndpointCache | None = None
        self._lock = asyncio.Lock()

    def _validate_endpoint(self, provider: str, uri: str) -> str:
        parsed = urlparse(uri)
        hostname = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443):
            raise UpstreamError(f"Discovered {provider} endpoint is not trusted")
        if not any(hostname.endswith(suffix.lower()) for suffix in self.settings.allowed_intune_suffixes):
            raise UpstreamError(f"Discovered {provider} host is not trusted")
        if EXPECTED_SERVICE_PATHS[provider].lower() not in parsed.path.lower():
            raise UpstreamError(f"Discovered {provider} path is not trusted")
        return uri.rstrip("/")

    async def endpoints(self, force: bool = False) -> dict[str, str]:
        async with self._lock:
            now = time.monotonic()
            if self._cache and self._cache.expires_at > now and not force:
                return self._cache.values
            rows = await self.graph.discover_intune_endpoints()
            values: dict[str, str] = {}
            for row in rows:
                provider = row.get("providerName")
                uri = row.get("uri")
                if provider in EXPECTED_SERVICE_PATHS and isinstance(uri, str):
                    values[provider] = self._validate_endpoint(provider, uri)
            missing = EXPECTED_SERVICE_PATHS.keys() - values.keys()
            if missing:
                raise UpstreamError(f"Intune discovery omitted services: {', '.join(sorted(missing))}")
            self._cache = EndpointCache(values, now + self.settings.endpoint_cache_seconds)
            return values

    async def proxy(
        self,
        provider: str,
        method: str,
        relative_path: str,
        token: str,
        query: dict[str, str],
        payload: dict | None = None,
    ) -> httpx.Response:
        endpoints = await self.endpoints()
        base = endpoints[provider] + "/"
        url = urljoin(base, relative_path.lstrip("/"))
        response = await self.http.request(
            method,
            str(httpx.URL(url, params=query)),
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            json=payload,
            retry=method.upper() == "GET",
        )
        return response
