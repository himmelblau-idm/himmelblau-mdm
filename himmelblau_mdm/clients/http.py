from __future__ import annotations

import asyncio
import random
from typing import Any

import httpx

from ..errors import GraphError, UpstreamError


class MicrosoftHttpClient:
    def __init__(self, client: httpx.AsyncClient, max_response_bytes: int) -> None:
        self.client = client
        self.max_response_bytes = max_response_bytes

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json: Any = None,
        retry: bool = False,
        graph: bool = False,
    ) -> httpx.Response:
        attempts = 4 if retry else 1
        for attempt in range(attempts):
            try:
                response = await self.client.request(
                    method, url, headers=headers, json=json, follow_redirects=False
                )
            except httpx.HTTPError as exc:
                if attempt + 1 < attempts:
                    await asyncio.sleep(0.25 * (2**attempt) + random.random() / 10)
                    continue
                error = GraphError if graph else UpstreamError
                raise error("Microsoft service request failed", retryable=True) from exc
            if len(response.content) > self.max_response_bytes:
                error = GraphError if graph else UpstreamError
                raise error("Microsoft response exceeded configured size limit")
            if response.status_code in (429, 500, 502, 503, 504) and attempt + 1 < attempts:
                retry_after = response.headers.get("Retry-After", "")
                try:
                    delay = min(float(retry_after), 30.0)
                except ValueError:
                    delay = 0.25 * (2**attempt) + random.random() / 10
                await asyncio.sleep(delay)
                continue
            return response
        raise AssertionError("unreachable")
