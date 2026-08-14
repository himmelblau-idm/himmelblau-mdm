from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlparse

from azure.identity.aio import ClientSecretCredential, ManagedIdentityCredential

from ..config import Settings
from ..constants import INTUNE_PORTAL_APP_ID
from ..errors import GraphError
from .http import MicrosoftHttpClient


class GraphClient:
    def __init__(self, settings: Settings, http: MicrosoftHttpClient) -> None:
        self.settings = settings
        self.http = http
        if settings.client_id and settings.client_secret:
            self.credential = ClientSecretCredential(
                settings.tenant_id,
                settings.client_id,
                settings.client_secret.get_secret_value(),
                authority=f"https://{settings.authority_host}",
            )
        else:
            self.credential = ManagedIdentityCredential(
                client_id=settings.managed_identity_client_id
            )
        self._token: tuple[str, int] | None = None
        self._token_lock = asyncio.Lock()

    async def close(self) -> None:
        await self.credential.close()

    async def _access_token(self) -> str:
        async with self._token_lock:
            now = int(time.time())
            if self._token and self._token[1] > now + 300:
                return self._token[0]
            try:
                token = await self.credential.get_token(self.settings.graph_scope)
            except Exception as exc:
                raise GraphError("Unable to obtain Microsoft Graph application token") from exc
            self._token = (token.token, token.expires_on)
            return token.token

    def _url(self, path: str) -> str:
        if path.startswith("http"):
            parsed = urlparse(path)
            expected = urlparse(self.settings.graph_origin)
            if parsed.scheme != "https" or parsed.netloc.lower() != expected.netloc.lower():
                raise GraphError("Graph pagination returned an untrusted URL")
            return path
        return f"{self.settings.graph_origin}/{path.lstrip('/')}"

    async def request_json(self, method: str, path: str, *, json: Any = None) -> dict[str, Any]:
        token = await self._access_token()
        response = await self.http.request(
            method,
            self._url(path),
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            json=json,
            retry=method.upper() == "GET",
            graph=True,
        )
        if not response.is_success:
            retryable = response.status_code in (429, 500, 502, 503, 504)
            raise GraphError(
                f"Microsoft Graph returned HTTP {response.status_code}", retryable=retryable
            )
        try:
            document = response.json()
        except ValueError as exc:
            raise GraphError("Microsoft Graph returned invalid JSON") from exc
        if not isinstance(document, dict):
            raise GraphError("Microsoft Graph returned an unexpected response")
        return document

    async def pages(self, path: str) -> AsyncIterator[list[dict[str, Any]]]:
        next_link: str | None = path
        seen: set[str] = set()
        while next_link:
            if next_link in seen:
                raise GraphError("Microsoft Graph pagination loop detected")
            seen.add(next_link)
            document = await self.request_json("GET", next_link)
            values = document.get("value")
            if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
                raise GraphError("Microsoft Graph collection response is malformed")
            yield values
            candidate = document.get("@odata.nextLink")
            next_link = candidate if isinstance(candidate, str) else None

    async def collect(self, path: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        async for page in self.pages(path):
            result.extend(page)
        return result

    async def discover_intune_endpoints(self) -> list[dict[str, Any]]:
        return await self.collect(
            f"v1.0/servicePrincipals(appId='{INTUNE_PORTAL_APP_ID}')/endpoints"
            "?$select=id,capability,providerId,providerName,providerResourceId,uri"
        )

    async def resolve_device(self, entra_device_id: str) -> dict[str, Any]:
        document = await self.request_json(
            "GET", f"v1.0/devices(deviceId='{entra_device_id}')?$select=id,deviceId,displayName"
        )
        if str(document.get("deviceId", "")).lower() != entra_device_id.lower():
            raise GraphError("Entra device identity could not be resolved")
        return document

    async def transitive_user_groups(self, user_id: str) -> set[str]:
        rows = await self.collect(
            f"v1.0/users/{user_id}/transitiveMemberOf/microsoft.graph.group?$select=id"
        )
        return {str(row["id"]).lower() for row in rows if row.get("id")}

    async def transitive_device_groups(self, device_object_id: str) -> set[str]:
        rows = await self.collect(
            f"v1.0/devices/{device_object_id}/transitiveMemberOf/microsoft.graph.group?$select=id"
        )
        return {str(row["id"]).lower() for row in rows if row.get("id")}

    async def list_native_policies(self) -> list[dict[str, Any]]:
        configuration, compliance = await asyncio.gather(
            self.collect(
                "beta/deviceManagement/configurationPolicies?"
                "$filter=platforms eq 'linux'&$select=id,name,description,platforms,technologies,"
                "lastModifiedDateTime,settingCount,isAssigned"
            ),
            self.collect(
                "beta/deviceManagement/compliancePolicies?"
                "$filter=platforms eq 'linux'&$select=id,name,description,platforms,technologies,"
                "lastModifiedDateTime,settingCount,isAssigned"
            ),
        )
        for item in configuration:
            item["_source"] = "configurationPolicies"
        for item in compliance:
            item["_source"] = "compliancePolicies"
        return configuration + compliance

    async def list_group_policies(self) -> list[dict[str, Any]]:
        return await self.collect(
            "beta/deviceManagement/groupPolicyConfigurations?"
            "$select=id,displayName,description,lastModifiedDateTime"
        )

    async def assignments(self, source: str, policy_id: str) -> list[dict[str, Any]]:
        return await self.collect(
            f"beta/deviceManagement/{source}/{policy_id}/assignments?$expand=target"
        )

    async def settings_for_policy(self, source: str, policy_id: str) -> list[dict[str, Any]]:
        return await self.collect(f"beta/deviceManagement/{source}/{policy_id}/settings")

    async def setting_definitions(
        self, source: str, policy_id: str, setting_id: str
    ) -> list[dict[str, Any]]:
        return await self.collect(
            f"beta/deviceManagement/{source}/{policy_id}/settings/{setting_id}/settingDefinitions"
        )
