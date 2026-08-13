from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Iterable

import httpx
import jwt

from .config import Settings
from .constants import LINUX_PORTAL_CLIENT_ID
from .errors import AuthenticationError
from .models import AuthenticatedPrincipal


@dataclass
class CachedMetadata:
    jwks_uri: str
    keys: dict[str, object]
    expires_at: float


class TokenValidator:
    def __init__(self, settings: Settings, client: httpx.AsyncClient) -> None:
        self.settings = settings
        self.client = client
        self._cache: CachedMetadata | None = None
        self._lock = asyncio.Lock()

    async def _keys(self, force: bool = False) -> dict[str, object]:
        async with self._lock:
            now = time.monotonic()
            if self._cache and self._cache.expires_at > now and not force:
                return self._cache.keys
            try:
                metadata = (await self.client.get(self.settings.oidc_metadata_url)).raise_for_status().json()
                jwks_uri = metadata["jwks_uri"]
                jwks = (await self.client.get(jwks_uri)).raise_for_status().json()
                keys = {
                    item["kid"]: jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(item))
                    for item in jwks.get("keys", [])
                    if item.get("kid") and item.get("kty") == "RSA"
                }
            except (httpx.HTTPError, KeyError, ValueError, jwt.PyJWTError) as exc:
                raise AuthenticationError("Unable to validate token signature") from exc
            self._cache = CachedMetadata(jwks_uri, keys, now + 3600)
            return keys

    async def validate(
        self, authorization: str | None, audiences: Iterable[str]
    ) -> AuthenticatedPrincipal:
        if not authorization or not authorization.startswith("Bearer "):
            raise AuthenticationError("Missing bearer token")
        token = authorization[7:].strip()
        if not token or len(token) > 65536:
            raise AuthenticationError("Malformed bearer token")
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not header.get("kid"):
                raise AuthenticationError("Unsupported token signature")
            keys = await self._keys()
            key = keys.get(header["kid"])
            if key is None:
                key = (await self._keys(force=True)).get(header["kid"])
            if key is None:
                raise AuthenticationError("Unknown signing key")
            claims = jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                audience=list(audiences),
                issuer=[self.settings.issuer_v1, self.settings.issuer_v2],
                leeway=60,
                options={"require": ["aud", "exp", "iat", "iss", "nbf", "tid", "oid"]},
            )
        except AuthenticationError:
            raise
        except jwt.ExpiredSignatureError as exc:
            raise AuthenticationError("Token expired") from exc
        except jwt.PyJWTError as exc:
            raise AuthenticationError("Invalid bearer token") from exc

        tenant = str(claims.get("tid", "")).lower()
        if tenant != self.settings.tenant_id:
            raise AuthenticationError("Token tenant is not configured")
        user_id = claims.get("oid")
        device_id = claims.get("deviceid")
        client_id = claims.get("appid") or claims.get("azp")
        if not all(isinstance(item, str) and item for item in (user_id, device_id, client_id)):
            raise AuthenticationError("Token lacks required user or device identity")
        if client_id.lower() != LINUX_PORTAL_CLIENT_ID:
            raise AuthenticationError("Token was not acquired by the Linux Company Portal client")
        return AuthenticatedPrincipal(
            tenant_id=tenant,
            user_id=user_id.lower(),
            entra_device_id=device_id.lower(),
            client_id=client_id.lower(),
            claims=claims,
        )
