import json
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from himmelblau_mdm.auth import CachedMetadata, TokenValidator
from himmelblau_mdm.config import Settings
from himmelblau_mdm.constants import CHECKIN_AUDIENCES, LINUX_PORTAL_CLIENT_ID
from himmelblau_mdm.errors import AuthenticationError
from conftest import DEVICE, TENANT, USER_A

AUDIENCE = next(iter(CHECKIN_AUDIENCES))


@pytest.fixture
def validator_and_key():
    settings = Settings(tenant_id=TENANT)
    validator = TokenValidator(settings, httpx.AsyncClient())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    validator._cache = CachedMetadata("unused", {"test": key.public_key()}, float("inf"))
    return validator, key


def token(validator, key, **overrides):
    now = datetime.now(timezone.utc)
    claims = {
        "aud": AUDIENCE, "iss": validator.settings.issuer_v2, "tid": TENANT,
        "oid": USER_A, "deviceid": DEVICE, "azp": LINUX_PORTAL_CLIENT_ID,
        "iat": now, "nbf": now - timedelta(seconds=1), "exp": now + timedelta(minutes=5),
    }
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test"})


@pytest.mark.asyncio
async def test_wrong_tenant_rejected(validator_and_key):
    validator, key = validator_and_key
    value = token(validator, key, tid="99999999-9999-9999-9999-999999999999")
    with pytest.raises(AuthenticationError):
        await validator.validate("Bearer " + value, CHECKIN_AUDIENCES)
    await validator.client.aclose()


@pytest.mark.asyncio
async def test_wrong_audience_rejected(validator_and_key):
    validator, key = validator_and_key
    with pytest.raises(AuthenticationError):
        await validator.validate("Bearer " + token(validator, key, aud="wrong"), CHECKIN_AUDIENCES)
    await validator.client.aclose()


@pytest.mark.asyncio
async def test_expired_token_rejected(validator_and_key):
    validator, key = validator_and_key
    expired = datetime.now(timezone.utc) - timedelta(minutes=2)
    with pytest.raises(AuthenticationError):
        await validator.validate("Bearer " + token(validator, key, exp=expired), CHECKIN_AUDIENCES)
    await validator.client.aclose()


@pytest.mark.asyncio
async def test_malformed_token_rejected(validator_and_key):
    validator, _key = validator_and_key
    with pytest.raises(AuthenticationError):
        await validator.validate("Bearer not-a-jwt", CHECKIN_AUDIENCES)
    await validator.client.aclose()
