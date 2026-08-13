from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from himmelblau_mdm.app import create_app
from himmelblau_mdm.compliance import ComplianceService
from himmelblau_mdm.config import Settings
from himmelblau_mdm.devices import DeviceBindingService
from himmelblau_mdm.models import ServedPolicySnapshot
from himmelblau_mdm.persistence import MemoryRepository
from conftest import DEVICE, DEVICE_OBJECT, INTUNE, TENANT, USER_A, principal


def csr():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    request = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "linux")])
    ).sign(key, hashes.SHA256())
    return request.public_bytes(serialization.Encoding.PEM).decode()


class FakeValidator:
    async def validate(self, _authorization, _audiences):
        return principal()


class FakeGraph:
    async def resolve_device(self, _device_id):
        return {"id": DEVICE_OBJECT, "deviceId": DEVICE}


class FakeIntune:
    def __init__(self):
        self.calls = []

    async def proxy(self, provider, method, path, token, query, payload=None):
        self.calls.append((provider, method, path, token, query, payload))
        request = httpx.Request(method, "https://upstream.example/" + path)
        if path == "enroll":
            body = {"deviceId": INTUNE, "certificate": {"certBlob": [1, 2, 3]}}
        elif path == "details":
            body = {"deviceFriendlyName": "linux"}
        elif path == "status":
            body = {"PolicyStatuses": payload["PolicyStatuses"]}
        else:
            body = {"Key": INTUNE, "AadId": DEVICE, "ComplianceState": "Compliant", "NoncompliantRules": []}
        return httpx.Response(200, json=body, request=request)


class FakePolicies:
    def __init__(self, repo): self.repo = repo

    async def effective_policies(self, device, user_id):
        snapshot = ServedPolicySnapshot(
            id=f"snapshot:{device.intune_device_id}:{user_id}", tenant_id=TENANT,
            intune_device_id=device.intune_device_id, user_id=user_id,
            served_at=datetime.now(timezone.utc), source_fingerprint="empty", policies=[],
        )
        await self.repo.save_snapshot(snapshot)
        return snapshot


@pytest.mark.asyncio
async def test_protocol_enrollment_details_policy_status_and_iw_are_compatible():
    repo = MemoryRepository()
    upstream = FakeIntune()
    services = SimpleNamespace(
        token_validator=FakeValidator(), graph=FakeGraph(), intune=upstream,
        repository=repo, devices=DeviceBindingService(repo), policies=FakePolicies(repo),
        compliance=ComplianceService(repo),
    )
    app = create_app(Settings(tenant_id=TENANT), injected_services=services)
    app.state.services = services
    transport = httpx.ASGITransport(app=app)
    headers = {"Authorization": "Bearer incoming-token"}
    async with httpx.AsyncClient(transport=transport, base_url="https://mdm.example") as client:
        enrolled = await client.post(
            "/LinuxMDM/LinuxEnrollmentService/enroll?api-version=1.0&client-version=1.2.3",
            headers=headers,
            json={"AppVersion": "0.0.0", "DeviceName": "linux", "CertificateSigningRequest": csr()},
        )
        assert enrolled.status_code == 200 and enrolled.json()["deviceId"] == INTUNE
        assert (await repo.get_device(TENANT, INTUNE)).entra_device_id == DEVICE

        details = await client.post(
            "/LinuxMDM/LinuxDeviceCheckinService/details?api-version=1.0&client-version=1.2.3",
            headers=headers,
            json={"DeviceId": INTUNE, "DeviceName": "linux", "Manufacturer": "ACME", "OSDistribution": "Test", "OSVersion": "1"},
        )
        assert details.json() == {"deviceFriendlyName": "linux"}

        policies = await client.get(
            f"/LinuxMDM/LinuxDeviceCheckinService/policies/{INTUNE}?api-version=1.0&client-version=1.2.3",
            headers=headers,
        )
        assert policies.json() == {"policies": []}

        status = await client.post(
            "/LinuxMDM/LinuxDeviceCheckinService/status?api-version=1.0&client-version=1.2.3",
            headers=headers, json={"DeviceId": INTUNE, "PolicyStatuses": []},
        )
        assert status.json() == {"PolicyStatuses": []}

        state = await client.get(
            f"/IWService/StatelessIWService/Devices(guid'{INTUNE}')"
            "?api-version=16.4&ssp=LinuxCP&ssp-version=1.2.3&os=Linux&os-version=1&os-sub=Test&arch=X64&mgmt-agent=mdm",
            headers=headers,
        )
        assert state.status_code == 200 and state.json()["ComplianceState"] == "Compliant"
        assert upstream.calls[0][3] == "incoming-token"
