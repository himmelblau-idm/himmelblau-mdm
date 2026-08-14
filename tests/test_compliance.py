from datetime import datetime, timezone

import pytest

from himmelblau_mdm.compliance import ComplianceService
from himmelblau_mdm.models import (
    PolicySetting, ServedPolicySnapshot, StatusRequest, WirePolicy,
)
from himmelblau_mdm.persistence import MemoryRepository
from conftest import INTUNE, TENANT, USER_A, USER_B, principal

POLICY = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
RULE = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


async def serve(repo, user):
    await repo.save_snapshot(ServedPolicySnapshot(
        id=f"snapshot:{INTUNE}:{user}", tenant_id=TENANT, intune_device_id=INTUNE,
        user_id=user, served_at=datetime.now(timezone.utc), source_fingerprint="x",
        policies=[WirePolicy(
            accountId=user, policyId=POLICY, description="", version=1,
            policyType="Configuration", policySettings=[PolicySetting(
                settingDefinitionItemId="setting", cspPath="./x", cspPathId="path",
                ruleId=RULE, value="expected",
            )],
        )],
    ))


def report(state):
    return StatusRequest.model_validate({
        "DeviceId": INTUNE,
        "PolicyStatuses": [{
            "PolicyId": POLICY, "LastStatusDateTime": datetime.now(timezone.utc).isoformat(),
            "Details": [{
                "RuleId": RULE, "SettingDefinitionItemId": "setting",
                "ActualValue": "actual", "ExpectedValue": "expected",
                "NewComplianceState": state, "OldComplianceState": "Unknown",
            }],
        }],
    })


@pytest.mark.asyncio
async def test_compliant_user_is_compliant(device):
    repo = MemoryRepository(); await serve(repo, USER_A)
    await ComplianceService(repo).record(principal(), device, report("Compliant"))
    aggregate = await repo.aggregate(f"{TENANT}:{INTUNE}")
    assert aggregate["complianceState"] == "Compliant"


@pytest.mark.asyncio
async def test_other_user_cannot_erase_noncompliance(device):
    repo = MemoryRepository(); await serve(repo, USER_A); await serve(repo, USER_B)
    service = ComplianceService(repo)
    await service.record(principal(), device, report("NonCompliant"))
    await service.record(principal(USER_B), device, report("Compliant"))
    aggregate = await repo.aggregate(f"{TENANT}:{INTUNE}")
    assert aggregate["complianceState"] == "NonCompliant"
    assert aggregate["failureCount"] == 1


@pytest.mark.asyncio
async def test_sync_failure_does_not_remove_local_result(device):
    repo = MemoryRepository(); await serve(repo, USER_A)
    results = await ComplianceService(repo).record(principal(), device, report("NonCompliant"))
    key = f"{TENANT}:{INTUNE}"
    await repo.update_sync(key, [results[0].id], "failed", "upstream rejected")
    assert (await repo.aggregate(key))["complianceState"] == "NonCompliant"
    assert repo.results[results[0].id].upstream_sync_status == "failed"
