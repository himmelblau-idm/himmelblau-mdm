from __future__ import annotations

from datetime import datetime, timezone

from .errors import InvalidRequestError
from .models import (
    AuthenticatedPrincipal,
    ComplianceResult,
    DeviceRecord,
    ServedPolicySnapshot,
    StatusRequest,
)
from .persistence import Repository


class ComplianceService:
    def __init__(self, repository: Repository) -> None:
        self.repository = repository

    async def record(
        self,
        principal: AuthenticatedPrincipal,
        device: DeviceRecord,
        report: StatusRequest,
    ) -> list[ComplianceResult]:
        snapshot = await self.repository.get_snapshot(
            principal.tenant_id, device.intune_device_id, principal.user_id
        )
        if snapshot is None:
            raise InvalidRequestError("No policy snapshot has been served to this user and device")
        allowed = self._allowed(snapshot)
        now = datetime.now(timezone.utc)
        results: list[ComplianceResult] = []
        device_key = f"{principal.tenant_id}:{device.intune_device_id}"
        for status in report.policy_statuses:
            for detail in status.details:
                key = (str(status.policy_id).lower(), str(detail.rule_id).lower(), detail.setting_id)
                if key not in allowed:
                    raise InvalidRequestError(
                        "Status contains a policy or rule that was not served to this user"
                    )
                result_id = (
                    f"result:{principal.user_id}:{status.policy_id}:{detail.rule_id}:"
                    f"{detail.setting_id}"
                ).lower()
                results.append(
                    ComplianceResult(
                        id=result_id,
                        device_key=device_key,
                        tenant_id=principal.tenant_id,
                        intune_device_id=device.intune_device_id,
                        user_id=principal.user_id,
                        policy_id=str(status.policy_id).lower(),
                        rule_id=str(detail.rule_id).lower(),
                        setting_id=detail.setting_id,
                        current_status=detail.new_state,
                        previous_status=detail.old_state,
                        actual_value=detail.actual_value,
                        expected_value=detail.expected_value,
                        reported_at=status.last_status,
                        received_at=now,
                    )
                )
        await self.repository.save_results(results)
        return results

    @staticmethod
    def _allowed(snapshot: ServedPolicySnapshot) -> set[tuple[str, str, str]]:
        return {
            (policy.policy_id.lower(), setting.rule_id.lower(), setting.setting_definition_item_id)
            for policy in snapshot.policies
            for setting in policy.policy_settings
        }
