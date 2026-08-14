from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import Assignment, AssignmentContext


@dataclass
class AssignmentDecision:
    applies: bool
    reasons: list[str] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)


class AssignmentResolver:
    """Evaluate Intune assignment targets conservatively.

    Assignment filters deliberately fail closed until their complete device-property
    semantics can be evaluated equivalently to Intune.
    """

    def resolve(
        self,
        policy_id: str,
        raw_assignments: list[dict[str, Any]],
        context: AssignmentContext,
    ) -> AssignmentDecision:
        included = False
        excluded = False
        reasons: list[str] = []
        diagnostics: list[dict[str, Any]] = []
        for raw in raw_assignments:
            try:
                assignment = Assignment.model_validate(raw)
            except Exception:
                diagnostics.append(
                    {"policyId": policy_id, "code": "unsupported_assignment", "assignment": raw.get("id")}
                )
                continue
            target = assignment.target
            if target.filter_id or (target.filter_type and target.filter_type.lower() != "none"):
                diagnostics.append(
                    {
                        "policyId": policy_id,
                        "code": "unsupported_assignment_filter",
                        "assignmentId": assignment.id,
                        "filterId": target.filter_id,
                        "filterType": target.filter_type,
                    }
                )
                return AssignmentDecision(False, reasons, diagnostics)

            kind = target.odata_type.rsplit(".", 1)[-1]
            matches = False
            is_exclusion = kind == "exclusionGroupAssignmentTarget"
            if kind == "allLicensedUsersAssignmentTarget":
                matches = True
                reason = "all_users"
            elif kind == "allDevicesAssignmentTarget":
                matches = True
                reason = "all_devices"
            elif kind in {"groupAssignmentTarget", "exclusionGroupAssignmentTarget"}:
                group_id = (target.group_id or "").lower()
                matches = group_id in context.user_group_ids or group_id in context.device_group_ids
                reason = "excluded_group" if is_exclusion else "assigned_group"
            elif kind == "scopeTagGroupAssignmentTarget" and target.entra_object_id:
                object_id = target.entra_object_id.lower()
                target_type = (target.target_type or "").lower()
                if target_type == "user":
                    matches = object_id == context.user_id or object_id in context.user_group_ids
                elif target_type == "device":
                    matches = object_id in {
                        context.entra_device_id,
                        context.entra_device_object_id,
                    } or object_id in context.device_group_ids
                reason = f"direct_{target_type or 'unknown'}"
            else:
                diagnostics.append(
                    {
                        "policyId": policy_id,
                        "code": "unsupported_assignment_target",
                        "assignmentId": assignment.id,
                        "targetType": target.odata_type,
                    }
                )
                continue

            if matches and is_exclusion:
                excluded = True
                reasons.append(reason)
            elif matches:
                included = True
                reasons.append(reason)
        return AssignmentDecision(included and not excluded, reasons, diagnostics)
