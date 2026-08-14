import pytest

from himmelblau_mdm.models import AssignmentContext
from himmelblau_mdm.policy.assignments import AssignmentResolver


def target(kind, **values):
    return {"id": kind + "-id", "target": {"@odata.type": "#microsoft.graph." + kind, **values}}


@pytest.fixture
def context():
    return AssignmentContext(
        user_id="user", entra_device_id="device-id", entra_device_object_id="device-object",
        user_group_ids={"direct", "nested"}, device_group_ids={"device-group"},
    )


@pytest.mark.parametrize("assignment,reason", [
    (target("allLicensedUsersAssignmentTarget"), "all_users"),
    (target("allDevicesAssignmentTarget"), "all_devices"),
    (target("groupAssignmentTarget", groupId="direct"), "assigned_group"),
    (target("groupAssignmentTarget", groupId="nested"), "assigned_group"),
    (target("groupAssignmentTarget", groupId="device-group"), "assigned_group"),
])
def test_inclusion_targets(context, assignment, reason):
    decision = AssignmentResolver().resolve("policy", [assignment], context)
    assert decision.applies and reason in decision.reasons


def test_exclusion_overrides_inclusion(context):
    decision = AssignmentResolver().resolve("policy", [
        target("allLicensedUsersAssignmentTarget"),
        target("exclusionGroupAssignmentTarget", groupId="direct"),
    ], context)
    assert not decision.applies


def test_user_and_device_union(context):
    user = target("groupAssignmentTarget", groupId="direct")
    device = target("groupAssignmentTarget", groupId="device-group")
    assert AssignmentResolver().resolve("p", [user], context).applies
    assert AssignmentResolver().resolve("p", [device], context).applies


def test_assignment_filter_fails_closed(context):
    assignment = target(
        "allDevicesAssignmentTarget",
        deviceAndAppManagementAssignmentFilterId="filter",
        deviceAndAppManagementAssignmentFilterType="include",
    )
    decision = AssignmentResolver().resolve("policy", [assignment], context)
    assert not decision.applies
    assert decision.diagnostics[0]["code"] == "unsupported_assignment_filter"
