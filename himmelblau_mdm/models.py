from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictProtocolModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class EnrollmentRequest(StrictProtocolModel):
    app_version: str = Field(alias="AppVersion", min_length=1, max_length=64)
    device_name: str = Field(alias="DeviceName", min_length=1, max_length=256)
    csr: str = Field(alias="CertificateSigningRequest", min_length=64, max_length=65536)


class CertificateResponse(BaseModel):
    model_config = ConfigDict(extra="allow")
    thumbprint: str | None = None
    cert_blob: list[int] = Field(alias="certBlob", min_length=1)
    renew_period: int | None = Field(default=None, alias="renewPeriod")


class EnrollmentResponse(BaseModel):
    model_config = ConfigDict(extra="allow")
    device_id: UUID = Field(alias="deviceId")
    certificate: CertificateResponse


class DeviceDetailsRequest(StrictProtocolModel):
    device_id: UUID = Field(alias="DeviceId")
    device_name: str = Field(alias="DeviceName", min_length=1, max_length=256)
    manufacturer: str = Field(alias="Manufacturer", min_length=1, max_length=256)
    os_distribution: str = Field(alias="OSDistribution", min_length=1, max_length=256)
    os_version: str = Field(alias="OSVersion", min_length=1, max_length=128)


class PolicySetting(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    setting_definition_reporting_id: str | None = Field(
        default=None, alias="settingDefinitionReportingId"
    )
    setting_definition_item_id: str = Field(alias="settingDefinitionItemId")
    csp_path: str = Field(alias="cspPath")
    csp_path_id: str = Field(alias="cspPathId")
    rule_id: str = Field(alias="ruleId")
    rule_name: str | None = Field(default=None, alias="ruleName")
    value: str


class WirePolicy(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    account_id: str = Field(alias="accountId")
    policy_id: str = Field(alias="policyId")
    description: str
    version: int
    policy_type: str = Field(alias="policyType")
    policy_settings: list[PolicySetting] = Field(alias="policySettings")


class PoliciesResponse(BaseModel):
    policies: list[WirePolicy]


ComplianceState = Literal["Compliant", "NonCompliant", "Noncompliant", "Error", "Unknown"]


class StatusDetail(StrictProtocolModel):
    actual_value: str = Field(alias="ActualValue", max_length=1_048_576)
    expected_value: str = Field(alias="ExpectedValue", max_length=1_048_576)
    new_state: ComplianceState = Field(alias="NewComplianceState")
    old_state: ComplianceState = Field(alias="OldComplianceState")
    rule_id: UUID = Field(alias="RuleId")
    setting_id: str = Field(alias="SettingDefinitionItemId", min_length=1, max_length=512)
    error_code: int | None = Field(default=None, alias="ErrorCode")
    error_type: int | None = Field(default=None, alias="ErrorType")


class PolicyStatus(StrictProtocolModel):
    details: list[StatusDetail] = Field(alias="Details", max_length=1000)
    last_status: datetime = Field(alias="LastStatusDateTime")
    policy_id: UUID = Field(alias="PolicyId")


class StatusRequest(StrictProtocolModel):
    device_id: UUID = Field(alias="DeviceId")
    policy_statuses: list[PolicyStatus] = Field(alias="PolicyStatuses", max_length=1000)


class StatusResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    policy_statuses: list[PolicyStatus] = Field(alias="PolicyStatuses")


class AuthenticatedPrincipal(BaseModel):
    tenant_id: str
    user_id: str
    entra_device_id: str
    client_id: str
    claims: dict[str, Any] = Field(exclude=True)


class DeviceRecord(BaseModel):
    id: str
    tenant_id: str
    entra_device_id: str
    entra_device_object_id: str
    intune_device_id: str
    enrolling_user_id: str
    device_name: str
    enrolled_at: datetime
    updated_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)
    upstream: dict[str, Any] = Field(default_factory=dict)


class ServedPolicySnapshot(BaseModel):
    id: str
    tenant_id: str
    intune_device_id: str
    user_id: str
    served_at: datetime
    source_fingerprint: str
    policies: list[WirePolicy]
    diagnostics: list[dict[str, Any]] = Field(default_factory=list)


class ComplianceResult(BaseModel):
    id: str
    device_key: str
    tenant_id: str
    intune_device_id: str
    user_id: str
    policy_id: str
    rule_id: str
    setting_id: str
    current_status: str
    previous_status: str
    actual_value: str
    expected_value: str
    reported_at: datetime
    received_at: datetime
    active: bool = True
    upstream_sync_status: str = "pending"
    upstream_sync_at: datetime | None = None
    upstream_error: str | None = None


class AssignmentTarget(BaseModel):
    odata_type: str = Field(alias="@odata.type")
    group_id: str | None = Field(default=None, alias="groupId")
    target_type: str | None = Field(default=None, alias="targetType")
    entra_object_id: str | None = Field(default=None, alias="entraObjectId")
    filter_id: str | None = Field(default=None, alias="deviceAndAppManagementAssignmentFilterId")
    filter_type: str | None = Field(default=None, alias="deviceAndAppManagementAssignmentFilterType")

    @field_validator("odata_type")
    @classmethod
    def normalize_type(cls, value: str) -> str:
        return value.removeprefix("#")


class Assignment(BaseModel):
    id: str
    target: AssignmentTarget


class AssignmentContext(BaseModel):
    user_id: str
    entra_device_id: str
    entra_device_object_id: str
    user_group_ids: set[str]
    device_group_ids: set[str]
