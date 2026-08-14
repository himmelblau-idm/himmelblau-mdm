from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Annotated, Any
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .constants import CHECKIN_AUDIENCES, ENROLLMENT_AUDIENCES, IWSERVICE_AUDIENCES
from .csr import validate_intune_csr
from .dependencies import Services
from .errors import InvalidRequestError, UpstreamError
from .models import (
    AuthenticatedPrincipal,
    DeviceDetailsRequest,
    DeviceRecord,
    EnrollmentRequest,
    EnrollmentResponse,
    PoliciesResponse,
    StatusRequest,
    StatusResponse,
)


LOG = logging.getLogger(__name__)
router = APIRouter()

ENROLL_PREFIXES = (
    "/LinuxMDM/LinuxEnrollmentService",
    "/TrafficGateway/TrafficRoutingService/LinuxMDM/LinuxEnrollmentService",
)
CHECKIN_PREFIXES = (
    "/LinuxMDM/LinuxDeviceCheckinService",
    "/TrafficGateway/TrafficRoutingService/LinuxMDM/LinuxDeviceCheckinService",
)
IW_PREFIXES = (
    "/IWService/StatelessIWService",
    "/TrafficGateway/TrafficRoutingService/IWService/StatelessIWService",
)


def services(request: Request) -> Services:
    return request.app.state.services


def bearer_value(authorization: str) -> str:
    return authorization[7:].strip()


async def principal_for(
    request: Request, authorization: str | None, audiences: frozenset[str]
) -> AuthenticatedPrincipal:
    return await services(request).token_validator.validate(authorization, audiences)


class ProtocolQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    api_version: str = Field(alias="api-version")
    client_version: str = Field(alias="client-version", min_length=1, max_length=64)


async def protocol_query(
    api_version: Annotated[str, Query(alias="api-version")],
    client_version: Annotated[str, Query(alias="client-version", min_length=1, max_length=64)],
) -> ProtocolQuery:
    if api_version != "1.0":
        raise InvalidRequestError("api-version must be 1.0")
    return ProtocolQuery.model_validate(
        {"api-version": api_version, "client-version": client_version}
    )


class IWQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    api_version: str
    ssp: str
    ssp_version: str
    os: str
    os_version: str | None
    os_sub: str | None
    arch: str | None
    mgmt_agent: str


async def iw_query(
    api_version: Annotated[str, Query(alias="api-version")],
    ssp_version: Annotated[str, Query(alias="ssp-version", min_length=1, max_length=64)],
    ssp: Annotated[str, Query()] = "LinuxCP",
    os: Annotated[str, Query()] = "Linux",
    os_version: Annotated[str | None, Query(alias="os-version", max_length=128)] = None,
    os_sub: Annotated[str | None, Query(alias="os-sub", max_length=128)] = None,
    arch: Annotated[str | None, Query(max_length=32)] = None,
    mgmt_agent: Annotated[str, Query(alias="mgmt-agent")] = "mdm",
) -> IWQuery:
    if api_version != "16.4" or ssp != "LinuxCP" or os != "Linux" or mgmt_agent != "mdm":
        raise InvalidRequestError("Invalid IWService protocol parameters")
    return IWQuery(
        api_version=api_version,
        ssp=ssp,
        ssp_version=ssp_version,
        os=os,
        os_version=os_version,
        os_sub=os_sub,
        arch=arch,
        mgmt_agent=mgmt_agent,
    )


async def _enroll(
    request: Request,
    payload: EnrollmentRequest,
    query: Annotated[ProtocolQuery, Depends(protocol_query)],
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> Response:
    svc = services(request)
    principal = await principal_for(request, authorization, ENROLLMENT_AUDIENCES)
    validate_intune_csr(payload.csr)
    upstream = await svc.intune.proxy(
        "LinuxEnrollmentService",
        "POST",
        "enroll",
        bearer_value(authorization or ""),
        {"api-version": query.api_version, "client-version": query.client_version},
        payload.model_dump(by_alias=True),
    )
    if not upstream.is_success:
        return _upstream_response(upstream)
    try:
        enrollment = EnrollmentResponse.model_validate(upstream.json())
    except Exception as exc:
        raise UpstreamError("Intune enrollment returned an invalid success response") from exc
    entra_device = await svc.graph.resolve_device(principal.entra_device_id)
    now = datetime.now(timezone.utc)
    intune_id = str(enrollment.device_id).lower()
    record = DeviceRecord(
        id=f"device:{intune_id}",
        tenant_id=principal.tenant_id,
        entra_device_id=principal.entra_device_id,
        entra_device_object_id=str(entra_device["id"]).lower(),
        intune_device_id=intune_id,
        enrolling_user_id=principal.user_id,
        device_name=payload.device_name,
        enrolled_at=now,
        updated_at=now,
        metadata={"appVersion": payload.app_version},
        upstream={"enrollmentStatus": "succeeded"},
    )
    try:
        await svc.repository.save_device(record)
    except ValueError as exc:
        raise InvalidRequestError(str(exc)) from exc
    return _upstream_response(upstream)


for prefix in ENROLL_PREFIXES:
    router.add_api_route(
        f"{prefix}/enroll", _enroll, methods=["POST"], response_model=None
    )


async def _details(
    request: Request,
    payload: DeviceDetailsRequest,
    query: Annotated[ProtocolQuery, Depends(protocol_query)],
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> Response:
    svc = services(request)
    principal = await principal_for(request, authorization, CHECKIN_AUDIENCES)
    device = await svc.devices.require(principal, str(payload.device_id))
    upstream = await svc.intune.proxy(
        "LinuxDeviceCheckinService",
        "POST",
        "details",
        bearer_value(authorization or ""),
        {"api-version": query.api_version, "client-version": query.client_version},
        payload.model_dump(by_alias=True, mode="json"),
    )
    if upstream.is_success:
        await svc.devices.update_metadata(
            device,
            {
                "deviceName": payload.device_name,
                "manufacturer": payload.manufacturer,
                "osDistribution": payload.os_distribution,
                "osVersion": payload.os_version,
                "detailsUpdatedAt": datetime.now(timezone.utc).isoformat(),
            },
        )
    return _upstream_response(upstream)


for prefix in CHECKIN_PREFIXES:
    router.add_api_route(
        f"{prefix}/details", _details, methods=["POST"], response_model=None
    )


async def _policies(
    request: Request,
    intune_device_id: UUID,
    query: Annotated[ProtocolQuery, Depends(protocol_query)],
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> PoliciesResponse:
    svc = services(request)
    principal = await principal_for(request, authorization, CHECKIN_AUDIENCES)
    device = await svc.devices.require(principal, str(intune_device_id))
    snapshot = await svc.policies.effective_policies(device, principal.user_id)
    return PoliciesResponse(policies=snapshot.policies)


for prefix in CHECKIN_PREFIXES:
    router.add_api_route(
        f"{prefix}/policies/{{intune_device_id}}",
        _policies,
        methods=["GET"],
        response_model=PoliciesResponse,
        response_model_by_alias=True,
        response_model_exclude_none=True,
    )


async def _status(
    request: Request,
    payload: StatusRequest,
    query: Annotated[ProtocolQuery, Depends(protocol_query)],
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> StatusResponse:
    svc = services(request)
    principal = await principal_for(request, authorization, CHECKIN_AUDIENCES)
    device = await svc.devices.require(principal, str(payload.device_id))
    results = await svc.compliance.record(principal, device, payload)
    result_ids = [item.id for item in results]
    device_key = f"{principal.tenant_id}:{device.intune_device_id}"
    try:
        upstream = await svc.intune.proxy(
            "LinuxDeviceCheckinService",
            "POST",
            "status",
            bearer_value(authorization or ""),
            {"api-version": query.api_version, "client-version": query.client_version},
            payload.model_dump(by_alias=True, mode="json", exclude_none=True),
        )
        if upstream.is_success:
            await svc.repository.update_sync(device_key, result_ids, "succeeded", None)
        else:
            await svc.repository.update_sync(
                device_key, result_ids, "failed", f"HTTP {upstream.status_code}"
            )
    except UpstreamError as exc:
        await svc.repository.update_sync(device_key, result_ids, "failed", exc.code)
        LOG.warning(
            "Native status mirror failed after local commit",
            extra={
                "tenant_id": principal.tenant_id,
                "user_id": principal.user_id,
                "entra_device_id": principal.entra_device_id,
                "intune_device_id": device.intune_device_id,
            },
        )
    return StatusResponse(PolicyStatuses=payload.policy_statuses)


for prefix in CHECKIN_PREFIXES:
    router.add_api_route(
        f"{prefix}/status",
        _status,
        methods=["POST"],
        response_model=StatusResponse,
        response_model_by_alias=True,
        response_model_exclude_none=True,
    )


async def _device_state(
    request: Request,
    intune_device_id: UUID,
    query: Annotated[IWQuery, Depends(iw_query)],
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> Response:
    svc = services(request)
    principal = await principal_for(request, authorization, IWSERVICE_AUDIENCES)
    device = await svc.devices.require(principal, str(intune_device_id))
    params = {
        "api-version": query.api_version,
        "ssp": query.ssp,
        "ssp-version": query.ssp_version,
        "os": query.os,
        "mgmt-agent": query.mgmt_agent,
    }
    for key, value in (
        ("os-version", query.os_version),
        ("os-sub", query.os_sub),
        ("arch", query.arch),
    ):
        if value is not None:
            params[key] = value
    upstream = await svc.intune.proxy(
        "IWService",
        "GET",
        f"Devices(guid'{device.intune_device_id}')",
        bearer_value(authorization or ""),
        params,
    )
    if not upstream.is_success:
        return _upstream_response(upstream)
    try:
        body = upstream.json()
    except ValueError as exc:
        raise UpstreamError("IWService returned invalid JSON") from exc
    if str(body.get("Key", "")).lower() != device.intune_device_id:
        raise UpstreamError("IWService returned a different Intune device")
    aad_id = str(body.get("AadId", "")).lower()
    if aad_id and aad_id != device.entra_device_id:
        raise UpstreamError("IWService returned a different Entra device")
    aggregate = await svc.repository.aggregate(
        f"{principal.tenant_id}:{device.intune_device_id}"
    )
    if aggregate["complianceState"] == "NonCompliant":
        body["ComplianceState"] = "NonCompliant"
        rules = body.setdefault("NoncompliantRules", [])
        existing = {str(item.get("SettingID")) for item in rules if isinstance(item, dict)}
        for failure in aggregate.get("failures", []):
            setting_id = f"Himmelblau.{failure['userId']}.{failure['settingId']}"
            if setting_id not in existing:
                rules.append(
                    {
                        "ComplianceSource": "HimmelblauMDM",
                        "SettingID": setting_id,
                        "Title": "Himmelblau per-user policy is not compliant",
                        "ExpectedValue": "Compliant",
                        "Description": (
                            f"Policy {failure['policyId']} rule {failure['ruleId']} "
                            f"reported {failure['state']}"
                        ),
                        "MoreInfoUri": "",
                        "RemediationOwner": 2,
                    }
                )
    return JSONResponse(body, status_code=upstream.status_code)


for prefix in IW_PREFIXES:
    router.add_api_route(
        f"{prefix}/Devices(guid'{{intune_device_id}}')",
        _device_state,
        methods=["GET"],
        response_model=None,
    )


def _upstream_response(upstream: httpx.Response) -> Response:
    headers = {}
    for name in ("content-type", "retry-after", "request-id", "client-request-id"):
        if name in upstream.headers:
            headers[name] = upstream.headers[name]
    return Response(content=upstream.content, status_code=upstream.status_code, headers=headers)
