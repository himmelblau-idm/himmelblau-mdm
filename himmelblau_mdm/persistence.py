from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from azure.cosmos import PartitionKey
from azure.cosmos.aio import CosmosClient
from azure.identity.aio import DefaultAzureCredential

from .config import Settings
from .models import ComplianceResult, DeviceRecord, ServedPolicySnapshot


class Repository(ABC):
    @abstractmethod
    async def save_device(self, device: DeviceRecord) -> None: ...

    @abstractmethod
    async def get_device(self, tenant_id: str, intune_device_id: str) -> DeviceRecord | None: ...

    @abstractmethod
    async def save_snapshot(self, snapshot: ServedPolicySnapshot) -> None: ...

    @abstractmethod
    async def get_snapshot(
        self, tenant_id: str, intune_device_id: str, user_id: str
    ) -> ServedPolicySnapshot | None: ...

    @abstractmethod
    async def save_results(self, results: list[ComplianceResult]) -> None: ...

    @abstractmethod
    async def update_sync(
        self, device_key: str, result_ids: list[str], status: str, error: str | None
    ) -> None: ...

    @abstractmethod
    async def aggregate(self, device_key: str) -> dict[str, Any]: ...

    async def close(self) -> None:
        return None


class MemoryRepository(Repository):
    def __init__(self) -> None:
        self.devices: dict[tuple[str, str], DeviceRecord] = {}
        self.snapshots: dict[tuple[str, str, str], ServedPolicySnapshot] = {}
        self.results: dict[str, ComplianceResult] = {}
        self.aggregates: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def save_device(self, device: DeviceRecord) -> None:
        async with self._lock:
            key = (device.tenant_id, device.intune_device_id)
            existing = self.devices.get(key)
            if existing and existing.entra_device_id != device.entra_device_id:
                raise ValueError("Intune device ID is already bound to another Entra device")
            self.devices[key] = device.model_copy(deep=True)

    async def get_device(self, tenant_id: str, intune_device_id: str) -> DeviceRecord | None:
        value = self.devices.get((tenant_id, intune_device_id.lower()))
        return value.model_copy(deep=True) if value else None

    async def save_snapshot(self, snapshot: ServedPolicySnapshot) -> None:
        async with self._lock:
            key = (snapshot.tenant_id, snapshot.intune_device_id, snapshot.user_id)
            self.snapshots[key] = snapshot.model_copy(deep=True)

    async def get_snapshot(
        self, tenant_id: str, intune_device_id: str, user_id: str
    ) -> ServedPolicySnapshot | None:
        value = self.snapshots.get((tenant_id, intune_device_id.lower(), user_id.lower()))
        return value.model_copy(deep=True) if value else None

    async def save_results(self, results: list[ComplianceResult]) -> None:
        async with self._lock:
            for result in results:
                previous = self.results.get(result.id)
                if previous:
                    result.previous_status = previous.current_status
                self.results[result.id] = result.model_copy(deep=True)
            if results:
                self._recompute(results[0].device_key)

    def _recompute(self, device_key: str) -> None:
        active = [item for item in self.results.values() if item.device_key == device_key and item.active]
        failures = [
            item for item in active if item.current_status.lower() in {"noncompliant", "error", "unknown"}
        ]
        self.aggregates[device_key] = {
            "deviceKey": device_key,
            "complianceState": "NonCompliant" if failures else "Compliant",
            "failureCount": len(failures),
            "updatedAt": datetime.now(timezone.utc).isoformat(),
            "failures": [
                {
                    "userId": item.user_id,
                    "policyId": item.policy_id,
                    "ruleId": item.rule_id,
                    "settingId": item.setting_id,
                    "state": item.current_status,
                }
                for item in failures
            ],
        }

    async def update_sync(
        self, device_key: str, result_ids: list[str], status: str, error: str | None
    ) -> None:
        async with self._lock:
            now = datetime.now(timezone.utc)
            for result_id in result_ids:
                item = self.results.get(result_id)
                if item:
                    item.upstream_sync_status = status
                    item.upstream_sync_at = now
                    item.upstream_error = error

    async def aggregate(self, device_key: str) -> dict[str, Any]:
        async with self._lock:
            if device_key not in self.aggregates:
                self._recompute(device_key)
            return dict(self.aggregates[device_key])


class CosmosRepository(Repository):
    def __init__(self, settings: Settings) -> None:
        if not settings.cosmos_endpoint:
            raise ValueError("HB_COSMOS_ENDPOINT is required")
        self.settings = settings
        self.credential = DefaultAzureCredential(
            managed_identity_client_id=settings.managed_identity_client_id
        )
        self.client = CosmosClient(settings.cosmos_endpoint, credential=self.credential)
        self.database = None
        self.devices = None
        self.policy_state = None
        self.compliance = None
        self._aggregate_lock = asyncio.Lock()

    async def initialize(self) -> None:
        self.database = await self.client.create_database_if_not_exists(self.settings.cosmos_database)
        self.devices = await self.database.create_container_if_not_exists(
            "devices", PartitionKey(path="/tenant_id")
        )
        self.policy_state = await self.database.create_container_if_not_exists(
            "policy_state", PartitionKey(path="/tenant_id")
        )
        self.compliance = await self.database.create_container_if_not_exists(
            "compliance", PartitionKey(path="/device_key")
        )

    async def close(self) -> None:
        await self.client.close()
        await self.credential.close()

    @staticmethod
    def _document(model: Any) -> dict[str, Any]:
        return model.model_dump(mode="json", by_alias=False)

    async def save_device(self, device: DeviceRecord) -> None:
        assert self.devices is not None
        existing = await self.get_device(device.tenant_id, device.intune_device_id)
        if existing and existing.entra_device_id != device.entra_device_id:
            raise ValueError("Intune device ID is already bound to another Entra device")
        await self.devices.upsert_item(self._document(device))

    async def get_device(self, tenant_id: str, intune_device_id: str) -> DeviceRecord | None:
        assert self.devices is not None
        try:
            row = await self.devices.read_item(
                item=f"device:{intune_device_id.lower()}", partition_key=tenant_id
            )
        except Exception as exc:
            if getattr(exc, "status_code", None) == 404:
                return None
            raise
        return DeviceRecord.model_validate(row)

    async def save_snapshot(self, snapshot: ServedPolicySnapshot) -> None:
        assert self.policy_state is not None
        await self.policy_state.upsert_item(self._document(snapshot))

    async def get_snapshot(
        self, tenant_id: str, intune_device_id: str, user_id: str
    ) -> ServedPolicySnapshot | None:
        assert self.policy_state is not None
        item_id = f"snapshot:{intune_device_id.lower()}:{user_id.lower()}"
        try:
            row = await self.policy_state.read_item(item=item_id, partition_key=tenant_id)
        except Exception as exc:
            if getattr(exc, "status_code", None) == 404:
                return None
            raise
        return ServedPolicySnapshot.model_validate(row)

    async def save_results(self, results: list[ComplianceResult]) -> None:
        assert self.compliance is not None
        async with self._aggregate_lock:
            for result in results:
                try:
                    old = await self.compliance.read_item(
                        item=result.id, partition_key=result.device_key
                    )
                    result.previous_status = old.get("current_status", result.previous_status)
                except Exception as exc:
                    if getattr(exc, "status_code", None) != 404:
                        raise
                await self.compliance.upsert_item(self._document(result))
            if results:
                await self._write_aggregate(results[0].device_key)

    async def _active_results(self, device_key: str) -> list[dict[str, Any]]:
        assert self.compliance is not None
        query = "SELECT * FROM c WHERE c.device_key = @d AND c.active = true AND NOT STARTSWITH(c.id, 'aggregate:')"
        iterator = self.compliance.query_items(
            query=query,
            parameters=[{"name": "@d", "value": device_key}],
            partition_key=device_key,
        )
        return [item async for item in iterator]

    async def _write_aggregate(self, device_key: str) -> dict[str, Any]:
        assert self.compliance is not None
        active = await self._active_results(device_key)
        failures = [
            item
            for item in active
            if str(item.get("current_status", "Unknown")).lower()
            in {"noncompliant", "error", "unknown"}
        ]
        aggregate = {
            "id": f"aggregate:{device_key}",
            "device_key": device_key,
            "deviceKey": device_key,
            "complianceState": "NonCompliant" if failures else "Compliant",
            "failureCount": len(failures),
            "updatedAt": datetime.now(timezone.utc).isoformat(),
            "failures": [
                {
                    "userId": item["user_id"],
                    "policyId": item["policy_id"],
                    "ruleId": item["rule_id"],
                    "settingId": item["setting_id"],
                    "state": item["current_status"],
                }
                for item in failures
            ],
        }
        await self.compliance.upsert_item(aggregate)
        return aggregate

    async def update_sync(
        self, device_key: str, result_ids: list[str], status: str, error: str | None
    ) -> None:
        assert self.compliance is not None
        for result_id in result_ids:
            try:
                row = await self.compliance.read_item(item=result_id, partition_key=device_key)
            except Exception as exc:
                if getattr(exc, "status_code", None) == 404:
                    continue
                raise
            row["upstream_sync_status"] = status
            row["upstream_sync_at"] = datetime.now(timezone.utc).isoformat()
            row["upstream_error"] = error
            await self.compliance.upsert_item(row)

    async def aggregate(self, device_key: str) -> dict[str, Any]:
        assert self.compliance is not None
        try:
            return await self.compliance.read_item(
                item=f"aggregate:{device_key}", partition_key=device_key
            )
        except Exception as exc:
            if getattr(exc, "status_code", None) != 404:
                raise
        async with self._aggregate_lock:
            return await self._write_aggregate(device_key)


async def build_repository(settings: Settings) -> Repository:
    if not settings.cosmos_endpoint:
        return MemoryRepository()
    repository = CosmosRepository(settings)
    await repository.initialize()
    return repository
