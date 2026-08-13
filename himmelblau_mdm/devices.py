from __future__ import annotations

from datetime import datetime, timezone

from .errors import DeviceBindingError
from .models import AuthenticatedPrincipal, DeviceRecord
from .persistence import Repository


class DeviceBindingService:
    def __init__(self, repository: Repository) -> None:
        self.repository = repository

    async def require(
        self, principal: AuthenticatedPrincipal, intune_device_id: str
    ) -> DeviceRecord:
        device = await self.repository.get_device(
            principal.tenant_id, intune_device_id.lower()
        )
        if not device:
            raise DeviceBindingError("Unknown Intune Device ID")
        if device.entra_device_id.lower() != principal.entra_device_id.lower():
            raise DeviceBindingError(
                "Intune Device ID is bound to a different Entra device"
            )
        return device

    async def update_metadata(self, device: DeviceRecord, metadata: dict) -> None:
        device.metadata.update(metadata)
        device.updated_at = datetime.now(timezone.utc)
        await self.repository.save_device(device)
