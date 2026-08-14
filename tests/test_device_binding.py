import pytest

from himmelblau_mdm.devices import DeviceBindingService
from himmelblau_mdm.errors import DeviceBindingError
from himmelblau_mdm.persistence import MemoryRepository
from conftest import INTUNE, USER_B, principal


@pytest.mark.asyncio
async def test_enrollment_mapping_allows_users_on_same_device(device):
    repo = MemoryRepository()
    await repo.save_device(device)
    binding = DeviceBindingService(repo)
    assert (await binding.require(principal(), INTUNE)).intune_device_id == INTUNE
    assert (await binding.require(principal(USER_B), INTUNE)).intune_device_id == INTUNE


@pytest.mark.asyncio
async def test_other_device_cannot_reuse_intune_id(device):
    repo = MemoryRepository()
    await repo.save_device(device)
    with pytest.raises(DeviceBindingError):
        await DeviceBindingService(repo).require(
            principal(entra_device="77777777-7777-7777-7777-777777777777"), INTUNE
        )


@pytest.mark.asyncio
async def test_enrollment_cannot_rebind_intune_id(device):
    repo = MemoryRepository()
    await repo.save_device(device)
    changed = device.model_copy(update={"entra_device_id": "77777777-7777-7777-7777-777777777777"})
    with pytest.raises(ValueError):
        await repo.save_device(changed)
