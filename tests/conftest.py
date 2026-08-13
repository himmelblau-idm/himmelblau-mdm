from datetime import datetime, timezone

import pytest

from himmelblau_mdm.models import AuthenticatedPrincipal, DeviceRecord


TENANT = "11111111-1111-1111-1111-111111111111"
DEVICE = "22222222-2222-2222-2222-222222222222"
DEVICE_OBJECT = "33333333-3333-3333-3333-333333333333"
INTUNE = "44444444-4444-4444-4444-444444444444"
USER_A = "55555555-5555-5555-5555-555555555555"
USER_B = "66666666-6666-6666-6666-666666666666"


@pytest.fixture
def device():
    now = datetime.now(timezone.utc)
    return DeviceRecord(
        id=f"device:{INTUNE}", tenant_id=TENANT, entra_device_id=DEVICE,
        entra_device_object_id=DEVICE_OBJECT, intune_device_id=INTUNE,
        enrolling_user_id=USER_A, device_name="linux", enrolled_at=now, updated_at=now,
    )


def principal(user=USER_A, entra_device=DEVICE):
    return AuthenticatedPrincipal(
        tenant_id=TENANT, user_id=user, entra_device_id=entra_device,
        client_id="b743a22d-6705-4147-8670-d92fa515ee2b", claims={},
    )
