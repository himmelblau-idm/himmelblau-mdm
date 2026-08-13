from __future__ import annotations

from dataclasses import dataclass

import httpx

from .auth import TokenValidator
from .clients.graph import GraphClient
from .clients.http import MicrosoftHttpClient
from .clients.intune import IntuneClient
from .compliance import ComplianceService
from .config import Settings
from .devices import DeviceBindingService
from .persistence import Repository
from .policy import PolicyService


@dataclass
class Services:
    settings: Settings
    httpx_client: httpx.AsyncClient
    token_validator: TokenValidator
    graph: GraphClient
    intune: IntuneClient
    repository: Repository
    devices: DeviceBindingService
    policies: PolicyService
    compliance: ComplianceService

    async def close(self) -> None:
        await self.graph.close()
        await self.repository.close()
        await self.httpx_client.aclose()
