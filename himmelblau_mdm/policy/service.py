from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from ..clients.graph import GraphClient
from ..models import AssignmentContext, DeviceRecord, ServedPolicySnapshot, WirePolicy
from ..persistence import Repository
from .assignments import AssignmentResolver
from .translation import NativeWireTranslator


LOG = logging.getLogger(__name__)


class PolicyService:
    def __init__(self, graph: GraphClient, repository: Repository) -> None:
        self.graph = graph
        self.repository = repository
        self.resolver = AssignmentResolver()
        self.translator = NativeWireTranslator()
        self._limit = asyncio.Semaphore(10)

    async def effective_policies(
        self, device: DeviceRecord, user_id: str
    ) -> ServedPolicySnapshot:
        user_groups, device_groups, policies, group_policies = await asyncio.gather(
            self.graph.transitive_user_groups(user_id),
            self.graph.transitive_device_groups(device.entra_device_object_id),
            self.graph.list_native_policies(),
            self.graph.list_group_policies(),
        )
        context = AssignmentContext(
            user_id=user_id,
            entra_device_id=device.entra_device_id,
            entra_device_object_id=device.entra_device_object_id,
            user_group_ids=user_groups,
            device_group_ids=device_groups,
        )
        diagnostics: list[dict[str, Any]] = []
        translated: list[WirePolicy] = []
        results = await asyncio.gather(
            *(self._process_native(policy, context, user_id) for policy in policies)
        )
        for wire, policy_diagnostics in results:
            diagnostics.extend(policy_diagnostics)
            if wire:
                translated.append(wire)

        group_results = await asyncio.gather(
            *(self._process_group_policy(policy, context) for policy in group_policies)
        )
        for result in group_results:
            diagnostics.extend(result)

        canonical = json.dumps(
            [item.model_dump(mode="json", by_alias=True, exclude_none=True) for item in translated],
            sort_keys=True,
            separators=(",", ":"),
        )
        snapshot = ServedPolicySnapshot(
            id=f"snapshot:{device.intune_device_id}:{user_id}",
            tenant_id=device.tenant_id,
            intune_device_id=device.intune_device_id,
            user_id=user_id,
            served_at=datetime.now(timezone.utc),
            source_fingerprint=hashlib.sha256(canonical.encode()).hexdigest(),
            policies=translated,
            diagnostics=diagnostics,
        )
        await self.repository.save_snapshot(snapshot)
        return snapshot

    async def _process_native(
        self, policy: dict[str, Any], context: AssignmentContext, account_id: str
    ) -> tuple[WirePolicy | None, list[dict[str, Any]]]:
        policy_id = str(policy.get("id", ""))
        source = str(policy.get("_source", "configurationPolicies"))
        async with self._limit:
            assignments = await self.graph.assignments(source, policy_id)
        decision = self.resolver.resolve(policy_id, assignments, context)
        self._log_decision(policy_id, decision.applies, decision.reasons, decision.diagnostics)
        if not decision.applies:
            return None, decision.diagnostics
        async with self._limit:
            settings = await self.graph.settings_for_policy(source, policy_id)
        definitions: dict[str, dict[str, Any]] = {}
        definition_lists = await asyncio.gather(
            *(self._definitions(source, policy_id, str(setting.get("id", ""))) for setting in settings)
        )
        for definition_list in definition_lists:
            for definition in definition_list:
                if definition.get("id"):
                    definitions[str(definition["id"])] = definition
        wire, translation_diagnostics = self.translator.translate(
            policy, settings, definitions, account_id
        )
        return wire, decision.diagnostics + translation_diagnostics

    async def _definitions(self, source: str, policy_id: str, setting_id: str):
        if not setting_id:
            return []
        async with self._limit:
            return await self.graph.setting_definitions(source, policy_id, setting_id)

    async def _process_group_policy(
        self, policy: dict[str, Any], context: AssignmentContext
    ) -> list[dict[str, Any]]:
        policy_id = str(policy.get("id", ""))
        async with self._limit:
            assignments = await self.graph.assignments("groupPolicyConfigurations", policy_id)
        decision = self.resolver.resolve(policy_id, assignments, context)
        if decision.applies:
            decision.diagnostics.append(
                {
                    "policyId": policy_id,
                    "code": "unsupported_policy_source",
                    "reason": "groupPolicyConfigurations require future ADMX translation",
                }
            )
        self._log_decision(policy_id, decision.applies, decision.reasons, decision.diagnostics)
        return decision.diagnostics

    @staticmethod
    def _log_decision(
        policy_id: str, applies: bool, reasons: list[str], diagnostics: list[dict[str, Any]]
    ) -> None:
        LOG.debug(
            "Policy assignment decision",
            extra={
                "policy_id": policy_id,
                "reason": {"applies": applies, "reasons": reasons, "diagnostics": diagnostics},
            },
        )
