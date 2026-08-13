from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from ..models import PolicySetting, WirePolicy


class UnsupportedSetting(ValueError):
    pass


def _string_value(instance: dict[str, Any]) -> str:
    if "simpleSettingValue" in instance:
        value = instance["simpleSettingValue"].get("value")
    elif "choiceSettingValue" in instance:
        value = instance["choiceSettingValue"].get("value")
        definition_id = str(instance.get("settingDefinitionId", ""))
        prefix = f"{definition_id}_"
        if isinstance(value, str) and value.startswith(prefix):
            value = value[len(prefix) :]
    else:
        raise UnsupportedSetting("unsupported value instance")
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (str, int, float)):
        return str(value)
    raise UnsupportedSetting("setting value is not scalar")


def _flatten_instances(instance: dict[str, Any], index: int | None = None):
    definition_id = str(instance.get("settingDefinitionId", ""))
    collections = instance.get("groupSettingCollectionValue")
    if isinstance(collections, list):
        for group_index, group in enumerate(collections, start=1):
            if not isinstance(group, dict):
                continue
            children = group.get("children", [])
            if not isinstance(children, list):
                continue
            for child in children:
                if isinstance(child, dict):
                    yield from _flatten_instances(child, group_index)
        return
    yield instance, definition_id, index


class NativeWireTranslator:
    def translate(
        self,
        policy: dict[str, Any],
        settings: list[dict[str, Any]],
        definitions: dict[str, dict[str, Any]],
        account_id: str,
    ) -> tuple[WirePolicy | None, list[dict[str, Any]]]:
        output: list[PolicySetting] = []
        diagnostics: list[dict[str, Any]] = []
        for setting in settings:
            root_instance = setting.get("settingInstance")
            if not isinstance(root_instance, dict):
                diagnostics.append(self._diagnostic(policy, setting, "missing_setting_instance"))
                continue
            for instance, definition_id, collection_index in _flatten_instances(root_instance):
                definition = definitions.get(definition_id)
                if not definition:
                    diagnostics.append(self._diagnostic(policy, setting, "missing_setting_definition", definition_id))
                    continue
                base_uri = definition.get("baseUri")
                offset_uri = definition.get("offsetUri")
                definition_key = definition.get("id")
                rule_id = setting.get("id")
                if not all(isinstance(value, str) and value for value in (base_uri, definition_key, rule_id)):
                    diagnostics.append(self._diagnostic(policy, setting, "incomplete_wire_metadata", definition_id))
                    continue
                pieces = [base_uri.rstrip("/")]
                if offset_uri:
                    pieces.append(str(offset_uri).strip("/"))
                csp_path = "/".join(pieces)
                if collection_index is not None:
                    csp_path = csp_path.replace("{0}", str(collection_index)).replace("%7B0%7D", str(collection_index))
                try:
                    value = _string_value(instance)
                except UnsupportedSetting as exc:
                    diagnostics.append(self._diagnostic(policy, setting, str(exc), definition_id))
                    continue
                output.append(
                    PolicySetting(
                        settingDefinitionItemId=definition_id,
                        cspPath=csp_path,
                        cspPathId=definition_key,
                        ruleId=rule_id,
                        ruleName=definition.get("displayName"),
                        value=value,
                    )
                )
        if not output:
            return None, diagnostics
        modified = str(policy.get("lastModifiedDateTime", ""))
        try:
            version = int(datetime.fromisoformat(modified.replace("Z", "+00:00")).timestamp())
        except ValueError:
            canonical = json.dumps(settings, sort_keys=True, separators=(",", ":")).encode()
            version = int.from_bytes(hashlib.sha256(canonical).digest()[:4], "big")
        version = max(1, min(version, 4_294_967_295))
        policy_type = "Compliance" if policy.get("_source") == "compliancePolicies" else "Configuration"
        return (
            WirePolicy(
                accountId=account_id,
                policyId=str(policy["id"]),
                description=str(policy.get("description") or ""),
                version=version,
                policyType=policy_type,
                policySettings=output,
            ),
            diagnostics,
        )

    @staticmethod
    def _diagnostic(
        policy: dict[str, Any], setting: dict[str, Any], reason: str, definition_id: str | None = None
    ) -> dict[str, Any]:
        return {
            "policyId": policy.get("id"),
            "settingId": setting.get("id"),
            "settingDefinitionId": definition_id,
            "code": "unsupported_setting",
            "reason": reason,
        }
