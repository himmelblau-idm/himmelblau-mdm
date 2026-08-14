import json
from pathlib import Path

from himmelblau_mdm.policy.translation import NativeWireTranslator


FIXTURES = Path(__file__).parent / "fixtures"


def test_exact_intune_wire_shape():
    policy = json.loads((FIXTURES / "graph_policy.json").read_text())
    settings = json.loads((FIXTURES / "graph_settings.json").read_text())
    definitions = {
        "linux_password_minimum_length": {
            "id": "linux_password_minimum_length", "baseUri": "./Device/Vendor/MSFT",
            "offsetUri": "Policy/Config/Linux/PasswordMinimumLength", "displayName": "Minimum length",
        }
    }
    wire, diagnostics = NativeWireTranslator().translate(policy, settings, definitions, "user-id")
    assert diagnostics == []
    assert wire.model_dump(by_alias=True, exclude_none=True) == {
        "accountId": "user-id",
        "policyId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "description": "Require password properties",
        "version": 1786528800,
        "policyType": "Configuration",
        "policySettings": [{
            "settingDefinitionItemId": "linux_password_minimum_length",
            "cspPath": "./Device/Vendor/MSFT/Policy/Config/Linux/PasswordMinimumLength",
            "cspPathId": "linux_password_minimum_length",
            "ruleId": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "ruleName": "Minimum length", "value": "12",
        }],
    }


def test_unmappable_setting_is_omitted():
    policy = json.loads((FIXTURES / "graph_policy.json").read_text())
    wire, diagnostics = NativeWireTranslator().translate(
        policy, [{"id": "rule", "settingInstance": {"settingDefinitionId": "unknown"}}], {}, "user"
    )
    assert wire is None and diagnostics[0]["code"] == "unsupported_setting"
