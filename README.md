# Himmelblau MDM

Himmelblau MDM is a single-tenant compatibility mediator for Microsoft Intune for Linux. It proxies native enrollment and check-in operations to the tenant's discovered Intune services, while calculating policies for each authenticated user and the verified Entra device through Microsoft Graph. This removes the native client's single-associated-user policy limitation without weakening device identity checks.

This is an MVP. Microsoft remains the policy and enrollment authority. Himmelblau MDM does not create policies, implement ADMX, or inject arbitrary compliance into Intune. It records per-user results locally, mirrors native status only when Intune accepts it, and returns a fail-closed merged state to Himmelblau clients.

## Security model

Every protocol call validates the Microsoft JWT signature, configured tenant, issuer, lifetime, operation-specific audience, Linux Company Portal caller application, user object ID, and Entra `deviceid` claim. Enrollment stores separate Entra Device ID, Entra device object ID, and Intune Device ID fields. Later requests must bind the caller's signed device claim to that enrollment mapping. The enrolling user is metadata, not an authorization boundary, so another user on the same verified device is accepted.

If a token has no trustworthy device claim, the request fails closed. Hostnames and caller-supplied IDs are never substitutes for device authentication. Tokens, certificates' private keys, app credentials, and Authorization headers are neither logged nor persisted.

## Azure prerequisites

- An Azure subscription and an Entra tenant with Microsoft Intune licensing for Linux enrollment.
- Azure CLI, Bicep support in Azure CLI, `zip`, `jq`, and `curl`.
- An administrator able to assign Microsoft Graph application roles (normally Global Administrator or Privileged Role Administrator).
- Permission to create a resource group, App Service, and Cosmos DB account.

The App Service managed identity receives these Microsoft Graph application permissions:

| Permission | Purpose |
|---|---|
| `DeviceManagementConfiguration.Read.All` | Read native Intune configuration/compliance policies, settings, assignments, and Group Policy assignment metadata. |
| `User.Read.All` | Resolve user directory data needed by transitive membership. |
| `Device.Read.All` | Resolve the signed Entra device ID and device membership. |
| `Member.Read.Hidden` | Include hidden membership when the tenant uses it. |
| `ServicePrincipalEndpoint.Read.All` | Discover the tenant's regional Linux Enrollment, Check-in, and IWService endpoints. |

No Microsoft Graph write permission is requested.

## Deploy

From the repository root:

```bash
./deploy/azure/bootstrap.sh \
  --subscription <subscription-id> \
  --resource-group himmelblau-mdm \
  --location <azure-region>
```

Use `--app-name <globally-unique-name>` to select the hostname. The script is idempotent where Azure permits it: it reuses the resource group and deployment, skips existing Graph role assignments, deploys the current source, checks `/health`, and prints all three protocol base URLs. If it cannot grant admin consent, it stops with an actionable message instead of producing a nominally deployed but unusable service. It never creates or prints a client secret.

To inspect the service:

```bash
curl https://<app-name>.azurewebsites.net/health
az webapp log tail --resource-group himmelblau-mdm --name <app-name>
```

For local development, install `requirements-dev.txt`, set at least `HB_TENANT_ID`, and run `uvicorn main:app`. With no `HB_COSMOS_ENDPOINT`, an in-memory repository is used and state is lost at restart.

## Protocol endpoints

The canonical endpoints are:

```text
<base>/LinuxMDM/LinuxEnrollmentService/enroll
<base>/LinuxMDM/LinuxDeviceCheckinService/details
<base>/LinuxMDM/LinuxDeviceCheckinService/policies/{intune-device-id}
<base>/LinuxMDM/LinuxDeviceCheckinService/status
<base>/IWService/StatelessIWService/Devices(guid'{intune-device-id}')
```

Aliases with `/TrafficGateway/TrafficRoutingService` before those paths are also registered. Query strings and property casing follow `intune-spec.md`; enrollment, details, native status, and IW state call Microsoft endpoints discovered from the Intune service principal rather than a hard-coded regional hostname.

## Client configuration requirement

The current `libhimmelblau` client discovers Microsoft's URLs and does **not** expose an endpoint override. Therefore a released client cannot yet be pointed at this service by configuration alone. The required companion change is a single-base-URL override which derives the three paths printed above and bypasses Microsoft endpoint discovery when configured; token acquisition must continue using the protocol's Microsoft audiences. This repository deliberately does not document a nonexistent setting. Until that separate change lands, use a compatible development build implementing that override.

Once configured, verify the sequence in client debug logs (without token logging): successful `enroll`, `details`, user-specific `policies`, `status`, and IW device state. A second Entra user on the same signed device should receive their user plus device assignments; the same Intune ID presented from another signed device must receive HTTP 403.

## Policy behavior and limitations

The resolver handles all-users, all-devices, transitive user/device group inclusion, group exclusion, and user/device union. Graph pagination is followed throughout. Assignment filters are not yet evaluated because reproducing the complete Intune filter property language safely requires more device inventory semantics; any policy depending on one is omitted with an `unsupported_assignment_filter` diagnostic. Unknown targets or settings are also omitted, never guessed. A Graph/permission failure returns an error and is not disguised as an empty policy set.

`groupPolicyConfigurations` assignments are evaluated and diagnosed, but their ADMX content is not served. The policy source, assignment resolver, effective-policy service, and wire translator are separate so native ADMX/Samba sources can be added later.

Local status is stored per tenant, device, user, policy, rule, and setting with previous/current state and upstream-sync outcome. Any active `NonCompliant`, `Error`, or `Unknown` result makes the local device aggregate non-compliant. A successful report from another user cannot erase it. This merged state only affects the response to the Himmelblau client; it does not claim that Intune Conditional Access knows about Himmelblau-specific state.

## Tests

```bash
python -m pip install -r requirements-dev.txt
pytest
```

Normal tests mock Microsoft interactions and require no tenant. Live-tenant integration remains a manual deployment verification because enrollment changes real tenant state.

## Remove

The deployment is contained in the selected resource group. After reviewing that it contains no unrelated resources:

```bash
az group delete --name himmelblau-mdm
```

Resource-group deletion is destructive and removes locally stored enrollment/compliance history. The managed identity and its Graph assignments are removed with the App Service. It does not retire devices from Intune; perform that separately according to your organization's retention process.
