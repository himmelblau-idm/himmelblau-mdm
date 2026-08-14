#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 --subscription ID --resource-group NAME --location REGION [--app-name NAME]"
}

subscription=""
resource_group=""
location=""
app_name=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --subscription) subscription="$2"; shift 2 ;;
    --resource-group) resource_group="$2"; shift 2 ;;
    --location) location="$2"; shift 2 ;;
    --app-name) app_name="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$subscription" || -z "$resource_group" || -z "$location" ]]; then
  usage >&2
  exit 2
fi
for tool in az zip curl jq; do
  command -v "$tool" >/dev/null || { echo "Required tool not found: $tool" >&2; exit 1; }
done

az account show >/dev/null 2>&1 || { echo "Run 'az login' before bootstrap." >&2; exit 1; }
az account set --subscription "$subscription"
tenant_id="$(az account show --query tenantId -o tsv)"
if [[ -z "$app_name" ]]; then
  suffix="$(printf '%s' "$tenant_id:$resource_group" | sha256sum | cut -c1-8)"
  app_name="himmelblau-mdm-$suffix"
fi
if [[ ! "$app_name" =~ ^[a-z0-9][a-z0-9-]{1,58}[a-z0-9]$ ]]; then
  echo "--app-name must be a 3-60 character lower-case App Service DNS name." >&2
  exit 2
fi

az group create --name "$resource_group" --location "$location" --output none
deployment="$(az deployment group create \
  --resource-group "$resource_group" \
  --template-file "$(dirname "$0")/main.bicep" \
  --parameters appName="$app_name" location="$location" tenantId="$tenant_id" \
  --query properties.outputs -o json)"
principal_id="$(printf '%s' "$deployment" | jq -r '.principalId.value')"
base_url="$(printf '%s' "$deployment" | jq -r '.baseUrl.value')"

graph_sp_id="$(az ad sp list --filter "appId eq '00000003-0000-0000-c000-000000000000'" --query '[0].id' -o tsv)"
permissions=(
  DeviceManagementConfiguration.Read.All
  User.Read.All
  Device.Read.All
  Member.Read.Hidden
  ServicePrincipalEndpoint.Read.All
)
for permission in "${permissions[@]}"; do
  role_id="$(az ad sp show --id "$graph_sp_id" --query "appRoles[?value=='$permission' && contains(allowedMemberTypes, 'Application')].id | [0]" -o tsv)"
  if [[ -z "$role_id" ]]; then
    echo "Microsoft Graph application role not found: $permission" >&2
    exit 1
  fi
  existing="$(az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/$principal_id/appRoleAssignments" --query "value[?resourceId=='$graph_sp_id' && appRoleId=='$role_id'].id | [0]" -o tsv)"
  if [[ -z "$existing" ]]; then
    if ! az rest --method POST \
      --url "https://graph.microsoft.com/v1.0/servicePrincipals/$principal_id/appRoleAssignments" \
      --headers Content-Type=application/json \
      --body "{\"principalId\":\"$principal_id\",\"resourceId\":\"$graph_sp_id\",\"appRoleId\":\"$role_id\"}" \
      --output none; then
      echo "Admin consent could not be granted. Ask a tenant Global Administrator or Privileged Role Administrator to rerun this command." >&2
      exit 1
    fi
  fi
done

archive="$(mktemp --suffix=.zip)"
trap 'rm -f "$archive"' EXIT
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
rm -f "$archive"
(cd "$repo_root" && zip -qr "$archive" . -x '.git/*' '.venv/*' '__pycache__/*' 'tests/*')
publish_user="$(az webapp deployment list-publishing-credentials \
  --resource-group "$resource_group" --name "$app_name" \
  --query publishingUserName -o tsv)"
publish_password="$(az webapp deployment list-publishing-credentials \
  --resource-group "$resource_group" --name "$app_name" \
  --query publishingPassword -o tsv)"
scm_url="https://${app_name}.scm.azurewebsites.net"
deploy_headers="$(mktemp)"
trap 'rm -f "$archive" "$deploy_headers"' EXIT
http_code="$(curl --silent --show-error --max-time 300 \
  -u "$publish_user:$publish_password" \
  -X POST --data-binary @"$archive" \
  "$scm_url/api/zipdeploy?isAsync=true" \
  -D "$deploy_headers" -o /dev/null -w '%{http_code}')"
if [[ "$http_code" != "202" && "$http_code" != "200" ]]; then
  echo "Zip deployment failed to start with HTTP $http_code." >&2
  exit 1
fi

deployed="false"
for _attempt in {1..60}; do
  status_json="$(curl --fail --silent --show-error --max-time 30 \
    -u "$publish_user:$publish_password" \
    "$scm_url/api/deployments/latest")"
  complete="$(printf '%s' "$status_json" | jq -r '.complete')"
  status="$(printf '%s' "$status_json" | jq -r '.status')"
  if [[ "$complete" == "true" ]]; then
    if [[ "$status" == "4" ]]; then
      deployed="true"
      break
    fi
    printf '%s\n' "$status_json" | jq -r '"Zip deployment failed: \(.status_text // .message // "unknown error")"' >&2
    exit 1
  fi
  sleep 10
done
if [[ "$deployed" != "true" ]]; then
  echo "Zip deployment did not finish before the timeout." >&2
  exit 1
fi

healthy="false"
for _attempt in {1..24}; do
  if curl --fail --silent --show-error --max-time 10 "$base_url/health" >/dev/null; then
    healthy="true"
    break
  fi
  sleep 5
done
if [[ "$healthy" != "true" ]]; then
  echo "Deployment completed but health check failed: $base_url/health" >&2
  echo "Inspect logs with: az webapp log tail -g $resource_group -n $app_name" >&2
  exit 1
fi

echo "Himmelblau MDM: $base_url"
echo "Enrollment: $base_url/LinuxMDM/LinuxEnrollmentService"
echo "Check-in:  $base_url/LinuxMDM/LinuxDeviceCheckinService"
echo "IWService: $base_url/IWService/StatelessIWService"
