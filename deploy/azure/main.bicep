@description('Globally unique lower-case App Service name.')
param appName string
param location string = resourceGroup().location
param tenantId string

var cosmosName = take(toLower('${appName}-cosmos'), 44)
var planName = '${appName}-plan'

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: planName
  location: location
  sku: {
    name: 'B1'
    tier: 'Basic'
  }
  kind: 'linux'
  properties: {
    reserved: true
  }
}

resource cosmos 'Microsoft.DocumentDB/databaseAccounts@2024-05-15' = {
  name: cosmosName
  location: location
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    disableLocalAuth: true
    enableAutomaticFailover: false
    consistencyPolicy: {
      defaultConsistencyLevel: 'Session'
    }
    locations: [
      {
        locationName: location
        failoverPriority: 0
        isZoneRedundant: false
      }
    ]
  }
}

resource database 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2024-05-15' = {
  parent: cosmos
  name: 'himmelblau-mdm'
  properties: {
    resource: {
      id: 'himmelblau-mdm'
    }
    options: {
      throughput: 400
    }
  }
}

resource devicesContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2024-05-15' = {
  parent: database
  name: 'devices'
  properties: {
    resource: {
      id: 'devices'
      partitionKey: {
        paths: [
          '/tenant_id'
        ]
        kind: 'Hash'
      }
    }
  }
}

resource policyStateContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2024-05-15' = {
  parent: database
  name: 'policy_state'
  properties: {
    resource: {
      id: 'policy_state'
      partitionKey: {
        paths: [
          '/tenant_id'
        ]
        kind: 'Hash'
      }
    }
  }
}

resource complianceContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2024-05-15' = {
  parent: database
  name: 'compliance'
  properties: {
    resource: {
      id: 'compliance'
      partitionKey: {
        paths: [
          '/device_key'
        ]
        kind: 'Hash'
      }
    }
  }
}

resource app 'Microsoft.Web/sites@2023-12-01' = {
  name: appName
  location: location
  kind: 'app,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    clientAffinityEnabled: false
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.12'
      alwaysOn: true
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      http20Enabled: true
      appCommandLine: 'bash startup.sh'
      appSettings: [
        { name: 'HB_TENANT_ID', value: tenantId }
        { name: 'HB_CLOUD', value: 'public' }
        { name: 'HB_COSMOS_ENDPOINT', value: cosmos.properties.documentEndpoint }
        { name: 'HB_COSMOS_DATABASE', value: 'himmelblau-mdm' }
        { name: 'SCM_DO_BUILD_DURING_DEPLOYMENT', value: 'true' }
        { name: 'ENABLE_ORYX_BUILD', value: 'true' }
        { name: 'PYTHON_ENABLE_GUNICORN_MULTIWORKERS', value: 'true' }
      ]
    }
  }
}

// Cosmos DB Built-in Data Contributor. This grants data-plane access only.
resource cosmosDataRole 'Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments@2024-05-15' = {
  parent: cosmos
  name: guid(cosmos.id, app.name, 'data-contributor')
  properties: {
    roleDefinitionId: '${cosmos.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002'
    principalId: app.identity.principalId
    scope: cosmos.id
  }
}

output appName string = app.name
output principalId string = app.identity.principalId
output baseUrl string = 'https://${app.properties.defaultHostName}'
output cosmosName string = cosmos.name
