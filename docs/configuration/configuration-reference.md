# Configuration Reference

EntraOps GUI reads its configuration from `EntraOpsConfig.json` in the repository root. The Settings screen in the GUI exposes most fields; the Connect Wizard manages the tenant identity fields.

## EntraOpsConfig.json Fields

### Core Identity

| Field | Type | Default | GUI Screen | Description |
|-------|------|---------|------------|-------------|
| `TenantId` | string (GUID) | - | Connect Wizard | Azure AD tenant GUID |
| `TenantName` | string | - | Connect Wizard | Tenant display name (e.g. `contoso.onmicrosoft.com`) |
| `AuthenticationType` | enum | - | Connect Wizard | Authentication method. One of: `UserInteractive`, `DeviceAuthentication`, `SystemAssignedMSI`, `UserAssignedMSI`, `FederatedCredentials`, `AlreadyAuthenticated` |
| `ClientId` | string (GUID) | - | Connect Wizard | App registration client ID used for delegated auth flows |
| `DevOpsPlatform` | enum | - | Settings | DevOps platform for workflow integration. One of: `GitHub`, `AzureDevOps`, `None` |
| `RbacSystems` | string[] | `["Azure","EntraID","IdentityGovernance","DeviceManagement","ResourceApps","Defender"]` | Settings | RBAC systems to analyse. Valid values: `Azure`, `AzureBilling`, `EntraID`, `IdentityGovernance`, `DeviceManagement`, `ResourceApps`, `Defender` |

### WorkflowTrigger

Controls automated GitHub/ADO workflow scheduling.

| Field | Type | Default | GUI Screen | Description |
|-------|------|---------|------------|-------------|
| `PullScheduledTrigger` | boolean | `true` | Settings | Enable scheduled pull workflow trigger |
| `PullScheduledCron` | string | `"0 2 * * 1"` | Settings | Cron expression for the pull schedule (default: Mondays at 02:00 UTC) |
| `PushAfterPullWorkflowTrigger` | boolean | `true` | Settings | Trigger a push workflow automatically after a pull completes |

### AutomatedControlPlaneScopeUpdate

Controls automatic scope updates for ControlPlane objects.

| Field | Type | Default | GUI Screen | Description |
|-------|------|---------|------------|-------------|
| `ApplyAutomatedControlPlaneScopeUpdate` | boolean | `false` | Settings | Enable automated ControlPlane scope update |
| `PrivilegedObjectClassificationSource` | string[] | `["EntraOps"]` | Settings | Source systems for privileged object classification |
| `EntraOpsScopes` | string[] | `["ControlPlane"]` | Settings | Scopes to apply automated ControlPlane updates to |
| `AzureHighPrivilegedRoles` | string[] | `["Owner","Contributor"]` | Settings | Azure RBAC roles considered high-privileged |
| `AzureHighPrivilegedScopes` | string[] | `["/"]` | Settings | Azure scopes considered high-privileged (root `/` = all subscriptions) |
| `ExposureCriticalityLevel` | string | `"High"` | Settings | Minimum exposure criticality level to include |

### AutomatedClassificationUpdate

Controls automatic classification updates.

| Field | Type | Default | GUI Screen | Description |
|-------|------|---------|------------|-------------|
| `ApplyAutomatedClassificationUpdate` | boolean | `true` | Settings | Enable automated classification updates |
| `Classifications` | string[] | `["AadResources","AppRoles"]` | Settings | Classification types to update automatically |

### AutomatedEntraOpsUpdate

Controls automatic EntraOps module self-update scheduling.

| Field | Type | Default | GUI Screen | Description |
|-------|------|---------|------------|-------------|
| `ApplyAutomatedEntraOpsUpdate` | boolean | `true` | Settings | Enable automated EntraOps module updates |
| `UpdateScheduledTrigger` | boolean | `true` | Settings | Enable scheduled update trigger |
| `UpdateScheduledCron` | string | `"0 3 * * 0"` | Settings | Cron expression for update schedule (default: Sundays at 03:00 UTC) |

### LogAnalytics

Controls ingestion of data into Azure Monitor / Log Analytics.

| Field | Type | Default | GUI Screen | Description |
|-------|------|---------|------------|-------------|
| `IngestToLogAnalytics` | boolean | `true` | Settings | Enable Log Analytics ingestion |
| `DataCollectionRuleName` | string | `""` | Settings | Name of the Data Collection Rule |
| `DataCollectionRuleSubscriptionId` | string | `""` | Settings | Subscription ID containing the DCR |
| `DataCollectionResourceGroupName` | string | `""` | Settings | Resource group containing the DCR |
| `TableName` | string | `"PrivilegedEAM_CL"` | Settings | Log Analytics custom table name |

### SentinelWatchLists

Controls ingestion into Microsoft Sentinel watchlists.

| Field | Type | Default | GUI Screen | Description |
|-------|------|---------|------------|-------------|
| `IngestToWatchLists` | boolean | `false` | Settings | Enable Sentinel watchlist ingestion |
| `WatchListTemplates` | string[] | `[]` | Settings | Watchlist template names to populate |
| `WatchListWorkloadIdentity` | string[] | `[]` | Settings | Workload identities for watchlist auth |
| `SentinelWorkspaceName` | string | `""` | Settings | Sentinel workspace name |
| `SentinelSubscriptionId` | string | `""` | Settings | Subscription containing the Sentinel workspace |
| `SentinelResourceGroupName` | string | `""` | Settings | Resource group containing the Sentinel workspace |
| `WatchListPrefix` | string | `"EntraOps"` | Settings | Prefix applied to all watchlist names |

### AutomatedAdministrativeUnitManagement

Controls automatic Administrative Unit assignments.

| Field | Type | Default | GUI Screen | Description |
|-------|------|---------|------------|-------------|
| `ApplyAdministrativeUnitAssignments` | boolean | `false` | Settings | Enable automated AU assignments |
| `ApplyToAccessTierLevel` | string[] | `["ControlPlane"]` | Settings | Tier levels to target for AU assignments |
| `FilterObjectType` | string[] | `["User","ServicePrincipal"]` | Settings | Object types to include |
| `RbacSystems` | string[] | `["EntraID"]` | Settings | RBAC systems to apply AU assignments within |
| `RestrictedAuMode` | string | `"Restricted"` | Settings | AU restriction mode (`Restricted` or `Unrestricted`) |

### AutomatedConditionalAccessTargetGroups

Controls automatic Conditional Access target group management.

| Field | Type | Default | GUI Screen | Description |
|-------|------|---------|------------|-------------|
| `ApplyConditionalAccessTargetGroups` | boolean | `false` | Settings | Enable automated CA target group management |
| `AdminUnitName` | string | `"EntraOps-CA"` | Settings | Name of the Administrative Unit for CA groups |
| `ApplyToAccessTierLevel` | string[] | `["ControlPlane"]` | Settings | Tier levels to target |
| `FilterObjectType` | string[] | `["User"]` | Settings | Object types to include in CA groups |
| `GroupPrefix` | string | `"EntraOps"` | Settings | Prefix for created CA target groups |
| `RbacSystems` | string[] | `["EntraID"]` | Settings | RBAC systems to manage CA groups within |

### AutomatedRmauAssignmentsForUnprotectedObjects

Controls RMAU assignments for objects not otherwise protected.

| Field | Type | Default | GUI Screen | Description |
|-------|------|---------|------------|-------------|
| `ApplyRmauAssignmentsForUnprotectedObjects` | boolean | `false` | Settings | Enable RMAU assignments for unprotected objects |
| `ApplyToAccessTierLevel` | string[] | `["ControlPlane"]` | Settings | Tier levels to target |
| `FilterObjectType` | string[] | `["User","ServicePrincipal"]` | Settings | Object types to include |
| `RbacSystems` | string[] | `["EntraID"]` | Settings | RBAC systems to apply RMAU assignments within |

### CustomSecurityAttributes

Attribute names used when stamping Custom Security Attributes on Entra objects. These are consumed by the PowerShell module and are not exposed in the GUI.

| Field | Type | Default | GUI Screen | Description |
|-------|------|---------|------------|-------------|
| `PrivilegedUserAttribute` | string | `"privilegedUser"` | - | CSA attribute name for privileged user accounts |
| `PrivilegedUserPawAttribute` | string | `"privilegedUserPaw"` | - | CSA attribute name for PAW accounts |
| `PrivilegedServicePrincipalAttribute` | string | `"privilegedServicePrincipal"` | - | CSA attribute name for privileged service principals |
| `UserWorkAccountAttribute` | string | `"userWorkAccount"` | - | CSA attribute name for work accounts |

## Environment Variables

These variables are read at startup by the Express API server (`gui/server/index.ts`).

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | TCP port the Express API server listens on. The React dev server always uses port `5173` regardless of this setting. |
| `ENTRAOPS_ROOT` | _(repo root, autodiscovered)_ | Path to the repository root containing `EntraOpsConfig.json`, `PrivilegedEAM/`, and `Classification/`. The server resolves this automatically from its own location; set this only if running the server from a non-standard working directory. |
| `NODE_ENV` | _(unset)_ | When set to `production`, Express serves the compiled React client from `gui/client/dist/` as static files. In development, leave unset and start the Vite dev server separately (`npm run dev` in `gui/client/`). |
