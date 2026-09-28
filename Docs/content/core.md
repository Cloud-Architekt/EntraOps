# Core

Authentication, the `EntraOpsConfig.json` file, alternative ways to classify users and service
principals, and how to keep EntraOps itself up to date.

## Authentication options

EntraOps supports several sign-in methods depending on how you run it - interactive/local, federated
credentials in GitHub Actions, an already-authenticated Azure PowerShell session, or a
user-assigned managed identity. See [Get Started &rarr; Import module and sign-in options](../get-started/index.html#import-module-and-sign-in-options)
for the full set of `Connect-EntraOps` examples.

## Service principal permissions

`New-EntraOpsWorkloadIdentity` creates or updates the workload identity from the current
`EntraOpsConfig.json`. Run it after changing feature settings so it can add the corresponding
optional grants. The account that runs this setup needs temporary directory and Azure permissions
to create the application, grant Microsoft Graph application permissions, and create the listed
Azure role assignments.

### Baseline collection permissions

The following Microsoft Graph **application permissions** are granted for standard Privileged EAM
collection. They cover the supported Entra ID, Identity Governance, Intune, Defender, Microsoft
Graph application-role, and Azure RBAC collection paths:

| Permission                                        | What EntraOps reads                                                                                            |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `AdministrativeUnit.Read.All`                     | Administrative Units and their scoped membership/management context.                                           |
| `Application.Read.All`                            | App registrations and application metadata used to identify workload identities and API permissions.           |
| `CustomSecAttributeAssignment.Read.All`           | Custom Security Attribute assignments used to classify users and service principals by intended tier.          |
| `DeviceManagementConfiguration.Read.All`          | Intune device-management configuration, including policies and settings relevant to privileged administration. |
| `DeviceManagementManagedDevices.Read.All`         | Intune-managed device inventory, including the device details used for PAW correlation.                        |
| `DeviceManagementRBAC.Read.All`                   | Intune RBAC roles, role assignments, and scope groups.                                                         |
| `DeviceManagementServiceConfig.Read.All`          | Intune service configuration needed to resolve device-management administrative context.                       |
| `Directory.Read.All`                              | Directory objects and relationships that do not have a more specific read permission.                          |
| `DirectoryRecommendations.Read.All`               | Microsoft Entra recommendations used to enrich workload identity posture.                                      |
| `EntitlementManagement.Read.All`                  | Identity Governance entitlement-management catalogs, access packages, and their assignments.                   |
| `Group.Read.All`                                  | Groups, membership, owners, and role-assignable group relationships.                                           |
| `Policy.Read.All`                                 | Entra ID policies, including policy context used in privilege analysis.                                        |
| `PrivilegedAccess.Read.AzureADGroup`              | Privileged access assignments for Entra ID groups.                                                             |
| `PrivilegedEligibilitySchedule.Read.AzureADGroup` | PIM eligibility schedules for Entra ID groups.                                                                 |
| `RemoteTenantGroups.Read.All`                     | Groups from governed tenants in cross-tenant Tenant Governance relationships.                                  |
| `RoleManagement.Read.All`                         | Entra ID role definitions, active assignments, eligibility, and role-management schedules.                     |
| `TenantGovernance-Relationship.Read.All`          | Tenant Governance delegated-administration relationships and managed-tenant context.                           |
| `ThreatHunting.Read.All`                          | Microsoft Defender advanced hunting data used for security-posture enrichment.                                 |
| `User.Read.All`                                   | User profiles and user-to-privileged-object relationships.                                                     |
| `Zone.Read.All`                                   | Microsoft Defender security zones used to resolve Unified RBAC CloudSet scope assignments.                     |

`CustomSecAttributeAssignment.Read.All` requires administrator consent. When using an existing
service principal, ensure this permission is granted explicitly; it is needed when object tiers
are read from Custom Security Attributes.

### Feature-specific permissions

These grants are added only when the related configuration is enabled. Disable an optional feature
and remove its grant if it is no longer required.

| Feature / configuration                                                                                                                          | Additional permission or role assignment                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Administrative Unit assignment or automatic RMAU assignment (`ApplyAdministrativeUnitAssignments` / `ApplyRmauAssignmentsForUnprotectedObjects`) | Microsoft Graph `AdministrativeUnit.ReadWrite.All`                                                                                                                                                                                                                                                                                                                                                                                      |
| Conditional Access target groups (`ApplyConditionalAccessTargetGroups`)                                                                          | Scoped **Group Administrator** directory role on the EntraOps Conditional Access Groups Administrative Unit                                                                                                                                                                                                                                                                                                                             |
| Privileged Entitlement Management catalog protection (`ApplyPrivilegedElmCatalogProtection`)                                                     | Microsoft Graph `EntitlementManagement.ReadWrite.All`                                                                                                                                                                                                                                                                                                                                                                                   |
| Tenant Governance snapshots (`EnableTenantGovernanceSnapshot`)                                                                                   | Microsoft Graph `ConfigurationMonitoring.ReadWrite.All`, plus least-privileged read permissions on the first-party **Microsoft Tenant Configuration Management** service principal for each selected resource type. See [Tenant Governance](../tenant-governance/index.html#permissions-and-prerequisites).                                                                                                                             |
| Log Analytics ingestion (`IngestToLogAnalytics`)                                                                                                 | **Monitoring Metrics Publisher** and **Reader** on the Data Collection Rule resource group                                                                                                                                                                                                                                                                                                                                              |
| Microsoft Sentinel WatchList ingestion (`IngestToWatchLists`)                                                                                    | **Microsoft Sentinel Contributor** on the Sentinel workspace resource group                                                                                                                                                                                                                                                                                                                                                             |
| Control Plane scope discovery from Azure Resource Graph, or selected Azure-backed WatchList templates                                            | **Reader** on the tenant root management group                                                                                                                                                                                                                                                                                                                                                                                          |
| Azure RBAC assignments made directly at the Azure Resource Manager tenant root (`/`)                                                             | Optional **Reader** at `/`, assigned only when `New-EntraOpsWorkloadIdentity -GrantArmRootScopeReader` is used. This is separate from the tenant root management group, requires elevated access to assign, is not shown in normal portal RBAC blades, and must be removed explicitly during offboarding. Without it, EntraOps still covers scopes under the root management group but cannot read assignments created directly at `/`. |

The setup cmdlet assigns these grants for a new or existing service principal. For an identity
managed outside EntraOps, use this table to review equivalent grants before running collection.

## Configuration file reference

The `EntraOpsConfig.json` file (for example, created with `New-EntraOpsConfigFile -TenantName "contoso.onmicrosoft.com"`)
controls almost every aspect of automated execution. The most relevant sections:

| Section / setting                                                                                                                                                              | Purpose                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TenantId` / `TenantName` / `ClientId`                                                                                                                                         | Target tenant and the workload identity used by EntraOps. `ClientId` is filled in automatically by `New-EntraOpsWorkloadIdentity`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `DevOpsPlatform`                                                                                                                                                               | Selects the shipped automation path: `GitHub` for GitHub Actions, `AzureDevOps` for Azure Pipelines with a WIF service connection, or `None` for configured local/custom automation. See [Get Started -> Automate with Azure DevOps](../get-started/index.html#deploy-with-azure-devops).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `UseInvokeRestMethodOnly`                                                                                                                                                      | Run all `Invoke-EntraOps*Query` cmdlets with `Invoke-RestMethod` instead of the Microsoft Graph SDK (`Invoke-MgGraphRequest`). Default `false`. When enabled, the Graph SDK is neither required nor installed - tokens are provided via `Connect-EntraOps -MsGraphAccessToken` or acquired from the Az PowerShell context. An explicit `Connect-EntraOps -UseInvokeRestMethodOnly` parameter wins over the config file. REST-only parallel object resolution pre-warms a Graph token from the Az PowerShell context; it falls back to sequential processing only when that token cannot be prepared.                                                                                                                                                                                                                               |
| `ConsoleOutput.IncludeObjectDetails`                                                                                                                                           | Controls descriptive object data in console and workflow logs. Default `false`: object IDs remain visible for diagnostics, while display names, UPNs, classification reasons, scope-tag names, application metadata, and detailed object-specific API errors are omitted. Set to `true` only when workflow logs may contain those details and should therefore be treated as confidential. An explicit cmdlet `-IncludeObjectDetails $true` or `$false` overrides the configured session preference for that invocation.                                                                                                                                                                                                                                                                                                           |
| `PullScheduledTrigger` / `PullScheduledCron`                                                                                                                                   | Enable and schedule the recurring pull workflow that collects and classifies Privileged EAM data.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `PushAfterPullWorkflowTrigger`                                                                                                                                                 | Trigger the ingestion workflow right after a successful pull.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `PushReportingAfterPullWorkflowTrigger` / `PushReportingScheduledTrigger` / `PushReportingScheduledCron`                                                                       | Control when the `Push-EntraOpsPrivilegedReporting` workflow regenerates the [Reporting apps](../reportings/index.html#entraops-reporting-apps) data - after every pull, on its own schedule (default weekly, Monday 09:00 UTC), or only on manual dispatch if both are disabled.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `AutomatedClassificationUpdate`                                                                                                                                                | Automatically update classification templates from the upstream repository.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `GeneratedArtifactValidation.FailOnContradictoryTierPair`                                                                                                                      | Controls how `Pull-EntraOpsPrivilegedEAM` reacts when an object's tier value contradicts its tier name (for example `0` paired with `ManagementPlane`). Default `false` reports each object as a warning and still commits the collected data, because the cause is Custom Security Attribute drift on the source object in Microsoft Entra rather than a code defect. Set to `true` to fail the workflow before the commit until the tagging is corrected.                                                                                                                                                                                                                                                                                                                                                                        |
| `GeneratedArtifactValidation.FailOnPrivilegedAssignmentWithoutClassification`                                                                                                  | Controls whether an assignment marked `RoleIsPrivileged` but carrying no classification result is a warning (`false`, default) or blocks the generated artifact before commit (`true`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `ApplyAutomatedControlPlaneScopeUpdate` and its `PrivilegedObjectClassificationSource`                                                                                         | Configure automatic Control Plane scope updates - see [Privileged EAM &rarr; Automatic Control Plane scope updates](../privileged-eam/index.html#automatic-updated-control-plane-scope).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `AutomatedControlPlaneScopeUpdate.EntraOpsScopes`                                                                                                                              | Which RBAC systems' already-classified EAM export data is read as **input** to discover current privileged objects/resources. See [Privileged EAM &rarr; EntraOpsScopes vs. ClassificationParameterScope](../privileged-eam/index.html#entraopsscopes-vs-classificationparameterscope).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `AutomatedControlPlaneScopeUpdate.ClassificationParameterScope`                                                                                                                | Which RBAC systems' classification template/parameter files are regenerated (placeholder substitution) as **output** of the same run. Not the same setting as `EntraOpsScopes` above - see [Privileged EAM &rarr; EntraOpsScopes vs. ClassificationParameterScope](../privileged-eam/index.html#entraopsscopes-vs-classificationparameterscope).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `AzureRbacClassification.ClassifyConstrainedDelegationAlwaysAsControlPlane`                                                                                                    | Controls how Azure RBAC constrained delegations (ABAC conditions on the role assignment and/or on built-in constrained-delegation role definitions, e.g. Key Vault Data Access Administrator) are tiered. Default `false`: a condition that provably limits delegation to a closed allow-list of role definitions is dynamically downgraded from Control Plane to Management Plane based on the tier of the allowed roles - only the constrained `roleAssignments` write/delete actions are downgraded, any other Control Plane powers granted by the same role stay Control Plane. Deny-list conditions and any condition EntraOps cannot fully evaluate are left at Control Plane, since they cannot prove all Control Plane delegation is prevented. Set to `true` to always classify constrained delegations as Control Plane. |
| `AzureRbacClassification.UnresolvedRoleDefinitionFallbackTier`                                                                                                                 | Tier assigned to Azure RBAC role assignments whose role definition could not be resolved from Azure Resource Graph (e.g. ARG replication lag for a new custom role, a deleted role definition, or a transient ARG failure), tagged `TaggedBy = "FallbackUnresolvedRoleDefinition"`. Default `Unclassified` (consistent with the other RBAC systems); `ManagementPlane`/`ControlPlane` apply a stricter fail-closed tier instead, `None` skips classification (previous behavior).                                                                                                                                                                                                                                                                                                                                                  |
| `AzureRbacClassification.DeletedPrincipalAssignmentHandling`                                                                                                                   | Controls Azure RBAC assignments whose principal is confirmed deleted by HTTP 404 responses from both the Microsoft Graph directory-object and user endpoints. Default `Filter` removes those assignments from Azure EAM output. `Keep` preserves the fail-closed unresolved object. Authentication, permission, throttling, network, and other unresolved failures are always retained. This setting applies only to Azure RBAC.                                                                                                                                                                                                                                                                                                                                                                                                   |
| `AutomatedEntraOpsUpdate`                                                                                                                                                      | Configure automated updates of the EntraOps-managed repository content. Disabled by default; GitHub uses `PublicationMode: PullRequest` while Azure DevOps defaults to `DirectPush`. Both use `Repository: EntraOps`, `Branch: main`, `ValidationFrequency: OnChange`, and browser validation. GitHub workflow definitions remain excluded from its default targets; the Azure DevOps default includes `.azure-pipelines`. See [Update EntraOps repository and CI/CD](#update-entraops-powershell-module-and-cicd).                                                                                                                                                                                                                                                                                                                |
| `AutomatedReportingGeneration.ApplyAutomatedReportingGeneration`                                                                                                               | Generate and test the selected static Reporting apps in GitHub Actions or Azure Pipelines. GitHub uploads a 30-day artifact; Azure DevOps publishes a pipeline artifact only after confirming the project is private. Disabled by default.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `AutomatedReportingGeneration.PublishReportsAsRelease` / `ReportingReleasesToKeep`                                                                                             | Optionally publish each report bundle as a GitHub Release in a private repository and prune older `reporting-*` releases. Release publishing is disabled by default because every release contains a full tenant-data snapshot. `New-EntraOpsConfigFile` accepts a retention of 1 to 1000, so a generated configuration always prunes; an empty `ReportingReleasesToKeep` (Configuration Wizard or a manual edit) keeps every release instead.                                                                                                                                                                                                                                                                                                                                                                                     |
| `IngestToLogAnalytics` / `IngestToWatchLists` / `WatchListTemplates` / `WatchListWorkloadIdentity`                                                                             | Ingest classification data into Microsoft Sentinel/Log Analytics custom tables or WatchLists - see [Reportings &rarr; Microsoft Sentinel integration](../reportings/index.html#microsoft-sentinel-integration).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `AutomatedConditionalAccessTargetGroups`                                                                                                                                       | Automatically create security groups for Conditional Access policies, scoped to an Administrative Unit named by `AdminUnitName`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `AutomatedAdministrativeUnitManagement` / `RestrictedAuMode`                                                                                                                   | Automate creation/management of Administrative Units based on the EntraOps tiering. `RestrictedAuMode` controls whether a Restricted Management AU (RMAU) is created for RBAC systems outside Microsoft Entra (which usually have no role-assignable groups).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `AutomatedRmauAssignmentsForUnprotectedObjects`                                                                                                                                | Automatically add every privileged user/group without existing restricted management (role-assignable group, Entra ID role or RMAU membership) to an RMAU. Set `IncludeUnprotectedDevices` to also add their owned or associated devices when no other RMAU protects them.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `RemovalSafetyThreshold` (in all four `Automated*` protection sections)                                                                                                        | Maximum fraction of a target's protected members/objects that one run may remove. Default `0.5`; `1.0` permits complete removal. See [Privileged EAM &rarr; Removal safety brake](../privileged-eam/index.html#removal-safety-brake) for planning, `SafetyAbort`, and the invocation-only force override.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `AutomatedElmCatalogProtection.ApplyPrivilegedElmCatalogProtection`                                                                                                            | Automatically sync the privilege level of Identity Governance Entitlement Management (access package) catalogs to match their EntraOps classification - see [Privileged EAM &rarr; Automated protection of privileged assets](../privileged-eam/index.html#automated-protection-of-privileged-assets).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `AutomatedReportingGeneration.GeneratePrivilegeHistory` / `PrivilegeHistory.EnablePrivilegeHistory` / `PrivilegeHistory.TimeRangeInDays` / `PrivilegeHistory.SnapshotInterval` | Control whether the reporting workflow and `New-EntraOpsReportingData` generate Privilege History, how far back its git-history trend data reaches (default: full history), and the snapshot interval used to sample it (default `P2W`, every 2 weeks) - see [Reportings &rarr; Privilege History](../reportings/index.html#privilege-history).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `AccessPathMap.ResolveObjectIdsOutsidePrivilegedEAM`                                                                                                                           | Resolve IDs referenced only through ownership, sponsor, or device edges with a best-effort live Microsoft Graph lookup. Enabled by default; disable it when Graph lookup is unavailable or materially slows generation. See [Reportings &rarr; Access Path Map](../reportings/index.html#access-path-map).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `ClassificationExplorer.GenerateChangeHistory`                                                                                                                                 | Generate the Classification Explorer change history from the AzurePrivilegedIAM git log. Disabled by default, including when the setting or configuration file is missing, because deriving the history is slow and rarely meaningful. Set it to `true` to populate the Change History view and its notifications. See [Reportings &rarr; Classification Explorer](../reportings/index.html#classification-explorer).                                                                                                                                                                                                                                                                                                                                                                                                              |
| `ConfigurationAnalyzer.ResolveGroupMembersForPrivilegedAssets`                                                                                                                 | Resolve included Conditional Access and authentication method policy groups through nested, PIM-aware membership when generating Configuration Analyzer data. Enabled by default; set to `false` to skip the Graph-backed enrichment. Exclusion targets are never evaluated.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `ConfigurationAnalyzer.AllowPartialTenantGovernanceSnapshot`                                                                                                                   | Allow the reporting workflow to generate Configuration Analyzer data after a partially successful UTCM capture. Enabled by default because Graph partial results are common; failed resource types remain marked stale. Set to `false` when only a complete point-in-time configuration view is acceptable.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `ConfigurationAnalyzer.PimRequestFlowExcludedRiskFlags`                                                                                                                        | Optional array of PIM Request Flow risk-flag IDs to omit from the report. Defaults to `[]`, which reports every supported flag. Select the IDs in the Configuration Wizard; the full ID-to-condition mapping is in the [PIM Request Flow documentation](../../Reports/PimRequestFlow/README.md).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `ConfigurationAnalyzer.AccessPackageFlowExcludedRiskFlags`                                                                                                                     | Optional array of Access Package Flow risk-flag IDs to omit from the report. Defaults to `[]`. Select the IDs in the Configuration Wizard; the supported ID mapping is in the [Access Package Flow documentation](../../Reports/AccessPackageFlow/README.md).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `ConfigurationAnalyzer.ConditionalAccessAnalysisExcludedFindings`                                                                                                              | Optional array of Conditional Access Analysis finding IDs to omit from the report. Defaults to `[]`. Select the IDs in the Configuration Wizard; the supported ID mapping is in the [Conditional Access Analysis documentation](../../Reports/ConditionalAccessAnalysis/README.md).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `ConfigurationAnalyzer.EidscaExcludedFindings`                                                                                                                                 | Optional array of EIDSCA check IDs to omit from the report. Defaults to `[]`; use the check IDs shown beside each EIDSCA finding.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `AlternateObjectTierLevelAttributes`                                                                                                                                           | Classify `User`/`ServicePrincipal` objects via PowerShell filter expressions instead of Custom Security Attributes, and `Group` objects (which don't support Custom Security Attributes) - see [Classify by Alternate Tier Level Attributes](#classify-by-alternate-tier-level-attributes). Disabled by default with empty filters.                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `TenantGovernanceSnapshot`                                                                                                                                                     | Capture and version Microsoft Entra, Intune, and Security & Compliance configuration through Microsoft Graph UTCM. Disabled by default. See [Tenant Governance Snapshots](../tenant-governance/index.html#tenant-governance-snapshots) for resource selection, permissions, schedules, and retention.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

See [Get Started &rarr; Review and customize configuration](../get-started/index.html#step-6-review-and-customize-the-entraopsconfig-file)
for the order these settings are typically reviewed in during initial setup, and
`Update-EntraOpsRequiredWorkflowParameters` to apply configuration changes to the GitHub workflow
files afterwards.

## Caching and performance

EntraOps caches Microsoft Graph and Azure Resource Manager responses in-memory (and on disk for
the duration of a run) to avoid re-fetching the same data multiple times within a session - caches
are shared safely across the runspaces used for parallel object resolution.

- `Get-EntraOpsCacheStatistics` (`-Detailed`) reports entry counts, TTL/expiry status and cache hit/miss statistics for the current session.
- `Clear-EntraOpsCache` (`-CacheType All|Memory|Persistent|Expired`, `-Pattern <wildcard>`) resets the cache - use it to force a refresh of already-cached data within the same session, or to selectively clear entries matching a URI pattern (e.g. `-Pattern "*roleManagement*"`).
- `Install-EntraOpsRequiredModule` / `Install-EntraOpsAllRequiredModules` verify that the required PowerShell modules (`Az.Accounts`, `Az.Resources`, `Microsoft.Graph.Authentication`) are installed at the minimum supported version, installing them if missing - useful to run once on a new client, agent or runner before `Connect-EntraOps`.

## Tenant Governance

Tenant Governance is an optional feature area for cross-tenant privileged access and UTCM
configuration snapshots. It is disabled by default and has dedicated documentation for its
permissions, automation workflow, scripts, Git-backed snapshot storage, and Configuration Analyzer
integration. See [Tenant Governance](../tenant-governance/index.html).

## Classify by Custom Security Attributes

You might want to classify privileged users on the target Enterprise Access Level and their
relation to a user/device. By default, the following custom security attributes are used to
identify the intended tiered level of the user or workload identity:

- `privilegedUser`
- `privilegedWorkloadIdentity`

These attributes are expected to already be set by your provisioning process. See these blog posts
to learn more about the integration:

- [Automated Lifecycle Workflows for Privileged Identities with Azure AD Identity Governance](https://www.cloud-architekt.net/manage-privileged-identities-with-azuread-identity-governance/)
- [Microsoft Entra Workload ID - Lifecycle Management and Operational Monitoring](https://www.cloud-architekt.net/entra-workload-id-lifecycle-management-monitoring/)

The intended tiered level of a user or workload identity is exposed as the `ObjectAdminTierLevel`
and `ObjectAdminTierLevelName` attributes in the EntraOps data of the user principal. These two
values come from a **paired set of custom security attribute fields** within the attribute set
(`adminTierLevel` and `adminTierLevelName` by default, independently overridable via
`EntraOpsConfig.json`'s `CustomSecurityAttributes.PrivilegedUserAdminTierLevelAttribute` /
`PrivilegedUserAdminTierLevelNameAttribute` for users, and
`PrivilegedServicePrincipalAdminTierLevelAttribute` / `PrivilegedServicePrincipalAdminTierLevelNameAttribute`
for service principals). Both fields must be tagged consistently by your provisioning process.

In addition, custom security attributes are used to build a correlation between the privileged
user and their associated PAW device and regular work account:

- `associatedSecureAdminWorkstation`
- `associatedWorkAccount`

Permissions to read the custom security attributes need to be granted manually to the service
principal used by EntraOps.

### Troubleshooting: contradictory tier pair

`Pull-EntraOpsPrivilegedEAM` validates generated output with
the `Test-EntraOpsGeneratedArtifacts` module command, which warns if an object's
`ObjectAdminTierLevel` and `ObjectAdminTierLevelName` are inconsistent (e.g. level `Unclassified`
paired with name `ControlPlane`) - a `Write-Warning` from `New-EntraOpsEAMOutputObject` names the
affected object and RBAC system before this happens. This is almost always caused by the two paired
custom security attribute fields above having drifted apart on that specific object - one field was
updated by your tagging process without the other. It can also occur if
[Alternate Tier Level Attributes](#classify-by-alternate-tier-level-attributes) is enabled and a
filter expression produces an inconsistent result.

EntraOps deliberately does **not** auto-correct a contradictory pair: silently preferring either
field risks masking a genuine tagging mistake in either direction. To resolve it: find the object
named in the warning, open it in the Microsoft Entra admin center, and correct whichever of
the two paired custom security attribute fields is stale so the level and name agree again - then
re-run collection. Do not edit the generated JSON directly; it will be regenerated on the next run.

Use `-FailOnContradictoryTierPair` when an environment requires this tenant-data diagnostic to
block a workflow; duplicate assignment paths, missing stable assignment IDs, and malformed JSON
always remain blocking integrity failures.
Use `-FailOnPrivilegedAssignmentWithoutClassification` to apply strict blocking behavior to
privileged assignments for which classification produced no result.

## Classify by Alternate Tier Level Attributes

As an alternative to Custom Security Attributes, EntraOps can classify **User**,
**ServicePrincipal** and **Group** objects by evaluating PowerShell filter expressions against the object's own
EntraOps details - the same details (e.g. `AssignedAdministrativeUnits`, `ObjectDisplayName`) that
end up in the `PrivilegedEAM` folder export - instead of reading `customSecurityAttributes`. This is
useful when you can't (or don't want to) provision Custom Security Attributes, but already have a
reliable signal in Entra ID itself, e.g. dedicated administrative units per tier, or a naming
convention for privileged service principals. For groups it is the only way to classify them, as
Microsoft Entra doesn't support Custom Security Attributes on groups.

This is configured in the `AlternateObjectTierLevelAttributes` section of `EntraOpsConfig.json`. It
is always included (with empty filters) when a new config file is created by
`New-EntraOpsConfigFile`, but is **disabled by default**:

```json
"AlternateObjectTierLevelAttributes": {
  "Enabled": false,
  "User": {
    "ControlPlane": "",
    "ManagementPlane": "",
    "UserAccess": ""
  },
  "ServicePrincipal": {
    "ControlPlane": "",
    "ManagementPlane": "",
    "UserAccess": ""
  },
  "Group": {
    "ControlPlane": "",
    "ManagementPlane": "",
    "UserAccess": ""
  }
}
```

| Property                    | Description                                                                                                                                                                                                                                                               |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Enabled`                   | Set to `true` to use this alternate classification instead of Custom Security Attributes for `User` and `ServicePrincipal` objects. When `false` or the whole section is missing (e.g. an older config file), Custom Security Attribute classification is used unchanged. |
| `User` / `ServicePrincipal` | One PowerShell filter expression per Enterprise Access Level (`ControlPlane`, `ManagementPlane`, `UserAccess`). Leave a filter as an empty string `""` to skip that tier.                                                                                                 |
| `Group`                     | Same filter syntax for `Group` objects. Groups don't support Custom Security Attributes, so these filters apply whenever at least one of them is set - **independent of `Enabled`**. This lets you keep Custom Security Attributes for users and service principals while classifying groups by filter. Without any `Group` filter, groups stay `Unclassified`. |

Each filter expression is a PowerShell expression that must evaluate to `$true`/`$false`; the
object's own resolved details are exposed as the `$Object` variable. For example, to classify a
user as Control Plane when it is a member of a dedicated administrative unit, and a service
principal as Control Plane by a naming convention:

```json
"AlternateObjectTierLevelAttributes": {
  "Enabled": true,
  "User": {
    "ControlPlane": "$Object.AssignedAdministrativeUnits.displayName -contains \"Tier0-ControlPlane.EntraID\"",
    "ManagementPlane": "$Object.AssignedAdministrativeUnits.displayName -contains \"Tier1-ManagementPlane.EntraID\"",
    "UserAccess": ""
  },
  "ServicePrincipal": {
    "ControlPlane": "$Object.ObjectDisplayName -like \"*-tier0-*\"",
    "ManagementPlane": "$Object.ObjectDisplayName -like \"*-tier1-*\"",
    "UserAccess": ""
  },
  "Group": {
    "ControlPlane": "$Object.AssignedAdministrativeUnits.displayName -contains \"Tier0-ControlPlane.EntraID\" -or $Object.ObjectDisplayName -like \"PRG-Tier0-*\"",
    "ManagementPlane": "$Object.ObjectDisplayName -like \"PRG-Tier1-*\"",
    "UserAccess": ""
  }
}
```

`$Object` exposes the following properties to filter expressions: `ObjectId`,
`ObjectDisplayName`, `ObjectSignInName`, `ObjectSubType`, `AssignedAdministrativeUnits` (array of
`id`/`displayName`), `OwnedObjects`, `Owners`, `Sponsors`, `RestrictedManagementByRAG`,
`RestrictedManagementByAadRole`, `RestrictedManagementByRMAU`, `OnPremSynchronized` and
`OutsideOfHomeTenant`. For groups, `ObjectSubType` is `Role-assignable` or `Security` and
`ObjectSignInName`, `OwnedObjects` and `Sponsors` are empty.

Filters are evaluated in order of decreasing privilege (`ControlPlane`, then `ManagementPlane`,
then `UserAccess`) and the **first matching tier wins**. If none of the filters for an enabled
object type match - or a filter expression fails to evaluate (e.g. a typo) - the object is
classified as `Unclassified` rather than falling back to Custom Security Attributes. Applications,
remote tenant groups (cross-tenant `ForeignGroup` references) and objects unresolved in the current
tenant are not affected by this feature and always keep their existing classification behavior.

## Why was this classification chosen for the role? {#why-was-this-classification-chosen}

Do you want to know why "Global Reader" is classified as "Control Plane"? What is the definition of
Microsoft's `isPrivileged` classification on the related role action?
[AzEntraIdRoleActionsAdvertizer](https://www.azadvertizer.net/azEntraIdRoleActionsAdvertizer.html)
and [AzEntraApiPermissionsAdvertizer](https://www.azadvertizer.net/azEntraIdAPIpermissionsAdvertizer.html)
let you visualize which role or API permission is assigned to a role, and what the specific
Administration Tier Level in EntraOps is.

Use AzAdvertizer to investigate a role or permission classification. This is separate from
`ControlPlaneReasoning`, which records why an object entered the Control Plane input set in the
EAM Dashboard, and from alternate object-tier filters, where the first matching tier wins.

*Enter the role definition name in "used by Roles" and choose the desired tier level in "EntraOps
TierLevel" to filter for the associated role action. In this example, reading BitLocker keys is
classified as "Control Plane" in EntraOps and is also flagged as "isPrivileged" by Microsoft.*

[View an example of the AzAdvertizer tier level lookup](https://cloud-architekt.github.io/assets/images/entraops/AzAdvertizer_IdentifyTierLevel.png)

## Update EntraOps repository and CI/CD (GitHub Actions) {#update-entraops-powershell-module-and-cicd}

EntraOps can be updated without losing your classification definitions and files by using the
cmdlet `Update-EntraOps`. The cmdlet can be executed interactively; changes must then be pushed to
your repository. By default, this command updates the PowerShell module, documentation, regression
tests, workflow actions and agent files, browser-test project files, changelog, and repository resources
(including workbooks and parsers). Every downloaded candidate must publish an
`EntraOpsUpdateContract.json` that declares the source repository, supported targets, and required
validation inputs. A source or target combination that does not satisfy that contract is rejected
before any local target is replaced. Use
`-TargetUpdateFolders` or `AutomatedEntraOpsUpdate.TargetUpdateFolders` in `EntraOpsConfig.json`
to narrow this scope for locally maintained variants.

The portable update decisions are module commands: `Resolve-EntraOpsUpdateSource` resolves the
configured distribution and credential requirement, `Test-EntraOpsUpdateContract` validates the
source contract, `Get-EntraOpsUpdateCandidate` prepares an immutable candidate, and
`Get-EntraOpsUpdatePlan` decides whether validation and application are required.
`Install-EntraOpsUpdateCandidate` applies a separately validated candidate and removes its checkout
before publication. These commands can be used
from GitHub Actions, GitLab CI, Azure Pipelines, or local PowerShell automation. The shipped GitHub
workflow adds only GitHub-specific artifact transfer, App-token creation, commit status, branch, and
pull-request publication around these commands. `.github/scripts` therefore contains only
GitHub-specific adapters and trusted validators that must run before candidate module code is imported.

There is also a workflow named `Update-EntraOps` that can run on demand or on the schedule defined
in `EntraOpsConfig.json`. It updates the default repository folders listed by `TargetUpdateFolders`,
including the module, documentation, reports, tests, parsers, workbooks, GitHub actions, and trusted
update scripts. GitHub workflow definitions are intentionally excluded from the default target set:
the built-in `GITHUB_TOKEN` can write ordinary repository content but cannot publish changes below
`.github/workflows`. The whole `./.github` directory is not an update target, so repository-specific
issue templates and other GitHub configuration remain untouched.

### Update workflow definitions manually

An operator can update the workflow definitions in a local checkout with the existing cmdlet. Select
the workflows together with their required actions and scripts, then review and publish the result
using the operator's normal GitHub credentials:

```powershell
Import-Module ./EntraOps -Force
Update-EntraOps -ConfigFile ./EntraOpsConfig.json -RunBrowserTests `
  -TargetUpdateFolders @('./.github/actions', './.github/scripts', './.github/workflows')
git diff -- .github
```

`Update-EntraOps` fetches the configured `AutomatedEntraOpsUpdate.Repository` and `Branch`, validates
the candidate, replaces the three selected targets, and runs
`Update-EntraOpsRequiredWorkflowParameters` so the existing deployment settings are restored. Commit
the reviewed result to a branch and open a pull request as your GitHub user. The upstream-read
`EntraOpsUpdatePat` does not publish this branch; the operator's Git credential must be authorized to
write workflow files.

### Enable workflow definitions in automated updates

Automated workflow-definition updates are opt-in. Create a dedicated GitHub App, install it only on
the deployment repository, and grant these repository permissions: **Contents: read and write**,
**Workflows: write**, **Pull requests: read and write**, and **Commit statuses: read and write**. Store
the App client ID in a repository variable named `EntraOpsUpdateAppClientId` and its private key in a
repository secret named `EntraOpsUpdateAppPrivateKey`. See GitHub's guides for
[choosing GitHub App permissions](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app)
and [using a GitHub App in a workflow](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/making-authenticated-api-requests-with-a-github-app-in-a-github-actions-workflow).

Then add `./.github/workflows` to `AutomatedEntraOpsUpdate.TargetUpdateFolders`, retaining
`./.github/actions` and `./.github/scripts` in the same list. Selecting workflows without both
companion targets is rejected. For example, the selected portion can be:

```json
"TargetUpdateFolders": [
  "./.github/actions",
  "./.github/scripts",
  "./.github/workflows"
]
```

The `Update-EntraOps` workflow uses `GITHUB_TOKEN` for normal updates
and creates the short-lived App token only when the applied candidate contains an actual workflow
diff. If `./.github/workflows` is a configured target but the `EntraOpsUpdateAppClientId` variable is
not set, the Resolve job fails immediately with an annotation naming the missing configuration, before
the candidate is validated or any file is pushed. If the App's private key or permissions are missing,
publication fails before any candidate file is pushed. Because App-authenticated pushes can trigger
workflows, the update commit uses
`[skip actions]`; the isolated candidate-validation result is posted as the trusted commit status
instead. The updater replaces the selected workflow folder rather than merging arbitrary local
customizations, so review every workflow diff before merging.

When a changed candidate includes workflow templates, candidate validation is mandatory even when
`ValidationFrequency` or the manual `validation_required` override is `Never`/`false`. After the
templates are replaced, `Update-EntraOps` automatically runs
`Update-EntraOpsRequiredWorkflowParameters -ConfigFile <path>` so values from the existing
`EntraOpsConfig.json` are written back into the new workflow files. The workflow run that performs
the update continues under its original definition; the updated templates apply to later runs.

> [!IMPORTANT]
> The scheduled update is **disabled by default** (`ApplyAutomatedEntraOpsUpdate: false`). Enable it
> deliberately after the repository settings below are in place. When enabled, it publishes through a
> pull request: the workflow replaces the selected module and repository folders on an update branch
> with the upstream content of `AutomatedEntraOpsUpdate.Branch`; it does not write directly to the
> base branch unless `AutomatedEntraOpsUpdate.PublicationMode` is explicitly set to `DirectPush`.
> The workflow resolves the candidate without executing it and applies that immutable SHA in a later
> job. When validation is required, it transfers the candidate to a separate job that has no update PAT
> or write token and checks out only the trusted validator scripts, so the candidate's tests cannot read
> the deployment's generated tenant data.
> `AutomatedEntraOpsUpdate.ValidationFrequency` controls candidate validation: `OnChange` (default)
> validates new source commits, changed target sets, and candidates that have not satisfied the current
> validation depth; `Always` validates every triggered run; and `Never` applies changed candidates
> without running their module import, action-reference, documentation, Pester, or browser tests.
> `Never` does not bypass validation for changed workflow templates.
> `AutomatedEntraOpsUpdate.RunBrowserTests` defaults to `true` and can omit only the Playwright portion
> when validation runs. `Never` should be used only with a fully trusted source because candidate code
> is not executed until after it has replaced the local files. The immutable SHA and update contract
> checks still run. A manual run can select **force** to validate and reapply the same candidate even
> when `ValidationFrequency` is `Never`. Its `validation_required`, `run_browser_tests`, and
> `publication_mode` inputs can independently use the configured value or override it for that invocation;
> browser tests only run when candidate validation is enabled. The supported update sources are declared
> centrally in the `DistributionRepositories` section of `EntraOpsUpdateContract.json`: `Repository`
> defaults to the public release channel `EntraOps`, which is cloned without credentials, and
> `EntraOps-Insiders` is the private preview channel that requires the `EntraOpsUpdatePat` repository
> secret. The updater reads the local contract before cloning, so a private source without a token
> fails early with a clear message and a token is never sent to the public source. `Branch` defaults to
> `main` so an enabled update needs no release-ref maintenance; set it to a release tag or a full
> 40-character commit SHA when you need every update to be reproducible and reviewable.
> `Update-EntraOps` emits a warning when it is updating from a mutable branch and records the resolved
> source commit in `.EntraOpsUpdateManifest.json`. In `PullRequest` mode, it creates or updates an
> `entraops/update-<12-character source SHA prefix>` branch and records the validation outcome as the
> `EntraOps / Update candidate validation` commit status on that branch. When the update contains no
> workflow diff, `Test-EntraOps.yaml` also runs on the pull request through its `pull_request` trigger.
> When the optional GitHub App publishes changed workflow definitions, the commit carries
> `[skip actions]` and no repository workflow runs on the branch before review, because otherwise the
> App-authenticated push could execute candidate-controlled workflow files with repository credentials;
> the commit status is the trusted check in that case, and `Test-EntraOps.yaml` runs on the base branch
> after the pull request is merged. Protect the base branch with a ruleset that requires the
> `EntraOps / Update candidate validation` status, which the Apply job posts on every update pull
> request; otherwise an update can be merged while its validation is still pending or has failed. Do
> not make the `Test-EntraOps` checks required for the base branch: GitHub keeps a required check that
> was skipped by `[skip actions]` pending indefinitely, which would permanently block every
> workflow-definition update. Pull requests opened by people do not carry the validation status, so
> add the maintainers who open them to the ruleset's bypass list or approve those merges as an
> administrator.
> It does not import the newly downloaded module into the updater process. Review the applied diff,
> clear update credentials, and load the module in a subsequent clean PowerShell process or session.

> [!IMPORTANT]
> `PullRequest` mode requires **Settings &rarr; Actions &rarr; General &rarr; Workflow permissions &rarr;
> Allow GitHub Actions to create and approve pull requests** in the repository. If the organization
> disables this option, the repository setting is greyed out and must be enabled by an organization
> owner first (organization **Settings &rarr; Actions &rarr; General**). See the GitHub documentation
> [Preventing GitHub Actions from creating or approving pull requests](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#preventing-github-actions-from-creating-or-approving-pull-requests).
> The Apply job receives only the repository permissions needed to push the update branch, create the
> pull request, and post the validation commit status. Changed workflow definitions additionally require
> the opt-in GitHub App described above; adding `workflows: write` to the YAML `permissions` block is not
> supported for `GITHUB_TOKEN`. If pull-request creation is
> disabled, the update branch is pushed, publication fails visibly with a hint naming this setting, and
> the workflow never falls back to `DirectPush`. `Update-EntraOpsRequiredWorkflowParameters` and the
> Configuration Wizard warn about this requirement whenever automated updates are enabled in
> `PullRequest` mode.

> [!NOTE]
> Generated-data workflows use the shared `Git-Push` composite action, which refuses to push if the
> repository is public. Its GitHub-specific implementation is a PowerShell adapter under
> `.github/scripts`. The updater copies its reviewed publisher adapter to runner-temporary storage
> before candidate application because `.github/actions` and `.github/scripts` are update targets;
> candidate-controlled code must not receive the write token. See [Get Started &rarr; Step 1](../get-started/index.html#step-1-create-your-repository-from-this-template).

> [!NOTE]
> A repository that redistributes EntraOps (a public mirror or an organization fork used as the
> update source for several deployments) must ship its own `EntraOpsUpdateContract.json` whose
> `DistributionRepositories` lists its full `Owner/Name` (with `RequiresPersonalAccessToken` set for a
> private repository) and whose `SupportedUpdateTargets` is limited to the folders it actually
> contains. `Update-EntraOps` requires the configured source to be listed in the candidate's contract
> and rejects a mismatch, so copying the file unchanged from another repository makes the copy
> unusable as an update source. Configurations without `Repository`, `Branch`, or
> `TargetUpdateFolders` resolve to the built-in defaults and log a warning naming the missing keys.

Regardless of how you update EntraOps files, you may need to update the `EntraOpsConfig.json` file and
the EntraOps service principal to benefit from new features. Create a new `EntraOpsConfig.json` file,
or manually add the newly documented properties. Use `New-EntraOpsWorkloadIdentity` together with
the `-ExistingSpObjectId` parameter and the object ID of the existing EntraOps service principal,
for example:

```powershell
New-EntraOpsWorkloadIdentity -AppDisplayName "EntraOps-Contoso" -ExistingSpObjectId 00000000-0000-0000-0000-000000000000
```

Ignore errors regarding existing API permissions or conflicts with existing roles.

Don't forget to update your workflow files with the cmdlet `Update-EntraOpsRequiredWorkflowParameters`.

### Maintain GitHub Action references

EntraOps pins external GitHub Actions to full commit SHAs and keeps a `# vN` version comment beside
each pin. The `Test-EntraOps` workflow validates that external references are immutable, annotated,
and consistent wherever the same action is used. Do not replace a pin with a mutable tag such as
`@v4`; update both the SHA and its version comment together.

The template also includes `.github/dependabot.yml`, which asks Dependabot to open weekly grouped
pull requests when newer GitHub Action releases are available. It is advisory: if Dependabot is
disabled, unsupported, or unavailable in your GitHub environment, EntraOps workflows continue to
run with their existing validated pins. Review and merge Dependabot pull requests through the
normal change process, or update the pins manually.

> [!TIP]
> If you run into issues while updating EntraOps, it is often faster to remove and re-create the service principal and re-create the `EntraOpsConfig.json` file from scratch.

### Build the documentation bundle

`Update-EntraOpsDocsContent.ps1` supports two deployment targets. Both write
`Docs/data/content.js`, so select the mode that matches the environment before publishing:

```powershell
# Complete repository checkout: keep links to Reports/, EntraOps/, workflows, and integrations local.
./Docs/Update-EntraOpsDocsContent.ps1 -DeploymentMode EntraOps

# Public website containing only Docs/: rewrite repository links to canonical GitHub URLs.
./Docs/Update-EntraOpsDocsContent.ps1 -DeploymentMode Standalone
```

`EntraOps` is the default. Use `Standalone` when deploying `Docs/` by itself so links to report
READMEs, PowerShell source, workflows, and integration files do not resolve to missing local paths.
Custom forks can set `-RepositoryUrl` and `-RepositoryBranch` for their public source links.
