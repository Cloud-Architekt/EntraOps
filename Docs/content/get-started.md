# Get Started with EntraOps

This guide follows the [adoption roadmap](#adoption-roadmap) from a single cmdlet to full tiering:
prerequisites, choosing how you want to run EntraOps, signing in, and deploying the automation -
either interactively/locally or fully automated with GitHub Actions - through to Sentinel
ingestion, automated protection, and full rollout.

> [!TIP]
> **Quick start:** sign in interactively and try EntraOps right now - no configuration file needed:
> ```powershell
> Import-Module ./EntraOps
> Connect-EntraOps -AuthenticationType "UserInteractive" -TenantName "contoso.onmicrosoft.com"
> Invoke-EntraOpsPrivilegedEAM
> ```
> See [1. Try it with zero configuration](#try-it-with-zero-configuration) below for details, or keep reading for prerequisites and the full adoption roadmap.

## Prerequisites

- **PowerShell 7.4 (Core)** or later on any platform (Windows, Linux, macOS), or GitHub Codespaces / GitHub Actions runners. The module enforces this minimum version during import.
- A Microsoft Entra ID tenant where you have (temporarily) **Global Administrator** and **User Access Administrator** permissions to register the application used by EntraOps and grant it the required Microsoft Graph and Azure RBAC permissions.
- Optional: a GitHub account/organization if you want to run EntraOps as a scheduled, automated pipeline instead of (or in addition to) interactive/local execution.
- Optional: a Log Analytics workspace or Microsoft Sentinel workspace if you want to ingest classification data into custom tables or WatchLists (see [Reportings &rarr; Microsoft Sentinel integration](../reportings/index.html#microsoft-sentinel-integration)).

## Adoption roadmap: from a single cmdlet to full tiering {#adoption-roadmap}

Most teams grow into EntraOps along the same path: start with a one-off, zero-configuration
export, then progressively turn on customization, automation, ingestion, and enforcement as
confidence and coverage increase. Each phase below links to the section of this guide (or the
feature area) that covers it - the rest of this guide walks through them in order.

**1. Try it &rarr; 2. Verify output &rarr; 3. Customize &amp; automate collection &rarr; 4. Ingest to Sentinel &rarr; 5. Automate protection &rarr; 6. Full tiering rollout** (optional branch: Tenant Governance)

![Adoption roadmap: Try it, verify output, customize and automate collection, ingest to Sentinel, automate protection, and complete the tiering rollout. Tenant Governance is an optional branch from customized collection.](../assets/automation/adoption-roadmap.svg)

| Phase                              | Goal                                                                          | What you enable                                                                                                                                                                                                               | Learn more                                                              |
| ---------------------------------- | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| 1. Try it                          | See your Enterprise Access Model classification with no setup                 | Sign in interactively with `Connect-EntraOps`, then run `Invoke-EntraOpsPrivilegedEAM`                                                                                                                                        | [1. Try it with zero configuration](#try-it-with-zero-configuration)    |
| 2. Verify output                   | Confirm classification and scope match expectations before automating         | Review the export with Classification Explorer or EAM Dashboard - no Sentinel or Azure subscription required                                                                                                                  | [2. Verify output with reports and workbooks](#phase-2-verify-output)   |
| 3. Customize & automate collection | Tailor tiering to your tenant and make collection repeatable, tracked-as-code | Create `EntraOpsConfig.json`, add [role/action overwrites](../privileged-eam/index.html#customize-classification-by-overwrites), deploy a workload identity with federated credentials and scheduled GitHub Actions pipelines | [3. Customize and automate collection with GitHub](#deploy-with-github) |
| 4. Ingest to Sentinel              | Centralize privileged access data for detection and hunting                   | Enable `IngestToLogAnalytics` / `IngestToWatchLists`                                                                                                                                                                          | [4. Ingest to Sentinel](#phase-4-ingest-to-sentinel)                    |
| 5. Automate protection             | Enforce tiering, not just report on it                                        | Enable Conditional Access target groups, Administrative Unit management, RMAU assignment for unprotected objects, and Entitlement Management catalog protection                                                               | [5. Automate protection](#phase-5-automate-protection)                  |
| 6. Full tiering rollout            | Validate the tiered implementation once more and connect it to your SOC       | Review reporting apps/workbooks again with live data, then build Sentinel detections on the Custom Table/WatchLists                                                                                                           | [6. Full tiering rollout](#phase-6-full-tiering-rollout)                |
| Optional: Tenant Governance        | Extend tiering across tenant boundaries and track configuration drift         | Enable cross-tenant delegated administration classification and/or Microsoft Graph UTCM configuration snapshots                                                                                                               | [Tenant Governance](#optional-tenant-governance)                        |

> [!TIP]
> You don't have to complete a phase fully before starting the next one - for example, many teams
> enable Sentinel ingestion (phase 4) before automating AU/group protection (phase 5). Treat this as
> a roadmap of capabilities to grow into, not a strict sequence.

## Choose your integration

EntraOps can be executed the same way in every scenario - only how you sign in and how often it runs differs:

| Scenario                                       | Sign-in                                                                                 | Best for                                                                |
| ---------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Interactive / local execution                  | `UserInteractive`, `DeviceAuthentication`                                               | Exploration, ad-hoc queries, one-off exports                            |
| Automated pipeline (GitHub Actions)            | Federated credentials via `Connect-EntraOps -AuthenticationType "FederatedCredentials"` | Scheduled collection, tracked history "as code", automated reporting    |
| Automation / worker with existing Az session   | `AlreadyAuthenticated`                                                                  | Custom automation, Azure Automation, other CI/CD systems                |
| Azure resource with a system-assigned identity | `SystemAssignedMSI`                                                                     | Azure Automation, Functions, VMs and other identity-enabled Azure hosts |
| User-assigned managed identity                 | `UserAssignedMSI`                                                                       | Execution from an Azure resource with an assigned managed identity      |

If you are unsure, start with interactive/local execution to explore your data, then follow
[3. Customize and automate collection with GitHub](#deploy-with-github) once you know which RBAC
systems and settings you want to automate.

## 1. Try it with zero configuration {#try-it-with-zero-configuration}

You can run a full Privileged EAM classification without creating an `EntraOpsConfig.json` file or a
`Classification` folder first. EntraOps signs in to Azure and Microsoft Graph interactively, so the
Microsoft Graph sign-in can request the delegated permissions required for collection:

> [!NOTE]
> You may be asked to grant consent if the Microsoft Graph PowerShell client does not already have
> the delegated scopes required for this run. Review the [baseline collection permissions](../core/index.html#service-principal-permissions).

For complete interactive collection, use an account with **Global Reader** activated in Microsoft
Entra ID and **Reader** on the root scope, which covers every management group,
subscription and resource below it. Event directly assignments on the root scope through `elevateAccess` are also considered. An administrator who can create role assignments at that scope
can grant the Azure role with
[`New-AzRoleAssignment`](https://learn.microsoft.com/en-us/powershell/module/az.resources/new-azroleassignment):


```powershell
New-AzRoleAssignment -ApplicationId "<workload-identity-client-id>" -RoleDefinitionName "Reader" -Scope "/"
```

`Invoke-EntraOpsPrivilegedEAM` resolves the tenant from the EntraOps connection, downloads the latest
classification templates, computes the Control Plane scope, runs
`Save-EntraOpsPrivilegedEAMJson`, and cleans up every intermediate file so only the PrivilegedEAM
JSON output remains (except for any pre-existing `Classification_RoleActionOverwrites.json` /
`Classification_RoleDefinitionOverwrites.json` tenant customization files, which are always
preserved). Use `-RbacSystems` to limit the scope, or `-PrivilegedObjectClassificationSource` to
change how Control Plane scope is determined - see
[Privileged EAM &rarr; Automatic Control Plane scope updates](../privileged-eam/index.html#automatic-updated-control-plane-scope).

> [!TIP]
> This is the fastest way to try EntraOps or produce a one-off export. Continue with [2. Verify output with reports and workbooks](#phase-2-verify-output) before you keep using it, or jump straight to [3. Customize and automate collection with GitHub](#deploy-with-github) for a repeatable, automated setup.

## 2. Verify output with reports and workbooks {#phase-2-verify-output}

Before automating collection, review the PrivilegedEAM export from
[1. Try it with zero configuration](#try-it-with-zero-configuration) (or a manual
`Save-EntraOpsPrivilegedEAMJson` run) to confirm the classification and Control Plane scope match
your expectations. Generate the
[reporting apps](../reportings/index.html#entraops-reporting-apps) against the local export -
Classification Explorer and EAM Dashboard are built entirely from it, no Log Analytics workspace or
Azure subscription required:

```powershell
New-EntraOpsReportingData
```

Azure Monitor workbooks are also available, but only once data has been ingested into Log
Analytics/Sentinel - see [4. Ingest to Sentinel](#phase-4-ingest-to-sentinel) below.

> [!TIP]
> Catching a misclassified role or an overly broad Control Plane scope now is much cheaper than
> after Conditional Access target groups, Administrative Units, or Sentinel ingestion have already
> been automated from it.

## Import module and sign-in options

Import the PowerShell module (by default, required modules are installed automatically):

```powershell
Import-Module ./EntraOps
```

### User Interactive with consented Microsoft Graph PowerShell

```powershell
Connect-EntraOps -AuthenticationType "UserInteractive" -TenantName "contoso.onmicrosoft.com"
```

### User Interactive in GitHub Codespaces (Device Authentication)

```powershell
Connect-EntraOps -AuthenticationType "DeviceAuthentication" -TenantName "contoso.onmicrosoft.com"
```

### User-Assigned Managed Identity

```powershell
Connect-EntraOps -AuthenticationType "UserAssignedMSI" -TenantName "contoso.onmicrosoft.com" -AccountId "00000000-0000-0000-0000-000000000000"
```

`AccountId` is the user-assigned managed identity **application (client) ID**, not its object ID.
The identity must already have the application permissions and Azure roles listed under
[Core &rarr; Service principal permissions](../core/index.html#service-principal-permissions).

### System-Assigned Managed Identity

```powershell
Connect-EntraOps -AuthenticationType "SystemAssignedMSI" -TenantName "contoso.onmicrosoft.com"
```

### Service Principal with client secret

```powershell
$ServicePrincipalCredentials = Get-Credential
Connect-AzAccount -Credential $ServicePrincipalCredentials -ServicePrincipal -Tenant $TenantName
Connect-EntraOps -TenantName $TenantName -AuthenticationType "AlreadyAuthenticated"
```

### Workload with already-authenticated Azure PowerShell

```powershell
Connect-EntraOps -AuthenticationType "AlreadyAuthenticated" -TenantName "contoso.onmicrosoft.com"
```

Continue with [Privileged EAM &rarr; Collecting and exporting data](../privileged-eam/index.html#collecting-and-exporting-data)
once you are signed in, or follow the steps below to deploy EntraOps as an automated GitHub pipeline.

## Configured local or custom automation run {#configured-local-run}

Use this path when you want repeatable settings locally or on a supported automation platform such
as Azure Automation Runbooks, without GitHub Actions. Use the guided setup above to download a
complete config directly, create it with `New-EntraOpsConfigFile`, or open the template in the
[Configuration Wizard](../configuration/index.html).
The browser wizard requires both the tenant domain and tenant ID because workload and managed
identities cannot resolve a placeholder ID during non-interactive startup.

```powershell
Import-Module ./EntraOps
Connect-EntraOps -AuthenticationType "UserInteractive" `
  -TenantName "contoso.onmicrosoft.com" `
  -TenantId "00000000-0000-0000-0000-000000000000" `
  -ConfigFilePath "./EntraOpsConfig.json"

Save-EntraOpsPrivilegedEAMJson -RbacSystems $EntraOpsConfig.RbacSystems
Disconnect-EntraOps
New-EntraOpsReportingData
```

For `UserAssignedMSI`, add `-AccountId <managed-identity-client-id>`. For
`AlreadyAuthenticated`, establish the Azure context before calling `Connect-EntraOps`. The account
or identity running configured local automation must have the same read or write permissions as a
GitHub workload identity; `New-EntraOpsWorkloadIdentity` only provisions those permissions for the
application it creates or updates.

Run enabled optional operations after collection. These are the same cmdlets used by the shipped
GitHub workflows:

| Config feature                            | Local/custom automation command                                                                                                                                                                        |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Update classification templates           | `$Params = $EntraOpsConfig.AutomatedClassificationUpdate; Update-EntraOpsClassificationFiles @Params`                                                                                                  |
| Update Control Plane scope                | `$Params = $EntraOpsConfig.AutomatedControlPlaneScopeUpdate; Update-EntraOpsClassificationControlPlaneScope @Params`                                                                                   |
| Log Analytics ingestion                   | `$Params = $EntraOpsConfig.LogAnalytics; Save-EntraOpsPrivilegedEAMInsightsCustomTable @Params`                                                                                                        |
| Sentinel WatchLists                       | `$Params = $EntraOpsConfig.SentinelWatchLists; Save-EntraOpsPrivilegedEAMWatchLists @Params`                                                                                                           |
| Administrative Units                      | `$Params = $EntraOpsConfig.AutomatedAdministrativeUnitManagement; New-EntraOpsPrivilegedAdministrativeUnit @Params; Update-EntraOpsPrivilegedAdministrativeUnit @Params`                               |
| Unprotected-object RMAU                   | `$Params = $EntraOpsConfig.AutomatedRmauAssignmentsForUnprotectedObjects; New-EntraOpsPrivilegedUnprotectedAdministrativeUnit @Params; Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit @Params` |
| Conditional Access target groups          | `$Params = $EntraOpsConfig.AutomatedConditionalAccessTargetGroups; New-EntraOpsPrivilegedConditionalAccessGroup @Params; Update-EntraOpsPrivilegedConditionalAccessGroup @Params`                      |
| Entitlement Management catalog protection | `$Params = $EntraOpsConfig.AutomatedElmCatalogProtection; Update-EntraOpsPrivilegedUnprotectedElmCatalog @Params`                                                                                      |

Only run write operations after reviewing the generated Privileged EAM export. Interactive sign-in
requests the delegated read scopes used for collection; write features and UTCM snapshots can need
additional consent or a pre-provisioned workload/managed identity. See the feature-specific
permission table before enabling them.

## 3. Customize and automate collection with GitHub {#deploy-with-github}

The following steps set up EntraOps as a scheduled, automated pipeline in your own GitHub
repository, using a Microsoft Entra workload identity with federated credentials (no secrets
stored in GitHub). Steps 3.4 and 3.6 customize your configuration; the rest set up the automated
pipeline itself, with 3.5 as optional prep for [4. Ingest to Sentinel](#phase-4-ingest-to-sentinel).

> [!TIP]
> Watch a [walkthrough of these steps](https://www.cloud-architekt.net/assets/images/entraops/setup_1-ghconfig.gif).

### 3.1 Create your repository from this template {#step-1-create-your-repository-from-this-template}

Use the [EntraOps GitHub template](https://github.com/Cloud-Architekt/EntraOps/generate) and choose a
**private** repository. This is enforced: the `Pull-EntraOpsPrivilegedEAM`,
`Pull-EntraOpsTenantGovernance` and `Update-EntraOps` workflows refuse to commit/push (and
`Push-EntraOpsPrivilegedReporting` skips publishing its artifact/release) if the repository is
public, since the pushed data may contain tenant details (object IDs, UPNs, role assignments,
policy configuration).

### 3.2 Clone your new EntraOps repository {#step-2}

Clone locally, or use a GitHub Codespace. A devcontainer is available to load the required dependencies.

```powershell
git clone "https://github.com/<GitHubUserOrOrg>/<PrivateRepoName>.git"
Set-Location "<PrivateRepoName>"
```

### 3.3 Import the EntraOps PowerShell module {#step-3}

```powershell
Import-Module ./EntraOps
```

### 3.4 Create a new EntraOpsConfig.json file (customize) {#step-4}

Use the guided setup at the top of this page to download a complete `EntraOpsConfig.json` directly,
or open its prefilled template in the [Configuration Wizard](../configuration/index.html) to review
every setting before downloading. You can also generate the file from PowerShell and update it for
your parameters and use case.

> [!NOTE]
> Use `Connect-AzAccount -UseDeviceAuthentication` before executing `New-EntraOpsConfigFile` if you are using GitHub Codespaces or Cloud Shell to perform device authentication.

```powershell
New-EntraOpsConfigFile -TenantName "contoso.onmicrosoft.com"
```

### 3.5 Optional - create a data collection rule and endpoint (Sentinel prep) {#step-5}

Needed only if you want to ingest data into a custom table in a Log Analytics or Microsoft Sentinel
workspace. Follow the instructions on [Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-portal#create-data-collection-endpoint)
to configure a data collection endpoint, custom table, and transformation rule. Use table name
`PrivilegedEAM_CL` so the shipped parser works. Run `Save-EntraOpsPrivilegedEAMJson` interactively
first to create a JSON file that can be used as sample data.

> [!TIP]
> There is a 10 KB limit for a single WatchList entry, which can be exceeded when a privileged object has many classification or owner properties. In larger environments, prefer **Custom tables** over WatchLists. If you do choose WatchLists, watch the deployment logs for warnings - entries are silently dropped if the limit is exceeded.

### 3.6 Review and customize the EntraOpsConfig.json file (customize) {#step-6-review-and-customize-the-entraopsconfig-file}

See [Core &rarr; Configuration file reference](../core/index.html#configuration-file-reference) for
the full list of settings. Key things to check:

- `TenantId`/`TenantName` are already set from the parameters used to create the config file; `ClientId` is filled in automatically by `New-EntraOpsWorkloadIdentity` (next step).
- The scheduled pull trigger (`PullScheduledTrigger` / `PullScheduledCron`) is enabled by default, and the reporting workflow runs right after every pull (`PushReportingAfterPullWorkflowTrigger`); it can additionally/alternatively run on its own recurring schedule (`PushReportingScheduledTrigger` / `PushReportingScheduledCron`, default weekly Monday 09:00 UTC), or only on manual dispatch if both are disabled.
- Automated updates for classification templates (`AutomatedClassificationUpdate`) or Control Plane scope (`ApplyAutomatedControlPlaneScopeUpdate`), and the data source used to identify Control Plane assets, are configured here too.
- The `AzureRbacClassification` section controls how Azure RBAC constrained delegations are tiered - see [Privileged EAM &rarr; Automatic Control Plane scope updates](../privileged-eam/index.html#automatic-updated-control-plane-scope).
- Review `AutomatedEntraOpsUpdate` to configure automated updates of the EntraOps PowerShell module itself (on demand or scheduled).
- Reporting generation and GitHub Release publishing are separate opt-ins. `ApplyAutomatedReportingGeneration` creates a 30-day workflow artifact. `PublishReportsAsRelease` additionally stores full tenant-data report snapshots as private-repository releases; it is disabled by default, and `ReportingReleasesToKeep` controls pruning when enabled.
- Enable `IngestToLogAnalytics` / `IngestToWatchLists` and their parameters if you want to ingest classification data into Microsoft Sentinel - see [Reportings &rarr; Microsoft Sentinel integration](../reportings/index.html#microsoft-sentinel-integration).
- Enable `AutomatedConditionalAccessTargetGroups` to automatically create security groups for Conditional Access policies.
- Enable `AutomatedAdministrativeUnitManagement` to automate creation and management of Administrative Units based on the selected EntraOps tiering. `RestrictedAuMode` controls whether an RMAU is created for RBAC systems outside of Microsoft Entra.
- `AutomatedRmauAssignmentsForUnprotectedObjects` protects all privileged users without existing restricted management by adding them to an RMAU automatically. Set `IncludeUnprotectedDevices` to also protect their owned or associated devices when no other RMAU protects them.
- `RemovalSafetyThreshold` (default `0.5`, persisted in every protection section above) caps how much one run may remove. Each target plans removals first; an oversized plan applies no removals, records a failing `SafetyAbort`, and still permits independent additions or protection operations. `1.0` permits removal of the complete current protected set, so threshold-based `SafetyAbort` protection does not apply to automated runs. Use `-ForceRemovalBeyondSafetyThreshold` only for an explicit, reviewed one-time reconciliation.
- Decide which automated protections are in scope: Conditional Access target groups, Administrative
  Units, RMAU coverage for unprotected objects, and Entitlement Management catalog protection. Keep
  the default disabled setting for anything you are not ready to automate.
- Decide whether Tenant Governance snapshots are in scope. Use the recommended default resource set,
  or select the exact Microsoft Entra and Microsoft Intune configuration resources in the
  Configuration Wizard. High-cardinality directory objects are excluded from the recommended defaults.
  The first setup needs Global Administrator consent so the first-party UTCM service principal can
  receive the permissions required by the selected resource types; follow the
  [Tenant Governance permission setup](../tenant-governance/index.html#permissions-and-prerequisites).
- By default, `User` and `ServicePrincipal` objects are classified from Custom Security Attributes - see [Core &rarr; Classify by Custom Security Attributes](../core/index.html#classify-by-custom-security-attributes). The `AlternateObjectTierLevelAttributes` section allows classifying them instead with PowerShell filter expressions - see [Core &rarr; Classify by Alternate Tier Level Attributes](../core/index.html#classify-by-alternate-tier-level-attributes). The filters are enabled per object type (`User.Enabled`, `ServicePrincipal.Enabled`, `Group.Enabled`) and disabled by default with empty filters. `Group` objects don't support Custom Security Attributes and stay `Unclassified` unless you enable `Group` filters in the same section.

### 3.7 Create an application registration with the required permissions {#step-7}

Requires the Global Administrator and User Access Administrator roles. This grants all necessary
Microsoft Graph API permissions and Azure RBAC roles for data collection and/or ingestion (as
configured in `EntraOpsConfig.json`). An Administrative Unit for Conditional Access Groups (named from
`AdminUnitName`) is created if `ApplyConditionalAccessTargetGroups` is enabled.

Review [Core &rarr; Service principal permissions](../core/index.html#service-principal-permissions)
for the baseline collection permissions and the feature-specific grants controlled by configuration.

```powershell
Connect-AzAccount -Tenant "<TenantId>"
New-EntraOpsWorkloadIdentity -AppDisplayName entraops -ConfigFile "./EntraOpsConfig.json" `
  -CreateFederatedCredential `
  -GitHubOrg "<YourGitHubUser/Org>" -GitHubRepo "<YourRepoName (e.g., EntraOps-Contoso)>" `
  -FederatedEntityType "Branch" -FederatedEntityName "main"
```

Copy the GitHub owner, repository, and branch names exactly, including capitalization. Microsoft
Entra matches the federated credential subject case-sensitively against the token issued by GitHub.
If provisioning reports a partial failure, correct the reported permission or federation problem
and rerun the same command with the reported `-ExistingSpObjectId`. This resumes against the created
identity instead of creating another application registration.

When `RbacSystems` contains `Azure`, the workload identity receives Reader on the tenant root
management group so the configured Azure collection can inspect its descendants. Add
`-GrantArmRootScopeReader` only when you also need assignments made directly at the ARM tenant root
scope (`/`) through `elevateAccess`.
That assignment is not shown in normal portal RBAC blades and must be included explicitly in access
reviews and offboarding.

When `TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot` is enabled,
`New-EntraOpsWorkloadIdentity` also grants the workload identity
`ConfigurationMonitoring.ReadWrite.All` and configures the first-party Microsoft Tenant
Configuration Management (UTCM) service principal for `ResourcesToInclude`. Use a Global
Administrator for this initial consent, then follow the
[Tenant Governance permission setup](../tenant-governance/index.html#permissions-and-prerequisites)
to validate the result and recover missing permissions.

### 3.8 Update GitHub workflow definitions {#step-8}

Applies tenant values, feature switches, update policy, and configured schedules from
`EntraOpsConfig.json` to the shipped GitHub Actions workflow files. Run it again after changing
those settings because GitHub Actions consumes the materialized workflow values.

```powershell
Update-EntraOpsRequiredWorkflowParameters -ConfigFile "./EntraOpsConfig.json"
```

The workflows declare their required OIDC and repository permissions and use the built-in
`GITHUB_TOKEN`; no client secret or personal access token is needed for normal collection and data
commits. The default automated update mode creates a pull request. Enable **Settings -> Actions ->
General -> Workflow permissions -> Allow GitHub Actions to create and approve pull requests** when
using that mode. Updating `.github/workflows` itself requires the separately configured publisher
GitHub App described in [Core -> Enable workflow definitions in automated updates](../core/index.html#enable-workflow-definitions-in-automated-updates).

Manual runs of `Update-EntraOps` can override force, validation, browser-test, and publication-mode
settings for that run; scheduled runs use `EntraOpsConfig.json`.

### 3.9 Commit and push the deployment {#step-9}

`New-EntraOpsWorkloadIdentity` writes the application client ID into `EntraOpsConfig.json`, and the
workflow updater writes tenant, client, trigger and feature values into `.github/workflows`.
Commit both together:

```powershell
git add EntraOpsConfig.json .github/workflows
git commit -m "Configure EntraOps"
git push
```

### 3.10 Run and verify the workflows {#step-10}

In the repository **Actions** tab, manually run `Pull-EntraOpsPrivilegedEAM`. A successful first
run must authenticate with OIDC, collect the configured RBAC systems, and commit tenant data under
`PrivilegedEAM/` (plus tenant-specific files under `Classification/` when scope/template updates
are enabled). Then verify the workflows enabled by your config:

- `Push-EntraOpsPrivilegedReporting` creates the 30-day `EntraOps-Reporting` artifact on a private repository when reporting generation is enabled. It publishes private GitHub Releases only when `PublishReportsAsRelease` is also enabled.
- `Push-EntraOpsPrivilegedEAM` performs enabled ingestion and protection actions after a successful pull.
- `Pull-EntraOpsTenantGovernance` receives scheduled triggers and runs setup or collection steps only when Tenant Governance snapshots are enabled.
- `Update-EntraOps` applies scheduled module updates when enabled.
- `Test-EntraOps` validates the manifest, generated documentation, Pester suite, and browser apps on pushes and pull requests. Add it as a required status check in the branch protection rules when changes must pass CI before merge.

For Tenant Governance, manually run `Pull-EntraOpsTenantGovernance` once before relying on its
schedule. This verifies the workload identity and the first-party UTCM service principal have the
permissions needed for the selected snapshot resources.

After changing integration or protection settings, rerun `New-EntraOpsWorkloadIdentity` with
`-ExistingSpObjectId <service-principal-object-id>` so new permissions are provisioned, rerun
`Update-EntraOpsRequiredWorkflowParameters`, and commit the resulting config/workflow changes.

## Automate with Azure DevOps {#deploy-with-azure-devops}

Azure DevOps is a first-class automation option alongside the GitHub workflow described above. It uses Azure Repos, Azure Pipelines, an Azure Resource Manager service connection with workload identity federation, and the same `EntraOpsConfig.json` feature switches.

Prerequisites are an Azure DevOps project with Pipelines enabled, an Azure subscription available
to the service connection, and Microsoft Entra permissions to create or update the workload identity.
Initial provisioning requires Global Administrator or Application Administrator plus User Access
Administrator when Azure role assignments are configured.

1. Create or import EntraOps into a **private** Azure Repos repository. Generated exports and reports contain tenant identifiers and access data.
2. Generate the configuration with `New-EntraOpsConfigFile -TenantName "contoso.onmicrosoft.com" -DevOpsPlatform AzureDevOps`, or select Azure DevOps in the guided setup above.
3. Run `New-EntraOpsWorkloadIdentity -AppDisplayName "EntraOps-ADO" -ConfigFile "./EntraOpsConfig.json"` to create the app registration and configured permissions.
4. Create an **Azure Resource Manager -> Workload Identity Federation (manual)** service connection. Add the exact issuer and subject shown by Azure DevOps as a federated credential on the app registration; use `api://AzureADTokenExchange` as the audience.
5. Import the five production YAML pipelines from `.azure-pipelines/`: pull, push, reporting, Tenant Governance, and update. Name the pull pipeline `azure-pipelines-pull` so its completion triggers resolve without modification. Optionally import `azure-pipelines-test.yml` for repository, cross-platform Pester, and browser validation; configure it as a build-validation policy for Azure Repos pull requests.
6. Name the service connection `EntraOps-ServiceConnection` to use the shipped default. Define `EntraOpsAzureServiceConnection` only when you use a different name. Add the secret `EntraOpsUpdatePat` only for a private update source.
7. Grant `<Project> Build Service (<Organization>)` **Contribute** permission on the repository, and authorize the service connection for the imported pipelines.
8. Apply config-driven schedules and commit the result:

```powershell
Import-Module ./EntraOps
Update-EntraOpsAzureDevOpsSchedules `
  -ConfigFile "./EntraOpsConfig.json" `
  -BranchName "main"
```

The module command changes only the marked YAML schedule regions; operational values remain in
`EntraOpsConfig.json` and are read by each pipeline at runtime. The pull pipeline separately updates
classification definitions, updates Entra ID Control Plane scope, collects Privileged EAM data, and
validates the generated artifacts. The push pipeline supports Log Analytics, Sentinel WatchLists,
Administrative Units, RMAU assignments, Conditional Access target groups, and privileged ELM
catalog protection. The reporting pipeline tests generated reports and publishes an artifact only
after confirming the ADO project is private. The Tenant Governance pipeline supports manual
`Start`, `Collect`, and `RunAndWait` operations plus the four configured start and collection
schedules.

For cross-tenant service connections, use the exact issuer and subject displayed by Azure DevOps;
do not derive either value. The pipeline runtime needs no client secret. `$(System.AccessToken)` is
used for repository commits, so the project Build Service requires **Contribute** permission and any
necessary branch-policy bypass. A PAT is needed only when the update pipeline reads a private
upstream source.

### Service connection details {#azure-devops-service-connection}

In **Project Settings -> Service connections**, create an **Azure Resource Manager -> Workload
Identity Federation (manual)** connection for the app registration. For a cross-tenant setup where
the ADO organization and app registration are backed by different tenants, automatic subscription
discovery does not work; enter these values manually:

| Field                | Value                                                   |
| -------------------- | ------------------------------------------------------- |
| Environment          | `AzureCloud`                                            |
| Scope level          | `Subscription`                                          |
| Subscription ID/name | The subscription exposed through the service connection |
| Tenant ID            | Tenant containing the EntraOps app registration         |
| Service principal ID | Application (client) ID from `EntraOpsConfig.json`      |

Copy the exact issuer and subject displayed by the service connection. Add them to the app
registration under **Certificates & secrets -> Federated credentials -> Other issuer**, with audience
`api://AzureADTokenExchange`. You can add it in the portal or rerun
`New-EntraOpsWorkloadIdentity` against the existing service principal:

```powershell
New-EntraOpsWorkloadIdentity `
  -AppDisplayName "EntraOps-ADO" `
  -ExistingSpObjectId "<service-principal-object-id>" `
  -ConfigFile "./EntraOpsConfig.json" `
  -CreateFederatedCredential `
  -AdoOrgName "<organization>" `
  -AdoProjectName "<project>" `
  -AdoServiceConnectionName "<service-connection>" `
  -AdoFederatedCredentialIssuer "<exact-issuer-from-ADO>"
```

On first use, select **View -> Permit** in the pipeline authorization prompt. To pre-authorize,
open the service connection's **Pipeline permissions** and add each imported EntraOps pipeline.

### Pipeline reference and permissions {#azure-devops-pipeline-reference}

| File                                         | Purpose                                                                                    | Trigger                                                           |
| -------------------------------------------- | ------------------------------------------------------------------------------------------ | ----------------------------------------------------------------- |
| `azure-pipelines-pull.yml`                   | Updates definitions and Control Plane scope, collects data, validates it, and commits JSON | Configured schedule or manual                                     |
| `azure-pipelines-push.yml`                   | Runs enabled ingestion and protection operations                                           | Successful `azure-pipelines-pull` completion or manual            |
| `azure-pipelines-push-reporting.yml`         | Generates and tests reports, then publishes a private-project artifact                     | Pull completion, configured schedule, or manual                   |
| `azure-pipelines-pull-tenant-governance.yml` | Starts or collects Tenant Governance snapshots and commits them                            | Configured start/collection schedules or manual                   |
| `azure-pipelines-update.yml`                 | Updates EntraOps from the configured upstream                                              | Configured schedule or manual                                     |
| `azure-pipelines-test.yml`                   | Validates the repository on Linux, Windows, and macOS and runs browser tests               | Pushes to `main`; pull requests through a build-validation policy |

The production pipelines default to the service connection name `EntraOps-ServiceConnection`. Set
`EntraOpsAzureServiceConnection` on the pipeline, or through a linked Variable Group, only when the
connection uses a different name. Define secret `EntraOpsUpdatePat` only for
a private update source. In **Project Settings -> Repositories -> Security**, grant
`<Project> Build Service (<Organization>)` **Contribute**; also grant branch-policy bypass when the
pull, Tenant Governance, or update pipeline must write to a protected branch.

`AzurePowerShell@5` authenticates Azure PowerShell through the WIF service connection.
`Connect-EntraOps -AuthenticationType FederatedCredentials` then obtains Microsoft Graph access
through that context. Repository writes use `$(System.AccessToken)` through
`.azure-pipelines/scripts/Ado-GitPush.ps1`; they do not require a stored Git credential.

Before enabling Log Analytics ingestion, create the workspace, `PrivilegedEAM_CL` custom table,
Data Collection Endpoint, and Data Collection Rule with a data flow for
`Custom-PrivilegedEAM_CL`. The workload identity needs **Monitoring Metrics Publisher** and
**Reader** on the DCR resource group; **Log Analytics Contributor** alone is insufficient. See
[Reportings -> Microsoft Sentinel integration](../reportings/index.html#microsoft-sentinel-integration)
for the full ingestion setup. After ingestion is operational, deploy the EntraOps workbooks from
that reporting guide.

### Azure DevOps troubleshooting {#azure-devops-troubleshooting}

- **Service connection unavailable:** verify the connection is named `EntraOps-ServiceConnection` or that `EntraOpsAzureServiceConnection` exactly matches its name, and authorize it for the pipeline.
- **Federated sign-in fails:** compare the exact issuer, case-sensitive subject, and `api://AzureADTokenExchange` audience shown by Azure DevOps with the app registration credential.
- **Git push returns HTTP 403:** grant `<Project> Build Service (<Organization>)` **Contribute** and any required branch-policy bypass.
- **Schedule is missing:** run `Update-EntraOpsAzureDevOpsSchedules`, commit the YAML changes, and verify `BranchName` matches the pipeline branch.
- **Push or reporting does not follow pull:** keep the pull pipeline name `azure-pipelines-pull`, or update the dependent pipelines' `resources.pipelines.source`.
- **Reporting has no artifact:** enable reporting and confirm the project is private; artifact publication fails closed when visibility cannot be verified.

### GitHub and Azure DevOps differences {#devops-platform-differences}

Both platforms execute the same EntraOps commands and honor the same feature switches. Their
automation plumbing differs:

| Area                         | GitHub Actions                                                                           | Azure DevOps                                                                                                                    |
| ---------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Definitions                  | `.github/workflows/*.yaml`                                                               | `.azure-pipelines/azure-pipelines-*.yml`                                                                                        |
| Workload federation          | GitHub OIDC; subject `repo:<org>/<repo>:ref:refs/heads/<branch>`                         | Azure Resource Manager WIF service connection; subject `sc://<org>/<project>/<service-connection>`                              |
| Runtime configuration        | `Update-EntraOpsRequiredWorkflowParameters` embeds values and schedules in workflow YAML | Pipelines read operational values from `EntraOpsConfig.json`; `Update-EntraOpsAzureDevOpsSchedules` materializes YAML schedules |
| Repository writes            | Built-in `GITHUB_TOKEN`; workflow permissions are declared in YAML                       | `$(System.AccessToken)`; the Build Service needs repository **Contribute** permission                                           |
| Pull/update linkage          | Native `workflow_run` triggers                                                           | Pipeline completion resources; keep the pull pipeline name `azure-pipelines-pull` or update each `source`                       |
| Automated update publication | `PullRequest` by default, with optional `DirectPush`                                     | `DirectPush`                                                                                                                    |
| Reporting                    | 30-day Actions artifact; optional releases in a private repository                       | Pipeline artifact only after ADO confirms the project is private                                                                |
| CI and pull requests         | `Test-EntraOps` runs on pushes and pull requests; it can be a required status check      | `azure-pipelines-test.yml` runs on pushes; configure it as an Azure Repos build-validation policy for pull requests             |
| Tenant Governance            | One workflow with manual and materialized start/collection schedules                     | One parameterized pipeline with `Start`, `Collect`, and `RunAndWait`, plus materialized schedules                               |

## 4. Ingest to Sentinel {#phase-4-ingest-to-sentinel}

Enable `IngestToLogAnalytics` and/or `IngestToWatchLists` in `EntraOpsConfig.json` when you are
ready to send classification data to Microsoft Sentinel. [Reportings &rarr; Microsoft Sentinel
integration](../reportings/index.html#microsoft-sentinel-integration) covers the parsers, workbooks,
permissions, and ingestion options.

## 5. Automate protection {#phase-5-automate-protection}

When the reviewed export is ready to drive enforcement, enable the needed protection feature in
`EntraOpsConfig.json`. [Privileged EAM &rarr; Automated protection of privileged assets](../privileged-eam/index.html#automated-protection-of-privileged-assets)
covers Conditional Access groups, Administrative Units, RMAU coverage, catalog protection, and
their removal safety controls.

## 6. Full tiering rollout {#phase-6-full-tiering-rollout}

Revisit the reporting apps and workbooks against continuously refreshed data to validate the tier
model and investigate breaches. [Reportings](../reportings/index.html) documents the available
views and Sentinel integration; use their outputs to build the SOC detections appropriate for your
environment.

## Optional: Tenant Governance {#optional-tenant-governance}

If you manage delegated administration across multiple tenants, or want to track configuration
drift over time, enable the optional [Tenant Governance](../tenant-governance/index.html) feature
area. It is independent of the phases above and can be adopted at any point once collection is set up.

## Updating EntraOps

EntraOps can be updated without losing your classification definitions and files by using the
cmdlet `Update-EntraOps`. See [Core &rarr; Update EntraOps PowerShell Module and CI/CD](../core/index.html#update-entraops-powershell-module-and-cicd)
for the full reference, including the scheduled "Update-EntraOps" workflow and how to re-run
`New-EntraOpsWorkloadIdentity` against an existing service principal.

> [!IMPORTANT]
> New releases sometimes require additional Microsoft Graph permissions. Because consent is granted
> once at provisioning time, an existing workload identity keeps the permission set it was created
> with, and the affected collection step fails with an HTTP 403 until consent is renewed. After every
> update, re-run `New-EntraOpsWorkloadIdentity` with `-ExistingSpObjectId` and the object ID of the
> existing EntraOps service principal, then grant admin consent. The update path adds missing
> permissions without replacing the existing application registration, federated credentials, or
> client ID. Omitting `-ExistingSpObjectId` creates a new application registration even when the same
> display name is supplied.
>
> ```powershell
> New-EntraOpsWorkloadIdentity -AppDisplayName "EntraOps-Contoso" `
>   -ExistingSpObjectId "00000000-0000-0000-0000-000000000000" `
>   -ConfigFile "./EntraOpsConfig.json"
> ```
>
> A typical symptom is a `CloudSetZoneResolutionError` entry in the run's warning summary, which
> indicates the `Zone.Read.All` permission introduced for Security Exposure Management zone
> resolution is not yet consented.
