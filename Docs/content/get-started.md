# Get Started with EntraOps

This guide follows the [adoption roadmap](#adoption-roadmap) from a single cmdlet to full tiering:
prerequisites, choosing how you want to run EntraOps, signing in, and deploying the automation -
either interactively/locally or fully automated with GitHub Actions - through to Sentinel
ingestion, automated protection, and full rollout.

> [!TIP]
> **Quick start:** sign in interactively and try EntraOps right now - no configuration file needed:
> ```powershell
> # Repository clone
> Import-Module ./EntraOps
> # or PowerShell Gallery (downloads classification templates, samples and reporting apps once)
> # -Prerelease is needed while 1.1.0 is a release candidate; drop it once 1.1.0 is generally available
> Install-PSResource -Name EntraOps -Prerelease -Repository PSGallery -Scope CurrentUser; Initialize-EntraOpsWorkspace
>
> Connect-EntraOps -AuthenticationType "UserInteractive" -TenantName "contoso.onmicrosoft.com"
> Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles -ExistingClassificationAction Reuse
> # The collection disconnects; reconnect for report enrichment.
> Connect-EntraOps -AuthenticationType "UserInteractive" -TenantName "contoso.onmicrosoft.com"
> New-EntraOpsReportingData
> Disconnect-EntraOps
> ```
> See [1. Try it with zero configuration](#try-it-with-zero-configuration) below for details, or keep reading for prerequisites and the full adoption roadmap.

## Prerequisites

- **PowerShell 7.4 (Core)** or later on any platform (Windows, Linux, macOS), or GitHub Codespaces / GitHub Actions runners. The module enforces this minimum version during import.
- A Microsoft Entra ID tenant where you have (temporarily) **Global Administrator** and **User Access Administrator** permissions to register the application used by EntraOps and grant it the required Microsoft Graph and Azure RBAC permissions.
- Optional: a GitHub account/organization if you want to run EntraOps as a scheduled, automated pipeline instead of (or in addition to) interactive/local execution.
- Optional: a Log Analytics workspace or Microsoft Sentinel workspace if you want to ingest classification data into custom tables or WatchLists (see [Reportings &rarr; Microsoft Sentinel integration](../reportings/index.html#microsoft-sentinel-integration)).

## Install EntraOps {#install-entraops}

You can use EntraOps from a clone of the repository or install the module from the PowerShell
Gallery. Both provide the same cmdlets; they differ in where EntraOps keeps its files and how it is
updated.

|                                            | Clone the repository                                                       | PowerShell Gallery                                                                   |
| ------------------------------------------ | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Best for                                   | Automation with GitHub Actions or Azure DevOps, version-controlled exports | Interactive use and local scripts                                                    |
| Import                                     | `Import-Module ./EntraOps`                                                 | `Import-Module EntraOps`                                                             |
| Working folder                             | Repository root                                                            | `ENTRAOPS_ROOT`, the current folder with `EntraOpsConfig.json`, or `<home>/EntraOps` |
| Classification templates, samples, reports | Included                                                                   | Downloaded with `Initialize-EntraOpsWorkspace`                                       |
| Update                                     | `Update-EntraOps` or the Update-EntraOps workflow                          | `Update-PSResource EntraOps`, then `Initialize-EntraOpsWorkspace -Force`             |
| Privilege History, Configuration Analyzer  | Supported (git history of the repository)                                  | Only in a working folder with git history                                            |

Required modules (Az.Accounts, Az.Resources and Microsoft.Graph.Authentication) are installed
automatically when you connect with `Connect-EntraOps`.

### Option A: Clone the repository {#install-from-repository}

```powershell
git clone https://github.com/Cloud-Architekt/EntraOps.git
cd EntraOps
Import-Module ./EntraOps
```

The repository contains the module, classification templates, samples and reporting apps. For a
scheduled, automated setup, create your own repository from the template instead - see
[3. Customize and automate collection with GitHub](#deploy-with-github) or
[Automate with Azure DevOps](#deploy-with-azure-devops).

### Option B: Install from the PowerShell Gallery {#install-from-powershell-gallery}

```powershell
Install-PSResource -Name EntraOps -Repository PSGallery -Scope CurrentUser
Initialize-EntraOpsWorkspace
```

Update the module with `Update-PSResource EntraOps`. If you installed it with `Install-Module`, use
`Update-Module EntraOps` instead.

The module package contains no classification templates, samples or reporting apps.
`Initialize-EntraOpsWorkspace` downloads them (`Classification`, `Samples` and `Reports` from the
`main` branch) into the working folder. Pass `-Ref` (or `-Branch`) with another branch, or with the release tag or commit that matches your
module version, and use `-Force` after a module update to refresh them. It never writes into the
module folder and never replaces `Classification/Global.json`, tenant classification folders or
generated report data. `Update-EntraOps` only updates repository clones.

> [!IMPORTANT]
> Run `Initialize-EntraOpsWorkspace` before `New-EntraOpsReportingData`: without the `Reports`
> folder, report generation stops with an error. `Invoke-EntraOpsPrivilegedEAM` works without it,
> because it downloads the classification templates it needs for the run.

### Working folder {#working-folder}

EntraOps reads and writes its configuration, classification files, exports and reports in a working
folder (`$EntraOpsBaseFolder`), which is resolved when the module is imported:

1. The folder in the environment variable `ENTRAOPS_ROOT`, if it is set.
2. The repository clone that contains the module - a GitHub or Azure DevOps pipeline checkout or a
   local clone.
3. The current folder, if it contains `EntraOpsConfig.json`.
4. `<home>/EntraOps`.

Run `Import-Module EntraOps -Verbose` to see which folder is used; the line `Working Folder` in the connection
summary of `Connect-EntraOps` shows it as well. To keep several tenants apart with a Gallery installation, use one
folder per tenant and run EntraOps from it, or set `ENTRAOPS_ROOT` before importing the module.

To use the current folder with a Gallery installation, run `Initialize-EntraOpsWorkspace -Path .` once: it installs
the content into the folder and uses it for the session. Create `EntraOpsConfig.json` there
(`New-EntraOpsConfigFile -ConfigFilePath ./EntraOpsConfig.json`), so later sessions started from this folder use it
automatically, or set `ENTRAOPS_ROOT`.

| Output                       | Location                       | Shown by                                                                         | `Remove-EntraOpsData -Content` |
| ---------------------------- | ------------------------------ | -------------------------------------------------------------------------------- | ------------------------------ |
| Privileged EAM export        | `PrivilegedEAM/<RbacSystem>/`  | `Save-EntraOpsPrivilegedEAMJson`, `Invoke-EntraOpsPrivilegedEAM` (summary)       | `PrivilegedEAM`                |
| Reporting app data           | `Reports/<App>/data/`          | `New-EntraOpsReportingData` (`Wrote ...`, `Open the reporting apps: ...`)        | `Reports`                      |
| Tenant classification files  | `Classification/<TenantName>/` | `Update-EntraOpsClassificationControlPlaneScope`, `Invoke-EntraOpsPrivilegedEAM` | `Classification`               |
| Tenant Governance snapshots  | `TenantGovernance/Snapshots/`  | `Save-EntraOpsTenantGovernanceSnapshotJson`                                      | `TenantGovernance`             |
| Graph and ARM response cache | `<user cache folder>/EntraOps` | `Get-EntraOpsCacheStatistics`                                                    | `Cache`                        |

`Remove-EntraOpsData` removes this output from the working folder, all content types by default. It prompts for
confirmation (`-WhatIf` lists what would be removed), keeps the manually maintained overwrite files
(`Classification_RoleActionOverwrites.json`, `Classification_RoleDefinitionOverwrites.json`,
`Classification_ApiPermissionOverwrites.json` and their `_<Tag>` variants), the classification
templates, `Global.json` and the Object Classification File, and only removes the classification folders of
`-TenantName` when it is passed. In a git repository the exports are tracked history, so it stops unless `-Force` is
used:

```powershell
Remove-EntraOpsData -WhatIf
Remove-EntraOpsData -Content PrivilegedEAM, Reports, Cache
```

`Initialize-EntraOpsWorkspace -Path <folder>` installs the content into another folder and uses it
as working folder for the current PowerShell session. For new sessions, set `ENTRAOPS_ROOT` to that
folder before importing the module. Use `-KeepWorkingFolder` to only prepare the folder, e.g. for
another tenant.

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
`Classification` folder first; an existing configuration is used (see below). With a PowerShell Gallery installation, run
[`Initialize-EntraOpsWorkspace`](#install-from-powershell-gallery) once if you want to generate the
reporting apps from the export afterwards. EntraOps signs in to Azure and Microsoft Graph interactively, so the
Microsoft Graph sign-in can request the delegated permissions required for collection:

> [!NOTE]
> You may be asked to grant consent if the Microsoft Graph PowerShell client does not already have
> the delegated scopes required for this run. Review the [baseline collection permissions](../core/index.html#service-principal-permissions).

For complete interactive collection, use an account with **Global Reader** activated in Microsoft
Entra ID and **Reader** on the root management group (Tenant Root Group), which covers every
management group, subscription and resource below it. Role assignments made directly at the tenant
root scope (`/`), e.g. through `elevateAccess`, are only visible with Reader at `/` as well. An
administrator who can create role assignments at the root management group can grant the Azure role
to the user with
[`New-AzRoleAssignment`](https://learn.microsoft.com/en-us/powershell/module/az.resources/new-azroleassignment)
(use `-ObjectId` instead of `-SignInName` to pass the user's object ID):


```powershell
$TenantId = (Get-AzContext).Tenant.Id
New-AzRoleAssignment -SignInName "AdeleV@contoso.com" -RoleDefinitionName "Reader" `
  -Scope "/providers/Microsoft.Management/managementGroups/$TenantId"
```

`Invoke-EntraOpsPrivilegedEAM` resolves the tenant from the EntraOps connection, provides the
classification templates, computes the Control Plane scope, runs
`Save-EntraOpsPrivilegedEAMJson`, and cleans up every intermediate file so only the PrivilegedEAM
JSON output remains (except for any pre-existing tenant overwrite files -
`Classification_RoleActionOverwrites.json`, `Classification_RoleDefinitionOverwrites.json`,
`Classification_ApiPermissionOverwrites.json` and their `_<Tag>` variants - which are always
preserved). Use `-RbacSystems` to limit the scope, or `-PrivilegedObjectClassificationSource` to
change how Control Plane scope is determined - see
[Privileged EAM &rarr; Automatic Control Plane scope updates](../privileged-eam/index.html#automatic-updated-control-plane-scope).
Use `-KeepClassificationFiles` to keep the classification files, e.g. to review them in the
Classification Explorer. The cmdlet stops when the Azure and Microsoft Graph contexts are connected to
different tenants.

No configuration file is required, but `Invoke-EntraOpsPrivilegedEAM` uses one when it finds it. The
settings are applied in this order (first match wins):

1. Parameters passed to the cmdlet.
2. The file passed with `-ConfigFilePath`.
3. The configuration loaded by `Connect-EntraOps`.
4. `EntraOpsConfig.json` in the current folder.
5. `EntraOpsConfig.json` in the EntraOps [working folder](#working-folder).
6. Built-in defaults.

> [!WARNING]
> `AlternateObjectTierLevelAttributes` filters are PowerShell expressions that run as code. The cmdlet
> shows a warning when an automatically found configuration file contains such filters; only use
> configuration files you trust.

When tenant classification files from a previous run exist (e.g. after `-KeepClassificationFiles`),
`-ExistingClassificationAction` controls the classification templates:

| Value              | Behavior                                                                                                                    |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------- |
| `Prompt` (default) | Asks whether to reuse or regenerate, only when tenant classification files exist. Non-interactive hosts stop with an error. |
| `Reuse`            | Keeps the local classification templates and downloads only missing ones.                                                   |
| `Regenerate`       | Downloads the latest classification templates.                                                                              |

Both `Reuse` and `Regenerate` rebuild the tenant classification files and the Control Plane scope
reasoning, with the preserved overwrite files. Pass `Reuse` or `Regenerate` for repeat or unattended
runs:

```powershell
Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles -ExistingClassificationAction Reuse
```

> [!TIP]
> This is the fastest way to try EntraOps or produce a one-off export. Continue with [2. Verify output with reports and workbooks](#phase-2-verify-output) before you keep using it, or jump straight to [3. Customize and automate collection with GitHub](#deploy-with-github) for a repeatable, automated setup.

## 2. Verify output with reports and workbooks {#phase-2-verify-output}

Before automating collection, review the PrivilegedEAM export from
[1. Try it with zero configuration](#try-it-with-zero-configuration) (or a manual
`Save-EntraOpsPrivilegedEAMJson` run) to confirm the classification and Control Plane scope match
your expectations. Generate the
[reporting apps](../reportings/index.html#entraops-reporting-apps) against the local export.
The apps use the export, with optional Microsoft Graph enrichment; no Log Analytics workspace or
Azure subscription required:

```powershell
Initialize-EntraOpsWorkspace -Ref '<release tag of your module version>' # module-only installations
Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles -ExistingClassificationAction Reuse
Connect-EntraOps -AuthenticationType "UserInteractive" -TenantName "contoso.onmicrosoft.com"
New-EntraOpsReportingData
Disconnect-EntraOps
```

The collection disconnects during teardown, so reconnect before generating reports to resolve
linked identities and related objects through Microsoft Graph. For generation without Graph
lookups, see [Reporting apps](../reportings/index.html#entraops-reporting-apps).

Azure Monitor workbooks are also available, but only once data has been ingested into Log
Analytics/Sentinel - see [4. Ingest to Sentinel](#phase-4-ingest-to-sentinel) below.

> [!TIP]
> Catching a misclassified role or an overly broad Control Plane scope now is much cheaper than
> after Conditional Access target groups, Administrative Units, or Sentinel ingestion have already
> been automated from it.

## Import module and sign-in options

Import the PowerShell module as described in [Install EntraOps](#install-entraops) - from a
repository clone or the PowerShell Gallery (by default, required modules are installed
automatically):

```powershell
Import-Module ./EntraOps   # repository clone
Import-Module EntraOps     # PowerShell Gallery
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

> [!NOTE]
> `Connect-EntraOps` automatically loads `EntraOpsConfig.json` from the current folder, otherwise from the
> EntraOps working folder, unless its `TenantName` differs from `-TenantName`. Use `-ConfigFilePath` for another
> file. The line `Config File` in the connection summary shows which file is used. The file can contain PowerShell
> filter expressions, so only run EntraOps in folders you trust (see
> [Configuration file reference](../core/index.html#configuration-file-reference)).

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
New-EntraOpsReportingData
Disconnect-EntraOps
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

1. Create or import EntraOps into a **private** Azure DevOps project. Generated exports and reports contain tenant identifiers and access data; this is enforced: the pull, Tenant Governance and update pipelines refuse to commit and push when the project isn't private, and the reporting pipeline skips publishing its artifact.
2. Generate the configuration with `New-EntraOpsConfigFile -TenantName "contoso.onmicrosoft.com" -DevOpsPlatform AzureDevOps`, or select Azure DevOps in the guided setup above.
3. Run `New-EntraOpsWorkloadIdentity -AppDisplayName "EntraOps-ADO" -ConfigFile "./EntraOpsConfig.json"` to create the app registration and configured permissions.
4. Create an **Azure Resource Manager -> Workload Identity Federation (manual)** service connection. Add the exact issuer and subject identifier shown by Azure DevOps as a federated credential on the app registration; use `api://AzureADTokenExchange` as the audience.
5. Import the five production YAML pipelines from `.azure-pipelines/`: pull, push, reporting, Tenant Governance, and update. Name the pull pipeline `entraops-pull` so its completion triggers resolve without modification. Optionally import `entraops-test.yml` for repository, cross-platform Pester, and browser validation; configure it as a build-validation policy for Azure Repos pull requests.
6. Name the service connection `EntraOps-ServiceConnection` to use the shipped default. For another name, set `AzureDevOpsServiceConnection` in `EntraOpsConfig.json` (or `New-EntraOpsConfigFile -AzureDevOpsServiceConnection`); step 8 writes it into the pipelines. Add the secret `EntraOpsUpdatePat` only for a private update source.
7. Grant `<Project> Build Service (<Organization>)` **Contribute** permission on the repository, plus **Create branch** and **Contribute to pull requests** for the update pipeline in its default `PullRequest` mode, and authorize the service connection for the imported pipelines. **Force push** isn't required. The build service also needs **View project-level information** (granted by default) so the pipelines can verify that the project is private.
8. Apply the config-driven schedules and service connection, and commit the result:

```powershell
Import-Module ./EntraOps
Update-EntraOpsAzureDevOpsSchedules `
  -ConfigFile "./EntraOpsConfig.json" `
  -BranchName "main"
```

The module command changes only the marked YAML schedule and service connection regions; operational
values remain in `EntraOpsConfig.json` and are read by each pipeline at runtime. Azure Pipelines
resolves the service connection before runtime variables exist, so its name is written as the default
of the `serviceConnection` pipeline parameter; `Update-EntraOps` applies it again after updating the
pipelines. A manual run can select another authorized service connection. The pull pipeline separately updates
classification definitions, updates Entra ID Control Plane scope, collects Privileged EAM data, and
validates the generated artifacts. The push pipeline supports Log Analytics, Sentinel WatchLists,
Administrative Units, RMAU assignments, Conditional Access target groups, and privileged ELM
catalog protection. The push and reporting pipelines check out the latest commit of their branch,
because a run triggered by `entraops-pull` otherwise starts on the commit the pull run started from,
without the data it committed. The reporting pipeline tests generated reports and publishes an artifact only
after confirming the ADO project is private. The Tenant Governance pipeline supports manual
`Start`, `Collect`, and `RunAndWait` operations plus the four configured start and collection
schedules.

For cross-tenant service connections, use the exact issuer and subject displayed by Azure DevOps;
do not derive either value. The pipeline runtime needs no client secret. `$(System.AccessToken)` is
used for repository commits, so the project Build Service requires **Contribute** permission and any
necessary branch-policy bypass. The token is passed to the individual git commands and never stored
in the checkout. A PAT is needed only when the update pipeline reads a private upstream source.

The update pipeline runs in three jobs: **Resolve** clones the configured upstream ref without
executing it, **Validate** runs the candidate's tests without a repository checkout and without
credentials, and **Apply** applies the validated candidate and opens a pull request from the branch
`entraops/update-<commit>`. With `AutomatedEntraOpsUpdate.PublicationMode` set to `DirectPush`, Apply
instead pushes the update to the pipeline branch without review; updated pipeline definitions then
apply to the next scheduled runs, which use the Azure service connection. A manual run can override
the mode with the **Publication mode for this run** parameter. No job signs in to Azure. While the pull request is active, later runs
leave its branch unchanged. A branch left from a completed or abandoned pull request is never
overwritten; the update then uses `entraops/update-<commit>-<n>`. Delete leftover update branches
when convenient. Keep `./.github/scripts` in `AutomatedEntraOpsUpdate.TargetUpdateFolders`;
it contains the trusted candidate validator. Candidate validation can't be skipped while
`./.azure-pipelines` is an update target.

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

Copy the exact issuer and subject identifier displayed by the service connection. Add them to the app
registration under **Certificates & secrets -> Federated credentials -> Other issuer**, with audience
`api://AzureADTokenExchange`. You can add it in the portal or rerun
`New-EntraOpsWorkloadIdentity` against the existing service principal. New service connections use
the Microsoft Entra issuer (`https://login.microsoftonline.com/<tenant-id>/v2.0`) with a generated
subject, so `-AdoFederatedCredentialSubject` is required; only for the deprecated Azure DevOps issuer
(`https://vstoken.dev.azure.com/<organization-id>`) can it be omitted, and the subject is then
`sc://<organization>/<project>/<service-connection>`.

```powershell
New-EntraOpsWorkloadIdentity `
  -AppDisplayName "EntraOps-ADO" `
  -ExistingSpObjectId "<service-principal-object-id>" `
  -ConfigFile "./EntraOpsConfig.json" `
  -CreateFederatedCredential `
  -AdoOrgName "<organization>" `
  -AdoProjectName "<project>" `
  -AdoServiceConnectionName "<service-connection>" `
  -AdoFederatedCredentialIssuer "<exact-issuer-from-ADO>" `
  -AdoFederatedCredentialSubject "<exact-subject-from-ADO>"
```

On first use, select **View -> Permit** in the pipeline authorization prompt. To pre-authorize,
open the service connection's **Pipeline permissions** and add each imported EntraOps pipeline.

### Pipeline reference and permissions {#azure-devops-pipeline-reference}

| File                                  | Purpose                                                                                    | Trigger                                                           |
| ------------------------------------- | ------------------------------------------------------------------------------------------ | ----------------------------------------------------------------- |
| `entraops-pull.yml`                   | Updates definitions and Control Plane scope, collects data, validates it, and commits JSON | Configured schedule or manual                                     |
| `entraops-push.yml`                   | Runs enabled ingestion and protection operations                                           | Successful `entraops-pull` completion or manual                   |
| `entraops-push-reporting.yml`         | Generates and tests reports, then publishes a private-project artifact                     | Pull completion, configured schedule, or manual                   |
| `entraops-pull-tenant-governance.yml` | Starts or collects Tenant Governance snapshots and commits them                            | Configured start/collection schedules or manual                   |
| `entraops-update.yml`                 | Validates an EntraOps update in isolation and opens a pull request or pushes directly      | Configured schedule or manual                                     |
| `entraops-test.yml`                   | Validates the repository on Linux, Windows, and macOS and runs browser tests               | Pushes to `main`; pull requests through a build-validation policy |

The production pipelines default to the service connection name `EntraOps-ServiceConnection`. For
another name, set `AzureDevOpsServiceConnection` in `EntraOpsConfig.json` and run
`Update-EntraOpsAzureDevOpsSchedules`. Define secret `EntraOpsUpdatePat` only for
a private update source. In **Project Settings -> Repositories -> Security**, grant
`<Project> Build Service (<Organization>)` **Contribute**, **Create branch** and **Contribute to pull
requests**; also grant branch-policy bypass when the pull or Tenant Governance pipeline must write
to a protected branch. In `PullRequest` mode, the update pipeline doesn't write to the branch; it
opens a pull request and never force-pushes, so **Force push** isn't required. `DirectPush` needs only
**Contribute** (plus branch-policy bypass for a protected branch), not **Create branch** or
**Contribute to pull requests**.

`AzurePowerShell@5` authenticates Azure PowerShell through the WIF service connection.
`Connect-EntraOps -AuthenticationType FederatedCredentials` then obtains Microsoft Graph access
through that context. Repository writes use `$(System.AccessToken)` through
`.azure-pipelines/scripts/Ado-GitPush.ps1`, and the update pipeline publishes through
`.azure-pipelines/scripts/Publish-EntraOpsAdoUpdate.ps1`; they do not require a stored Git credential.

Before enabling Log Analytics ingestion, create the workspace, `PrivilegedEAM_CL` custom table,
Data Collection Endpoint, and Data Collection Rule with a data flow for
`Custom-PrivilegedEAM_CL`. The workload identity needs **Monitoring Metrics Publisher** and
**Reader** on the DCR resource group; **Log Analytics Contributor** alone is insufficient. See
[Reportings -> Microsoft Sentinel integration](../reportings/index.html#microsoft-sentinel-integration)
for the full ingestion setup. After ingestion is operational, deploy the EntraOps workbooks from
that reporting guide.

### Azure DevOps troubleshooting {#azure-devops-troubleshooting}

- **Service connection unavailable:** verify the connection is named `EntraOps-ServiceConnection`, or that `AzureDevOpsServiceConnection` in `EntraOpsConfig.json` exactly matches its name and `Update-EntraOpsAzureDevOpsSchedules` was run and committed; then authorize it for the pipeline.
- **Federated sign-in fails:** compare the exact issuer, case-sensitive subject, and `api://AzureADTokenExchange` audience shown by Azure DevOps with the app registration credential.
- **Git push returns HTTP 403:** grant `<Project> Build Service (<Organization>)` **Contribute** and any required branch-policy bypass; for the update pipeline in `PullRequest` mode also **Create branch** and **Contribute to pull requests**. `TF401027 ... 'CreateBranch' permission` means **Create branch** is missing.
- **Schedule is missing:** run `Update-EntraOpsAzureDevOpsSchedules`, commit the YAML changes, and verify `BranchName` matches the pipeline branch.
- **Push or reporting does not follow pull:** keep the pull pipeline name `entraops-pull`, or update the dependent pipelines' `resources.pipelines.source`.
- **Reporting has no artifact:** enable reporting and confirm the project is private; artifact publication fails closed when visibility cannot be verified.

### GitHub and Azure DevOps differences {#devops-platform-differences}

Both platforms execute the same EntraOps commands and honor the same feature switches. Their
automation plumbing differs:

| Area                         | GitHub Actions                                                                           | Azure DevOps                                                                                                                                               |
| ---------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Definitions                  | `.github/workflows/*.yaml`                                                               | `.azure-pipelines/entraops-*.yml`                                                                                                                          |
| Workload federation          | GitHub OIDC; subject `repo:<org>/<repo>:ref:refs/heads/<branch>`                         | Azure Resource Manager WIF service connection; exact issuer and subject shown by the service connection                                                    |
| Runtime configuration        | `Update-EntraOpsRequiredWorkflowParameters` embeds values and schedules in workflow YAML | Pipelines read operational values from `EntraOpsConfig.json`; `Update-EntraOpsAzureDevOpsSchedules` materializes YAML schedules and the service connection |
| Repository writes            | Built-in `GITHUB_TOKEN`; workflow permissions are declared in YAML                       | `$(System.AccessToken)`; the Build Service needs repository **Contribute** permission                                                                      |
| Pull/update linkage          | Native `workflow_run` triggers                                                           | Pipeline completion resources; keep the pull pipeline name `entraops-pull` or update each `source`                                                         |
| Automated update publication | `PullRequest` by default, with optional `DirectPush`                                     | `PullRequest` by default, with optional `DirectPush`                                                                                                       |
| Reporting                    | 30-day Actions artifact; optional releases in a private repository                       | Pipeline artifact only after ADO confirms the project is private                                                                                           |
| CI and pull requests         | `Test-EntraOps` runs on pushes and pull requests; it can be a required status check      | `entraops-test.yml` runs on pushes; configure it as an Azure Repos build-validation policy for pull requests                                               |
| Tenant Governance            | One workflow with manual and materialized start/collection schedules                     | One parameterized pipeline with `Start`, `Collect`, and `RunAndWait`, plus materialized schedules                                                          |

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
