# EntraOps (Privileged EAM) - Management and Monitoring of Enterprise Access Model

- [EntraOps (Privileged EAM) - Management and Monitoring of Enterprise Access Model](#entraops-privileged-eam---management-and-monitoring-of-enterprise-access-model)
  - [Introduction](#introduction)
  - [Key features](#key-features)
  - [Service EM - Service-scoped Landing Zones](#service-em---service-scoped-landing-zones)
  - [Videos and demos of EntraOps Privileged EAM](#videos-and-demos-of-entraops-privileged-eam)
  - [Documentation](#documentation)
  - [Quick starts](#quick-starts)
  - [Executing EntraOps interactively](#executing-entraops-interactively)
    - [Import module and sign-in options](#import-module-and-sign-in-options)
    - [Export and collecting EntraOps data](#export-and-collecting-entraops-data)
    - [Filter on classification in EntraOps](#filter-on-classification-in-entraops)
    - [Filter on classified objects and object details](#filter-on-classified-objects-and-object-details)
  - [Using EntraOps with GitHub](#using-entraops-with-github)
  - [Using EntraOps with Azure DevOps](#using-entraops-with-azure-devops)
  - [Log Analytics Ingestion Setup](#log-analytics-ingestion-setup)
    - [Overview of Components](#overview-of-components)
    - [Step 1: Create the Log Analytics Workspace](#step-1-create-the-log-analytics-workspace)
    - [Step 2: Create the Custom Table](#step-2-create-the-custom-table)
    - [Step 3: Create the Data Collection Endpoint (DCE)](#step-3-create-the-data-collection-endpoint-dce)
    - [Step 4: Create the Data Collection Rule (DCR)](#step-4-create-the-data-collection-rule-dcr)
    - [Step 5: Assign Required RBAC Roles](#step-5-assign-required-rbac-roles)
      - [PowerShell example](#powershell-example)
      - [Automated assignment via EntraOps cmdlet](#automated-assignment-via-entraops-cmdlet)
    - [Step 6: Configure EntraOpsConfig.json](#step-6-configure-entraopsconfigjson)
    - [Ingestion Behavior and Limits](#ingestion-behavior-and-limits)
  - [EntraOps Integration in Microsoft Sentinel](#entraops-integration-in-microsoft-sentinel)
    - [Parser for Custom Tables and WatchLists](#parser-for-custom-tables-and-watchlists)
    - [Examples to use EntraOps data in Unified SecOps Platform (Sentinel and XDR)](#examples-to-use-entraops-data-in-unified-secops-platform-sentinel-and-xdr)
    - [Workbook for visualization of EntraOps classification data](#workbook-for-visualization-of-entraops-classification-data)
      - [Prerequisites](#prerequisites)
      - [Deployment Steps](#deployment-steps)
      - [Available Workbooks](#available-workbooks)
      - [Post-Deployment Configuration](#post-deployment-configuration)
  - [EntraOps Integration to Attack Path Management](#entraops-integration-to-attack-path-management)
    - [BloodHound Integration](#bloodhound-integration)
  - [Tenant Governance Relationship Support](#tenant-governance-relationship-support)
    - [Configuring EntraOps for Tenant Governance Relationships](#configuring-entraops-for-tenant-governance-relationships)
    - [Authentication Recommendations for Tenant Governance](#authentication-recommendations-for-tenant-governance)
  - [Classify privileged objects by Custom Security Attributes](#classify-privileged-objects-by-custom-security-attributes)
  - [Classification of Identity Governance delegation and roles](#classification-of-identity-governance-delegation-and-roles)
    - [Identify delegated management with different classifications](#identify-delegated-management-with-different-classifications)
  - [Automatic updated Control Plane Scope by EntraOps and other data sources](#automatic-updated-control-plane-scope-by-entraops-and-other-data-sources)
    - [Azure Resource Graph](#azure-resource-graph)
    - [Microsoft Security Exposure Management](#microsoft-security-exposure-management)
    - [Adjusted Control Plane Scope by using Restricted Management and Role Assignments](#adjusted-control-plane-scope-by-using-restricted-management-and-role-assignments)
  - [Why was this classification chosen for the role?](#why-was-this-classification-chosen-for-the-role)
  - [Update EntraOps PowerShell Module and CI/CD](#update-entraops-powershell-module-and-cicd)
  - [Changelog](#changelog)
  - [Project Policies and License](#project-policies-and-license)
    - [Managed Service or Commercial Use Notice](#managed-service-or-commercial-use-notice)

## Introduction

EntraOps is a community research project that demonstrates automated management of a Microsoft Entra ID tenant at scale using a DevOps approach. The PowerShell module and repository templates analyze privileges and apply a customizable classification model to identify access sensitivity based on [Microsoft's Enterprise Access Model](https://aka.ms/SPA). EntraOps requires PowerShell 7.4 or later and can run in GitHub Actions, Azure Pipelines, custom automation, managed-identity hosts, or local environments.

Start with the **[EntraOps Docs](./Docs/index.html)** and guided **[Get Started setup guide](./Docs/get-started/index.html)** for an interactive run, a local configuration, GitHub Actions, or Azure Pipelines.

## Key features

- 🚀 Automate deployment with GitHub Actions or Azure Pipelines, or run locally on any platform that supports PowerShell Core.

- ☑️ Track changes to privileged principals and their assignments as code.

- 🆕 Update classification templates, the PowerShell module, and other repository resources automatically.

- 👑 Identify privileged assets through automated, customizable classification based on the Enterprise Access Model tiering model. Customize Control Plane scope automatically using critical assets in Microsoft Security Exposure Management, high-privilege Azure RBAC roles and scopes, and privileged Microsoft Entra objects.

- 🔬 Ingest detailed classification data into a custom Microsoft Sentinel/Log Analytics table or Sentinel WatchLists for hunting and enrichment. Supported WatchList templates include High Value Assets, VIP Users, and Identity Correlation.

- 🤖 Use advanced WatchLists to understand relationships between managed identities and Azure resources, and to review workload-identity posture from Microsoft Entra recommendations and Microsoft Defender for Cloud CSPM attack paths.

- 📊 Build reports and queries that identify Enterprise Access Model tier breaches and privilege-escalation paths. Use the included workbook to visualize classified role assignments and objects classified with Custom Security Attributes.

- 🖥️ EntraOps Reporting: a portal of ten static, self-contained, offline-capable web apps for classification, privileged identities, access paths, tier breaches, privilege history, tenant configuration, Conditional Access, EIDSCA findings, PIM request flows, and access-package flows. The apps visualize data as drill-down grids, graphs, or Sankey flows, and share a cross-tool Review list — no backend or Azure subscription required.

- 🛡️ Assign privileged assets automatically to Conditional Access groups and Restricted Management Administrative Units (RMAUs). Privileged users and groups that are not already protected by an Administrative Unit, role-assignable group, or Entra ID role can be assigned to an RMAU named `UnprotectedObjects`.

- 🏢 Collect and classify privileged access across Tenant Governance delegated-administration relationships. EntraOps resolves identities from governed tenants and maps each principal to its source tenant through `ObjectTenantId`.

- 📸 Track tenant configuration as code with point-in-time Tenant Governance snapshots from the Microsoft Graph Tenant Configuration Management (UTCM) API. Version Microsoft Entra, Intune, and Security & Compliance configuration as individual JSON files, compare changes in Configuration Analyzer, and review Conditional Access coverage with a filterable Sankey visualization.

- 🩸 Export EntraOps Privileged EAM data as OpenGraph JSON to enrich attack paths in BloodHound, including classification, nested group assignments, and relationships to PAW devices and users. The Access Path Map reporting app additionally includes Azure RBAC roles and assignments from the Azure Privileged EAM export.

- 🕵️‍♂️ Use GitHub Custom Agents to analyze privileged objects in EntraOps.
  - **EntraOps Report Agent:** Applies Enterprise Access Model tiers and identity-hygiene rules; detects tier mismatches, permanent high-privilege assignments, risky identity types, and insecure ownership; and can add Microsoft Sentinel risk and incident context. It produces an executive summary with categorized findings, severity, file-and-line evidence, and ASCII attack-path diagrams.
  - **EntraOps QA Agent:** Answers focused questions about one identity or role by locating only the relevant JSON files. It evaluates role assignments, PIM status, identity hygiene, ownership, and simplified attack paths, and can add Microsoft Sentinel user-risk or incident context.

Currently the following RBAC systems are supported:

- 🔑 Microsoft Entra roles
- 🔄 Microsoft Entra Identity Governance
- 🛡️ Microsoft Defender XDR Unified RBAC
- 🤖 Microsoft Graph App Roles
- 🖥️ Microsoft Intune RBAC
- ☁️ Microsoft Azure RBAC

The EntraOps PowerShell module can be executed locally, as part of a CI/CD pipeline, or in any automation/worker environment that supports PowerShell Core. Shipped automation templates support both GitHub Actions and Azure Pipelines.

## Service EM - Service-scoped Landing Zones

**Service EM**, developed in collaboration with **Michael Soule**, provisions service-scoped Azure and Entra ID landing zones aligned with the Enterprise Access Model. It combines tiered groups, PIM for Groups, Entra ID Governance access packages, Azure RBAC, and ABAC-constrained delegation for least-privilege administration. See the [Service EM documentation](./Docs/service-em/index.html) for setup, governance models, configuration, and dependency diagrams.

## Videos and demos of EntraOps Privileged EAM

- [TEC Talk: Protecting Privileged User and Workload Identities in Entra ID](https://www.quest.com/webcast-ondemand/tec-talk-protecting-privileged-user-and-workload-identities-in-entra-id/)
- [SpecterOps Webinar: Defining the Undefined: What is Tier Zero Part III](https://youtu.be/ykrse1rsvy4?si=f7fLcf1rAN0MGlti&t=1223)

## Documentation

Full documentation - including a **Get Started** guide, configuration reference and feature deep-dives for **Core**,
**Privileged EAM**, **Service EM**, and **Reportings** - is available in the **[EntraOps Docs](./Docs/index.html)**.

- 🚩 [Get Started](./Docs/get-started/index.html) - prerequisites, sign-in options, and deploying EntraOps
  interactively or as an automated GitHub pipeline.
- ⚙️ [Core](./Docs/core/index.html) - authentication, the `EntraOpsConfig.json` reference, Tenant Governance
  relationships and configuration snapshots, object classification by Custom Security Attributes or Alternate
  Tier Level Attributes, and updating the module.
- 🛡️ [Privileged EAM](./Docs/privileged-eam/index.html) - collecting and exporting data, filtering examples,
  customizing classification with overwrite files, Identity Governance delegation, and automatic Control Plane scope
  updates.
- 🏗️ [Service EM](./Docs/service-em/index.html) - service-scoped Azure and Entra ID landing zones with tiered
  groups, PIM for Groups, access packages, Azure RBAC, and constrained delegation.
- 📊 [Reportings](./Docs/reportings/index.html) - ten static Reporting apps, including Classification Explorer, EAM
  Dashboard, Access Path Map, Tier Breach Analyzer, Privilege History, Configuration Analyzer, Conditional Access
  Analysis, EIDSCA Findings, PIM Request Flow, and Access Package Flow; plus Microsoft Sentinel/Unified SecOps
  Platform and BloodHound OpenGraph integrations.
- 🏢 [Tenant Governance](./Docs/tenant-governance/index.html) - cross-tenant delegated administration,
  Microsoft Graph UTCM configuration snapshots, permissions, scheduling, quotas, and Configuration Analyzer.

Open [`Reports/index.html`](./Reports/index.html) to use the reporting apps directly.

## Quick starts

## Executing EntraOps interactively

A complete list of all existing PowerShell query templates is available as YAML file in the [Queries](./Queries/PowerShell/PrivilegedEAM.yaml) folder.

### Import module and sign-in options

Import PowerShell module (by default, required modules will be installed automatically)

```powershell
Import-Module ./EntraOps
```
  
User Interactive with consented Microsoft Graph PowerShell

```powershell
Connect-EntraOps -AuthenticationType "UserInteractive" -TenantName <TenantName>
```

User Interactive in GitHub Codespaces with consented Microsoft Graph PowerShell

```powershell
Connect-EntraOps -AuthenticationType "DeviceAuthentication" -TenantName <TenantName>
```

User-Assigned Managed Identity

```powershell
Connect-EntraOps -AuthenticationType "UserAssignedMSI" -TenantName <TenantName>`
-AccountId <UserAssignedMSIObjectId>
```

Service Principal with ClientSecret

```powershell
$ServicePrincipalCredentials = Get-Credential
Connect-AzAccount -Credential $ServicePrincipalCredentials -ServicePrincipal -Tenant $TenantName
Connect-EntraOps -TenantName $TenantName -AuthenticationType "AlreadyAuthenticated"
```

Workload with already authenticated Azure PowerShell

```powershell
Connect-EntraOps -AuthenticationType "AlreadyAuthenticated" -TenantName "contoso.onmicrosoft.com"
```

### Export and collecting EntraOps data

Export all classification of privileged objects using `Save-EntraOpsPrivilegedEAMJson` (saves to JSON files) or `Get-EntraOpsPrivilegedEAM` (returns data in-memory).

Both cmdlets process all supported RBAC systems by default. Use the `-RbacSystems` parameter to limit scope:

- **EntraID** – [Entra ID directory roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/custom-overview) (built-in and custom roles)
- **IdentityGovernance** – [Entra ID Governance](https://learn.microsoft.com/en-us/entra/id-governance/identity-governance-overview) (access packages, entitlement management)
- **DeviceManagement** – [Microsoft Intune RBAC](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/role-based-access-control) (device management roles)
- **ResourceApps** – [Microsoft Graph API permissions and app roles](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview) (application permissions)
- **Defender** – [Microsoft Defender XDR Unified RBAC](https://learn.microsoft.com/en-us/defender-xdr/manage-rbac) (security operations roles)

There are two ways, I've you want to filter the EntraOps results in PowerShell:
**Option A** – Export RBAC systems to JSON files, then load one or more systems into a variable for filtering:

```powershell
Save-EntraOpsPrivilegedEAMJson -RBACSystems @("EntraID", "ResourceApps")
# Load exported EntraID data for filtering
$EntraOpsData = Get-Content -Raw .\PrivilegedEAM\EntraID\EntraID.json | ConvertFrom-Json
```

**Option B** – Load RBAC systems directly into a variable (no files saved):

```powershell
$EntraOpsData = Get-EntraOpsPrivilegedEAM
```

### Filter on classification in EntraOps

All privileged objects with Control Plane Permissions

```powershell
$EntraOpsData | Where-Object { $_.RoleAssignments.Classification.AdminTierLevelName -contains "ControlPlane" }
```

All privileged objects with permissions with related permissions to "Conditional Access"

```powershell
$EntraOpsData | Where-Object { $_.RoleAssignments.Classification.Service -contains "Conditional Access" }
```

Entra ID Custom Roles with role actions which has been classified as "Control Plane"

```powershell
$EntraOpsData | Where-Object {$_.RoleSystem -eq "EntraID"} `
| select-Object -ExpandProperty RoleAssignments `
| Where-Object {$_.RoleType -eq "CustomRole" -and $_.Classification.AdminTierLevelName -contains "ControlPlane"}
```

### Filter on classified objects and object details

Administrative Units with assigned privileged objects

```powershell
$EntraOpsData | Select-Object -ExpandProperty AssignedAdministrativeUnits `
| Select-Object -Unique displayName | Sort-Object displayName
```

External users with privileged role assignments

```powershell
$EntraOpsData | Where-Object { $_.ObjectSubType -eq "Guest"}
```

Hybrid identities with privileges (excl. Directory Synchronization Service Account)

```powershell
$EntraOpsData | Where-Object { $_.OnPremSynchronized -eq $true `
  -and $_.RoleAssignments.RoleDefinitionName -notcontains "Directory Synchronization Accounts" }
```

Privileged objects (e.g., groups or service principals) with privileges and delegations by ownership

```powershell
$EntraOpsData | Where-Object { $_.Owners -ne $null}
```

Privileged objects without restricted management by assigning role-assignable group membership, Entra ID role or RMAU membership
(excluding service principal which are not protected by those features)

```powershell
$EntraOpsData `
  | Where-Object {$_.RestrictedManagementByRAG -ne $True `
    -and $_.RestrictedManagementByAadRole -ne $True `
    -and $_.RestrictedManagementByRMAU -ne $True `
    -and $_.ObjectType -ne "serviceprincipal"}
```

Role Assignments by using eligible membership in "PIM for Groups" or nested group membership

```powershell
$EntraOpsData | Select-Object -ExpandProperty RoleAssignments `
 | Where-Object {$_.RoleAssignmentSubType -eq "Eligible member" -or $_.RoleAssignmentSubType -like "*Nested*"} `
 | sort-object RoleAssignmentSubType `
 | ft RoleAssignmentId, RoleAssignmentScopeName, RoleSystem, RoleAssignmentType, RoleAssignmentSubType, PIMAssignmentType, Transitive*
 ```

Role Assignments of privileges without using PIM capabilities (excluded service principals)

```powershell
$EntraOpsData | select-Object -ExpandProperty RoleAssignments `
 | Where-Object {$_.ObjectType -ne "serviceprincipal" -and $_.PIMAssignmentType -ne "Eligible"}
```

## Using EntraOps with GitHub

<a href="https://github.com/Cloud-Architekt/cloud-architekt.github.io/blob/master/assets/images/entraops/setup_1-ghconfig.gif" target="_blank"><img src="https://github.com/Cloud-Architekt/cloud-architekt.github.io/blob/master/assets/images/entraops/setup_1-ghconfig.gif" width="1000" /></a>

_All steps to use automated setup for configuring GitHub and Microsoft Entra Workload ID for EntraOps_
<br>

1. Create repository from this template
Choose private repository to keep data internal

2. Clone your new EntraOps repository to your client or use GitHub Codespace. Devcontainer is available to load the required dependencies.

3. Import EntraOps PowerShell Module in PowerShell Core

    ```powershell
    Import-Module ./EntraOps
    ```

4. Create a new EntraOps.config File and update the settings based on your parameters and use case
_Tip: Use `Connect-AzAccount -UseDeviceAuthentication` before executing `New-EntraOpsConfigFile` if you are using GitHub Codespaces or Cloud Shell to perform Device Authentication._

    ```powershell
    New-EntraOpsConfigFile -TenantName <TenantName>
    ```

5. Optional: Set up Log Analytics ingestion if you want to push classification data to a custom table.
   See the [Log Analytics Ingestion Setup](#log-analytics-ingestion-setup) section for step-by-step instructions on creating the workspace, custom table, DCE, DCR, and assigning the required RBAC roles. Use `PrivilegedEAM_CL` as the table name so the parser and workbooks function correctly.

    _Recommendation: There is a limitation of 10 KB for a single WatchList entry. This limit can be exceeded in the case of a high number of property items (e.g., classification or owner properties). Therefore, I can strongly recommend choosing "Custom tables" in a large environment. If you are choosing WatchList as ingestion option, keep an eye on the deployment logs for any warnings of this limitation. Entries will not be added if the limit has been exceeded._

6. Review and customize the EntraOps.config file based on your requirements.
   - `TenantId` and `TenantName` should be already updated based on the provided parameters to create the config file. `ClientId` will be automatically updated by running the cmdlet `New-EntraOpsWorkloadIdentity`.
   - The default scheduled time for running the pull workflow will be a also enabled (`PullScheduledTrigger`) and defined (`PullScheduledCron`) in the config file. By default, the workflow to ingest data will be triggered right after the pull has been completed (by default value of `PushAfterPullWorkflowTrigger`).
   - Automated updates for classification templates from AzurePrivilegedIAM repository (`AutomatedClassificationUpdate`) or Control Plane scope (`ApplyAutomatedControlPlaneScopeUpdate`) can also be enabled by parameters. Customization of classification updates or data source to identify Control Plane assets is also available from here.
   - Review the settings in the section `AutomatedEntraOpsUpdate` to configure an automated update of the EntraOps PowerShell module on demand or scheduled basis.
   - Enable and update the following parameters if you want to ingest classification data to Custom Tables in Microsoft Sentinel/Log Analytics Workspace (`IngestToLogAnalytics`) or Microsoft Sentinel WatchLists (`IngestToWatchLists`). You need to add the required parameters of the workspace and/or data collection endpoints.
     - Optional: Use parameter `WatchListTemplates` to define Microsoft Sentinel WatchList templates which should be updated based on EntraOps data. Use the value `All` to update VIP Users, High Value Assets and Identity Correlation watchlists.
     - Optional: Use parameter `WatchListWorkloadIdentity` to create and update WatchList Templates for Workload Identities which are required for EntraOps workbooks and enhanced enrichment in combination with EntraOps data. Use the value `All` or one of the following values to create the WatchLists for Workload Identities:
        - "ManagedIdentityAssignedResourceId" - List of resources with assigned Managed Identity
        - "WorkloadIdentityAttackPaths" - List of attack paths in Microsoft Defender for Cloud for service principals and managed identities
        - "WorkloadIdentityInfo" - List of service principals with detailed information for Workload Identity
        - "WorkloadIdentityRecommendations" - List of recommendations for Workload Identity in Microsoft Entra ID
   - Enable and configure `AutomatedConditionalAccessTargetGroups` if you like to create Security Groups for Conditional Access Policies automatically. Name of the Administrative Unit and scope can be customized by the properties in this section.
   - Creation and Management of Administrative Unit based on the selected EntraOps Tiering can be automated by using `AutomatedAdministrativeUnitManagement`. All supported objects (users and groups) will be added to the Administrative Unit. `RestrictedAuMode` allows to control if a RMAU will be created for RBAC Systems outside of Microsoft Entra which are not using role-assignable group usually.
   - All privileged users outside of existing protection by role-assignable group, existing (Restricted) Management Administrative Unit (RMAU) or role-assignable groups can be protected by the setting `AutomatedRmauAssignmentsForUnprotectedObjects`. All users or groups without restricted management will be added automatically to an RMAU for protection.
  
7. Create an application registration with required permissions (Global Admin role required and User Access Administrator). All necessary permissions on Microsoft Graph API permissions but also Azure RBAC roles for data collection and/or ingestion (if configured in `EntraOps.config`) will be added. Administrative Unit, based on the defined name in the config file (`AdminUnitName`) for Conditional Access Groups will be created to scoped delegation on Group Administrator if `ApplyConditionalAccessTargetGroups` has been enabled.

    ```powershell
    New-EntraOpsWorkloadIdentity -AppDisplayName entraops -CreateFederatedCredential -GitHubOrg "<YourGitHubUser/Org>" -GitHubRepo "<YourRepoName (e.g., EntraOps-Contoso)>" -FederatedEntityType "Branch" -FederatedEntityName "main"
    ```

8. Update GitHub workflow definition based on the definitions in EntraOps.config

    ```powershell
    Update-EntraOpsRequiredWorkflowParameters
    ```

  ## Using EntraOps with Azure DevOps

  EntraOps also ships Azure Pipelines for collection, push operations, reporting, Tenant Governance
  snapshots, repository updates, and CI validation. They use an Azure Resource Manager service
  connection with workload identity federation and read operational settings directly from
  `EntraOpsConfig.json`. Apply YAML schedules with the public module command:

  ```powershell
  Import-Module ./EntraOps
  Update-EntraOpsAzureDevOpsSchedules -ConfigFile ./EntraOpsConfig.json -BranchName main
  ```

  Use the [Get Started guide](./Docs/get-started/index.html?guide=expert#deploy-with-azure-devops) for
  the integrated service-connection setup, pipeline import, repository permissions, cross-tenant
  guidance, reporting behavior, troubleshooting, and GitHub/Azure DevOps comparison.

## Log Analytics Ingestion Setup

If you want to ingest EntraOps classification data into a Microsoft Sentinel or Log Analytics Workspace custom table, you must provision several Azure resources and assign the correct RBAC roles before running the pipeline.

### Overview of Components

| Component                                | Purpose                                                                                 |
| ---------------------------------------- | --------------------------------------------------------------------------------------- |
| **Log Analytics Workspace (LAW)**        | Destination workspace where the custom table resides.                                   |
| **Custom Table (`PrivilegedEAM_CL`)**    | Stores the ingested EntraOps JSON records.                                              |
| **Data Collection Endpoint (DCE)**       | Public endpoint that receives the logs over HTTPS.                                      |
| **Data Collection Rule (DCR)**           | Defines the data flow, schema mapping, and transformation from DCE to the custom table. |
| **Service Principal / Managed Identity** | Authenticates to the DCE and is authorized via Azure RBAC.                              |

### Step 1: Create the Log Analytics Workspace

If you do not already have a workspace:

```powershell
$RGName      = "<Your-ResourceGroup-Name>"
$Location    = "<Your-Azure-Region>"
$WorkspaceName = "<Your-Workspace-Name>"

New-AzResourceGroup -Name $RGName -Location $Location -ErrorAction SilentlyContinue
New-AzOperationalInsightsWorkspace `
  -ResourceGroupName $RGName `
  -Name $WorkspaceName `
  -Location $Location
```

> **Note:** The workspace and the DCR do not need to be in the same resource group, but keeping them together simplifies RBAC management.

### Step 2: Create the Custom Table

EntraOps expects a custom log table named `PrivilegedEAM_CL` (the `_CL` suffix is added automatically by Azure Monitor).

**Option A: Use sample data (recommended for first-time setup)**
1. Run EntraOps interactively to generate sample JSON:
   ```powershell
   Save-EntraOpsPrivilegedEAMJson -RbacSystems @("EntraID")
   ```
2. Use the generated `./PrivilegedEAM/EntraID/User/*.json` files as sample input when creating the DCR. This ensures the schema is inferred correctly from real data.

**Option B: Deploy via ARM/Bicep**
Create a custom table via ARM template or Bicep with columns matching the EntraOps JSON schema. The minimum expected columns include:
- `TimeGenerated` (datetime) — added automatically by the ingestion API
- `ObjectId`, `ObjectType`, `ObjectDisplayName`, `RoleSystem`, `Classification`, `RoleAssignments`, `Owners`, etc. (inferred from JSON)

### Step 3: Create the Data Collection Endpoint (DCE)

```powershell
$DceName = "<Your-DCE-Name>"

New-AzResourceGroupDeployment `
  -Name "EntraOps-DCE" `
  -ResourceGroupName $RGName `
  -TemplateFile "<path-to-dce-arm-template>.json" `
  -dceName $DceName `
  -location $Location
```

Or via Azure CLI:
```bash
az monitor data-collection endpoint create \
  --name "<Your-DCE-Name>" \
  --resource-group "<Your-RG>" \
  --location "<Your-Region>"
```

The DCE exposes a logs ingestion endpoint (e.g., `https://<dce-name>-<region>.ingest.monitor.azure.com`).

### Step 4: Create the Data Collection Rule (DCR)

The DCR must:
1. Reference the DCE created in Step 3.
2. Define a data flow with **Output Stream** = `Custom-PrivilegedEAM_CL`.
3. Map the incoming JSON schema to the custom table columns.

Example ARM template snippet for the DCR data flow:
```json
"dataFlows": [
  {
    "streams": ["Custom-PrivilegedEAM_CL"],
    "destinations": ["<Your-LAW-Name>"]
  }
]
```

> **Important:** The `outputStream` in the DCR must exactly match `Custom-PrivilegedEAM_CL`. EntraOps validates this match at runtime. If the stream name differs, ingestion will fail with the error:  
> `Custom table <TableName> does not match with data flow in data collection rule <DCRName>!`

### Step 5: Assign Required RBAC Roles

The service principal or managed identity used by EntraOps needs the following Azure RBAC assignments:

| Role                                            | Scope                                                                                        | Why it is needed                                                                                                                                                                                    |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Monitoring Metrics Publisher**                | Resource Group containing the DCR                                                            | Required by the [Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview) to write data to the DCR.                                              |
| **Reader**                                      | Resource Group containing the DCR                                                            | Required to read DCR and DCE metadata (endpoint URI, immutableId) via Azure Resource Manager.                                                                                                       |
| *(Optional)* **Microsoft Sentinel Contributor** | Resource Group containing the Sentinel workspace                                             | Only required if ingesting to Sentinel WatchLists (`IngestToWatchLists`).                                                                                                                           |
| *(Optional)* **Reader**                         | Tenant Root Management Group (`/providers/Microsoft.Management/managementGroups/<TenantId>`) | Only required if using Azure Resource Graph for Control Plane scope updates or certain WatchLists (e.g., High Value Assets, Workload Identity Attack Paths, Managed Identity Assigned Resource Id). |

> **Note:** `Log Analytics Contributor` on the resource group is **not sufficient** for the Logs Ingestion API. You must assign `Monitoring Metrics Publisher` directly on the DCR scope (or its resource group).

#### PowerShell example

```powershell
$SpObjectId = "<Service-Principal-ObjectId>"
$DcrRG      = "<DCR-ResourceGroup-Name>"
$DcrSub     = "<DCR-Subscription-Id>"

Set-AzContext -SubscriptionId $DcrSub

New-AzRoleAssignment `
  -ObjectId $SpObjectId `
  -RoleDefinitionName "Monitoring Metrics Publisher" `
  -ResourceGroupName $DcrRG

New-AzRoleAssignment `
  -ObjectId $SpObjectId `
  -RoleDefinitionName "Reader" `
  -ResourceGroupName $DcrRG
```

#### Automated assignment via EntraOps cmdlet

Alternatively, populate the `LogAnalytics` section in `EntraOpsConfig.json` first, then run:

```powershell
New-EntraOpsWorkloadIdentity `
  -AppDisplayName "EntraOps" `
  -ConfigFile ./EntraOpsConfig.json
```

The cmdlet will automatically assign `Monitoring Metrics Publisher` and `Reader` on the DCR resource group, plus any additional roles required by other enabled features (Sentinel WatchLists, Resource Graph, etc.).

### Step 6: Configure EntraOpsConfig.json

Update the `LogAnalytics` section in your config file:

```json
{
  "LogAnalytics": {
    "IngestToLogAnalytics": true,
    "DataCollectionRuleName": "<Your-DCR-Name>",
    "DataCollectionRuleSubscriptionId": "<Your-Subscription-Id>",
    "DataCollectionResourceGroupName": "<Your-RG-Name>",
    "TableName": "PrivilegedEAM_CL"
  }
}
```

After updating the config, run `New-EntraOpsWorkloadIdentity` (if not already done) to apply RBAC roles, then commit `EntraOpsConfig.json` to your repository.

### Ingestion Behavior and Limits

- **Chunking:** Data is automatically split into chunks of approximately 950 KB to stay under the 1 MB per-request limit enforced by the Logs Ingestion API.
- **Batching:** JSON files are processed in batches of 50 to avoid exceeding DCR file size limits.
- **Transformation:** If you need to transform or filter data before ingestion, configure a [transformation rule](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-transformations) on the DCR.
- **No Microsoft Graph access required for push:** The `azure-pipelines-push.yml` pipeline (and the equivalent GitHub `Push-EntraOpsPrivilegedEAM` workflow) only requires Azure PowerShell context to read local JSON and send it to the DCE. It does not call Microsoft Graph.

## EntraOps Integration in Microsoft Sentinel

### Parser for Custom Tables and WatchLists

I have built a parser which ensures a standardized schema for EntraOps data across the various ingestion options.
This allows you to use the same queries and workbooks, regardless of whether you have used WatchLists or Custom Table.

Deploy the according parser for your ingestion option.
_Recommendation: Choose the parser for "Custom table" if you have enabled ingestion to both targets._

**Parser for Custom Table (Log Analytics/Sentinel Workspace)**

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCloud-Architekt%2FEntraOps%2Fmain%2FParsers%2FPrivilegedEAM_CustomTable.json)

**Parser for Microsoft Sentinel Watchlists**
  
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCloud-Architekt%2FEntraOps%2Fmain%2FParsers%2FPrivilegedEAM_WatchLists.json)

### Examples to use EntraOps data in Unified SecOps Platform (Sentinel and XDR)

**Devices in Exposure Management with authentication from Control Plane users**

```kusto
let ClassifiedTier0User = PrivilegedEAM
                | where Classification contains "ControlPlane"
                | where ObjectType == "user"
                | summarize arg_max(TimeGenerated, *) by ObjectId
                | project tostring(ObjectId), tostring(ObjectAdminTierLevel);
let Tier0Nodes = ExposureGraphNodes
                | where NodeLabel == "user"
                | mv-expand parse_json(EntityIds)
                | where parse_json(EntityIds).type == "AadObjectId"
                | extend NodeId = tostring(NodeId)
                | extend AadObjectId = tostring(parse_json(EntityIds).id)
                | extend TenantId = extract("tenantid=([\\w-]+)", 1, AadObjectId)
                | extend ObjectId = tostring(extract("objectid=([\\w-]+)", 1, AadObjectId))
                | where ObjectId in (ClassifiedTier0User);
let SensitiveRelation = dynamic(["can authenticate as","has credentials of","can authenticate as", "frequently logged in by"]);                
ExposureGraphEdges
| where TargetNodeId in (Tier0Nodes) and EdgeLabel in (SensitiveRelation)
| where SourceNodeLabel == "device"
// Get details of devices
| join kind = inner ( ExposureGraphNodes ) on $left.SourceNodeId == $right.NodeId
// Get ObjectId of Target (Tier0) Nodes
| join kind = inner ( Tier0Nodes ) on $left.TargetNodeId == $right.NodeId
| mv-expand parse_json(NodeProperties)
| summarize make_list(EdgeLabel) by SourceNodeName, SourceNodeLabel, tostring(SourceNodeCategories), TargetNodeId, TargetNodeName, TargetNodeLabel, tostring(TargetNodeCategories),
    VulnerableToPrivilegeEscalation = tostring(parse_json(tostring(parse_json(tostring(NodeProperties.rawData)).highRiskVulnerabilityInsights)).vulnerableToPrivilegeEscalation),
    MdeExpsoureScore = tostring(parse_json(NodeProperties).rawData.exposureScore),
    MdeRiskScore = tostring(parse_json(NodeProperties).rawData.riskScore),
    MdeSensorHealth = tostring(parse_json(NodeProperties).rawData.sensorHealthState),
    MdeMachineGroup = tostring(parse_json(NodeProperties).rawData.machineGroup)
```

**Resources with access or authentication to classified privileges in EntraOps**

```kusto
let SensitiveRelation = dynamic(["can authenticate as","has credentials of","affecting", "can authenticate as", "frequently logged in by"]);
let ClassifiedTier0Assets = PrivilegedEAM
                | summarize arg_max(TimeGenerated, *) by tostring(ObjectId);
let Tier0Nodes = ExposureGraphNodes
                | mv-expand parse_json(EntityIds)
                | where parse_json(EntityIds).type == "AadObjectId"
                | extend NodeId = tostring(NodeId)
                | extend AadObjectId = tostring(parse_json(EntityIds).id)
                | extend TenantId = extract("tenantid=([\\w-]+)", 1, AadObjectId)
                | extend ObjectId = extract("objectid=([\\w-]+)", 1, AadObjectId)
                | where ObjectId in (ClassifiedTier0Assets);
let ExposedEdges = ExposureGraphEdges
            | where EdgeLabel in (SensitiveRelation)
            | extend TargetNodeId = tostring(TargetNodeId)
            | join kind=inner ( Tier0Nodes ) on $left.TargetNodeId == $right.NodeId;
ClassifiedTier0Assets
| join kind=inner ( ExposedEdges ) on ObjectId
| project Type2, SourceNodeName, SourceNodeLabel, SourceNodeCategories, EdgeLabel, TargetNodeId, TargetNodeLabel, TargetNodeCategories, Classification, RoleAssignments, Categories
```

### Workbook for visualization of EntraOps classification data

The following workbooks can be used to visualize users, workload identities, groups, and their classified role assignments. They allow filtering for hybrid/cloud users and specific tiered administration levels.

#### Prerequisites

Before deploying the workbooks, ensure the following are in place:

1. **EntraOps data has been ingested** to either:
   - A **Custom Table** in your Microsoft Sentinel/Log Analytics Workspace, **or**
   - **Microsoft Sentinel WatchLists**
2. The **associated Parser** has been deployed to your workspace (see [Parser for Custom Tables and WatchLists](#parser-for-custom-tables-and-watchlists)).
3. You have **Contributor** or equivalent permissions on the target resource group where the workbooks will be deployed.

#### Deployment Steps

**Option A: Deploy via Azure Portal (One-Click)**

1. Click the **Deploy to Azure** button for the desired workbook below.
2. In the Azure Portal, select your **Subscription** and the **Resource Group** where your Sentinel/Log Analytics workspace resides.
3. Review the parameters. The default values are environment-agnostic; update the `workbookDisplayName` if desired.
4. Click **Review + create**, then **Create**.
5. After deployment, open the workbook in Azure Monitor / Microsoft Sentinel. On first open, select your Log Analytics workspace from the **Select Workspace** dropdown.

**Option B: Deploy via Azure CLI / PowerShell**

Use the ARM template files directly for automated or scripted deployment:

```powershell
# Define environment-specific variables
$SubscriptionId     = "<Your-Subscription-Id>"
$ResourceGroupName  = "<Your-Resource-Group-Name>"
$WorkbookName       = "EntraOps Privileged EAM - Overview"
$TemplateFile       = "./Workbooks/EntraOps Privileged EAM - Overview.json"

# Set context
Set-AzContext -SubscriptionId $SubscriptionId

# Deploy workbook
New-AzResourceGroupDeployment `
  -Name "EntraOpsWorkbook-Overview" `
  -ResourceGroupName $ResourceGroupName `
  -TemplateFile $TemplateFile `
  -workbookDisplayName $WorkbookName
```

#### Available Workbooks

| Workbook                                          | Description                                                                                | Deploy                                                                                                                                                                                                                                                                   |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **EntraOps Privileged EAM - Overview**            | Primary dashboard for classified role assignments across all RBAC systems.                 | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCloud-Architekt%2FEntraOps%2Fmain%2FWorkbooks%2FEntraOps%20Privileged%20EAM%20-%20Overview.json)              |
| **EntraOps Privileged EAM - Agent Identities**    | Insights into Agent Identities and inherited permissions through blueprint principals.     | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCloud-Architekt%2FEntraOps%2Fmain%2FWorkbooks%2FEntraOps%20Privileged%20EAM%20-%20Agent%20Identities.json)    |
| **EntraOps Privileged EAM - Workload Identities** | Deep-dive into workload identities, managed identities, attack paths, and recommendations. | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCloud-Architekt%2FEntraOps%2Fmain%2FWorkbooks%2FEntraOps%20Privileged%20EAM%20-%20Workload%20Identities.json) |

#### Post-Deployment Configuration

- **Workspace Selection**: Each workbook requires selecting the target Log Analytics workspace on first use. The dropdown queries available workspaces via Azure Resource Graph.
- **Parameter Defaults**: If you are deploying multiple workbooks to the same workspace, consider saving a copy of the workbook with the workspace pre-selected to streamline access for your team.
- **Permissions**: Ensure the users accessing the workbooks have `Microsoft.OperationalInsights/workspaces/read` and `Microsoft.Insights/workbooks/read` on the target scope.

## EntraOps Integration to Attack Path Management

### BloodHound Integration

EntraOps can export its Privileged EAM classification data as a [BloodHound OpenGraph](https://bloodhound.specterops.io/opengraph/overview) JSON payload, enriching an existing AzureHound-ingested tenant graph with EntraOps node types and tier classifications. This makes Enterprise Access Model tier-boundary violations — including cloud-managed PAW paths — demoable as attack paths directly in BloodHound CE or Enterprise.

The exporter is modeled as an AzureHound enrichment layer. It reuses AzureHound-compatible node and edge kinds for principals, devices, service principals, groups, and Entra ID role definitions, while adding `EO_`-prefixed kinds for EntraOps-owned context: concrete role assignments, assignment scope, classification evidence, PAW relationships, sponsor links, identity parent links, and Intune device permissions.

**Key cmdlets:**

- `Export-EntraOpsPrivilegedEAMBloodHound` — converts per-RBAC-system EAM export files (produced by `Save-EntraOpsPrivilegedEAMJson`) into a BloodHound-compatible OpenGraph JSON file, ready for upload alongside the custom extension schema.
- `Save-EntraOpsPrivilegedEAMJson` / `Update-EntraOpsClassificationControlPlaneScope` — must run first to generate classified EAM JSON. The scope update step also writes `DeviceManagement_ScopeGroupDeviceMembers.json`, which the exporter uses to build traversable `EO_IntuneRolePermission` edges from Intune role assignments to concrete `AZDevice` nodes.

**Graph model highlights:**

- Entra ID, Intune, Identity Governance, Defender, and App Role assignments are all represented as first-class `EO_*RoleAssignment` nodes, preserving scope, PIM state, and classification evidence without replacing native AzureHound paths.
- For DeviceManagement, `EO_IntuneRolePermission` edges connect role assignments and their principals to scoped `AZDevice` nodes when matched Intune actions indicate device-impacting capability, making PAW tier-boundary paths visible and traversable.
- Classification decisions are linked via `EO_ClassifiedViaObject` edges, showing exactly which object drove an Enterprise Access Model tier assignment.

For detailed setup steps, schema documentation, Cypher query examples, and privilege zone rules see the [BloodHound Integration README](./Integrations/BloodHound/README.md).

## Tenant Governance Relationship Support

EntraOps supports collecting and classifying privileged access across tenants that are part of a cross-tenant delegated admin relationship in Tenant Governance. EntraOps can enumerate the governance relationships and resolve privileged object identities from the governed tenants, mapping each principal back to its source tenant via `ObjectTenantId`.

Tenant governance relationships are fetched via the Microsoft Graph beta endpoint and resolved using cross-tenant object resolution during classification.

### Configuring EntraOps for Tenant Governance Relationships

Add the following parameters to your `EntraOps.config` file to enable tenant governance support:

```json
{
  "ManagingTenantId": "<ObjectId of the managing/governing tenant>",
  "ManagingTenantName": "<Tenant name of the managing/governing tenant, e.g. contoso.onmicrosoft.com>"
}
```

| Parameter            | Description                                                                                              |
| -------------------- | -------------------------------------------------------------------------------------------------------- |
| `ManagingTenantId`   | The tenant ID of the governing (managing) tenant — the one that holds the delegated admin relationships. |
| `ManagingTenantName` | The display name or `.onmicrosoft.com` domain of the managing tenant.                                    |

When configured, EntraOps sets `$Global:ManagingTenantIdContext` at connect time and uses it to scope cross-tenant object resolution during classification runs.

### Authentication Recommendations for Tenant Governance

Using a **service principal** (multi-tenant application) is strongly recommended when collecting data across governed and governing tenants:

- **Governing tenant**: Register an app with federated identity credential in the managing tenant and grant the required Microsoft Graph application permissions. The service principal is used to authenticate against the managing tenant and enumerate all governance relationships.
- **Governed tenants**: Consent the multitenant application in the governed tenant to allow EntraOps to resolve object identities and fetch role assignments across tenants. This can be done by consenting the app in the tenant or by granting the application with required permissions in the policy configuration of tenant governance relationship in the managing tenant.
- **Avoid interactive / user-based authentication** in automated or multitenant scenarios: interactive sessions typically only cover a single tenant and cannot be silently re-used across tenant boundaries.

## Classify privileged objects by Custom Security Attributes

You might want to classify privileged users on the target Enterprise Access Level and relation to user/device. By default, the following custom security attributes will be used to identify what is the purposed tiered level of the user or workload identity.

- `privilegedUser`
- `privilegedWorkloadIdentity`

These attributes should be already set by the provisioning process. Check out the following blog posts to learn more about the integration:

- [Automated Lifecycle Workflows for Privileged Identities with Azure AD Identity Governance](https://www.cloud-architekt.net/manage-privileged-identities-with-azuread-identity-governance/)
- [Microsoft Entra Workload ID - Lifecycle Management and Operational Monitoring](https://www.cloud-architekt.net/entra-workload-id-lifecycle-management-monitoring/)

The purposed tiered level of a user or workload identity will be visible as attribute `ObjectAdminTierLevel` and `ObjectAdminTierLevelName` in the EntraOps data of the user principal.

In addition, custom security attributes will be also used to build a correlation between the privileged user and the associated PAW device and regular work account.

- `associatedSecureAdminWorkstation`
- `associatedWorkAccount`

Permissions to read the custom security attributes needs to be granted manually to the service principal which will be used by EntraOps.

## Classification of Identity Governance delegation and roles

Microsoft Entra Identity Governance allows to [delegate and grant roles](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-delegate) on catalog-level. There are two methods of classification of those delegations in EntraOps.

- TaggedBy "`JSONwithAction`": Define the classification by scope and role in the classification template file [Classification_IdentityGovernance.json](./Classification/Templates/Classification_IdentityGovernance.json) manually. The schema is like the other classification templates and offers flexible tagging for your classification of Tiered Administration Level and Service.
- TaggedBy "`AssignedCatalogObjects`": EntraOps is collecting the classification data of assigned resources in a catalog and applies the classification to the scope of the delegated role. This needs no further manual tagging and ensures that privileged or role-assignable groups will be identified in access packages and catalogs. Any delegation to this scope will get the `TierLevelDefinition` of the assigned resource.

Example of Identity Governance role which has been classified by tagging of classification template file (JSON) and assigned objects:

```json
"RoleAssignments": [
      {
        "RoleAssignmentId": "58c673ff-dc05-4038-9a59-826e777289c2",
        "RoleAssignmentScopeId": "/AccessPackageCatalog/5279fb65-7ccf-460b-8893-75087b855588",
        "RoleAssignmentScopeName": "Privileged Access - Helpdesk Delegation to change passwords of admins",
        "RoleAssignmentType": "Direct",
        "RoleAssignmentSubType": "",
        "PIMManagedRole": false,
        "PIMAssignmentType": "Permanent",
        "RoleDefinitionName": "Catalog owner",
        "RoleDefinitionId": "ae79f266-94d4-4dab-b730-feca7e132178",
        "RoleType": "BuiltIn",
        "RoleIsPrivileged": null,
        "ObjectId": "f742b7a6-d2b6-497d-9443-215505d5998a",
        "ObjectType": "user",
        "TransitiveByObjectId": "",
        "TransitiveByObjectDisplayName": "",
        "Classification": [
          {
            "AdminTierLevel": "0",
            "AdminTierLevelName": "ControlPlane",
            "Service": "Entitlement Management",
            "TaggedBy": "JSONwithAction"
          },
          {
            "AdminTierLevel": "0",
            "AdminTierLevelName": "ControlPlane",
            "Service": "Privileged User Management",
            "TaggedBy": "AssignedCatalogObjects"
          }
        ]
      }
  ]
```

### Identify delegated management with different classifications

The following PowerShell query helps to identify delegated roles on catalogs to an user which owns not the same classification as the assigned resources. For example, regular user has access as "Catalog owner" which includes resources of role-assignable groups with Entra ID role assignments.

```powershell
$ElmCatalogAssignments = $EntraOpsData | where-object {$_.RoleSystem -eq "IdentityGovernance"} `
                            | Select-Object -ExpandProperty RoleAssignments `
                            | Where-Object {$_.Classification.TaggedBy -contains "AssignedCatalogObjects"}
foreach($ElmCatalogAssignment in $ElmCatalogAssignments){
    $PrincipalClassification = $EntraOpsData | Where-Object {$_.ObjectId -eq $ElmCatalogAssignment.ObjectId} `
                                | Where-Object {$_.RoleSystem -ne "IdentityGovernance"} `
                                | Select-Object -ExpandProperty RoleAssignments `
                                | Select-Object -ExpandProperty Classification `
                                | Select-Object -Unique AdminTierLevelName, Service `
                                | Sort-Object -Property AdminTierLevelName, Service
    if ($null -eq $PrincipalClassification) {
        Write-Warning "No Principal Classification found for $($ElmCatalogAssignment.ObjectId)"
        $PrincipalClassification = @(
            [PSCustomObject]@{
                AdminTierLevelName = "User Access"
                Service = "No Classification"
            }
        )
    }
    $ElmCatalogClassification = $ElmCatalogAssignment | Select-Object -ExpandProperty Classification `
                                | Where-Object {$_.TaggedBy -eq "AssignedCatalogObjects"} `
                                | Select-Object -Unique AdminTierLevelName, Service `
                                | Sort-Object -Property AdminTierLevelName, Service                              

    $Differences = Compare-Object -ReferenceObject ($ElmCatalogClassification) `
    -DifferenceObject ($PrincipalClassification) -Property AdminTierLevelName, Service `
    | Where-Object {$_.SideIndicator -eq "<="} | Select-Object * -ExcludeProperty SideIndicator
    if ($null -ne $Differences) {
        try {
            $Principal = Get-EntraOpsEntraObject -AadObjectId $ElmCatalogAssignment.ObjectId    
        }
        catch {
            $Principal = [PSCustomObject]@{
                ObjectDisplayName = "Unknown"
                ObjectType = "Unknown"
            }
        }
    }
    if ($Differences) {
        $Differences | ForEach-Object {
                [PSCustomObject]@{
                    "PrincipalName" = $Principal.ObjectDisplayName
                    "PrincipalType" = $Principal.ObjectType
                    "RoleAssignmentId" = $ElmCatalogAssignment.RoleAssignmentId
                    "RoleAssignmentScopeId"  = $ElmCatalogAssignment.RoleAssignmentScopeId
                    "RoleAssignmentScopeName"  = $ElmCatalogAssignment.RoleAssignmentScopeName
                    "AdminTierLevelName" = $_.AdminTierLevelName
                    "Service" = $_.Service
                }
        }
    }
}
```

## Automatic updated Control Plane Scope by EntraOps and other data sources

EntraOps offers an optional feature (`ApplyAutomatedControlPlaneScopeUpdate`) to identify high-sensitive privileged assignments by other sources and adjustment of Control Plane scope based on using restricted management.

<a href="https://github.com/Cloud-Architekt/cloud-architekt.github.io/blob/master/assets/images/entraops/setup_2-cpupdate.gif" target="_blank"><img src="https://github.com/Cloud-Architekt/cloud-architekt.github.io/blob/master/assets/images/entraops/setup_2-cpupdate.gif"/></a>

Let's have a few examples about use cases and benefits of using the feature in combination with the supported data sources:

### Azure Resource Graph

Included "PrivilegedRolesFromAzGraph" in the property "PrivilegedObjectClassificationSource" of the EntraOps.config file allows to gather privileged role assignments from the Azure Resource Graph. The property "AzureHighPrivilegedRoles" and "AzureHighPrivilegedScopes" allows you to define which Azure RBAC Roles and Scope will be considered as Control Plane scope. Every delegation with a scoped role assignment in Entra ID to the principal (Azure RBAC role member) will be identified as Control Plane. For example, Group Administrator of the Entra ID security group which has been assigned to the "Owner" role on the Tenant Root Group. The following Resource Graph query will be used (parameter "%AzureHighPrivilegedRoles%" and the Scope will be replaced by the value in the EntraOps.config file)

```kusto
AuthorizationResources
| where type =~ "microsoft.authorization/roleassignments"
| extend principalType = tostring(properties["principalType"])
| extend principalId = tostring(properties["principalId"])
| extend roleDefinitionId = tolower(tostring(properties["roleDefinitionId"]))
| extend scope = tolower(tostring(properties["scope"]))
| where isnotempty(scope)
| join kind=inner ( AuthorizationResources
| where type =~ "microsoft.authorization/roledefinitions"
| extend roleDefinitionId = tolower(id)
| extend Scope = tolower(properties.assignableScopes)
| extend RoleName = (properties.roleName)
| where RoleName in (%AzureHighPrivilegedRoles%)
) on roleDefinitionId
| distinct principalId, principalType
```

### Microsoft Security Exposure Management

Critical assets defined in Microsoft Security Exposure Management (XSPM) can be integrated by using the value "PrivilegedEdgesFromExposureManagement" in the property "PrivilegedObjectClassificationSource". You can also filter by using "ExposureCriticalityLevel" which "tier" classification in the XSPM critical asset management will be included. The following hunting query will be used to identify high-privileged nodes (parameter "%CriticalLevel%" will be replaced by the value in the EntraOps.config file):

```kusto
let Tier0CloudResources = ExposureGraphNodes
    | where isnotnull(NodeProperties.rawData.criticalityLevel) and (NodeProperties.rawData.criticalityLevel.criticalityLevel %CriticalLevel%) and (NodeProperties.rawData.environmentName == "Azure");
let Tier0EntraObjects = ExposureGraphNodes
    | where isnotnull(NodeProperties.rawData.criticalityLevel) and (NodeProperties.rawData.criticalityLevel.criticalityLevel %CriticalLevel%) and (NodeProperties.rawData.primaryProvider == "AzureActiveDirectory");
let Tier0Devices = ExposureGraphNodes
    | where isnotnull(NodeProperties.rawData.criticalityLevel) and (NodeProperties.rawData.criticalityLevel.criticalityLevel %CriticalLevel%) and (NodeLabel == "device") and (NodeProperties.rawData.isAzureADJoined == true);
let Tier0Assets = union Tier0EntraObjects, Tier0Devices, Tier0CloudResources | project NodeId;
let SensitiveRelation = dynamic(["has permissions to","can authenticate as","has role on","has credentials of","affecting", "can authenticate as", "Member of", "frequently logged in by"]);
// Devices are not supported yet, no AadObject Id available in ExposureGraphNodes, DeviceInfo shows only AadDeviceId
let FilteredNodes = dynamic(["user","group","serviceprincipal","managedidentity","device"]);
ExposureGraphEdges
| where EdgeLabel in (SensitiveRelation) and (TargetNodeId in (Tier0Assets) or SourceNodeId in (Tier0Assets)) and SourceNodeLabel in (FilteredNodes)
| join kind=leftouter ( ExposureGraphNodes
    | mv-expand parse_json(EntityIds)
    | where parse_json(EntityIds).type == "AadObjectId"
    | extend AadObjectId = tostring(parse_json(EntityIds).id)
    | extend TenantId = extract("tenantid=([\\w-]+)", 1, AadObjectId)
    | extend ObjectId = extract("objectid=([\\w-]+)", 1, AadObjectId)
    | project ObjectDisplayName = NodeName, ObjectType = NodeLabel, ObjectId, NodeId) on $left.SourceNodeId == $right.NodeId
| where isnotempty(ObjectId)
| summarize make_set(EdgeLabel), make_set(TargetNodeName) by ObjectDisplayName, SourceNodeName, ObjectType, ObjectId, NodeId
```

As already described, any Entra ID role assignment on scope of the critical assets in XSPM will be classified as Control Plane.

### Adjusted Control Plane Scope by using Restricted Management and Role Assignments

There are a couple of integrated protection capabilities for privileged assets in Entra ID to avoid management from lower privileged roles.
For example, Restricted Management AUs to protect sensitive security groups from membership changes by Group Administrators or reset passwords of users with Entra ID roles by Helpdesk administrators. EntraOps identifies if the objects are protected by these features or only scoped delegations (excluding privileged assets) have been assigned. In this case, the scope of Control Plane will be automatically updated and customized on your environment. For example: Group Administrator on directory level are not classified as "Control Plane" if all privileged groups with assignments on Control Plane privileges are protected by RMAU or using role-assignable groups.

## Why was this classification chosen for the role?

Do you like to know which role action is why "Global Reader" has been classified as "Control Plane"? What is the definition of Microsoft's `isPrivileged` classification on the related role action? [AzEntraIdRoleActionsAdvertizer](https://www.azadvertizer.net/azEntraIdRoleActionsAdvertizer.html) and [AzEntraApiPermissionsAdvertizer](https://www.azadvertizer.net/azEntraIdAPIpermissionsAdvertizer.html) allows to have a visualized view which role or API permission is assigned to a role and what is the specific Administration Tier Level in EntraOps.

_Enter the role definition name in the "used by Roles" and choose the desired tier level in "EntraOps TierLevel" to filter for the associated role action. In this case, read BitLocker keys are classified as "Control Plane" in EntraOps and also flagged as "isPrivileged" by Microsoft._
<br>
<a href="https://cloud-architekt.github.io/assets/images/entraops/AzAdvertizer_IdentifyTierLevel.png" target="_blank"><img src="https://cloud-architekt.github.io/assets/images/entraops/AzAdvertizer_IdentifyTierLevel.png" width="1000" /></a>
<br>

## Update EntraOps PowerShell Module and CI/CD

EntraOps can be updated without losing classification definition and files by using the cmdlet `Update-EntraOps`.
The cmdlet can be executed interactively, and changes must be pushed to your repository. This command updates the PowerShell module, workflow files, repository resources (incl. workbooks and parsers) and parameters in workflows based on "EntraOps.config" file.

The GitHub `Update-EntraOps` workflow and Azure DevOps `azure-pipelines-update` pipeline can run on
demand or on the schedule defined in `EntraOpsConfig.json`. GitHub defaults to publishing updates
through a pull request; Azure DevOps uses direct push. Updating GitHub workflow definitions requires
the separately configured publisher GitHub App, while Azure DevOps pipeline definitions are included
in its default update targets.

Regardless of the way to update EntraOps files, it could be required to update the EntraOps.config file and service principals of EntraOps to take benefit of new features. Create a new EntraOps.config file or add manually the named properties in the description of the feature. Use `New-EntraOpsWorkloadIdentity` in combination of the parameter `-ExistingSpObjectId` and the object ID of the EntraOps service principal (Example: `New-EntraOpsWorkloadIdentity -AppDisplayName "EntraOps-CloudLab" -ExistingSpObjectId eca9154b-0d2a-4609-aa41-064eb317bfb3`). Ignore errors regarding existing API permissions or conflicts with existing roles.

After changing automation settings, run `Update-EntraOpsRequiredWorkflowParameters` for GitHub or
`Update-EntraOpsAzureDevOpsSchedules` for Azure DevOps, then commit the resulting definition changes.

I recommend to remove and create a service principal but also re-create the EntraOps.config file if there should be any issues by updating EntraOps.

## Changelog

Added features, changes or bug fixes can be found in the [GitHub issues](https://github.com/Cloud-Architekt/EntraOps/issues) of the repository or in the [changelog](./CHANGELOG.md).

## Project Policies and License

EntraOps is a community project, provided as-is without warranties. It does not include a support
commitment, service-level agreement, guaranteed response time, or guaranteed remediation schedule.
Community contributions, issue reports, and feature requests are welcome through GitHub Issues.

- [LICENSE](./LICENSE) - MIT license, including the full warranty disclaimer and limitation of liability.
- [SECURITY.md](./SECURITY.md) - responsible vulnerability reporting instructions.
- [SUPPORT.md](./SUPPORT.md) - community support boundaries and security-reporting route.
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) - respectful and constructive community participation standards.
- [PRIVACY.md](./PRIVACY.md) - operator-controlled tenant-data handling and sharing guidance.
- [TRADEMARKS.md](./TRADEMARKS.md) - third-party trademark and non-affiliation notice.
- [THIRD-PARTY-NOTICES.md](./THIRD-PARTY-NOTICES.md) - index of notices for vendored report dependencies.
- [CONTRIBUTING.md](./CONTRIBUTING.md) - contribution and inbound-license terms.

### Managed Service or Commercial Use Notice

EntraOps is licensed under the MIT License. The MIT License permits the use, modification, distribution, and commercial use of EntraOps, including use in managed or hosted service offerings.

If you are considering offering EntraOps, or a substantially modified version of EntraOps, as a managed service, SaaS, MSP, service-bureau, or other recurring service to third parties, we kindly ask that you contact the EntraOps maintainers in advance.

We would appreciate the opportunity to discuss your use case, understand how EntraOps is being used, and explore potential collaboration, support or partnership.