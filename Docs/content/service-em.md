# Service EM

**Developed in collaboration with Michael Soule**

## Introduction

ServiceEM is a submodule of EntraOps that automates the provisioning and management of tiered, service-scoped landing zones aligned with Microsoft's Enterprise Access Model. It provides a complete solution for delegated administration with least-privilege access across Azure and Entra ID.

ServiceEM creates and manages:
- **Azure Resource Groups** with tier-specific RBAC assignments
- **Entra ID Security Groups** (role-assignable) for each service and tier
- **PIM for Groups** (opt-in) for the admin groups with configurable authentication contexts
- **Entra ID Governance Access Packages** for self-service membership
- **Constrained Delegation** using Azure ABAC conditions to limit role assignment capabilities

### Key Benefits

- **Automated Tier Enforcement**: Implements ControlPlane, ManagementPlane, and WorkloadPlane separation automatically
- **Least-Privilege Delegation**: ABAC conditions prevent escalation (e.g., ManagementPlane cannot assign Owner role)
- **Self-Service Access**: Access packages enable requestor-driven group membership with approval workflows
- **Configuration-Driven**: All settings managed through `EntraOpsConfig.json` for consistent, repeatable deployments
- **Smart Provisioning**: Detects inherited permissions to avoid redundant role assignments

## Get started

### Quick start

Get your first landing zone deployed in 3 steps:

#### Step 1: Import EntraOps and sign in (One-time per session)

```powershell
Import-Module ./EntraOps

# "ServiceEM" adds the ServiceEM write scopes to the delegated Microsoft Graph sign-in
Connect-EntraOps -AuthenticationType "UserInteractive" -TenantName "contoso.onmicrosoft.com" -Scope "ServiceEM"
```

No separate `Install-Module`, `Connect-MgGraph` or `Connect-AzAccount` call is needed: `Connect-EntraOps` installs the
required modules (`Az.Accounts`, `Az.Resources` and - unless `UseInvokeRestMethodOnly` is used - `Microsoft.Graph.Authentication`),
signs in to Azure and Microsoft Graph and, with `-Scope "ServiceEM"`, requests all delegated scopes ServiceEM needs
(see [Required permissions](#required-permissions)). Add `-ConfigFilePath "./EntraOpsConfig.json"` to load the `ServiceEM`
settings (governance model, delegation groups, constrained delegation, PIM authentication context) into the session.

> **Governance model:** without a configuration, landing zones use the **PerService** model. A configuration file created by
> `New-EntraOpsConfigFile` sets `ServiceEM.GovernanceModel` to `"Centralized"`. It is applied when loaded via `-ConfigFilePath`
> or when `EntraOpsConfig.json` exists in the current directory (`New-EntraOpsSubscriptionLandingZone` loads it automatically
> if no configuration is loaded yet). Pass `-GovernanceModel "PerService"` to override it.

#### Step 2: Deploy Your First Landing Zone

```powershell
New-EntraOpsSubscriptionLandingZone `
    -DeploymentPrefix "MyFirstApp" `
    -AzureRegion "westeurope" `
    -SubscriptionId "<subscription-id>" `
    -WorkloadPlaneAdmin "alice@contoso.com" `
    -ServiceMembers @("bob@contoso.com") `
    -Verbose
```

> **Note:** `-WorkloadPlaneAdmin` assigns the admin to the admin access package: ManagementPlane-Admins in the default PerService
> single scope, WorkloadPlane-Admins (which approves WorkloadPlane-Users requests) in the Centralized model or when
> ManagementPlane-Admins is delegated. In the PerService model the admin is also assigned to the CatalogPlane-Members access package (Initial Catalog Members
> Policy), so they can request the other access packages. The admin isn't added to WorkloadPlane-Users unless
> `-AddWorkloadPlaneAdminToUsers` is set. It doesn't make the admin a
> group owner: ownership of the WorkloadPlane groups is opt-in with `-GroupOwnership Eligible` or `Permanent`, because owners
> can add members directly, bypassing access package approvals and access reviews. See [Group owners](#group-owners)
> for details and the Microsoft 365 group exception.

**That's it!** This creates one resource group scope `Rg-MyFirstApp` (default `-DeploymentScope ResourceGroup`, see [Deployment Scopes](#deployment-scopes)):
- ✅ Role-assignable Entra ID security groups per tier (plus the optional Microsoft 365 group `Rg-MyFirstApp Members` for team collaboration with [`-CreateM365Group`](#createm365group-parameter))
- ✅ One Entitlement Management catalog `Catalog-Rg-MyFirstApp` with access packages and assignment policies
- ✅ Opt-in PIM for Groups with eligible membership through access packages (Microsoft Entra ID Governance license): ControlPlane-/ManagementPlane-Admins with `-EnablePimForGroups` (recommended) and WorkloadPlane-Admins with `-EnableWorkloadPlanePimForGroups` (see [EnablePimForGroups and EnableWorkloadPlanePimForGroups Parameters](#enablepimforgroups-and-enableworkloadplanepimforgroups-parameters))
- ✅ Azure Resource Group `RG-MyFirstApp` with PIM-eligible RBAC assignments

#### Step 3: Verify Deployment

```powershell
# Created groups
Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/groups?`$filter=startswith(mailNickname,'Rg-MyFirstApp.')" -OutputType PSObject |
    Select-Object displayName, id

# Catalog, access packages, assignment policies and delivered assignments of this landing zone
(Get-EntraOpsServiceEMReport).Catalogs |
    Where-Object { $_.Catalog.displayName -eq 'Catalog-Rg-MyFirstApp' }
```

**Next Steps:**
- See [Detailed Setup Guide](#detailed-setup-guide) for production configurations
- See [Governance Models](#governance-models-and-persona-based-groups) to choose between PerService and Centralized
- See [Common Deployment Scenarios](#common-deployment-scenarios) for advanced examples

---

### Guidance for automated assistants

If you're an AI assistant working with ServiceEM, here's what you need to know:

#### Core Capability
ServiceEM automates the creation of **tiered, service-scoped landing zones** following Microsoft's Enterprise Access Model. It provisions Entra ID groups, access packages, PIM policies, and Azure RBAC as a unified capability.

#### Key Concepts
- **Three Tiers**: ControlPlane (highest privilege), ManagementPlane (resource management), WorkloadPlane (application access), plus CatalogPlane groups for catalog governance
- **Scopes**: `New-EntraOpsSubscriptionLandingZone` runs `New-EntraOpsServiceBootstrap` once for a single scope - `Rg-<DeploymentPrefix>` with the Azure resource group `RG-<DeploymentPrefix>` (default `-DeploymentScope ResourceGroup`) or `Sub-<DeploymentPrefix>` with role assignments on the subscription (`Subscription`). To separate governance from workload groups, create the governance groups once and pass them as delegation groups (see [Separating governance and workload groups](#separating-governance-and-workload-groups))
- **Two Governance Models**:
  - **PerService** (runtime default): Creates dedicated admin groups per service - use for dev/test or isolated services
  - **Centralized** (default in configuration files generated by `New-EntraOpsConfigFile`): Uses shared tenant-wide admin groups - use for production with dedicated ops teams
- **Access Packages**: Self-service group membership with approval workflows via Entra ID Governance

#### When to Use ServiceEM
- ✅ Creating new service landing zones in Azure
- ✅ Implementing tiered administration with least-privilege access
- ✅ Setting up delegated administration with PIM
- ✅ Enabling self-service access requests via access packages

#### Key Parameters for AI
`New-EntraOpsSubscriptionLandingZone` parameters:

| Parameter                                                                                      | Description                                                                                                                                                                                                                                                                                                                                                         |
| ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-DeploymentPrefix <string>`                                                                   | Service name prefix (default: `"Default"`); the scope is named `Rg-<Prefix>` or `Sub-<Prefix>`                                                                                                                                                                                                                                                                      |
| `-DeploymentScope <string>`                                                                    | `"ResourceGroup"` (default) or `"Subscription"`, see [Deployment Scopes](#deployment-scopes)                                                                                                                                                                                                                                                                        |
| `-AzureRegion <string>`                                                                        | Azure region of the resource group (e.g. `"westeurope"`); required unless `-SkipAzureResourceGroup` is set or `-DeploymentScope` is `Subscription`                                                                                                                                                                                                                  |
| `-SubscriptionId <string>`                                                                     | Subscription (GUID) of the resource group; required unless `-SkipAzureResourceGroup` is set. Validated before any object is created; the Azure context is switched for the RBAC step and restored afterwards                                                                                                                                                        |
| `-ServiceMembers <string[]>`                                                                   | UPNs/object IDs assigned to the WorkloadPlane-Users access package; defaults to the signed-in user (empty for app-only). The deployment stops before any object is created if a member or the admin can't be resolved                                                                                                                                               |
| `-GroupOwnership <string>`                                                                     | `None` (default), `Eligible` or `Permanent`: opt-in (PIM for Groups eligible or permanent) ownership of the WorkloadPlane groups (WorkloadPlane-Admins, WorkloadPlane-Users) for the admin; shows a warning, because owners can add members directly, bypassing access package approvals and access reviews (see [Group owners](#group-owners))                     |
| `-WorkloadPlaneAdmin <string>`                                                                 | UPN, object ID or Graph URL of the admin, assigned to the admin access package and, in the PerService model, to CatalogPlane-Members (defaults to the signed-in user only with `-GroupOwnership Eligible` or `Permanent`)                                                                                                                                           |
| `-CatalogPlaneMembers <string[]>`                                                              | UPNs assigned to the CatalogPlane-Members access package (Initial Catalog Members Policy), in addition to the admin; ignored with `AdministratorGroupId` / Centralized                                                                                                                                                                                              |
| `-ControlPlaneAdmins <string[]>`                                                               | UPNs added as initial members of the per-service ControlPlane-Admins group (PerService only, ignored with a warning in the Centralized model or with `-ControlPlaneDelegationGroupId`): PIM for Groups eligible members with `-EnablePimForGroups`, otherwise permanent members                                                                                     |
| `-AddWorkloadPlaneAdminToUsers`                                                                | Also assign the admin to the WorkloadPlane-Users access package (default: admin access package only; `ServiceEM.AddWorkloadPlaneAdminToUsers`)                                                                                                                                                                                                                      |
| `-GovernanceModel <string>`                                                                    | `"PerService"` or `"Centralized"`; parameter > `ServiceEM.GovernanceModel` in config > `"PerService"`                                                                                                                                                                                                                                                               |
| `-ControlPlaneDelegationGroupId`, `-ManagementPlaneDelegationGroupId`, `-AdministratorGroupId` | Existing groups to use instead of per-service groups; fall back to the `ServiceEM` config values                                                                                                                                                                                                                                                                    |
| `-SkipAzureResourceGroup`                                                                      | Entra-only: no Azure resource group and no Azure RBAC                                                                                                                                                                                                                                                                                                               |
| `-SkipCatalogOwnerAssignment`                                                                  | No permanent Catalog Owner assignment for ControlPlane-Admins in the catalog (recommended, see [Catalog Owner assignment](#catalog-owner-assignment-for-controlplane-admins))                                                                                                                                                                                       |
| `-EnablePimForGroups`                                                                          | Opt-in (recommended): PIM for Groups policy for the owned ControlPlane-Admins and ManagementPlane-Admins groups; their access packages grant **eligible** membership. Requires Microsoft Entra ID Governance licenses (see [EnablePimForGroups and EnableWorkloadPlanePimForGroups Parameters](#enablepimforgroups-and-enableworkloadplanepimforgroups-parameters)) |
| `-EnableWorkloadPlanePimForGroups`                                                             | Opt-in: the same for WorkloadPlane-Admins, e.g. for multi-activation scenarios (group membership, then the PIM-eligible Azure roles)                                                                                                                                                                                                                                |
| `-CreateM365Group`                                                                             | Also creates the Microsoft 365 group `<Scope>-<Prefix> Members` for team collaboration; it is added to every access package of its scope (members via any access package), but gets no PIM for Groups eligibilities or other access (see [CreateM365Group Parameter](#createm365group-parameter))                                                                   |
| `-GroupPrefix <string>`                                                                        | Prefix of the security group display names (default `SG`; `ServiceEM.GroupPrefix`), see [Naming Conventions](#naming-conventions)                                                                                                                                                                                                                                   |

#### AI Context Checklist
Before suggesting ServiceEM commands, verify:
1. **Session is connected** with `Connect-EntraOps -Scope "ServiceEM"` (delegated) or a workload identity with the application permissions listed in [Required permissions](#required-permissions)
2. **For Centralized model**: Delegation groups exist (or can be created) and `AdministratorGroupId` is configured in the `ServiceEM` section of `EntraOpsConfig.json`
3. **For Azure resources**: Caller has Owner (or Contributor + User Access Administrator) on the target subscription and the Azure context points to it
4. **ServiceMembers / WorkloadPlaneAdmin**: Existing users in the tenant

#### Common AI Patterns
```powershell
# Dev/Test (simplest)
New-EntraOpsSubscriptionLandingZone -DeploymentPrefix "DevApp" -AzureRegion "westeurope" -SubscriptionId "<subscription-id>" -WorkloadPlaneAdmin "dev@contoso.com"

# Production with Centralized governance
New-EntraOpsSubscriptionLandingZone -DeploymentPrefix "ProdAPI" -AzureRegion "westeurope" -SubscriptionId "<subscription-id>" -WorkloadPlaneAdmin "api-owner@contoso.com" -ServiceMembers @("dev1@contoso.com") -GovernanceModel "Centralized"

# Entra-only (no Azure resources)
New-EntraOpsSubscriptionLandingZone -DeploymentPrefix "IdentityOnly" -WorkloadPlaneAdmin "admin@contoso.com" -SkipAzureResourceGroup
```

#### Troubleshooting for AI
- **Missing groups**: Centralized removes per-service ControlPlane-/ManagementPlane-Admins and CatalogPlane-Members groups; the Microsoft 365 group is only created with `-CreateM365Group`
- **Centralized silently became PerService**: A delegation group could not be resolved or created - check the `CENTRALIZED GOVERNANCE MODEL FAILED` warnings
- **Assignment policy errors**: Usually a referenced approver or requestor group does not exist in the same scope (see [Assignment Policies](#assignment-policies)) or the users are invalid
- **Azure RBAC failures**: Caller lacks Azure subscription permissions or the Azure context points to another subscription

> [!TIP]
> See the [Landing Zone Visualization](../service-em/landing-zone-visualization.html) for Mermaid diagrams of the group structure, access packages, policies, and RBAC assignments in Centralized and PerService governance models.

---

## Reviewing ServiceEM Deployments with EntraOps Reporting

After deploying a ServiceEM landing zone, run the EntraOps reporting pipeline to generate report objects and review the newly created resources across the reporting apps.

### Step 1: Verify with the ServiceEM Report

Confirm the landing zone resources were created correctly:

```powershell
Get-EntraOpsServiceEMReport
```

This returns a structured per-catalog view of all Entitlement Management resources, including catalogs, access packages, assignment policies, and active deliveries created by the deployment.

### Step 2: Run the Push-Reporting Pipeline

Generate the full set of EntraOps reporting artifacts so the newly created ServiceEM resources appear across all reporting apps.

**Locally:**

```powershell
Import-Module ./EntraOps -Force
New-EntraOpsReportingData
```

**Configuration-driven automation:**

```powershell
Import-Module ./EntraOps -Force
Invoke-EntraOpsReportingGeneration -ConfigFilePath ./EntraOpsConfig.json `
  -AuthenticationType AlreadyAuthenticated
```

**Via CI/CD:**

- **GitHub Actions:** Trigger the `Push-EntraOpsPrivilegedReporting` workflow. It regenerates the selected apps, runs the offline browser smoke suite, and uploads a 30-day artifact when every report passes.
- **Azure DevOps:** Run the `azure-pipelines-push-reporting.yml` pipeline, which calls `Invoke-EntraOpsReportingGeneration` and publishes the `Reports/` output as a pipeline artifact.

### Step 3: Review New Resources in Reporting Apps

Open `Reports/index.html` and use these apps to inspect the landing zone resources:

| Reporting App              | What to Review                                                                                                                                                                                           |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EAM Dashboard**          | Newly created groups, their classified tier levels, and role assignments. Filter by RBAC system (`IdentityGovernance`) or principal type (`group`) to isolate ServiceEM objects.                         |
| **Access Package Flow**    | Access packages, assignment policies, requestor scopes, and approver chains created by ServiceEM. Validates that the approval workflow matches the intended governance model.                            |
| **Configuration Analyzer** | If Tenant Governance snapshots are enabled, compare snapshots before and after the deployment to see exactly which resources were added (Change Timeline) and review their property-level configuration. |
| **Tier Breach Analyzer**   | Verify that the new landing zone does not introduce tier boundary violations (e.g., a WorkloadPlane identity with a path to ControlPlane privileges).                                                    |

> **Tip:** Use the cross-tool **Review list** to bookmark findings across apps. Export filtered results as CSV or JSON for triage and remediation tracking. See the [Reportings documentation](../reportings/index.html) for detailed guidance on each app.

---

## Detailed Setup Guide

### Prerequisites

#### Required (All Deployments)

1. **PowerShell 7+** and the **EntraOps PowerShell Module** imported:
   ```powershell
   Import-Module ./EntraOps
   ```
   Required modules are installed by `Connect-EntraOps` (see [Module Dependencies](#module-dependencies)).

2. **Connected session** via `Connect-EntraOps`:
   ```powershell
   # Interactive (delegated): -Scope "ServiceEM" requests the ServiceEM write scopes
   Connect-EntraOps -AuthenticationType "UserInteractive" -TenantName "contoso.onmicrosoft.com" -Scope "ServiceEM" -ConfigFilePath "./EntraOpsConfig.json"

   # Workload identity (application permissions, see Required permissions)
   Connect-EntraOps -AuthenticationType "FederatedCredentials" -TenantName "contoso.onmicrosoft.com" -ConfigFilePath "./EntraOpsConfig.json"
   ```

3. **Azure access** to the subscription where the landing zone resource group should be created, with Owner or
   Contributor + User Access Administrator permissions. Pass it with `-SubscriptionId`: ServiceEM checks that the
   subscription is accessible in the current tenant before creating any object, switches the Azure context for the
   resource group and RBAC step, and restores the previous context afterwards.

#### Required permissions

| Identity type                        | Microsoft Graph                                                                                                                                                                                                                                                                                                                                                                                        | Entra ID directory roles                                                                                                                                          |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| User (delegated, `-Scope ServiceEM`) | Requested automatically: `Directory.AccessAsUser.All`, `EntitlementManagement.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `RoleManagementPolicy.ReadWrite.Directory`, `RoleManagementPolicy.ReadWrite.AzureADGroup`, `PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup`, `PrivilegedAccess.ReadWrite.AzureADGroup` (plus the EntraOps read scopes)                                       | Privileged Role Administrator (role-assignable groups, PIM for Groups) and Identity Governance Administrator (catalogs, access packages), or Global Administrator |
| Workload identity (application)      | `Group.ReadWrite.All`, `User.Read.All`, `EntitlementManagement.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `RoleManagementPolicy.ReadWrite.Directory`, `RoleManagementPolicy.ReadWrite.AzureADGroup`, `PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup`, `PrivilegedAccess.ReadWrite.AzureADGroup` - grant manually with admin consent (not assigned by `New-EntraOpsWorkloadIdentity`) | -                                                                                                                                                                 |

All created security groups are **role-assignable** (only Privileged Role Administrators and Global Administrators can manage
their members and owners, which protects them against less privileged administrators), therefore `RoleManagement.ReadWrite.Directory`
is required in both governance models.

#### Required for PerService Model (Default)

The **PerService** governance model is the runtime default and requires **no pre-existing groups**:
- All admin groups are created automatically per service
- Recommended for getting started, dev/test and isolated services

#### Required for Centralized Model (Optional)

The **Centralized** governance model uses tenant-wide, role-assignable **Security Groups** for ControlPlane and ManagementPlane
and an existing group for CatalogPlane (`AdministratorGroupId`):

1. **Create persona groups** (one-time setup, optional - see step 3):
   ```powershell
   # Example: Create ControlPlane delegation group
   $controlPlaneGroup = Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/groups" -OutputType PSObject -Body (@{
       displayName        = "PRG-Tenant-ControlPlane-IdentityOps"
       mailNickname       = "PRGControlPlane"
       securityEnabled    = $true
       mailEnabled        = $false
       isAssignableToRole = $true
   } | ConvertTo-Json)

   # Example: Create ManagementPlane delegation group
   $managementPlaneGroup = Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/groups" -OutputType PSObject -Body (@{
       displayName        = "PRG-Tenant-ManagementPlane-PlatformOps"
       mailNickname       = "PRGManagementPlane"
       securityEnabled    = $true
       mailEnabled        = $false
       isAssignableToRole = $true
   } | ConvertTo-Json)
   ```

2. **Add group IDs to the `ServiceEM` section in EntraOpsConfig.json**:
   ```json
   {
     "ServiceEM": {
       "GovernanceModel": "Centralized",
       "ControlPlaneDelegationGroupId": "<control-plane-group-id>",
       "ManagementPlaneDelegationGroupId": "<management-plane-group-id>",
       "AdministratorGroupId": "<catalog-plane-group-id>"
     }
   }
   ```
   `AdministratorGroupId` is required: in the Centralized model no per-service CatalogPlane-Members group is created,
   and this group is the requestor scope of the assignment policies. Without it,
   `New-EntraOpsSubscriptionLandingZone` stops before creating any object. The `-WorkloadPlaneAdmin` must be a
   member of it; ServiceEM checks this before creating any object and stops otherwise.

3. **Alternative: automatic lookup or creation**:
   - If no ID is configured, ServiceEM searches for a group with the display name `ControlPlaneGroupName` /
     `ManagementPlaneGroupName` (defaults `PRG-Tenant-ControlPlane-IdentityOps` / `PRG-Tenant-ManagementPlane-PlatformOps`)
   - If none exists and the session token contains `RoleManagement.ReadWrite.Directory` (included in `-Scope "ServiceEM"`),
     a role-assignable group is created (always without owner, see [Group owners](#group-owners))
   - Found or created group IDs are persisted to `EntraOpsConfig.json` in the current directory
   - If resolution fails, ServiceEM warns and **falls back to the PerService model**

#### Governance Model Comparison

| Feature                 | PerService (Default)                              | Centralized                                                               |
| ----------------------- | ------------------------------------------------- | ------------------------------------------------------------------------- |
| **Pre-existing groups** | ❌ Not required                                    | ✅ Required or auto-created (role-assignable), plus `AdministratorGroupId` |
| **Permissions needed**  | See [Required permissions](#required-permissions) | Same                                                                      |
| **Group count**         | More (per service)                                | Fewer (shared)                                                            |
| **Use case**            | 5-10 services, dev/test                           | 50+ services, production                                                  |
| **Isolation**           | Higher (dedicated admins)                         | Lower (shared admins)                                                     |

### Deployment Scopes

`-DeploymentScope` of `New-EntraOpsSubscriptionLandingZone` defines where the Azure permissions are assigned. Every
landing zone deploys exactly one scope and one catalog:

| `-DeploymentScope`        | Scope / catalog                         | Microsoft 365 group (only with `-CreateM365Group`) | Azure                                                                                |
| ------------------------- | --------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `ResourceGroup` (default) | `Rg-<Prefix>` / `Catalog-Rg-<Prefix>`   | `Rg-<Prefix> Members`                              | Resource group `RG-<Prefix>`; all role assignments on the resource group             |
| `Subscription`            | `Sub-<Prefix>` / `Catalog-Sub-<Prefix>` | `Sub-<Prefix> Members`                             | No resource group; the same role assignments on the subscription (`-SubscriptionId`) |

All groups of the service (own or delegated) live in **one scope and one catalog**. In the PerService model this includes
ControlPlane-Admins and ManagementPlane-Admins, so they receive their PIM eligible Azure roles on the resource group or
subscription.

```powershell
# Subscription deployment: no resource group, role assignments on the subscription
New-EntraOpsSubscriptionLandingZone `
    -DeploymentPrefix "Connectivity" `
    -DeploymentScope Subscription `
    -SubscriptionId "<subscription-id>" `
    -WorkloadPlaneAdmin "alice@contoso.com"
```

> **Warning (Subscription):** eligible Contributor and constrained Role Based Access Control Administrator apply to the whole
> subscription. ServiceEM also changes the PIM for Azure resources settings of Contributor, User Access Administrator and Role
> Based Access Control Administrator **on the subscription** so that eligible assignments don't have to expire. This affects all
> eligible assignments of these roles on the subscription, not only the ones of the landing zone.

#### Separating governance and workload groups

To keep the governance groups (ControlPlane-Admins, ManagementPlane-Admins, CatalogPlane-Members) apart from the workload
groups, create the governance groups once and pass them as delegation groups to the workload landing zone:

```powershell
# 1. Governance scope without Azure resources
$governance = New-EntraOpsServiceBootstrap -ServiceName "Sub-MyApp" -SkipAzureResourceGroup `
    -EnablePimForGroups -ServiceRoles (@"
accessLevel,name,groupType
CatalogPlane,Members,
ControlPlane,Admins,
ManagementPlane,Admins,
"@ | ConvertFrom-Csv)
$groupId = { param($name) ($governance.Groups | Where-Object DisplayName -like "*-$name").Id }

# 2. One workload landing zone per workload, using the governance groups as delegated groups
New-EntraOpsSubscriptionLandingZone -DeploymentPrefix "MyApp" `
    -AzureRegion "westeurope" -SubscriptionId "<subscription-id>" `
    -ControlPlaneDelegationGroupId (& $groupId 'ControlPlane-Admins') `
    -ManagementPlaneDelegationGroupId (& $groupId 'ManagementPlane-Admins') `
    -AdministratorGroupId (& $groupId 'CatalogPlane-Members')
```

The workload scope creates only WorkloadPlane-Users and WorkloadPlane-Admins (plus the optional Microsoft 365 group). The
delegated groups are injected into it and get:

| Delegated group        | Catalog role                                       | Workload policies                                                   | PIM eligible Azure roles on `RG-<Prefix>`                         |
| ---------------------- | -------------------------------------------------- | ------------------------------------------------------------------- | ----------------------------------------------------------------- |
| ControlPlane-Admins    | Catalog Owner                                      | Approver/reviewer where ControlPlane-Admins is the default          | User Access Administrator                                         |
| ManagementPlane-Admins | Catalog Reader + Access package assignment manager | Approves the Workload Plane Policy (WorkloadPlane-Admins); reviewer | Contributor + constrained Role Based Access Control Administrator |
| CatalogPlane-Members   | Catalog Reader                                     | Requestor scope of the Workload Plane Policy                        | -                                                                 |

Delegated groups never get owners or PIM for Groups policies from the workload landing zone; PIM for Groups for them comes
from the governance call (`-EnablePimForGroups` there). `-ControlPlaneAdmins` is ignored with a warning in the workload call
(no per-service ControlPlane-Admins); pass the initial members to the governance call instead.

For many workloads that share tenant-wide governance groups, the **Centralized** model (`-GovernanceModel Centralized`, see
[Governance Models](#governance-models-and-persona-based-groups)) remains the recommended option; the two calls above are the
per-application (PerService) variant.

| Variant                             | How                                                                          |
| ----------------------------------- | ---------------------------------------------------------------------------- |
| ManagementPlane-Admins per workload | Delegate only ControlPlane-Admins (omit `-ManagementPlaneDelegationGroupId`) |
| CatalogPlane-Members per workload   | Omit `-AdministratorGroupId` in the workload call                            |
| Custom group sets                   | `New-EntraOpsServiceBootstrap -ServiceRoles`                                 |

### Basic Landing Zone Deployment

**Simple deployment with defaults (PerService model - no pre-existing groups required):**
```powershell
New-EntraOpsSubscriptionLandingZone `
    -DeploymentPrefix "MyFirstApp" `
    -AzureRegion "westeurope" `
    -SubscriptionId "<subscription-id>" `
    -WorkloadPlaneAdmin "alice@contoso.com" `
    -ServiceMembers @("bob@contoso.com") `
    -Verbose
```

**What gets created:**
- **Scope** (`Rg-MyFirstApp`): all groups of the service, catalog `Catalog-Rg-MyFirstApp`, access packages and resource group `RG-MyFirstApp` with Azure RBAC (PIM for Groups only with `-EnablePimForGroups` / `-EnableWorkloadPlanePimForGroups`)
- **Governance**: PerService model (creates per-service admin groups automatically)

**Explicit Centralized deployment (requires delegation groups, see above):**
```powershell
New-EntraOpsSubscriptionLandingZone `
    -DeploymentPrefix "MyFirstApp" `
    -AzureRegion "westeurope" `
    -SubscriptionId "<subscription-id>" `
    -WorkloadPlaneAdmin "alice@contoso.com" `
    -ServiceMembers @("bob@contoso.com") `
    -GovernanceModel "Centralized" `
    -Verbose
```

### Understanding Verbose Output

ServiceEM provides detailed verbose logging to help you understand what's being created and why. Key messages to watch for:

**Governance Model Detection:**
```
VERBOSE: [New-EntraOpsSubscriptionLandingZone] Centralized governance model - using tenant-wide delegation groups
VERBOSE: [New-EntraOpsSubscriptionLandingZone] ControlPlane delegation group ID supplied: a6b79e96... — validating
VERBOSE: [New-EntraOpsSubscriptionLandingZone] Validated ControlPlane group: prg - IdentityOps (a6b79e96...)
```
✅ **Meaning**: ServiceEM found `ControlPlaneDelegationGroupId` in config and validated the group exists

**Group Creation:**
```
VERBOSE: [New-EntraOpsServiceEntraGroup] Processing 2 Groups
VERBOSE: [New-EntraOpsServiceEntraGroup] {"DisplayName":"SG-Rg-MyFirstApp-WorkloadPlane-Users",...}
VERBOSE: [New-EntraOpsServiceEntraGroup] Groups available (Graph consistency confirmed)
```
✅ **Meaning**: Groups were created and are now indexed by Microsoft Graph. ServiceEM waits for replication with a
growing interval (capped at 30 seconds) for at most 5 minutes per step; a step that isn't consistent by then fails with
a "consistency ... not achieved" error.

**Delegation Injection:**
```
VERBOSE: [New-EntraOpsServiceBootstrap] Injecting delegated ControlPlane-Admins group (ID: a6b79e96...)
VERBOSE: [New-EntraOpsServiceBootstrap] Delegated ControlPlane-Admins: prg - Contoso - IdentityOps
```
✅ **Meaning**: Tenant-wide persona group was added to the service catalog (Centralized model)

**Access Package Creation:**
```
VERBOSE: [New-EntraOpsServiceEMAccessPackage] Processing 2 Access Package Roles
VERBOSE: [New-EntraOpsServiceEMAccessPackage] Creating Access Package
```
✅ **Meaning**: Access packages for WorkloadPlane-Users and WorkloadPlane-Admins are being created

**Skipped Components (Centralized Model):**
```
VERBOSE: [New-EntraOpsServiceEMAccessPackage] Processing 0 Access Package Roles
VERBOSE: [New-EntraOpsServiceBootstrap] No access packages to configure — skipping resource assignment, policies, and member assignments
```
✅ **Meaning**: The scope has no groups that need an access package (e.g. a governance scope with custom `-ServiceRoles` that only contains a Microsoft 365 group) → zero access packages created (expected). A scope without any own group is skipped:
```
VERBOSE: [New-EntraOpsServiceBootstrap] No groups left to create for Rg-MyApp (all roles delegated or skipped), skipping this scope
```

**Inherited Permission Detection:**
```
VERBOSE: [New-EntraOpsServiceAZContainer] ManagementPlane-Admins already has Contributor eligible at a higher scope — skipping assignment
VERBOSE: [New-EntraOpsServiceAZContainer] ControlPlane-Admins already has User Access Administrator eligible at a higher scope — skipping assignment
```
✅ **Meaning**: ServiceEM detected PIM eligible assignments at a parent scope (subscription, management group or root) and skipped redundant assignments (these messages only appear for ManagementPlane-Admins and ControlPlane-Admins groups that receive Azure roles, i.e. per-service groups and delegated groups)

### Complete Centralized Deployment Example with Annotated Output

Here's a complete example showing how persona-based groups (IdentityOps, PlatformOps) flow through a Centralized governance deployment
with the default `ResourceGroup` scope and `-CreateM365Group`.

**Command:**
```powershell
New-EntraOpsSubscriptionLandingZone `
    -DeploymentPrefix "MyEntraOpsApp" `
    -CreateM365Group `
    -AzureRegion "westeurope" `
    -SubscriptionId "<subscription-id>" `
    -WorkloadPlaneAdmin "admin@contoso.com" `
    -ServiceMembers @("alice@contoso.com", "bob@contoso.com") `
    -GovernanceModel "Centralized" `
    -Verbose
```

**EntraOpsConfig.json (relevant section):**
```json
{
  "ServiceEM": {
    "ControlPlaneDelegationGroupId": "a6b79e96-8a71-4b22-8946-1bbde6bbe8bd",
    "ManagementPlaneDelegationGroupId": "0463b6cf-de08-46c9-9fc1-48615ef75099",
    "AdministratorGroupId": "7c6eb065-92e0-4c22-9908-7506d022e05b"
  }
}
```

**Annotated Verbose Output:**

```
# 1. ServiceEM reads delegation group IDs from EntraOpsConfig.json
VERBOSE: [New-EntraOpsSubscriptionLandingZone] Reading ControlPlaneDelegationGroupId from EntraOpsConfig
VERBOSE: [New-EntraOpsSubscriptionLandingZone] Reading ManagementPlaneDelegationGroupId from EntraOpsConfig
VERBOSE: [New-EntraOpsSubscriptionLandingZone] Reading AdministratorGroupId from EntraOpsConfig

# 2. Centralized governance model auto-detected
VERBOSE: [New-EntraOpsSubscriptionLandingZone] Centralized governance model - using tenant-wide delegation groups

# 3. ControlPlane group (IdentityOps) validated
VERBOSE: [New-EntraOpsSubscriptionLandingZone] ControlPlane delegation group ID supplied: a6b79e96-8a71-4b22-8946-1bbde6bbe8bd — validating
VERBOSE: [New-EntraOpsSubscriptionLandingZone] Validated ControlPlane group: prg - Contoso - IdentityOps  (a6b79e96-8a71-4b22-8946-1bbde6bbe8bd)

# 4. ManagementPlane group (PlatformOps) validated
VERBOSE: [New-EntraOpsSubscriptionLandingZone] ManagementPlane delegation group ID supplied: 0463b6cf-de08-46c9-9fc1-48615ef75099 — validating
VERBOSE: [New-EntraOpsSubscriptionLandingZone] Validated ManagementPlane group: prg - Contoso - PlatformOps (0463b6cf-de08-46c9-9fc1-48615ef75099)

# 5. Per-service ControlPlane/ManagementPlane groups removed from ServiceRoles
VERBOSE: [New-EntraOpsSubscriptionLandingZone] Removing ControlPlane/ManagementPlane/CatalogPlane from per-service groups
VERBOSE: [New-EntraOpsSubscriptionLandingZone] Removing ControlPlane components from ServiceRoles

# 6. Processing the single scope (default -DeploymentScope ResourceGroup: Rg-MyEntraOpsApp)
VERBOSE: [New-EntraOpsSubscriptionLandingZone] Deployment scope: ResourceGroup
VERBOSE: [New-EntraOpsSubscriptionLandingZone] Processing LZ

# 7. WorkloadPlaneAdmin and ServiceMembers forwarded from parent cmdlet
VERBOSE: [New-EntraOpsServiceBootstrap] WorkloadPlaneAdmin set, looking up admin@contoso.com

# 8. ControlPlane/ManagementPlane creation skipped (centralized model)
VERBOSE: [New-EntraOpsServiceBootstrap] ControlPlaneDelegationGroupId provided — enforcing SkipControlPlaneDelegation
VERBOSE: [New-EntraOpsServiceBootstrap] ManagementPlaneDelegationGroupId provided — enforcing SkipManagementPlaneDelegation

# 9. WorkloadPlane groups and Microsoft 365 group created
VERBOSE: [New-EntraOpsServiceEntraGroup] Processing 3 Groups
VERBOSE: [New-EntraOpsServiceEntraGroup] {"DisplayName":"Rg-MyEntraOpsApp Members",...}
VERBOSE: [New-EntraOpsServiceEntraGroup] {"DisplayName":"SG-Rg-MyEntraOpsApp-WorkloadPlane-Users",...}
VERBOSE: [New-EntraOpsServiceEntraGroup] {"DisplayName":"SG-Rg-MyEntraOpsApp-WorkloadPlane-Admins",...}

# 10. Tenant-wide delegation groups injected into the service catalog
VERBOSE: [New-EntraOpsServiceBootstrap] Injecting delegated ControlPlane-Admins group (ID: a6b79e96-8a71-4b22-8946-1bbde6bbe8bd)
VERBOSE: [New-EntraOpsServiceBootstrap] Delegated ControlPlane-Admins: prg - Contoso - IdentityOps

VERBOSE: [New-EntraOpsServiceBootstrap] Injecting delegated ManagementPlane-Admins group (ID: 0463b6cf-de08-46c9-9fc1-48615ef75099)
VERBOSE: [New-EntraOpsServiceBootstrap] Delegated ManagementPlane-Admins: prg - Contoso - PlatformOps

VERBOSE: [New-EntraOpsServiceBootstrap] Injecting delegated CatalogPlane-Members group (ID: 7c6eb065-92e0-4c22-9908-7506d022e05b)
VERBOSE: [New-EntraOpsServiceBootstrap] Delegated CatalogPlane-Members: dug - Contoso - PrivilegedAccounts

# 11. Access packages created for WorkloadPlane-Users and WorkloadPlane-Admins
VERBOSE: [New-EntraOpsServiceEMAccessPackage] Processing 2 Access Package Roles
VERBOSE: [New-EntraOpsServiceEMAccessPackage] Creating Access Package
VERBOSE: [New-EntraOpsServiceBootstrap] Service Access Package IDs: ["b564d5cf-2d4a-4b82-ba76-2e663687ec8d","691e8983-7ef3-47a2-ab9b-3901978dafd6"]

# 12. Assignment policies created, including the admin-only initial policies
VERBOSE: [New-EntraOpsServiceEMAssignmentPolicy] Assigning Policy for Access Package ID: b564d5cf-2d4a-4b82-ba76-2e663687ec8d
VERBOSE: [New-EntraOpsServiceEMAssignmentPolicy] Creating Initial Workload Admin Policy for Access Package ID: b564d5cf-2d4a-4b82-ba76-2e663687ec8d
VERBOSE: [New-EntraOpsServiceEMAssignmentPolicy] Assigning Policy for Access Package ID: 691e8983-7ef3-47a2-ab9b-3901978dafd6
VERBOSE: [New-EntraOpsServiceEMAssignmentPolicy] Creating Initial Workload Users Policy for Access Package ID: 691e8983-7ef3-47a2-ab9b-3901978dafd6

# 13. Service members assigned to WorkloadPlane-Users (Initial Workload Users Policy), owner to WorkloadPlane-Admins (Initial Workload Admin Policy)
VERBOSE: [New-EntraOpsServiceEMAssignment] Processing Service Member ID: alice-object-id
VERBOSE: [New-EntraOpsServiceEMAssignment] Processing Service Member ID: bob-object-id
VERBOSE: [New-EntraOpsServiceEMAssignment] Creating Assignment Request for Workload Plane Admin - {...}

# 14. No PIM for Groups policy in this example (WorkloadPlane-Admins only with -EnableWorkloadPlanePimForGroups)

# 15. Azure Resource Group created with RBAC assignments
VERBOSE: [New-EntraOpsServiceAZContainer] Azure Resource Group not found, creating
VERBOSE: Created resource group 'RG-MyEntraOpsApp' in location 'westeurope'

# 16. Inherited subscription-level eligibilities of the delegated groups detected, RG assignments skipped
VERBOSE: [New-EntraOpsServiceAZContainer] ManagementPlane-Admins already has Contributor eligible at a higher scope — skipping assignment
VERBOSE: [New-EntraOpsServiceAZContainer] ControlPlane-Admins already has User Access Administrator eligible at a higher scope — skipping assignment

# 17. RG-scoped PIM eligible assignments (e.g. constrained RBAC Administrator for WorkloadPlane-Admins)
VERBOSE: [New-EntraOpsServiceAZContainer] Creating PIM Eligible Assignment for PrincipalId: d0daf544-dc42-4a9c-83b9-27e2d3f6c436
VERBOSE: [New-EntraOpsServiceAZContainer] Creating PIM Eligible Assignment for PrincipalId: baa5996e-1aee-4422-9473-1900fda1f679
```

**Key Takeaways:**
1. **IdentityOps group** (ControlPlane) was read from config, validated, and injected into the catalog `Catalog-Rg-MyEntraOpsApp`
2. **PlatformOps group** (ManagementPlane) was read from config, validated, and injected into the same catalog
3. **No per-service ControlPlane/ManagementPlane groups** were created (Centralized model)
4. **WorkloadPlane groups** and the Microsoft 365 group `Rg-MyEntraOpsApp Members` created in the single scope
5. **Service members** (alice, bob) assigned to WorkloadPlane-Users access package (the admin as well with `-AddWorkloadPlaneAdminToUsers`)
6. **Service owner** (admin, because of `-WorkloadPlaneAdmin`) assigned to WorkloadPlane-Admins access package (no ManagementPlane-Admins access package exists in the Centralized model)
7. **Inherited permissions** detected at RG level, preventing redundant RBAC assignments

### Common Deployment Scenarios

**Scenario 1: Production Service with Centralized Governance**
```powershell
# 1. Configure delegation groups in EntraOpsConfig.json
function Get-GroupIdByName ($Name) {
    (Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/groups?`$filter=displayName eq '$Name'" -OutputType PSObject).id
}
$config = Get-Content ./EntraOpsConfig.json -Raw | ConvertFrom-Json
$config.ServiceEM.GovernanceModel = "Centralized"
$config.ServiceEM.ControlPlaneDelegationGroupId = Get-GroupIdByName "PRG-Tenant-ControlPlane-IdentityOps"
$config.ServiceEM.ManagementPlaneDelegationGroupId = Get-GroupIdByName "PRG-Tenant-ManagementPlane-PlatformOps"
$config.ServiceEM.AdministratorGroupId = Get-GroupIdByName "Governance-Admins"
$config | ConvertTo-Json -Depth 10 | Set-Content ./EntraOpsConfig.json

# 2. Reload the configuration into the session (landing zone cmdlets use an already loaded configuration)
$Global:EntraOpsConfig = Get-Content ./EntraOpsConfig.json -Raw | ConvertFrom-Json -AsHashtable

# 3. Deploy landing zone
New-EntraOpsSubscriptionLandingZone `
    -DeploymentPrefix "ProdAPI" `
    -AzureRegion "westeurope" `
    -SubscriptionId "<subscription-id>" `
    -WorkloadPlaneAdmin "api-owner@contoso.com" `
    -ServiceMembers @("dev1@contoso.com", "dev2@contoso.com") `
    -GovernanceModel "Centralized" `
    -Verbose
```

**Scenario 2: Dev/Test Service with PerService Governance (Entra only)**
```powershell
# -SkipAzureResourceGroup: only Entra ID / Entitlement Management objects, no Azure resource group
New-EntraOpsSubscriptionLandingZone `
    -DeploymentPrefix "DevApp" `
    -WorkloadPlaneAdmin "dev-lead@contoso.com" `
    -ServiceMembers @("dev1@contoso.com") `
    -GovernanceModel "PerService" `
    -SkipAzureResourceGroup `
    -Verbose
```

**Scenario 3: Resource Group Only (No Subscription Scope)**
```powershell
New-EntraOpsServiceBootstrap `
    -ServiceName "Rg-MyMicroservice" `
    -AzureRegion "westeurope" `
    -SubscriptionId "<subscription-id>" `
    -WorkloadPlaneAdmin "owner@contoso.com" `
    -ServiceMembers @("dev@contoso.com") `
    -ManagementPlaneDelegationGroupId "<platform-ops-group-id>" `
    -ServiceRoles @(
        [PSCustomObject]@{accessLevel=''; name='Members'; groupType='Unified'}
        [PSCustomObject]@{accessLevel='CatalogPlane'; name='Members'; groupType=''}
        [PSCustomObject]@{accessLevel='WorkloadPlane'; name='Users'; groupType=''}
        [PSCustomObject]@{accessLevel='WorkloadPlane'; name='Admins'; groupType=''}
    ) `
    -Verbose
```

This creates the resource group `RG-MyMicroservice` (the `Sub-`/`Rg-` prefix is stripped). CatalogPlane-Members is needed as
requestor scope; the delegated ManagementPlane-Admins group approves the WorkloadPlane-Admins access package (without a
ManagementPlane-Admins approver, the Workload Plane Policy isn't created and only the admin-assigned Initial Workload Admin
Policy exists). Unlike the landing zone cmdlet, `New-EntraOpsServiceBootstrap` does not read delegation group
IDs or the governance model from `EntraOpsConfig.json`; constrained delegation and PIM authentication context settings are taken
from the configuration loaded via `Connect-EntraOps -ConfigFilePath`.

## Configuration Structure

All ServiceEM configuration is located in `EntraOpsConfig.json` under the `ServiceEM` section, specifically the governance model,
delegation groups, constrained delegations and PIM authentication context enforcement.

Landing zone cmdlets use the configuration loaded by `Connect-EntraOps -ConfigFilePath`. If none is loaded,
`New-EntraOpsSubscriptionLandingZone` tries `./EntraOpsConfig.json` and the path in `$env:ENTRAOPS_CONFIG`, otherwise parameter defaults apply.

### Creating Configuration File

Use the `New-EntraOpsConfigFile` cmdlet to create a new configuration file with default values:

```powershell
New-EntraOpsConfigFile -TenantName "contoso.onmicrosoft.com"
```

This will create `EntraOpsConfig.json` with a `ServiceEM` section containing:
- `GovernanceModel: "Centralized"`, empty delegation group IDs and the default delegation group names
- **ConstrainedDelegation** section with the default role definition IDs (role names are not written to the JSON file, see [Default Excluded Roles](#managementplane-constrained-delegation) and [Default Allowed Roles](#workloadplane-constrained-delegation))
- **PIMAuthenticationContext** section with `EnableAuthenticationContext: false` and empty authentication context IDs
- **PIMForGroups**, **AssignmentPolicies** and **AccessReviews** sections with the default durations, approval timeouts and review cadence (see [Assignment Policy, Access Review and PIM for Groups Settings](#assignment-policy-access-review-and-pim-for-groups-settings))

**Default Behavior:**
- Authentication context is **disabled** by default (`EnableAuthenticationContext: false`)
- When disabled, PIM policies enforce **MFA + Business Justification only**
- Constrained delegation is configured with sensible defaults for ManagementPlane and WorkloadPlane tiers

> **Governance model default:** New-EntraOpsSubscriptionLandingZone defaults to PerService at runtime, but New-EntraOpsConfigFile generates config with GovernanceModel = "Centralized".

### Basic Settings

The **`ServiceEM`** section of `EntraOpsConfig.json` contains the following basic settings:

```json
{
  "ServiceEM": {
    "GovernanceModel": "Centralized",
    "ControlPlaneDelegationGroupId": "",
    "ControlPlaneGroupName": "PRG-Tenant-ControlPlane-IdentityOps",
    "ManagementPlaneDelegationGroupId": "",
    "ManagementPlaneGroupName": "PRG-Tenant-ManagementPlane-PlatformOps",
    "AdministratorGroupId": "",
    "DefaultAzureRegion": "",
    "SkipCatalogOwnerAssignment": false,
    "CreateM365Group": false,
    "AddWorkloadPlaneAdminToUsers": false,
    "GroupPrefix": "SG"
  }
}
```

| Setting                            | Description                                                                                                                                                                                                                             |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GovernanceModel`                  | `Centralized` or `PerService`; used when `-GovernanceModel` is not passed                                                                                                                                                               |
| `ControlPlaneDelegationGroupId`    | Existing group used as ControlPlane-Admins (instead of a per-service group)                                                                                                                                                             |
| `ControlPlaneGroupName`            | Display name used to look up or create the ControlPlane delegation group (Centralized, no ID configured)                                                                                                                                |
| `ManagementPlaneDelegationGroupId` | Existing group used as ManagementPlane-Admins                                                                                                                                                                                           |
| `ManagementPlaneGroupName`         | Display name used to look up or create the ManagementPlane delegation group (Centralized, no ID configured)                                                                                                                             |
| `AdministratorGroupId`             | Existing group used as CatalogPlane-Members (catalog reader, requestor scope)                                                                                                                                                           |
| `DefaultAzureRegion`               | Azure region used when `-AzureRegion` is not passed (e.g. `westeurope`); empty means the parameter is required                                                                                                                          |
| `SkipCatalogOwnerAssignment`       | Default of `-SkipCatalogOwnerAssignment` (see [Catalog Owner assignment](#catalog-owner-assignment-for-controlplane-admins)); an explicitly passed parameter wins                                                                       |
| `CreateM365Group`                  | Default of `-CreateM365Group`: `true` also creates the Microsoft 365 group `<Scope>-<Prefix> Members` for team collaboration (see [CreateM365Group Parameter](#createm365group-parameter)); an explicitly passed parameter wins         |
| `AddWorkloadPlaneAdminToUsers`     | Default of `-AddWorkloadPlaneAdminToUsers`: `true` also assigns the `-WorkloadPlaneAdmin` to the WorkloadPlane-Users access package; an explicitly passed parameter wins                                                                |
| `GroupPrefix`                      | Default of `-GroupPrefix`: prefix of the security group display names (`SG` = `SG-Rg-MyApp-WorkloadPlane-Users`); letters, digits, `_`, `.` or `-`; an explicitly passed parameter wins (see [Naming Conventions](#naming-conventions)) |

> **Note:** The `ControlPlaneDelegationGroupId` and `ManagementPlaneDelegationGroupId` values must be **Security Groups** (role-assignable). They are also honored in the PerService model (see [How ServiceEM Reads EntraOpsConfig.json](#how-serviceem-reads-entraopsconfigjson)).

### Assignment Policy, Access Review and PIM for Groups Settings

The `PIMForGroups`, `AssignmentPolicies` and `AccessReviews` sections control the durations of the PIM for Groups policies, the
expiration and approval timeout of each assignment policy (see [Assignment Policies](#assignment-policies)) and the access
review cadence. The defaults written by `New-EntraOpsConfigFile` (and used when a setting is missing) are:

```json
{
  "ServiceEM": {
    "PIMForGroups": {
      "MaximumActivationDuration": "PT10H",
      "MaximumActiveAssignmentDuration": "P15D"
    },
    "AssignmentPolicies": {
      "BaselinePolicy":              { "Expiration": "P365D", "ApprovalTimeout": "P2D", "AllowExtension": true },
      "WorkloadPlaneUsers":          { "Expiration": "P365D", "ApprovalTimeout": "P2D", "RequestorScope": "AllMemberUsers", "AllowExtension": true },
      "WorkloadPlaneAdmins":         { "Expiration": "P365D", "ApprovalTimeout": "P2D", "AllowExtension": true },
      "ManagementPlaneAdmins":       { "Expiration": "P365D", "ApprovalTimeout": "P1D", "AllowExtension": true },
      "InitialWorkloadMembership":   { "Expiration": "P365D" },
      "InitialManagementAdmins":     { "Expiration": "P365D" },
      "InitialWorkloadUsers":        { "Expiration": "P365D" },
      "InitialWorkloadAdmins":       { "Expiration": "P365D" },
      "InitialCatalogMembers":       { "Expiration": "P365D" }
    },
    "AccessReviews": {
      "EnableAccessReviews": true,
      "RecurrenceIntervalInMonths": 3,
      "StartAfterDays": 4,
      "ReviewDuration": "P25D",
      "Policies": {
        "BaselinePolicy":              { "ReviewerType": "Group", "Reviewers": ["ManagementPlane-Admins"] },
        "WorkloadPlaneUsers":          { "ReviewerType": "Group", "Reviewers": ["WorkloadPlane-Admins"] },
        "WorkloadPlaneAdmins":         { "ReviewerType": "Group", "Reviewers": ["ManagementPlane-Admins"] },
        "ManagementPlaneAdmins":       { "ReviewerType": "Group", "Reviewers": ["ControlPlane-Admins"] },
        "InitialWorkloadMembership":   { "ReviewerType": "Group", "Reviewers": ["ManagementPlane-Admins"] },
        "InitialManagementAdmins":     { "ReviewerType": "Group", "Reviewers": ["ControlPlane-Admins"] },
        "InitialWorkloadUsers":        { "ReviewerType": "Group", "Reviewers": ["WorkloadPlane-Admins"] },
        "InitialWorkloadAdmins":       { "ReviewerType": "Group", "Reviewers": ["ManagementPlane-Admins"] },
        "InitialCatalogMembers":       { "ReviewerType": "Group", "Reviewers": ["ManagementPlane-Admins"] }
      }
    }
  }
}
```

| Setting                                                | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PIMForGroups.MaximumActivationDuration`               | Maximum duration of a PIM for Groups activation (ISO 8601, e.g. `PT8H`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `PIMForGroups.MaximumActiveAssignmentDuration`         | Maximum duration of an active (non-eligible) PIM for Groups assignment (e.g. `P15D`); eligible assignments don't expire                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `AssignmentPolicies.<Policy>.Expiration`               | "Assignments expire after": default `P365D` (365 days) for every policy; `noExpiration` or another ISO 8601 duration such as `P30D`, `P6M` or `PT12H`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `AssignmentPolicies.<Policy>.ApprovalTimeout`          | Time until a pending request is automatically denied, in whole days, e.g. `P2D` (Entra ID allows up to 14 days)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `AssignmentPolicies.WorkloadPlaneUsers.RequestorScope` | `AllMemberUsers` (every member user, no guests) or `CatalogPlaneMembers` (members of CatalogPlane-Members only)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `AssignmentPolicies.<Policy>.AllowExtension`           | Standard request policies only (`BaselinePolicy`, `WorkloadPlaneUsers`, `WorkloadPlaneAdmins`, `ManagementPlaneAdmins`): `true` (default) lets users extend an expiring assignment ("Allow users to extend access"), always with approval by the policy's approvers; ignored with `noExpiration`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `AccessReviews.EnableAccessReviews`                    | `false` creates the assignment policies without recurring access reviews                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `AccessReviews.RecurrenceIntervalInMonths`             | Months between two reviews (1 to 12, default 3 = quarterly)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `AccessReviews.StartAfterDays`                         | Days between the deployment and the start of the first review                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `AccessReviews.ReviewDuration`                         | Length of each review period in whole days (e.g. `P25D`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `AccessReviews.Policies.<Policy>.ReviewerType`         | Who reviews the assignments of the policy: `Group` (default, members of the `Reviewers` groups), `SelfReview` (users review their own access), `SpecificReviewers` (the users in `Reviewers`) or `Manager` (the user's manager, the `Reviewers` groups as fallback reviewers)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `AccessReviews.Policies.<Policy>.Reviewers`            | `Group` and `Manager`: service group name suffixes (e.g. `WorkloadPlane-Admins`) or group object IDs; `SpecificReviewers`: user object IDs or UPNs (required); ignored for `SelfReview`. Default `WorkloadPlane-Admins` for `WorkloadPlaneUsers` and `InitialWorkloadUsers` (the WorkloadPlane-Users access package), `ControlPlane-Admins` for `ManagementPlaneAdmins` and `InitialManagementAdmins` (the ManagementPlane-Admins access package), `ManagementPlane-Admins` for all other policies. Group names resolve only to the groups of the scope (own or delegated). A missing admin group falls back to a higher tier only (WorkloadPlane-Admins → ManagementPlane-Admins → ControlPlane-Admins), never to CatalogPlane-Members; without a reviewer of the same or a higher tier, the policy is created without access review and a warning |

The policy keys map to the assignment policies as follows:

| Key                         | Assignment policy                                                                                                                         |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `BaselinePolicy`            | Baseline Policy (CatalogPlane-Members access package and the policy template)                                                             |
| `WorkloadPlaneUsers`        | Workload Plane Users Policy (requests for WorkloadPlane-Users)                                                                            |
| `WorkloadPlaneAdmins`       | Workload Plane Policy (requests for WorkloadPlane-Admins)                                                                                 |
| `ManagementPlaneAdmins`     | Management Plane Policy (requests for ManagementPlane-Admins)                                                                             |
| `InitialWorkloadMembership` | Initial Workload Membership Policy (WorkloadPlane-Members)                                                                                |
| `InitialManagementAdmins`   | Initial Management Admin Policy (admin-assigned only)                                                                                     |
| `InitialWorkloadUsers`      | Initial Workload Users Policy (admin-assigned initial `-ServiceMembers` assignment)                                                       |
| `InitialWorkloadAdmins`     | Initial Workload Admin Policy (admin-assigned initial `-WorkloadPlaneAdmin` assignment)                                                   |
| `InitialCatalogMembers`     | Initial Catalog Members Policy (admin-assigned initial `-WorkloadPlaneAdmin` / `-CatalogPlaneMembers` assignment to CatalogPlane-Members) |

Invalid values stop the deployment with an error that names the setting, e.g.
`Invalid ServiceEM.AssignmentPolicies.InitialWorkloadUsers.Expiration '90 days'`.

> **Note:** Assignment policy and access review settings are applied when a policy is created; existing policies aren't updated
> on a re-run. PIM for Groups settings are applied every time `New-EntraOpsServicePIMPolicy` runs.

## Governance Models and Persona-Based Groups

ServiceEM supports two distinct governance approaches for delegated administration: **Centralized** and **PerService**. The model you choose determines whether high-privilege administrative groups are shared tenant-wide or created per-service.

### Centralized Governance Model

In the **Centralized** model, ControlPlane and ManagementPlane administrative groups are **shared across all services** in the tenant. This approach is ideal for organizations with dedicated persona-based teams (e.g., IdentityOps, PlatformOps) who manage multiple services.

It is used when `-GovernanceModel "Centralized"` is passed or `ServiceEM.GovernanceModel` is `"Centralized"` (the value written
by `New-EntraOpsConfigFile`); the runtime default without configuration is PerService.

**Key Characteristics:**
- **Shared delegation groups**: ControlPlane-Admins and ManagementPlane-Admins are tenant-wide groups configured once in `EntraOpsConfig.json`
- **Consistent permissions**: Same administrators have access across all landing zones
- **Reduced complexity**: Fewer groups to manage across multiple services
- **Skipped per-service groups**: ServiceEM removes the per-service ControlPlane-Admins, ManagementPlane-Admins and CatalogPlane-Members groups from all scopes
- **Fallback**: If a delegation group can neither be found nor created, ServiceEM warns and falls back to the PerService model

**Configuration in EntraOpsConfig.json (under the `ServiceEM` section):**

```json
{
  "ServiceEM": {
    "GovernanceModel": "Centralized",
    "ControlPlaneDelegationGroupId": "a6b79e96-8a71-4b22-8946-1bbde6bbe8bd",
    "ManagementPlaneDelegationGroupId": "0463b6cf-de08-46c9-9fc1-48615ef75099",
    "AdministratorGroupId": "7c6eb065-92e0-4c22-9908-7506d022e05b"
  }
}
```

> **Group Type Requirement:** The delegation groups referenced by `ControlPlaneDelegationGroupId` and `ManagementPlaneDelegationGroupId` must be **Security Groups** (role-assignable). These are existing tenant-wide groups that ServiceEM references rather than creates (unless auto-created, see [Required for Centralized Model](#required-for-centralized-model-optional)).

**Real-World Example:**

Consider an organization with two dedicated operations teams:

1. **IdentityOps Team (ControlPlane)**
   - Group: `prg - Contoso - IdentityOps`
   - Object ID: `a6b79e96-8a71-4b22-8946-1bbde6bbe8bd`
   - Responsible for: User Access Administrator delegation across all Azure subscriptions
   - PIM eligible for: User Access Administrator on each landing zone resource group (assigned by ServiceEM), or at subscription level (assigned by you)
   - Manages: All identity-related privileged access across the tenant

2. **PlatformOps Team (ManagementPlane)**
   - Group: `prg - Contoso - PlatformOps`
   - Object ID: `0463b6cf-de08-46c9-9fc1-48615ef75099`
   - Responsible for: Azure resource management across all subscriptions
   - PIM eligible for: Contributor and constrained Role Based Access Control Administrator on each landing zone resource group
   - Manages: Platform infrastructure, networking, monitoring

3. **Administrator Group (CatalogPlane)**
   - Group: `dug - Contoso - PrivilegedAccounts`
   - Object ID: `7c6eb065-92e0-4c22-9908-7506d022e05b`
   - Responsible for: Entitlement Management catalog governance
   - Manages: Requests for the WorkloadPlane access packages (requestor scope); approves only its own package

When you run `New-EntraOpsSubscriptionLandingZone` with Centralized governance:

```powershell
New-EntraOpsSubscriptionLandingZone `
    -DeploymentPrefix "MyApp" `
    -AzureRegion "westeurope" `
    -SubscriptionId "<subscription-id>" `
    -WorkloadPlaneAdmin "alice@contoso.com" `
    -ServiceMembers @("bob@contoso.com", "carol@contoso.com") `
    -GovernanceModel "Centralized"
```

**What happens:**
1. ServiceEM reads `ControlPlaneDelegationGroupId`, `ManagementPlaneDelegationGroupId`, and `AdministratorGroupId` from `EntraOpsConfig.json` (unless passed as parameters)
2. Validates that the ControlPlane and ManagementPlane groups exist (falls back to name-based lookup/creation, see [Required for Centralized Model](#required-for-centralized-model-optional))
3. **Skips creating** per-service ControlPlane-Admins, ManagementPlane-Admins and CatalogPlane-Members groups
4. **References** the tenant-wide groups in the catalog (catalog roles, policy approvers/requestors); they are not added as catalog resources and are never modified
5. Creates only the following groups for the service (default `-DeploymentScope ResourceGroup`; `Subscription` uses the `Sub-MyApp` prefix):
   - `Rg-MyApp Members` (Microsoft 365 group, only with `-CreateM365Group`)
   - `SG-Rg-MyApp-WorkloadPlane-Users` (Security group)
   - `SG-Rg-MyApp-WorkloadPlane-Admins` (Security group, PIM eligible)
6. Assigns the tenant-wide groups:
   - IdentityOps → Catalog Owner; PIM eligible User Access Administrator on `RG-MyApp` (skipped if already eligible at subscription level)
   - PlatformOps → Catalog Reader + AP Assignment Manager; approver of the WorkloadPlane-Admins access package; PIM eligible Contributor and constrained Role Based Access Control Administrator on `RG-MyApp` (Contributor skipped if already eligible at subscription level)
   - dug - Contoso - PrivilegedAccounts → Catalog Reader; requestor scope of the WorkloadPlane-Admins access package (the `-WorkloadPlaneAdmin` must be a member)

**Benefits in Practice:**
- **Consistency**: The same IdentityOps team manages UAA across all 50 subscriptions in your tenant
- **Efficiency**: A subscription-level eligibility for PlatformOps (assigned outside of ServiceEM) covers all landing zones in that subscription
- **Auditability**: All ControlPlane actions trace back to a single, well-governed group
- **Reduced blast radius**: ControlPlane and ManagementPlane groups are managed outside service landing zones

### PerService Governance Model

In the **PerService** model, every service landing zone gets its own dedicated ControlPlane-Admins and ManagementPlane-Admins groups. This approach is ideal for:
- Services with dedicated administrative teams
- Security boundaries requiring fully isolated permissions
- Development/test environments where autonomy is prioritized

**Configuration:**

```powershell
New-EntraOpsSubscriptionLandingZone `
    -DeploymentPrefix "MyApp" `
    -AzureRegion "westeurope" `
    -SubscriptionId "<subscription-id>" `
    -WorkloadPlaneAdmin "alice@contoso.com" `
    -GovernanceModel "PerService"
```

**What gets created (per service, default `-DeploymentScope ResourceGroup`):**
- `SG-Rg-MyApp-ControlPlane-Admins` (Catalog Owner, approver and access reviewer of the ManagementPlane-Admins access package, PIM eligible User Access Administrator on `RG-MyApp`)
- `SG-Rg-MyApp-ManagementPlane-Admins` (Catalog Reader + AP Assignment Manager, approver; PIM eligible Contributor and constrained Role Based Access Control Administrator on `RG-MyApp`)
- `SG-Rg-MyApp-CatalogPlane-Members` (catalog readers, requestor scope of the other access packages; approve only their own access package)
- `SG-Rg-MyApp-WorkloadPlane-Users`
- `SG-Rg-MyApp-WorkloadPlane-Admins` (permanent Reader, PIM eligible constrained Role Based Access Control Administrator on `RG-MyApp`)
- `Rg-MyApp Members` (Microsoft 365 group for team collaboration, only with `-CreateM365Group`)

With `-DeploymentScope Subscription` the same groups are created with the `Sub-MyApp` prefix and the Azure roles are assigned
on the subscription.

**With governance groups separated from the workload** (see [Separating governance and workload groups](#separating-governance-and-workload-groups)):

- Governance call (`New-EntraOpsServiceBootstrap -ServiceName "Sub-MyApp" -SkipAzureResourceGroup`): `SG-Sub-MyApp-ControlPlane-Admins`,
  `SG-Sub-MyApp-ManagementPlane-Admins`, `SG-Sub-MyApp-CatalogPlane-Members` in `Catalog-Sub-MyApp` (access packages for
  ManagementPlane-Admins and CatalogPlane-Members); no Azure resources
- Workload call (delegation IDs of these groups): `SG-Rg-MyApp-WorkloadPlane-Users`, `SG-Rg-MyApp-WorkloadPlane-Admins`
  (and `Rg-MyApp Members` with `-CreateM365Group`) in `Catalog-Rg-MyApp`; the delegated groups get their catalog roles, approve
  and review the workload policies and receive their PIM eligible Azure roles on `RG-MyApp`

### How ServiceEM Reads EntraOpsConfig.json

ServiceEM integrates deeply with the `EntraOpsConfig.json` configuration file. Here's what happens when `New-EntraOpsSubscriptionLandingZone` runs:

1. **Configuration source**: The configuration loaded by `Connect-EntraOps -ConfigFilePath` (`$Global:EntraOpsConfig`); if none is loaded, `./EntraOpsConfig.json` or `$env:ENTRAOPS_CONFIG`

2. **Delegation Group IDs**: `ControlPlaneDelegationGroupId`, `ManagementPlaneDelegationGroupId` and `AdministratorGroupId` are read from the `ServiceEM` section when the corresponding parameter is not passed

3. **Governance Model**: `-GovernanceModel` parameter > `ServiceEM.GovernanceModel` > `"PerService"`. The governance model is **not** derived from configured group IDs

4. **Delegation Group Resolution** (`Resolve-EntraOpsServiceEMDelegationGroup`):
   - Centralized: always resolves both groups - by configured ID, then by `ControlPlaneGroupName` / `ManagementPlaneGroupName`, then by creating a role-assignable group; found/created IDs are written back to `./EntraOpsConfig.json`
   - PerService: configured delegation IDs are still honored, the corresponding per-service ControlPlane-/ManagementPlane-Admins groups are then not created (CatalogPlane-Members still is, unless `AdministratorGroupId` is set)
   - A configured ID that cannot be found triggers a warning and the name-based lookup; if Centralized resolution fails completely, the deployment continues with PerService

**Complete EntraOpsConfig.json Example for Centralized Governance:**

The following example shows the full `ServiceEM` section inside `EntraOpsConfig.json`. The `ControlPlaneDelegationGroupId` and `ManagementPlaneDelegationGroupId` must reference existing **Security Groups** (role-assignable) in your tenant.

```json
{
  "TenantId": "df8f0d44-5f52-4402-9a26-68566daa9fbe",
  "TenantName": "contoso.onmicrosoft.com",
  "ServiceEM": {
    "GovernanceModel": "Centralized",
    "ControlPlaneDelegationGroupId": "a6b79e96-8a71-4b22-8946-1bbde6bbe8bd",
    "ControlPlaneGroupName": "PRG-Tenant-ControlPlane-IdentityOps",
    "ManagementPlaneDelegationGroupId": "0463b6cf-de08-46c9-9fc1-48615ef75099",
    "ManagementPlaneGroupName": "PRG-Tenant-ManagementPlane-PlatformOps",
    "AdministratorGroupId": "7c6eb065-92e0-4c22-9908-7506d022e05b",
    "ConstrainedDelegation": {
      "ManagementPlane": {
        "ExcludedRoleDefinitionIds": [
          "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
          "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
          "f58310d9-a9f6-439a-9e8d-f62e7b41a168"
        ],
        "AllowedTargetGroupFilter": "WorkloadPlane-Admins"
      },
      "WorkloadPlane": {
        "AllowedRoleDefinitionIds": [
          "00482a5a-887f-4fb3-b363-3b7fe8e74483",
          "ba92f5b4-2d11-453d-a403-e96b0029c9fe"
        ],
        "AllowedTargetGroupFilter": "WorkloadPlane-Users"
      }
    },
    "PIMAuthenticationContext": {
      "EnableAuthenticationContext": false
    }
  }
}
```

### Choosing an Operating Model

Choose the governance model by the teams that operate the planes, using the existing parameters:

| Team type                                                                  | Scenario                    | ControlPlane | ManagementPlane                  | WorkloadPlane | How to deploy                                                                                                                                                                               |
| -------------------------------------------------------------------------- | --------------------------- | ------------ | -------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Generalists (small team operates everything)                               | PerService                  | Per service  | Per service                      | Per service   | `-GovernanceModel PerService` (runtime default without config file), single scope; seed people with `-ControlPlaneAdmins`, `-WorkloadPlaneAdmin`, `-CatalogPlaneMembers`, `-ServiceMembers` |
| Mixed (central identity team, service teams operate their Azure resources) | Hybrid                      | Centralized  | Per service                      | Per service   | `-GovernanceModel PerService -ControlPlaneDelegationGroupId <tenant-wide group>`                                                                                                            |
| Specialists (dedicated identity and platform teams)                        | Centralized                 | Centralized  | Centralized                      | Per service   | `-GovernanceModel Centralized` + `AdministratorGroupId` (default of a config file from `New-EntraOpsConfigFile`)                                                                            |
| Platform team for subscriptions                                            | Centralized on subscription | Centralized  | Centralized (subscription scope) | Per service   | `-GovernanceModel Centralized -DeploymentScope Subscription`                                                                                                                                |

> **Default:** without a configuration file the runtime default is **PerService**; a configuration file generated by
> `New-EntraOpsConfigFile` sets `GovernanceModel` to `"Centralized"`. An explicitly passed `-GovernanceModel` wins.

To keep per-application governance groups (ControlPlane-Admins, ManagementPlane-Admins, CatalogPlane-Members) apart from the
workload groups, create them once and pass them as delegation groups to the workload landing zones (see
[Separating governance and workload groups](#separating-governance-and-workload-groups)); for many
workloads sharing tenant-wide governance groups, use the Centralized model.

**Self-service paths in the PerService model:**
- **ControlPlane-Admins**: no access package; initial members via `-ControlPlaneAdmins`, otherwise an Entra administrator
  (Privileged Role Administrator, the group is role-assignable) adds them in the portal
- **CatalogPlane-Members**: initial members via `-WorkloadPlaneAdmin` and `-CatalogPlaneMembers` (Initial Catalog Members
  Policy). The Baseline Policy only lets existing CatalogPlane-Members request (and extend) it, approved by CatalogPlane-Members;
  new members are assigned by catalog owners or access package assignment managers, or via the parameters
- **ManagementPlane-Admins**: requested by CatalogPlane-Members (Management Plane Policy), approved by ControlPlane-Admins; the
  initial `-WorkloadPlaneAdmin` is assigned directly
- **WorkloadPlane-Admins**: requested by CatalogPlane-Members, approved by ManagementPlane-Admins
- **WorkloadPlane-Users**: requested by all member users (default), approved by WorkloadPlane-Admins

These paths only apply to the PerService model. In the Centralized model, ControlPlane-/ManagementPlane-Admins and
CatalogPlane-Members are tenant-wide groups managed outside ServiceEM.

Requests are only approved by the same or a higher tier; CatalogPlane-Members never approve privileged access packages.

**Security considerations:**
- **Group ownership** is opt-in (`-GroupOwnership Eligible` or `Permanent`) and limited to the WorkloadPlane groups: owners can
  add members directly, bypassing access package approvals and access reviews (see [Group owners](#group-owners))
- **Access package assignment manager**: ManagementPlane-Admins hold this catalog role permanently and can directly assign every
  access package of the catalog without approval, including ManagementPlane-Admins itself (see
  [Access package assignment manager](#access-package-assignment-manager-for-managementplane-admins))
- **PIM for Groups** (`-EnablePimForGroups`, recommended): makes the membership of ControlPlane-Admins and ManagementPlane-Admins
  eligible, so their permanent catalog roles only apply after a just-in-time activation (see
  [EnablePimForGroups and EnableWorkloadPlanePimForGroups Parameters](#enablepimforgroups-and-enableworkloadplanepimforgroups-parameters))
- **Catalog Owner**: permanent catalog role of ControlPlane-Admins unless `-SkipCatalogOwnerAssignment` is set (see
  [Catalog Owner assignment](#catalog-owner-assignment-for-controlplane-admins))

### Governance Model Comparison

| Aspect                     | Centralized                                                           | PerService                                          |
| -------------------------- | --------------------------------------------------------------------- | --------------------------------------------------- |
| **ControlPlane-Admins**    | Single tenant-wide group (e.g., IdentityOps)                          | Dedicated group per service                         |
| **ManagementPlane-Admins** | Single tenant-wide group (e.g., PlatformOps)                          | Dedicated group per service                         |
| **Use Case**               | 50+ services, dedicated operations teams                              | 5-10 services, service-specific teams               |
| **PIM Scope**              | One activation across all services                                    | Separate activation per service                     |
| **Complexity**             | Low (fewer groups)                                                    | High (groups scale with services)                   |
| **Isolation**              | Lower (shared administrators)                                         | Higher (dedicated administrators)                   |
| **Configuration**          | `GovernanceModel: "Centralized"` + group IDs in `EntraOpsConfig.json` | `-GovernanceModel "PerService"` or no configuration |

### Migration Between Models

**Centralized → PerService:**
1. Remove `ControlPlaneDelegationGroupId`, `ManagementPlaneDelegationGroupId` and `AdministratorGroupId` from `EntraOpsConfig.json` (configured IDs are also used in the PerService model)
2. Re-run `New-EntraOpsSubscriptionLandingZone` with `-GovernanceModel "PerService"`
3. ServiceEM will create missing per-service groups (lookups are idempotent)

**PerService → Centralized:**
1. Create tenant-wide IdentityOps and PlatformOps groups
2. Add their ObjectIds to `EntraOpsConfig.json`
3. Re-run landing zone provisioning
4. Clean up the old per-service groups, their access packages and role assignments manually. `Remove-EntraOpsServiceCatalog` is **not** suitable for this step: it removes the complete catalog, all its access packages and all groups of the landing zone registered as catalog resources (i.e. the whole landing zone scope)

## Constrained Delegation Configuration

Constrained delegations limit which roles can be assigned and to which principals. This implements least-privilege access for delegated administrators.

### Configuration Schema

```json
{
  "ServiceEM": {
    "ConstrainedDelegation": {
      "ManagementPlane": {
        "ExcludedRoleDefinitionIds": [
          "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
          "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
          "f58310d9-a9f6-439a-9e8d-f62e7b41a168"
        ],
        "AllowedTargetGroupFilter": "WorkloadPlane-Admins",
        "_Comment_ExcludedRoles": "Owner, User Access Administrator, Role Based Access Control Administrator"
      },
      "WorkloadPlane": {
        "AllowedRoleDefinitionIds": [
          "00482a5a-887f-4fb3-b363-3b7fe8e74483",
          "..."
        ],
        "AllowedTargetGroupFilter": "WorkloadPlane-Users",
        "_Comment_AllowedRoles": "Key Vault Administrator, Key Vault Certificates Officer, ..."
      }
    }
  }
}
```

**Note:** The `_Comment_` fields are optional, not generated by `New-EntraOpsConfigFile`, and ignored by EntraOps. You can add them to document the role names corresponding to the GUIDs.

Constrained delegations are applied as [Azure ABAC conditions](https://learn.microsoft.com/en-us/azure/role-based-access-control/conditions-format) on PIM eligible **Role Based Access Control Administrator** assignments on the landing zone resource group (`RG-<DeploymentPrefix>`). The conditions restrict both creating (`roleAssignments/write`) and deleting (`roleAssignments/delete`) role assignments.

> **`AllowedTargetGroupFilter` is currently not evaluated.** The target principal is always the object ID of the WorkloadPlane-Admins
> group (ManagementPlane) or WorkloadPlane-Users group (WorkloadPlane) of the same landing zone scope. Only
> `ExcludedRoleDefinitionIds` and `AllowedRoleDefinitionIds` are read from the configuration; built-in defaults apply if they are missing.

### ManagementPlane Constrained Delegation

**Scope:** ManagementPlane-Admins group (PIM eligible Role Based Access Control Administrator on the resource group). Assigned when a ManagementPlane-Admins group and WorkloadPlane-Admins exist for the Azure scope, i.e. in a single-scope PerService deployment or with a delegated ManagementPlane group (Centralized model or `ManagementPlaneDelegationGroupId`)

**Permissions:** Can assign **any** Azure role **EXCEPT** the high-privileged roles listed in `ExcludedRoleDefinitionIds`

**Target:** Can only assign roles to the WorkloadPlane-Admins group of the landing zone

**Default Excluded Roles:**
- `8e3af657-a8ff-443c-a75c-2fe8c4bcb635` - Owner
- `18d7d88d-d35e-4fb5-a5c3-7773c20a72d9` - User Access Administrator
- `f58310d9-a9f6-439a-9e8d-f62e7b41a168` - Role Based Access Control Administrator

**Use Case:** Management-tier administrators assign resource-level or limited roles (e.g. Website Contributor) to the WorkloadPlane-Admins group without granting control-plane access. WorkloadPlane-Admins get no Contributor on the resource group from ServiceEM (see [Azure RBAC Implementation](#azure-rbac-implementation-resource-group-or-subscription-scope)).

### WorkloadPlane Constrained Delegation

**Scope:** WorkloadPlane-Admins group (PIM eligible Role Based Access Control Administrator on the resource group)

**Permissions:** Can assign **only** the data-plane roles listed in `AllowedRoleDefinitionIds`

**Target:** Can only assign roles to the WorkloadPlane-Users group of the landing zone

**Default Allowed Roles:**
- **Key Vault roles:**
  - `00482a5a-887f-4fb3-b363-3b7fe8e74483` - Key Vault Administrator
  - `a4417e6f-fecd-4de8-b567-7b0420556985` - Key Vault Certificates Officer
  - `14b46e9e-c2b7-41b4-b07b-48a6ebf60603` - Key Vault Crypto Officer
  - `12338af0-0e69-4776-bea7-57ae8d297424` - Key Vault Crypto User
  - `21090545-7ca7-4776-b22c-e363652d74d2` - Key Vault Reader
  - `b86a8fe4-44ce-4948-aee5-eccb2c155cd7` - Key Vault Secrets Officer
  - `4633458b-17de-408a-b874-0445c86b69e6` - Key Vault Secrets User

- **Storage roles:**
  - `ba92f5b4-2d11-453d-a403-e96b0029c9fe` - Storage Blob Data Contributor
  - `b7e6dc6d-f1e8-4753-8033-0f276bb0955b` - Storage Blob Data Owner
  - `2a2b9908-6ea1-4ae2-8e65-a410df84e7d1` - Storage Blob Data Reader
  - `0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3` - Storage Table Data Contributor
  - `76199698-9eea-4c19-bc75-cec21354c6b6` - Storage Table Data Reader
  - `974c5e8b-45b9-4653-ba55-5f855dd0fb88` - Storage Queue Data Contributor
  - `19e7f393-937e-4f77-808e-94535e297925` - Storage Queue Data Reader
  - `8a0f0c08-91a1-4084-bc3d-661d67233fed` - Storage Queue Data Message Processor
  - `c6a89b2d-59bc-44d0-9896-0f6e12d7b80a` - Storage Queue Data Message Sender

**Use Case:** Workload administrators can grant data-plane permissions to workload users for key management and storage operations without granting management-plane access.

## PIM Authentication Context Configuration

Authentication context enforcement requires users to meet additional Conditional Access requirements when activating PIM-eligible roles.

### Configuration Schema

```json
{
  "ServiceEM": {
    "PIMAuthenticationContext": {
      "EnableAuthenticationContext": true,
      "ControlPlane": {
        "AuthenticationContextClassReferenceId": "c1",
        "AuthenticationContextDisplayName": "Require compliant device + MFA + Phishing-resistant MFA"
      },
      "ManagementPlane": {
        "AuthenticationContextClassReferenceId": "c2",
        "AuthenticationContextDisplayName": "Require compliant device + MFA"
      },
      "WorkloadPlane": {
        "AuthenticationContextClassReferenceId": "c3",
        "AuthenticationContextDisplayName": "Require MFA"
      }
    }
  }
}
```

### Settings Explained

**EnableAuthenticationContext:** `true` or `false`
- When `true`, PIM policies will require authentication context for role activation
- When `false` or not defined, PIM policies enforce **MFA + Business Justification only** (default behavior)

> **Implementation note:** New-EntraOpsServicePIMPolicy adds the authentication context step-up only when EnableAuthenticationContext is `true` and an AuthenticationContextClassReferenceId is configured for the relevant tier. Otherwise it enforces MFA + Business Justification only.

**Scope of the policy:** The settings apply to the **PIM for Groups** member policy of ControlPlane-Admins and ManagementPlane-Admins
with `-EnablePimForGroups` and of WorkloadPlane-Admins with `-EnableWorkloadPlanePimForGroups` (see
[EnablePimForGroups and EnableWorkloadPlanePimForGroups Parameters](#enablepimforgroups-and-enableworkloadplanepimforgroups-parameters));
without these switches nothing is configured. The tier is derived from the group display name. Delegated groups are never
modified and PIM for Azure resources (the eligible roles on the resource group) is not affected. Changes take effect when the landing
zone is deployed again.

**Default Enforcement (when authentication context is disabled):**
The following settings are always applied to the PIM for Groups policies:
- **Multi-Factor Authentication (MFA):** Required for all role activations
- **Business Justification:** Required for all role activations
- **Maximum Duration:** 10 hours for role activation (`ServiceEM.PIMForGroups.MaximumActivationDuration`)
- **Approval:** Not required for activation
- **Expiration:** Eligible assignments don't expire; active assignments expire after at most 15 days (`ServiceEM.PIMForGroups.MaximumActiveAssignmentDuration`)

**Per-Tier Configuration:**

Each access tier (ControlPlane, ManagementPlane, WorkloadPlane) can have different authentication contexts:

- **AuthenticationContextClassReferenceId**: The ID of the authentication context in Entra ID (e.g., "c1", "c2", "c3")
  - These must be pre-configured in **Microsoft Entra admin center > Conditional Access > Authentication contexts**
  
- **AuthenticationContextDisplayName**: Descriptive name for documentation purposes (not evaluated)

### Example Authentication Context Strategy

**ControlPlane (Tier 0):**
- Requires phishing-resistant MFA (FIDO2/Windows Hello for Business)
- Requires compliant device (Intune managed)
- Requires MFA

**ManagementPlane (Tier 1):**
- Requires compliant device
- Requires MFA

**WorkloadPlane (Tier 2):**
- Requires MFA only

### Prerequisites

Before enabling authentication context:

1. **Create Authentication Contexts in Entra ID:**
   - Navigate to: Microsoft Entra admin center > Conditional Access > Authentication contexts
   - Create contexts with IDs matching your configuration (c1, c2, c3, etc.)

2. **Create Conditional Access Policies:**
   - Create CA policies targeting each authentication context
   - Configure required controls (MFA, device compliance, etc.)

3. **Test Authentication Contexts:**
   - Verify users can successfully authenticate with each context
   - Test PIM activation with authentication context requirements

## How It Works

### Constrained Delegation Flow

1. **User gets group membership**: A user receives membership in `SG-Rg-<Prefix>-WorkloadPlane-Admins` through the WorkloadPlane-Admins access package
2. **User activates the Azure role**: As group member, the user activates the eligible **Role Based Access Control Administrator** role on `RG-<Prefix>` in PIM for Azure resources
3. **Azure RBAC evaluates the ABAC condition** on every role assignment write or delete:
   - Checks if the role being assigned is allowed/excluded
   - Checks if the target principal is the landing zone's WorkloadPlane-Users (or WorkloadPlane-Admins) group
4. **Role assignment succeeds** only if conditions are met

### Authentication Context Flow

1. **User activates eligible group membership** in PIM for Groups
2. **PIM checks** if authentication context is required
3. **User is prompted** to satisfy authentication context requirements
4. **Conditional Access evaluates** the authentication context policy
5. **Role is activated** only after successful authentication context validation

## Customization Examples

### Example 1: Add Service Bus Data Plane Roles to WorkloadPlane

```json
{
  "ServiceEM": {
    "ConstrainedDelegation": {
      "WorkloadPlane": {
        "AllowedRoleDefinitionIds": [
          "00482a5a-887f-4fb3-b363-3b7fe8e74483",
          "...",
          "4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0",
          "69a216fc-b8fb-44d8-bc22-1f3c2cd27a39"
        ],
        "AllowedTargetGroupFilter": "WorkloadPlane-Users"
      }
    }
  }
}
```

Role IDs added:
- `4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0` - Azure Service Bus Data Receiver
- `69a216fc-b8fb-44d8-bc22-1f3c2cd27a39` - Azure Service Bus Data Sender

> **Note:** `AllowedRoleDefinitionIds` replaces the default list, so keep all default IDs you still want to allow (`...` above).
> Avoid adding management-plane roles such as Contributor (`b24988ac-6180-42a0-ab88-20f7382dd24c`) to the WorkloadPlane list.

### Example 2: Different Authentication Contexts per Environment

Development environment (relaxed):
```json
{
  "PIMAuthenticationContext": {
    "EnableAuthenticationContext": true,
    "WorkloadPlane": {
      "AuthenticationContextClassReferenceId": "c5",
      "AuthenticationContextDisplayName": "Require MFA only"
    }
  }
}
```

Production environment (strict):
```json
{
  "PIMAuthenticationContext": {
    "EnableAuthenticationContext": true,
    "WorkloadPlane": {
      "AuthenticationContextClassReferenceId": "c6",
      "AuthenticationContextDisplayName": "Require MFA + Compliant Device + Terms of Use"
    }
  }
}
```

### Example 3: Disable Authentication Context

```json
{
  "ServiceEM": {
    "PIMAuthenticationContext": {
      "EnableAuthenticationContext": false
    }
  }
}
```

When disabled, PIM policies will still require MFA and Justification (as defined in the base policy), but will not enforce authentication context.

## Troubleshooting

### Authentication Context Not Applied

**Symptom:** Users can activate roles without being prompted for authentication context

**Possible Causes:**
1. `EnableAuthenticationContext` is set to `false`, or the configuration was not loaded when the landing zone was deployed
2. Authentication context ID doesn't exist in Entra ID
3. No Conditional Access policy targets the authentication context
4. User's session already satisfies the authentication context requirements
5. The activated role is an Azure resource role (PIM for Azure resources), or the landing zone was deployed without `-EnablePimForGroups` / `-EnableWorkloadPlanePimForGroups` - authentication context is only configured for PIM for Groups

**Resolution:**
1. Verify configuration in `EntraOpsConfig.json` and re-run the landing zone deployment
2. Check authentication contexts exist: Microsoft Entra admin center > Conditional Access > Authentication contexts
3. Verify CA policies are enabled and properly scoped
4. Test with a fresh browser session

### Constrained Delegation Not Working

**Symptom:** Users can assign roles they shouldn't be able to

**Possible Causes:**
1. Configuration not loaded from `EntraOpsConfig.json`
2. Role assignment conditions not applied correctly
3. User has a direct (non-constrained) role assignment

**Resolution:**
1. Check verbose logs during ServiceEM deployment
2. Verify role assignment conditions in Azure Portal: Resource > Access Control (IAM) > Role assignments > View conditions
3. Review all role assignments for the user/group

## Security Considerations

### EnablePimForGroups and EnableWorkloadPlanePimForGroups Parameters

PIM for Groups is **opt-in**. Without these switches, ServiceEM configures **no PIM for Groups policy** for any group and the
access packages grant active (regular) group membership. The Azure roles of the admin groups are PIM-eligible in any case
(PIM for Azure resources, not affected by these switches).

| Switch                              | Groups                                                                           | Default |
| ----------------------------------- | -------------------------------------------------------------------------------- | ------- |
| `-EnablePimForGroups` (recommended) | Owned (non-delegated) per-service ControlPlane-Admins and ManagementPlane-Admins | Off     |
| `-EnableWorkloadPlanePimForGroups`  | WorkloadPlane-Admins                                                             | Off     |

The two switches are available on `New-EntraOpsSubscriptionLandingZone` (forwarded to the scope) and `New-EntraOpsServiceBootstrap`.

**Why ControlPlane-Admins and ManagementPlane-Admins:** both groups hold **permanent catalog roles** in Entitlement Management that
can't be PIM-protected: ControlPlane-Admins is Catalog Owner, ManagementPlane-Admins is Access package assignment manager and can
directly assign every access package of the catalog without approval. Their Azure roles are already PIM-eligible, so PIM for
Groups protects the identity governance delegation: the catalog roles only apply after the group membership is activated.

**What ServiceEM configures for a selected group:**
- **PIM for Groups member policy:** MFA and justification, no approval, maximum activation
  `ServiceEM.PIMForGroups.MaximumActivationDuration` (default `PT10H`), active assignments at most
  `ServiceEM.PIMForGroups.MaximumActiveAssignmentDuration` (default `P15D`), eligible assignments don't expire, optional
  authentication context (see [PIM Authentication Context Configuration](#pim-authentication-context-configuration)). The policy is applied **before** the
  group is added to the catalog, so the catalog offers the **Eligible Member** role.
- **Eligible membership through the access package:** the access package of the group delivers the **Eligible Member** resource
  role (PIM for Groups eligible membership) instead of the active **Member** role. Assigned users become eligible members and
  activate the membership in PIM. If the access package still has the active Member role of the group (e.g. a landing zone
  first deployed without the switch), it is **removed and replaced** by Eligible Member (warning; assigned users lose their active membership). If the catalog doesn't
  offer Eligible Member (group not yet managed by PIM, or missing license), ServiceEM warns and adds **no** resource role - it never
  falls back to active Member; re-run the deployment later.
- **`-ControlPlaneAdmins`** become PIM for Groups eligible members of ControlPlane-Admins (without the switch: permanent members).

**WorkloadPlane-Admins:** `-EnableWorkloadPlanePimForGroups` applies the same handling (policy, Eligible Member in its access
package, license warning), e.g. for **multi-activation** scenarios: activate the group membership, then the PIM-eligible Azure
roles of the group. It isn't needed by default, because the Azure roles of WorkloadPlane-Admins (constrained Role Based Access
Control Administrator) are already PIM-eligible.

**Never PIM for Groups:** WorkloadPlane-Users, CatalogPlane-Members, the Microsoft 365 group of
[`-CreateM365Group`](#createm365group-parameter) and delegated or tenant-wide groups (Centralized model,
`-ControlPlaneDelegationGroupId`, `-ManagementPlaneDelegationGroupId`, `-AdministratorGroupId`).

> **License warning:** Eligible group memberships through access packages are a **Microsoft Entra ID Governance** feature: they
> require Microsoft Entra ID Governance or Microsoft Entra Suite licenses. **Microsoft Entra ID P2 alone is not sufficient**
> (PIM for Groups by itself requires P2). ServiceEM shows a warning when one of the switches is used. See
> [Assign eligible group membership and ownership in access packages](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-access-package-eligible)
> and [Microsoft Entra ID Governance licensing fundamentals](https://learn.microsoft.com/en-us/entra/id-governance/licensing-fundamentals).

> **Important:** A group that is managed by PIM for Groups can't be taken out of PIM management again
> ([Enable management of group with PIM](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-access-package-eligible#enable-management-of-group-with-pim)).
> The access package expiration (default 365 days) and the PIM eligibility (no expiration) are independent: the eligibility ends
> when the access package assignment ends
> ([PIM and access package reference](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-access-package-pim-reference)).

```powershell
# Recommended: ControlPlane-Admins and ManagementPlane-Admins with PIM for Groups
New-EntraOpsSubscriptionLandingZone -DeploymentPrefix "MyApp" `
    -AzureRegion "westeurope" -SubscriptionId "<subscription-id>" `
    -EnablePimForGroups

# Additionally WorkloadPlane-Admins (multi-activation)
New-EntraOpsSubscriptionLandingZone -DeploymentPrefix "MyApp" `
    -AzureRegion "westeurope" -SubscriptionId "<subscription-id>" `
    -EnablePimForGroups -EnableWorkloadPlanePimForGroups
```

**Escalation path:** ServiceEM assigns no Owner role. Unrestricted Azure access (role assignments including Owner) remains only
with ControlPlane-Admins via the PIM-eligible User Access Administrator; ManagementPlane-Admins keep the eligible Contributor and
the constrained Role Based Access Control Administrator.

**When to use:**
- ✅ `-EnablePimForGroups`: production landing zones with Microsoft Entra ID Governance licenses (no standing catalog roles)
- ✅ `-EnableWorkloadPlanePimForGroups`: WorkloadPlane-Admins should activate the group membership before their Azure roles
- ❌ Only Microsoft Entra ID P2 licenses: keep the defaults (active membership through access packages)

### CreateM365Group Parameter

By default, a landing zone only contains security groups. With `-CreateM365Group` (or `ServiceEM.CreateM365Group` set to
`true` in `EntraOpsConfig.json`, also available in the Configuration Wizard), ServiceEM additionally creates the Microsoft 365
group `<Scope>-<Prefix> Members`. An explicitly passed `-CreateM365Group:$false` wins over the setting.

**Purpose:** the group is the collaboration space of the service team:
- **Email and ChatOps:** a group mailbox and calendar, e.g. as recipient for alerts, deployment and incident notifications
- **Knowledge:** when SharePoint Online or Microsoft Teams is used, the group's SharePoint site (documents, runbooks, wiki) or a
  Microsoft Teams team created for the group (channels for operations and ChatOps bots)

**Members:** the group is added as a resource (Member role) to **every access package of its scope**. Every user assigned to any
access package of the scope automatically becomes a member and loses the membership when the assignment ends:

| Persona                                                                                                | Privileged group of the persona              | Member of the Microsoft 365 group                      |
| ------------------------------------------------------------------------------------------------------ | -------------------------------------------- | ------------------------------------------------------ |
| Workload users (developers, data-plane operators)                                                      | `SG-<Scope>-<Prefix>-WorkloadPlane-Users`    | ✅ via the WorkloadPlane-Users access package           |
| Workload admins (service owners, workload operators)                                                   | `SG-<Scope>-<Prefix>-WorkloadPlane-Admins`   | ✅ via the WorkloadPlane-Admins access package          |
| Management admins (platform operators of the service, PerService model)                                | `SG-<Scope>-<Prefix>-ManagementPlane-Admins` | ✅ via the ManagementPlane-Admins access package        |
| Catalog members (`CatalogPlane-Members`, PerService model)                                             | `SG-<Scope>-<Prefix>-CatalogPlane-Members`   | ✅ via the CatalogPlane-Members access package          |
| Control plane admins (identity and access administrators, PerService model)                            | `SG-<Scope>-<Prefix>-ControlPlane-Admins`    | ❌ not automatically (no access package)                |
| `AdministratorGroupId` and tenant-wide delegation groups (Centralized model: IdentityOps, PlatformOps) | Delegated groups                             | ❌ not automatically (managed outside the landing zone) |

> **Note:** the Microsoft 365 group gets no PIM for Groups eligibilities, no access package of its own and no Azure or catalog
> role: membership only grants access to the group's collaboration resources (mailbox, calendar, SharePoint site or team). Access
> to the admin and user groups is always granted through the access packages. A scope without access packages (e.g. custom
> `-ServiceRoles` with only delegated groups) gets no automatic members.

```powershell
New-EntraOpsSubscriptionLandingZone `
    -DeploymentPrefix "MyApp" `
    -AzureRegion "westeurope" `
    -SubscriptionId "<subscription-id>" `
    -WorkloadPlaneAdmin "admin@contoso.com" `
    -CreateM365Group
```

**Without `-CreateM365Group` (default):**
- No Microsoft 365 group; a scope without other own groups (e.g. custom `-ServiceRoles` with only delegated groups) is skipped
  completely, without catalog
- A Microsoft 365 group created by a run with `-CreateM365Group` is left untouched but no longer used: it isn't added to the catalog
- Unchanged: access packages, assignment policies and the initial assignments of `-ServiceMembers` and `-WorkloadPlaneAdmin`,
  PIM for Groups settings of `-EnablePimForGroups` / `-EnableWorkloadPlanePimForGroups`, and Azure RBAC

`New-EntraOpsServiceBootstrap` uses the same switch: `Unified` entries of `-ServiceRoles` are only created with `-CreateM365Group`.

### Catalog Owner assignment for ControlPlane-Admins

By default, `New-EntraOpsServiceEMCatalogResourceRole` assigns the **Catalog Owner** role of every service catalog to the
ControlPlane-Admins group (per-service group or the `ControlPlaneDelegationGroupId`).

> **Warning:** Entitlement Management catalog roles can't be managed by PIM. This assignment is **permanent** (standing access):
> every active member of ControlPlane-Admins can modify the catalog at any time, e.g. add resources, change access packages and
> assignment policies (requestors, approvers, expiration) or assign access directly, without a separate activation of the role.
> With [`-EnablePimForGroups`](#enablepimforgroups-and-enableworkloadplanepimforgroups-parameters) the membership of
> ControlPlane-Admins is eligible, so the role only applies after a just-in-time activation of the membership.

Use `-SkipCatalogOwnerAssignment` to skip this assignment (`New-EntraOpsSubscriptionLandingZone` and
`New-EntraOpsServiceBootstrap`), or set `ServiceEM.SkipCatalogOwnerAssignment` to `true` to make it the default. The other catalog roles and the PIM eligible Azure User Access Administrator assignment on the
resource group are not affected.

```powershell
New-EntraOpsSubscriptionLandingZone `
    -DeploymentPrefix "MyApp" `
    -AzureRegion "westeurope" `
    -SubscriptionId "<subscription-id>" `
    -WorkloadPlaneAdmin "alice@contoso.com" `
    -SkipCatalogOwnerAssignment
```

**Recommendation:** Skip the assignment and give ControlPlane-Admins an **eligible** assignment of the corresponding Microsoft
Entra ID role **Identity Governance Administrator** via PIM (the group must be role-assignable, or assign the role to its
members). Catalog changes then require a just-in-time activation with the controls of the PIM role settings (MFA or
authentication context, justification, approval). Note that this role is tenant-wide and covers all catalogs, not only the
service catalog.

### Access package assignment manager for ManagementPlane-Admins

`New-EntraOpsServiceEMCatalogResourceRole` assigns the catalog role **Access package assignment manager** (AP Assignment Manager)
of every service catalog to ManagementPlane-Admins (per-service group or the `ManagementPlaneDelegationGroupId`).

> **Warning:** This assignment is **permanent**. In the PerService model the catalog also contains the ManagementPlane-Admins
> access package, and every deployment shows a warning: members of ManagementPlane-Admins can directly assign every access
> package of the catalog without approval (administrator direct assignments bypass the approval of the assignment policies),
> including the ManagementPlane-Admins access package itself. They can add further ManagementPlane admins without the approval of
> ControlPlane-Admins. The escalation stays within the ManagementPlane tier: ControlPlane-Admins has no access package, and an
> assignment manager can't change policies, resources or catalog roles.
>
> **Recommendation:** Use the **Centralized** governance model (`-GovernanceModel Centralized`) for production. ManagementPlane-Admins
> is then a tenant-wide group (`ManagementPlaneDelegationGroupId`) that is governed outside the service catalogs, so the service
> catalogs contain no ManagementPlane-Admins access package and no warning is shown. The tenant-wide group still holds the
> assignment manager role on every service catalog, i.e. it can directly assign the lower-tier packages of all services; protect
> its membership centrally (e.g. PIM for Groups, own catalog with ControlPlane approval). In the PerService model, make the
> membership of ManagementPlane-Admins eligible with [`-EnablePimForGroups`](#enablepimforgroups-and-enableworkloadplanepimforgroups-parameters)
> so the permission is just-in-time.

### Service Owner and Member Assignment

**Owner vs. Members** (initial `adminAdd` assignments by `New-EntraOpsServiceEMAssignment`):
- **WorkloadPlaneAdmin**: Assigned to the ManagementPlane-Admins access package ("Initial Management Admin Policy") where it exists (PerService model with an own ManagementPlane-Admins group); otherwise to the WorkloadPlane-Admins access package ("Initial Workload Admin Policy"), e.g. in the Centralized model or with a delegated ManagementPlane-Admins group. The two policies are admin-assigned only, without approval, and expire after 365 days by default (`ServiceEM.AssignmentPolicies`). Landing zones created before the initial policies existed fall back to the "Workload Plane Policy" (with approval). Only with `-AddWorkloadPlaneAdminToUsers` the admin is also added to the service members
- **WorkloadPlaneAdmin and CatalogPlaneMembers**: In a scope with a per-service CatalogPlane-Members group (PerService model), the admin and the users of `-CatalogPlaneMembers` are assigned to the CatalogPlane-Members access package ("Initial Catalog Members Policy", admin-assigned only, no approval, expires after 365 days by default). CatalogPlane-Members is the requestor scope of its own Baseline Policy, so new users can't request it; without these parameters an Entra or Identity Governance administrator (or a catalog owner / access package assignment manager) assigns the first members. Ignored with `AdministratorGroupId` and in the Centralized model
- **ServiceMembers**: Assigned to the WorkloadPlane-Members access package ("Initial Workload Membership Policy", requires approval by the requestor's manager and CatalogPlane-Members, so the request waits for approval) where it exists (only with custom `-ServiceRoles`); otherwise to the WorkloadPlane-Users access package ("Initial Workload Users Policy", admin-assigned only, no approval, expires after 365 days by default; fallback "Workload Plane Users Policy"). In the default landing zone this is the WorkloadPlane-Users package of the scope

The cmdlet waits up to 5 minutes (at most 30 seconds between checks) until the submitted requests are delivered. Requests that
wait for approval or failed are reported with a warning and not awaited; requests that are still in progress after 5 minutes are
listed with their last state and completed in the background.

**ControlPlaneAdmins** (`-ControlPlaneAdmins`, PerService only): ControlPlane-Admins has no access package. The users are added
directly to the per-service ControlPlane-Admins group: as **PIM for Groups eligible members** with
[`-EnablePimForGroups`](#enablepimforgroups-and-enableworkloadplanepimforgroups-parameters), otherwise as **permanent (active)
members**. `New-EntraOpsSubscriptionLandingZone` only forwards them to the scope that contains
ControlPlane-Admins. In the Centralized model or with `-ControlPlaneDelegationGroupId` the parameter is ignored with a warning;
the tenant-wide group is managed outside ServiceEM. Without the parameter, an Entra administrator (Privileged Role
Administrator, because the group is role-assignable) adds the members in the portal.

WorkloadPlaneAdmin is resolved when `-WorkloadPlaneAdmin` is passed (or, with `-GroupOwnership Eligible` or `Permanent`,
defaults to the signed-in user). Whether it owns the WorkloadPlane groups is controlled by `-GroupOwnership` (see [Group owners](#group-owners)).

#### Group owners

`-GroupOwnership` (`New-EntraOpsSubscriptionLandingZone` and `New-EntraOpsServiceBootstrap`) controls the ownership of the
**WorkloadPlane groups** (WorkloadPlane-Admins, WorkloadPlane-Users) for the WorkloadPlaneAdmin:

| Value            | Behavior                                                                                                       |
| ---------------- | -------------------------------------------------------------------------------------------------------------- |
| `None` (default) | No owner and no PIM for Groups eligible owner assignment                                                       |
| `Permanent`      | WorkloadPlaneAdmin is set as owner when the WorkloadPlane groups are created (existing groups are not updated) |
| `Eligible`       | WorkloadPlaneAdmin becomes a PIM for Groups eligible owner of the WorkloadPlane groups                         |

> **Warning:** Ownership is opt-in and shown as a warning at deployment: owners can add members directly, bypassing access
> package approvals and access reviews.

ControlPlane-Admins, ManagementPlane-Admins, CatalogPlane-Members, the Microsoft
365 group and the tenant-wide delegation groups (Centralized model, auto-created by `Resolve-EntraOpsServiceEMDelegationGroup`)
never get an owner from ServiceEM. Following the tier model, owning a higher-tier group (e.g. the role-assignable
ControlPlane-Admins) would let the owner add themselves and escalate (tier breach). Ownership is therefore limited to the
WorkloadPlane, which the WorkloadPlaneAdmin (ManagementPlane-Admins in the PerService model) already governs.

Microsoft Entra ID still applies its own defaults when groups are created
without owners in a **delegated** (user) sign-in:

- **Microsoft 365 groups** (`{ServiceName} Members`, with `-CreateM365Group`): the signed-in user is automatically added as owner, and the last owner
  can't be removed afterwards. Owners manage the membership of the team's collaboration group, review them after deployment.
- **Security groups** (all `SG-*` groups): no owner is added when the signed-in user is an administrator (required for
  role-assignable groups).

With a workload identity (app-only sign-in), all groups are created without owners.

By default, the admin only gets the admin access package. Use `-AddWorkloadPlaneAdminToUsers` (or set
`ServiceEM.AddWorkloadPlaneAdminToUsers` to `true`) to assign the admin to the WorkloadPlane-Users access package as well, e.g.
when the same account also works with the workload's data plane. Leave it off when admins use dedicated admin accounts.

```powershell
New-EntraOpsSubscriptionLandingZone `
    -DeploymentPrefix "MyApp" `
    -AzureRegion "westeurope" `
    -SubscriptionId "<subscription-id>" `
    -WorkloadPlaneAdmin "manager@contoso.com" `
    -ServiceMembers @("dev1@contoso.com", "dev2@contoso.com") `
    -AddWorkloadPlaneAdminToUsers  # Manager gets admin and user access
```

## Security Considerations (General)

1. **Regular Review:** Periodically review and update allowed/excluded role lists
2. **Least Privilege:** Start with minimal permissions and expand as needed
3. **Monitoring:** Monitor PIM activations and role assignments through Azure Monitor
4. **Authentication Context Updates:** Ensure CA policies remain effective as threats evolve
5. **Break-Glass Accounts:** Maintain emergency access accounts that bypass authentication context for critical scenarios

---

## Reference

### Cmdlet Inventory

ServiceEM exports 16 cmdlets for automated landing zone provisioning and management:

| #   | Cmdlet                                                 | Purpose                                                                                                                                                                                                                                                                                                                                                                                                  |
| --- | ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `New-EntraOpsServiceBootstrap`                         | **Orchestrator** — calls all other cmdlets in correct sequence for complete service provisioning of one scope                                                                                                                                                                                                                                                                                            |
| 2   | `New-EntraOpsServiceEntraGroup`                        | Creates role-assignable security groups and unified (M365) groups with correct naming                                                                                                                                                                                                                                                                                                                    |
| 3   | `New-EntraOpsServiceEMCatalog`                         | Creates Entitlement Management catalog (e.g., `Catalog-Sub-MyApp`) with idempotent lookup                                                                                                                                                                                                                                                                                                                |
| 4   | `New-EntraOpsServiceEMCatalogResource`                 | Registers the owned (non-delegated) service groups as catalog resources (required before creating access packages)                                                                                                                                                                                                                                                                                       |
| 5   | `New-EntraOpsServiceEMCatalogResourceRole`             | Assigns catalog roles: Owner (ControlPlane-Admins, skipped with `-SkipCatalogOwnerAssignment`), Reader (CatalogPlane-Members, WorkloadPlane-Admins, ManagementPlane-Admins), AP Assignment Manager (ManagementPlane-Admins)                                                                                                                                                                              |
| 6   | `New-EntraOpsServiceEMAccessPackage`                   | Creates one access package per non-Unified role except ControlPlane-Admins                                                                                                                                                                                                                                                                                                                               |
| 7   | `New-EntraOpsServiceEMAccessPackageResourceAssignment` | Maps group roles into access packages as resource role scopes: Member, or Eligible Member for PIM-managed groups (`-EligibleMemberGroupIds`, set by the bootstrap with `-EnablePimForGroups` / `-EnableWorkloadPlanePimForGroups`)                                                                                                                                                                       |
| 8   | `New-EntraOpsServiceEMAssignmentPolicy`                | Creates assignment policies: requestor scopes, approvers, expiration, quarterly access reviews                                                                                                                                                                                                                                                                                                           |
| 9   | `New-EntraOpsServiceEMAssignment`                      | Initial `adminAdd` assignments: service members → WorkloadPlane-Members (fallback WorkloadPlane-Users); admin → ManagementPlane-Admins (fallback WorkloadPlane-Admins); admin and `-CatalogPlaneMembers` → CatalogPlane-Members                                                                                                                                                                          |
| 10  | `New-EntraOpsServicePIMPolicy`                         | Configures PIM for Groups activation policies (MFA, justification, optional authentication context, max duration (10 hours), no approval) for ControlPlane-/ManagementPlane-Admins with `-EnablePimForGroups` and WorkloadPlane-Admins with `-EnableWorkloadPlanePimForGroups`, before the groups are added to the catalog; only called when a group is selected (`PimPolicies` in the bootstrap report) |
| 11  | `New-EntraOpsServicePIMAssignment`                     | Creates the PIM for Groups eligible owner assignments of the WorkloadPlane groups; only called with `-GroupOwnership Eligible`. Returned as `PimForGroupsAssignments` in the bootstrap report                                                                                                                                                                                                            |
| 12  | `New-EntraOpsServiceAZContainer`                       | Creates the Azure Resource Group `RG-<Prefix>` (or, with `-AzureScope Subscription`, uses the subscription) with PIM-eligible RBAC (Contributor, UAA, constrained RBAC Administrator) and permanent Reader for WorkloadPlane-Admins; assigns no Owner role                                                                                                                                               |
| 13  | `New-EntraOpsSubscriptionLandingZone`                  | **Landing Zone** — exactly one scope: resource group (default) or subscription (`-DeploymentScope`); resolves governance model and delegation groups                                                                                                                                                                                                                                                     |
| 14  | `Get-EntraOpsServiceEMReport`                          | Read-only report of **all** Entitlement Management catalogs in the tenant (roles, resources, access packages, policies, delivered assignments)                                                                                                                                                                                                                                                           |
| 15  | `Remove-EntraOpsServiceCatalog`                        | Cleanup cmdlet — removes assignments, access packages, the catalog and the groups of the landing zone registered as catalog resources; deletes the Azure RG only with `-RemoveAzureResourceGroup -SubscriptionId` (see note below)                                                                                                                                                                       |
| 16  | `Resolve-EntraOpsServiceEMDelegationGroup`             | Resolves (by ID or display name) or creates a role-assignable ControlPlane/ManagementPlane delegation group and persists its ID to `EntraOpsConfig.json`                                                                                                                                                                                                                                                 |

> **`Remove-EntraOpsServiceCatalog` and the resource group:** the resource group is **kept by default**; role assignments of the
> deleted groups remain on it as orphaned assignments. Add the opt-in switch `-RemoveAzureResourceGroup` together with
> `-SubscriptionId` to delete `RG-MyApp` (including all its resources) in that subscription when removing `Catalog-Rg-MyApp`;
> without `-SubscriptionId` the cmdlet stops before deleting anything, so a resource group with the same name in the subscription
> of the current Azure context can't be deleted by mistake. Only a resource group with the tag `EntraOpsServiceEM = {ServiceName}`
> (set when the landing zone creates it) is deleted; an existing resource group that the landing zone reused is kept with a
> warning. Removing `Catalog-Sub-MyApp` never deletes a resource group
> and warns that Azure role assignments on the subscription (`-DeploymentScope Subscription`) must be removed manually.
> Only groups created by the landing zone are deleted: catalog resources whose mailNickname starts with `{ServiceName}.`.
> Other groups in the catalog (e.g. shared groups added manually) are kept with a warning, delegated groups
> are never registered as catalog resources, and `-ExcludeGroupIds` protects additional groups.
> The cmdlet asks for confirmation before deleting anything; `-Force` (or `-Confirm:$false`) skips the prompt for automation,
> and `-WhatIf` shows the catalog, number of access packages and group resources without changing anything.
>
> ```powershell
> Remove-EntraOpsServiceCatalog -ServiceCatalogName "Catalog-Rg-MyApp" -WhatIf
> Remove-EntraOpsServiceCatalog -ServiceCatalogName "Catalog-Rg-MyApp" -Force -RemoveAzureResourceGroup -SubscriptionId "<subscription-id>"
> ```

### Naming Conventions

ServiceEM follows consistent naming patterns for all created resources. `{ServiceName}` is `{Scope}-{DeploymentPrefix}` for landing
zones (e.g. `Sub-MyApp`, `Rg-MyApp`) or the `-ServiceName` of `New-EntraOpsServiceBootstrap`.

| Resource Type                          | Pattern                                                                                                                                                                                                                                                                                                           | Example                                  |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| **Unified Group**                      | `{ServiceName} Members` (mailNickname `{ServiceName}.Members`), only with `-CreateM365Group`                                                                                                                                                                                                                      | `Rg-MyApp Members`                       |
| **Security Group**                     | `{GroupPrefix}-{ServiceName}-{AccessLevel}-{Name}` (mailNickname `{ServiceName}.{AccessLevel}.{Name}`)                                                                                                                                                                                                            | `SG-Rg-MyApp-WorkloadPlane-Admins`       |
| **Delegation Group (ControlPlane)**    | `ControlPlaneGroupName` (default)                                                                                                                                                                                                                                                                                 | `PRG-Tenant-ControlPlane-IdentityOps`    |
| **Delegation Group (ManagementPlane)** | `ManagementPlaneGroupName` (default)                                                                                                                                                                                                                                                                              | `PRG-Tenant-ManagementPlane-PlatformOps` |
| **EM Catalog**                         | `Catalog-{ServiceName}`                                                                                                                                                                                                                                                                                           | `Catalog-Rg-MyApp`                       |
| **Access Package**                     | `AP-{ServiceName}-{AccessLevel}-{Name}`                                                                                                                                                                                                                                                                           | `AP-Rg-MyApp-WorkloadPlane-Users`        |
| **Assignment Policy**                  | Fixed names per access package: `Baseline Policy`, `Workload Plane Users Policy`, `Workload Plane Policy`, `Management Plane Policy`, `Initial Workload Membership Policy`, `Initial Management Admin Policy`, `Initial Workload Users Policy`, `Initial Workload Admin Policy`, `Initial Catalog Members Policy` | `Initial Workload Admin Policy`          |
| **Resource Group**                     | `RG-{ServiceName}` without `Sub-`/`Rg-` prefix                                                                                                                                                                                                                                                                    | `RG-MyApp`                               |

**Scope Prefixes:**
- `Sub-{DeploymentPrefix}` — Subscription scope (`-DeploymentScope Subscription`: role assignments on the subscription)
- `Rg-{DeploymentPrefix}` — Resource group scope (default)

**Customizable names:** `{GroupPrefix}` (default `SG`, `-GroupPrefix` or `ServiceEM.GroupPrefix`), the delegation group names
(`ControlPlaneGroupName`, `ManagementPlaneGroupName`) and `{DeploymentPrefix}`. All other parts (`Catalog-`, `AP-`, `RG-`, the
scope prefixes, plane/role names and policy names) are fixed, because ServiceEM uses them to find its objects again. Existing
groups are matched by mailNickname, which doesn't contain `{GroupPrefix}`: after changing the prefix, re-runs keep using the
existing groups with their previous display names, only new groups get the new prefix. The diagrams in this documentation use `SG`.

### Groups Created per Service

Groups created depend on the **governance model** and the **deployment scope**.

#### Single scope (`-DeploymentScope ResourceGroup` or `Subscription`)

One scope `{Scope}-{Prefix}` (`Rg-` or `Sub-`) with one catalog:

| Group                                        | Centralized                | PerService                | Purpose                                                                                           |
| -------------------------------------------- | -------------------------- | ------------------------- | ------------------------------------------------------------------------------------------------- |
| `{Scope}-{Prefix} Members`                   | ✅ with `-CreateM365Group`  | ✅ with `-CreateM365Group` | Microsoft 365 group for team collaboration (no access to the other groups)                        |
| `SG-{Scope}-{Prefix}-WorkloadPlane-Users`    | ✅                          | ✅                         | End-user data-plane access; target group of the WorkloadPlane constrained delegation              |
| `SG-{Scope}-{Prefix}-WorkloadPlane-Admins`   | ✅                          | ✅                         | Permanent Reader, PIM eligible constrained RBAC Administrator                                     |
| `SG-{Scope}-{Prefix}-CatalogPlane-Members`   | ❌ (`AdministratorGroupId`) | ✅                         | Catalog Reader; requestor scope, approver of its own package                                      |
| `SG-{Scope}-{Prefix}-ManagementPlane-Admins` | ❌ (delegated)              | ✅                         | Catalog Reader + AP Assignment Manager; PIM eligible Contributor + constrained RBAC Administrator |
| `SG-{Scope}-{Prefix}-ControlPlane-Admins`    | ❌ (delegated)              | ✅                         | Catalog Owner (unless `-SkipCatalogOwnerAssignment`); PIM eligible User Access Administrator      |

**NOT Created (Centralized):**
- ❌ ControlPlane-Admins (delegated from `ServiceEM.ControlPlaneDelegationGroupId`)
- ❌ ManagementPlane-Admins (delegated from `ServiceEM.ManagementPlaneDelegationGroupId`)
- ❌ CatalogPlane-Members (delegated from `ServiceEM.AdministratorGroupId`)
- ❌ WorkloadPlane-Members (not part of the landing zone roles in either model)

The same applies to the PerService model for every group passed as delegation group (`-ControlPlaneDelegationGroupId`,
`-ManagementPlaneDelegationGroupId`, `-AdministratorGroupId`), see
[Separating governance and workload groups](#separating-governance-and-workload-groups).

### Azure RBAC Implementation (Resource Group or Subscription Scope)

All assignments target the resource group `RG-{Prefix}` (`-DeploymentScope ResourceGroup`) or, with
`-DeploymentScope Subscription`, the subscription `-SubscriptionId` (no resource group is created). Delegated groups receive
their roles on the same resource group or subscription. The table shows the resource group case; the subscription case uses the same roles.

#### Assignments on `RG-{Prefix}` (or the subscription)

| Group (if present in the scope)                   | Azure RBAC Role                         | Type                        | Notes                                                                                     |
| ------------------------------------------------- | --------------------------------------- | --------------------------- | ----------------------------------------------------------------------------------------- |
| `SG-{Scope}-{Prefix}-WorkloadPlane-Admins`        | Reader                                  | Permanent (active)          | Always assigned                                                                           |
| `SG-{Scope}-{Prefix}-WorkloadPlane-Admins`        | Role Based Access Control Administrator | PIM eligible, no expiration | ABAC: only `WorkloadPlane.AllowedRoleDefinitionIds` → WorkloadPlane-Users                 |
| ManagementPlane-Admins (per-service or delegated) | Contributor                             | PIM eligible, no expiration | Skipped if already eligible at a parent scope                                             |
| ManagementPlane-Admins (per-service or delegated) | Role Based Access Control Administrator | PIM eligible, no expiration | ABAC: all roles except `ManagementPlane.ExcludedRoleDefinitionIds` → WorkloadPlane-Admins |
| ControlPlane-Admins (per-service or delegated)    | User Access Administrator               | PIM eligible, no expiration | Skipped if already eligible at a parent scope                                             |

ServiceEM also updates the PIM for Azure resources policy of these roles on the resource group (or subscription) so that
eligible assignments are not required to expire. ServiceEM assigns no Owner role: unrestricted access (role assignments
including Owner) remains only with ControlPlane-Admins via the PIM-eligible User Access Administrator.

> **No Contributor for WorkloadPlane-Admins:** Contributor on the resource group (or subscription) equals ManagementPlane control
> (e.g. managed identities, Key Vault access policies, run command on virtual machines) and would be a tier breach for the
> WorkloadPlane. WorkloadPlane-Admins therefore only get Reader and the constrained Role Based Access Control Administrator;
> resource-level or other roles (e.g. Website Contributor) are assigned to them by ManagementPlane-Admins through their constrained
> Role Based Access Control Administrator. Without any ManagementPlane-Admins for the scope (e.g.
> custom `-ServiceRoles`), a warning states that nobody gets Contributor from ServiceEM.

#### Prerequisites for Azure RBAC

To create the resource group and the Azure RBAC assignments, the calling identity requires on the subscription:
- **Owner**, or **Contributor** + **User Access Administrator** (resource group creation, role eligibility schedule requests and role management policy updates)

No additional Microsoft Graph permission is needed for the Azure part.

#### When Azure RBAC is NOT Created

Azure RBAC assignments are **skipped** when:
- `-SkipAzureResourceGroup` parameter is used (e.g. a governance scope created with `New-EntraOpsServiceBootstrap`; its groups get their roles as delegated groups of the workload landing zones)
- The caller lacks Azure subscription permissions (errors are written, the deployment continues)
- No Azure context/subscription is selected

> **Important:** When using `-SkipAzureResourceGroup`, only Entra ID objects (groups, catalogs, access packages, PIM for Groups) are created - the group and access package counts don't change. Azure RBAC assignments and resource groups are not created. This is useful for testing or when Azure resources will be managed separately.

#### PIM for Groups Integration

ServiceEM configures PIM for Groups only with the opt-in switches (see
[EnablePimForGroups and EnableWorkloadPlanePimForGroups Parameters](#enablepimforgroups-and-enableworkloadplanepimforgroups-parameters)):

1. **PIM Policies** (ControlPlane-/ManagementPlane-Admins with `-EnablePimForGroups`, WorkloadPlane-Admins with
   `-EnableWorkloadPlanePimForGroups`; none without these switches):
   - MFA and justification required, no approval
   - Authentication context can be enforced (if configured in EntraOpsConfig.json)
   - Maximum activation duration of 10 hours (default, `ServiceEM.PIMForGroups.MaximumActivationDuration`)

2. **Eligible assignments** (no expiration):
   - Access packages of the selected groups grant **eligible membership** (Eligible Member resource role); the eligibility ends
     with the access package assignment
   - With `-EnablePimForGroups` and `-ControlPlaneAdmins`: the users become eligible **members** of ControlPlane-Admins
   - With `-GroupOwnership Eligible`: the admin becomes eligible **owner** of the WorkloadPlane groups (WorkloadPlane-Admins, WorkloadPlane-Users)
   - WorkloadPlane-Users, CatalogPlane-Members, the Microsoft 365 group of [`-CreateM365Group`](#createm365group-parameter) and
     delegated groups never get PIM for Groups

The report of `New-EntraOpsServiceBootstrap` (returned by `New-EntraOpsSubscriptionLandingZone` for its scope) lists the configured policies
in `PimPolicies` and the eligible owner assignments of `-GroupOwnership Eligible` in `PimForGroupsAssignments` (absent or empty
otherwise).

#### Verification Commands

```powershell
# Check PIM for Groups eligible assignments of a group
Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$groupId'" -OutputType PSObject

# Check PIM eligible and active Azure RBAC assignments on the landing zone resource group
$rgId = (Get-AzResourceGroup -Name "RG-MyApp").ResourceId
Get-AzRoleEligibilitySchedule -Scope $rgId
Get-AzRoleAssignment -Scope $rgId
```

### Access Packages Created

Access packages are created for every owned, non-Unified group except ControlPlane-Admins - never for delegated groups. The number and type depend on governance model and scope:

#### Centralized Governance

Same access packages for every landing zone with delegated ControlPlane-/ManagementPlane-Admins and `AdministratorGroupId`
(with `-DeploymentScope Subscription` the names start with `AP-Sub-`).

| Access Package                        | Grants Membership To                  | Policy                        | Requestors                                          | Approver                                  | Expiration |
| ------------------------------------- | ------------------------------------- | ----------------------------- | --------------------------------------------------- | ----------------------------------------- | ---------- |
| `AP-Rg-{Prefix}-WorkloadPlane-Users`  | `SG-Rg-{Prefix}-WorkloadPlane-Users`  | Workload Plane Users Policy   | All member users³                                   | WorkloadPlane-Admins                      | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Users`  | `SG-Rg-{Prefix}-WorkloadPlane-Users`  | Initial Workload Users Policy | Admin-assigned only (initial `-ServiceMembers`)     | No approval                               | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Admins` | `SG-Rg-{Prefix}-WorkloadPlane-Admins` | Workload Plane Policy         | CatalogPlane-Members (`AdministratorGroupId`)       | ManagementPlane-Admins (delegated group)² | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Admins` | `SG-Rg-{Prefix}-WorkloadPlane-Admins` | Initial Workload Admin Policy | Admin-assigned only (initial `-WorkloadPlaneAdmin`) | No approval                               | 365 days   |

The same applies to the workload landing zone of
[Separating governance and workload groups](#separating-governance-and-workload-groups); the
governance scope gets the CatalogPlane-Members and ManagementPlane-Admins access packages of the PerService table below.

#### PerService Governance

**Single scope (default `-DeploymentScope ResourceGroup`, 4 access packages; `Subscription` uses `AP-Sub-`):**
| Access Package                          | Grants Membership To                    | Policy                          | Requestors                                                                  | Approver                | Expiration |
| --------------------------------------- | --------------------------------------- | ------------------------------- | --------------------------------------------------------------------------- | ----------------------- | ---------- |
| `AP-Rg-{Prefix}-CatalogPlane-Members`   | `SG-Rg-{Prefix}-CatalogPlane-Members`   | Baseline Policy                 | CatalogPlane-Members                                                        | CatalogPlane-Members    | 365 days   |
| `AP-Rg-{Prefix}-CatalogPlane-Members`   | `SG-Rg-{Prefix}-CatalogPlane-Members`   | Initial Catalog Members Policy  | Admin-assigned only (initial `-WorkloadPlaneAdmin`, `-CatalogPlaneMembers`) | No approval             | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Users`    | `SG-Rg-{Prefix}-WorkloadPlane-Users`    | Workload Plane Users Policy     | All member users³                                                           | WorkloadPlane-Admins    | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Users`    | `SG-Rg-{Prefix}-WorkloadPlane-Users`    | Initial Workload Users Policy   | Admin-assigned only (initial `-ServiceMembers`)                             | No approval             | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Admins`   | `SG-Rg-{Prefix}-WorkloadPlane-Admins`   | Workload Plane Policy           | CatalogPlane-Members¹                                                       | ManagementPlane-Admins² | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Admins`   | `SG-Rg-{Prefix}-WorkloadPlane-Admins`   | Initial Workload Admin Policy   | Admin-assigned only                                                         | No approval             | 365 days   |
| `AP-Rg-{Prefix}-ManagementPlane-Admins` | `SG-Rg-{Prefix}-ManagementPlane-Admins` | Management Plane Policy         | CatalogPlane-Members                                                        | ControlPlane-Admins⁴    | 365 days   |
| `AP-Rg-{Prefix}-ManagementPlane-Admins` | `SG-Rg-{Prefix}-ManagementPlane-Admins` | Initial Management Admin Policy | Admin-assigned only (initial `-WorkloadPlaneAdmin`)                         | No approval             | 365 days   |

In the single scope the `-WorkloadPlaneAdmin` is initially assigned to ManagementPlane-Admins (not WorkloadPlane-Admins),
because the ManagementPlane-Admins access package exists in the scope, and to CatalogPlane-Members.

¹ WorkloadPlane-Members if such a group exists in the scope (only with custom `-ServiceRoles`); neither the landing zone roles nor the `New-EntraOpsServiceBootstrap` default roles include it.

² ManagementPlane-Admins of the scope: the per-service group or the delegated group (`-ManagementPlaneDelegationGroupId`, Centralized model). If no ManagementPlane-Admins approver exists at all (e.g. custom `-ServiceRoles` or `-SkipManagementPlaneDelegation` without a delegation group), the Workload Plane Policy isn't created; the admin-assigned Initial Workload Admin Policy still is. The Workload Plane Users Policy is approved by WorkloadPlane-Admins, otherwise by the ManagementPlane-Admins approver, otherwise it isn't created. CatalogPlane-Members only approve their own access package (Baseline Policy).

³ Default `ServiceEM.AssignmentPolicies.WorkloadPlaneUsers.RequestorScope` = `AllMemberUsers`; `CatalogPlaneMembers` restricts requests to CatalogPlane-Members.

⁴ No escalation and no fallback approver. The Management Plane Policy is only created when an approver exists: ControlPlane-Admins of the same scope (own or delegated). Missing Management Plane Policies are checked by policy name and added to existing landing zones on a re-run; earlier versions could fail to create it, so ManagementPlane-Admins could only be assigned by administrators.

The Initial Catalog Members Policy is only created for a per-service CatalogPlane-Members group (PerService model), not when `AdministratorGroupId` replaces it.

The expiration ("Assignments expire after") of each policy, and therefore of each access package, is configured separately in
`ServiceEM.AssignmentPolicies.<Policy>.Expiration` or in the Configuration Wizard (default 365 days for all policies, see
[Assignment Policy, Access Review and PIM for Groups Settings](#assignment-policy-access-review-and-pim-for-groups-settings)).

> **Note**: No access packages are created for ControlPlane-Admins — initial members are added with `-ControlPlaneAdmins` (see [Service Owner and Member Assignment](#service-owner-and-member-assignment)), otherwise by an Entra administrator in the portal.

> **Note**: With `-EnablePimForGroups` the ManagementPlane-Admins access package (and with `-EnableWorkloadPlanePimForGroups` the
> WorkloadPlane-Admins access package) grants **eligible** membership instead of active membership (see
> [EnablePimForGroups and EnableWorkloadPlanePimForGroups Parameters](#enablepimforgroups-and-enableworkloadplanepimforgroups-parameters)).

### Assignment Policies

Each access package has an **assignment policy** that controls who can request access, who must approve, and how long access lasts. ServiceEM automatically creates assignment policies with default configurations.

#### Default Assignment Policy Configuration

| Setting                                       | Default Value                       | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| --------------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Allowed Requestors** (`allowedTargetScope`) | `specificDirectoryUsers`            | Members of the requestor group listed above; `allMemberUsers` for WorkloadPlane-Members and WorkloadPlane-Users; `allMemberUsers` with all requests disabled (admin-assigned only) for the Initial Management Admin, Initial Workload Users, Initial Workload Admin and Initial Catalog Members policies, because administrator direct assignments are also limited to the target scope                                                                                                                                                                 |
| **Requestor Settings**                        | Self-add, self-remove and extension | No custom schedule, no on-behalf requests; extension ("Allow users to extend access", with approval) only for the Baseline, Workload Plane (Users) and Management Plane policies (`AllowExtension`); no requests and no extension for the admin-assigned initial policies                                                                                                                                                                                                                                                                               |
| **Approval Required**                         | Yes                                 | Single stage with approver justification (two stages - requestor's manager, then CatalogPlane-Members - for WorkloadPlane-Members); not required for the admin-assigned initial policies                                                                                                                                                                                                                                                                                                                                                                |
| **Approvers**                                 | Tier-specific groups                | See tables above; only the same or a higher tier approves, a policy without such an approver isn't created (see footnote ² above). CatalogPlane-Members only approve their own access package (Baseline Policy)                                                                                                                                                                                                                                                                                                                                         |
| **Access Duration** (`expiration`)            | 365 days                            | Assignments of all policies expire after 365 days; configurable per policy in `ServiceEM.AssignmentPolicies` (see [Assignment Policy, Access Review and PIM for Groups Settings](#assignment-policy-access-review-and-pim-for-groups-settings)). Users get reminders 14 days and 1 day before expiry and can request an extension through the standard policies; an initial assignment can't be extended, the user requests the access package again through the standard policy of the package                                                         |
| **Approval Timeout**                          | 2 days / 1 day                      | Pending requests are denied after 2 days (1 day for the Management Plane Policy); configurable in `ServiceEM.AssignmentPolicies`                                                                                                                                                                                                                                                                                                                                                                                                                        |
| **Access Reviews**                            | Quarterly                           | Every 3 months starting 4 days after deployment, 25-day review period; reviewers ManagementPlane-Admins (WorkloadPlane-Admins for the WorkloadPlane-Users access package, ControlPlane-Admins for the ManagementPlane-Admins access package; only groups of the scope (own or delegated) are used; a missing group falls back to a higher tier only, otherwise the policy gets no access review); access is kept if not reviewed; configurable in `ServiceEM.AccessReviews`, including self-review, specific reviewers or the user's manager per policy |
| **Questions**                                 | None                                | No custom questions configured by default                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |

> **Policy precedence:** Entra ID applies a policy for specific users and groups before an "all members" policy of the same access
> package and ignores the latter for users in its scope ([Multiple policies](https://learn.microsoft.com/entra/id-governance/entitlement-management-troubleshoot#multiple-policies)).
> A workload plane admin who is a member of the requestor group of the Workload Plane Policy (e.g. `AdministratorGroupId`) is
> therefore rejected by the Initial Workload Admin Policy (`You don't meet policy requirements`). `New-EntraOpsServiceEMAssignment`
> then adds the rejected user as a specific user to the admin-assigned initial policy (it becomes `specificDirectoryUsers`) and
> retries for up to 60 seconds. Later initial assignments through this policy add their users the same way.

#### Assignment Policy Creation Behavior

**Successfully Created:**
- Policies are linked to their respective access packages
- Existing policies of an access package are not modified when the deployment is re-run

**Common Issues:**
- **BadRequest errors**: Some assignment policies may fail to create due to:
  - A referenced requestor or approver group that doesn't exist (e.g. CatalogPlane-Members without `AdministratorGroupId` in the Centralized model)
  - Graph API replication delays of newly created groups
  
> **Note:** If assignment policy creation fails, the access package is still created but won't have an assignment policy, and the initial member/admin assignments of that scope are skipped. Create the policy manually in the Microsoft Entra admin center or via PowerShell.

#### Post-Deployment Actions

After deployment, review and customize assignment policies:

1. **Review in the Microsoft Entra admin center:**
   - Navigate to Identity Governance > Entitlement management > Access packages
   - Select the access package
   - Review the "Policies" tab

2. **Customize Approvers:**
   - Adjust approver groups based on your organization structure
   - Add fallback approvers
   - Configure multi-stage approval if needed

3. **Adjust Access Duration:**
   - Modify expiration settings per organizational requirements
   - Adjust the access review settings for compliance

4. **Add Custom Questions:**
   - Add justification questions
   - Configure required fields

#### PowerShell Commands

```powershell
# Get all assignment policies for an access package
(Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/identityGovernance/entitlementManagement/accessPackages/$($accessPackageId)?`$expand=assignmentPolicies" -OutputType PSObject).assignmentPolicies

# Create a new assignment policy (same schema as used by ServiceEM)
$newPolicy = @{
    displayName            = "Custom Policy"
    description            = "Custom policy"
    accessPackage          = @{ id = $accessPackageId }
    allowedTargetScope     = "specificDirectoryUsers"
    specificAllowedTargets = @(
        @{
            "@odata.type" = "#microsoft.graph.groupMembers"
            groupId       = $requestorGroupId
        }
    )
    requestApprovalSettings = @{
        isApprovalRequiredForAdd    = $true
        isApprovalRequiredForUpdate = $false
        stages = @(
            @{
                durationBeforeAutomaticDenial   = "P2D"
                isApproverJustificationRequired = $true
                isEscalationEnabled             = $false
                durationBeforeEscalation        = "PT0S"
                primaryApprovers = @(
                    @{
                        "@odata.type" = "#microsoft.graph.groupMembers"
                        groupId       = $approverGroupId
                    }
                )
            }
        )
    }
    expiration = @{
        duration = "P365D"
        type     = "afterDuration"
    }
}

Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/assignmentPolicies" `
    -Body ($newPolicy | ConvertTo-Json -Depth 10) -OutputType PSObject
```

#### Troubleshooting Assignment Policy Failures

**Symptom:**
```
WARNING: Failed to execute .../assignmentPolicies
Error: Response status code does not indicate success: BadRequest
```

**Resolution Steps:**
1. Wait 5-10 minutes for group replication, then retry
2. Verify WorkloadPlaneAdmin and ServiceMembers are valid users
3. Check that all referenced groups exist in the same scope (see [Access Packages Created](#access-packages-created))
4. Manually create the assignment policy in the Microsoft Entra admin center

### Module Dependencies

ServiceEM uses the same module dependencies as the rest of EntraOps. No separate `Install-Module` is needed:
`Connect-EntraOps` (or `Install-EntraOpsAllRequiredModules`) installs missing modules automatically.

| Module                             | Purpose                                                                                                                                                                                  |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Az.Accounts**                    | Azure sign-in and context (`Get-AzContext`, `Get-AzAccessToken`)                                                                                                                         |
| **Az.Resources**                   | Resource group, Azure RBAC and PIM for Azure resources operations                                                                                                                        |
| **Microsoft.Graph.Authentication** | Graph sign-in and `Get-MgContext` (default user/member lookup, delegation group auto-creation); not needed with `UseInvokeRestMethodOnly` and service principal/managed identity sign-in |

All Microsoft Graph calls of the ServiceEM cmdlets (groups, users, Entitlement Management, PIM for Groups) go through
`Invoke-EntraOpsMsGraphQuery`, so no further Microsoft Graph SDK modules (e.g. `Microsoft.Graph.Groups`, `Microsoft.Graph.Users`,
`Microsoft.Graph.Identity.Governance`) and no `Az.ResourceGraph` are required.

**Required Scopes:** Use `Connect-EntraOps -Scope "ServiceEM"` for delegated sign-in; see [Required permissions](#required-permissions)
for the requested delegated scopes and the application permissions of workload identities.

### Delegation Behavior Summary

When a delegation Group ID is provided (via `EntraOpsConfig.json` or parameter), the following behavior applies:

| Behavior                           | ControlPlane                                                                         | ManagementPlane                                                    | CatalogPlane            |
| ---------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------ | ----------------------- |
| **Group created**                  | No                                                                                   | No                                                                 | No                      |
| **Synthetic entry injected**       | Yes (with DisplayName)                                                               | Yes (with DisplayName)                                             | Yes (with DisplayName)  |
| **Registered as catalog resource** | No                                                                                   | No                                                                 | No                      |
| **Catalog role assigned**          | Yes (Owner)                                                                          | Yes (Reader, AP Assignment Manager)                                | Yes (Reader)            |
| **Referenced in AP policies**      | Approver/reviewer of ManagementPlane-Admins AP (if ManagementPlane is not delegated) | Approver and access reviewer                                       | Requestor scope         |
| **Azure RBAC assigned (RG)**       | Yes (UAA, PIM-eligible)                                                              | Yes (Contributor and constrained RBAC Administrator, PIM-eligible) | —                       |
| **PIM policy applied to group**    | No (managed externally)                                                              | No (managed externally)                                            | No (managed externally) |
| **PIM eligibility created**        | No (managed externally)                                                              | No (managed externally)                                            | No (managed externally) |
| **Access package created**         | No                                                                                   | No                                                                 | No                      |

The delegated groups are **read-only** from ServiceEM's perspective — they receive role assignments and policy references but are never modified (no PIM policies, no eligibility assignments) and are not deleted by `Remove-EntraOpsServiceCatalog`.

### Parameter Impact Matrix

This matrix shows how each parameter affects the objects created during deployment:

#### New-EntraOpsSubscriptionLandingZone Parameters

| Parameter                                                                                                                             | Groups                                                  | Catalogs | Azure Resources                      | Access Packages                                                     | PIM for Groups                                                                                       |
| ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | -------- | ------------------------------------ | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| **None (defaults: ResourceGroup, PerService)**                                                                                        | ✅ 5 created                                             | 1        | ✅ RG + RBAC                          | ✅ 4 created                                                         | ❌ None (opt-in)                                                                                      |
| `-DeploymentScope Subscription`                                                                                                       | ✅ 5 created                                             | 1        | ⚠️ No RG; RBAC on the subscription    | ✅ 4 created                                                         | ❌ None (opt-in)                                                                                      |
| `-SkipAzureResourceGroup`                                                                                                             | ✅ 5 created                                             | 1        | ❌ Skipped                            | ✅ 4 created                                                         | ❌ None (opt-in)                                                                                      |
| `-EnablePimForGroups`                                                                                                                 | ✅ 5 created                                             | 1        | ✅ RG + RBAC                          | ✅ 4 created                                                         | ✅ Policies for ControlPlane-/ManagementPlane-Admins; their access packages grant eligible membership |
| `-EnableWorkloadPlanePimForGroups`                                                                                                    | ✅ 5 created                                             | 1        | ✅ RG + RBAC                          | ✅ 4 created                                                         | ✅ Policy for WorkloadPlane-Admins; its access package grants eligible membership                     |
| `-CreateM365Group`                                                                                                                    | ✅ +1 (Microsoft 365 group)                              | 1        | ✅ RG + RBAC                          | ✅ 4 created (each also grants Microsoft 365 group membership)       | ❌ None (never for the Microsoft 365 group)                                                           |
| `-GovernanceModel Centralized`                                                                                                        | ⚠️ 2 created                                             | 1        | ✅ RG + RBAC (incl. delegated groups) | ⚠️ 2 created                                                         | ❌ None (WorkloadPlane-Admins only with `-EnableWorkloadPlanePimForGroups`)                           |
| Delegation IDs of a governance scope (`-ControlPlaneDelegationGroupId`, `-ManagementPlaneDelegationGroupId`, `-AdministratorGroupId`) | ⚠️ 2 created (WorkloadPlane-Users, WorkloadPlane-Admins) | 1        | ✅ RG + RBAC (incl. delegated groups) | ⚠️ 2 created                                                         | ❌ None (delegated groups get PIM for Groups from the governance call)                                |
| `-WorkloadPlaneAdmin`                                                                                                                 | —                                                       | —        | N/A                                  | Admin assigned (adminAdd) to the admin and CatalogPlane-Members APs | N/A                                                                                                  |
| `-CatalogPlaneMembers`                                                                                                                | —                                                       | —        | N/A                                  | Users assigned to the CatalogPlane-Members AP (adminAdd)            | N/A                                                                                                  |
| `-ControlPlaneAdmins`                                                                                                                 | Members of ControlPlane-Admins (PerService)             | —        | N/A                                  | —                                                                   | Eligible members with `-EnablePimForGroups`, otherwise permanent members                             |
| `-SkipCatalogOwnerAssignment`                                                                                                         | —                                                       | —        | N/A                                  | No Catalog Owner for ControlPlane-Admins                            | N/A                                                                                                  |
| `-GroupOwnership Permanent`                                                                                                           | Admin is owner of created WorkloadPlane groups          | —        | N/A                                  | —                                                                   | N/A                                                                                                  |
| `-GroupOwnership Eligible`                                                                                                            | —                                                       | —        | N/A                                  | —                                                                   | Admin is eligible owner of the WorkloadPlane groups                                                  |
| `-ServiceMembers`                                                                                                                     | —                                                       | —        | N/A                                  | Members assigned to the WorkloadPlane-Users AP (adminAdd)           | N/A                                                                                                  |

**Legend:**
- ✅ Created/Configured as expected
- ⚠️ Reduced/changed set of objects
- ❌ Not created/Skipped

#### Detailed Impact Explanations

**`-SkipAzureResourceGroup`**

When this parameter is used:

**Created:**
- All groups of the scope
- The catalog
- All access packages, assignment policies and initial assignments
- PIM for Groups policies and eligible assignments (only with `-EnablePimForGroups`, `-EnableWorkloadPlanePimForGroups` or `-GroupOwnership Eligible`)

**Skipped:**
- Azure Resource Group creation
- Azure RBAC assignments on the resource group or subscription (incl. constrained delegation conditions)

`-AzureRegion` and `-SubscriptionId` are not required in this case.

**`-GovernanceModel Centralized`**

When using Centralized governance:

**Created (default `ResourceGroup` scope):**
- SG-Rg-{Prefix}-WorkloadPlane-Users
- SG-Rg-{Prefix}-WorkloadPlane-Admins
- Rg-{Prefix} Members (Unified, only with `-CreateM365Group`)
- 2 access packages

**Delegated (Not Created):**
- ControlPlane-Admins (uses tenant-wide delegation group)
- ManagementPlane-Admins (uses tenant-wide delegation group)
- CatalogPlane-Members (uses administrator group)

**Prerequisites:**
- ControlPlaneDelegationGroupId in EntraOpsConfig.json (or resolvable/creatable via `ControlPlaneGroupName`)
- ManagementPlaneDelegationGroupId in EntraOpsConfig.json (or resolvable/creatable via `ManagementPlaneGroupName`)
- AdministratorGroupId in EntraOpsConfig.json

**`-EnablePimForGroups` and `-EnableWorkloadPlanePimForGroups`**

When these parameters are used:

**Impact:**
- PIM for Groups policy for ControlPlane-Admins and ManagementPlane-Admins (`-EnablePimForGroups`) and WorkloadPlane-Admins (`-EnableWorkloadPlanePimForGroups`), applied before the groups are added to the catalog
- Their access packages grant eligible membership (Eligible Member) instead of active membership; an existing active Member role is replaced (warning)
- `-ControlPlaneAdmins` are added as eligible members (`-EnablePimForGroups`)
- License warning: requires Microsoft Entra ID Governance or Microsoft Entra Suite licenses (Microsoft Entra ID P2 alone is not sufficient)
- Azure RBAC on the resource group remains PIM eligible (unchanged)

**Use Case:** No standing catalog roles for ControlPlane-/ManagementPlane-Admins (recommended); multi-activation for WorkloadPlane-Admins

**`-WorkloadPlaneAdmin` and `-ServiceMembers`**

**WorkloadPlaneAdmin:**
- Owner of the WorkloadPlane groups only with `-GroupOwnership Permanent` (groups created in this run) or `Eligible` (PIM for Groups eligible owner); never owner of other groups
- Assigned (adminAdd) to the ManagementPlane-Admins access package, or to WorkloadPlane-Admins where no ManagementPlane-Admins package exists, and to the CatalogPlane-Members access package (PerService, Initial Catalog Members Policy)
- Accepts a UPN, object ID or a Graph OData URL (`https://graph.microsoft.com/v1.0/users/<id>` or `.../servicePrincipals/<id>`); defaults to the signed-in user only with `-GroupOwnership Eligible` or `Permanent` (required for app-only sign-in in that case)
- Added to the service members (WorkloadPlane-Users access package) only with `-AddWorkloadPlaneAdminToUsers`

**ServiceMembers:**
- Assigned (adminAdd) to the WorkloadPlane-Members access package, or to WorkloadPlane-Users where no WorkloadPlane-Members package exists
- Defaults to the signed-in user; empty for app-only sign-in
- Must be valid user objects (UPN or object ID)

> **Note:** If WorkloadPlaneAdmin or ServiceMembers are invalid, the user lookup fails and the corresponding assignments are skipped.

### Troubleshooting

This section provides solutions for common issues encountered during ServiceEM deployment.

#### Issue: Assignment Policy Creation Fails

**Symptom:**
```
WARNING: Failed to execute .../assignmentPolicies
Error: Response status code does not indicate success: BadRequest
```

**Causes:**
1. **Missing requestor/approver group in the scope** - e.g. no `AdministratorGroupId` in the Centralized model (CatalogPlane-Members is the requestor scope)
2. **Graph replication delay** - Groups created but not yet available to Entitlement Management
3. **Invalid WorkloadPlaneAdmin or ServiceMembers** - User not found in directory (affects the initial assignments)

**Resolution:**

1. **Wait and Retry** (all ServiceEM steps are idempotent):
   ```powershell
   # Wait 5-10 minutes for Graph replication
   Start-Sleep -Seconds 300
   
   # Retry deployment
   New-EntraOpsSubscriptionLandingZone @params
   ```

2. **Verify Users:**
   ```powershell
   # Check WorkloadPlaneAdmin exists
   Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/users/$WorkloadPlaneAdmin" -OutputType PSObject
   
   # Check ServiceMembers exist
   $ServiceMembers | ForEach-Object {
       Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/users/$_" -OutputType PSObject
   }
   ```

3. **Manual Creation:**
   If retry fails, manually create assignment policies (see [PowerShell Commands](#powershell-commands)).

#### Issue: Service Principal Authentication Fails

**Symptom:**
```
Connect-AzAccount: Unix LocalMachine X509Store is limited to the Root and CertificateAuthority stores.
```

**Cause:**
Certificate thumbprint-based sign-in against the `LocalMachine` certificate store doesn't work on Unix/Linux systems

**Resolution:**
Sign in to Azure with the certificate file and let EntraOps reuse the Azure context for Microsoft Graph:
```powershell
$certPassword = Read-Host -AsSecureString -Prompt "Certificate password"
Connect-AzAccount -ServicePrincipal `
    -ApplicationId "your-client-id" `
    -Tenant "your-tenant-id" `
    -CertificatePath "./path/to/certificate.pfx" `
    -CertificatePassword $certPassword

Connect-EntraOps -AuthenticationType "AlreadyAuthenticated" -TenantName "contoso.onmicrosoft.com"
```

#### Issue: Access Package Assignment Stuck

**Symptom:**
```
WARNING: [New-EntraOpsServiceEMAssignment] Fulfillment can take 5+ minutes to complete
WARNING: [New-EntraOpsServiceEMAssignment] Assignment requests not fulfilled after 300 seconds, continuing without waiting: <request-id>=delivering
```

**Cause:**
Access package assignments require background processing. The cmdlet stops waiting after 5 minutes; the requests are still
completed by Entitlement Management.

**Resolution:**
1. This is normal behavior - wait 5-10 minutes
2. Check assignment status:
   ```powershell
   Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/identityGovernance/entitlementManagement/assignments?`$count=true&`$filter=accessPackage/id eq '$accessPackageId'&`$expand=target" `
       -ConsistencyLevel "eventual" -OutputType PSObject
   ```
3. If still pending after 30 minutes, check the assignment request history in the Microsoft Entra admin center

#### Issue: Catalog Resource Creation Fails

**Symptom:**
```
WARNING: Failed to execute .../resourceRequests
Error: Response status code does not indicate success: BadRequest
```

**Cause:**
Groups not fully replicated before catalog resource registration

**Resolution:**
1. Wait 5-10 minutes for Graph replication and re-run the deployment (already registered groups are skipped)
2. Or add a group to the catalog manually:
   ```powershell
   $resourceRequest = @{
       requestType = "adminAdd"
       resource    = @{ originId = $groupId; originSystem = "AadGroup" }
       catalog     = @{ id = $catalogId }
   }
   Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/resourceRequests" `
       -Body ($resourceRequest | ConvertTo-Json -Depth 5) -OutputType PSObject
   ```

#### Issue: Missing Azure RBAC Assignments

**Symptom:**
No Azure RBAC role assignments created after deployment

**Causes:**
1. Using `-SkipAzureResourceGroup`
2. Looking at the wrong scope - ServiceEM only assigns roles on `RG-<DeploymentPrefix>` (on the subscription only with `-DeploymentScope Subscription`), for the groups of the scope including delegated groups
3. Caller lacks Azure permissions on the subscription passed with `-SubscriptionId`
4. Assignment skipped because the group is already eligible for Contributor/UAA at subscription level (see verbose output)

**Resolution:**

1. **Check Parameter and subscription:**
   ```powershell
   # Ensure -SkipAzureResourceGroup is NOT used and -SubscriptionId targets the right subscription
   Get-AzSubscription -SubscriptionId "<subscription-id>" -TenantId (Get-AzContext).Tenant.Id
   ```

2. **Verify Azure Permissions:**
   ```powershell
   # Check the calling identity has Owner (or Contributor + User Access Administrator) on the subscription
   Get-AzRoleAssignment `
       -ObjectId $callerObjectId `
       -Scope "/subscriptions/$subscriptionId"
   ```

3. **Manual Assignment:**
   ```powershell
   # Manually create a PIM eligible assignment on the landing zone resource group
   $rgId = (Get-AzResourceGroup -Name "RG-MyApp").ResourceId
   $roleId = (Get-AzRoleDefinition -Name "Contributor").Id
   New-AzRoleEligibilityScheduleRequest `
       -Name (New-Guid).Guid `
       -Scope $rgId `
       -PrincipalId $groupId `
       -RoleDefinitionId "/subscriptions/$subscriptionId/providers/Microsoft.Authorization/roleDefinitions/$roleId" `
       -RequestType "AdminAssign" `
       -ScheduleInfoStartDateTime (Get-Date -Format o) `
       -ExpirationType "NoExpiration" `
       -Justification "Manual ServiceEM assignment"
   ```

#### Issue: PIM Policy Not Applied

**Symptom:**
Groups don't have PIM policies configured; 403 Forbidden on `roleManagementPolicyAssignments` or `eligibilityScheduleRequests`

**Cause:**
Deployment without `-EnablePimForGroups` / `-EnableWorkloadPlanePimForGroups` (PIM for Groups is opt-in), the group is never PIM-managed (WorkloadPlane-Users, CatalogPlane-Members, Microsoft 365 group), the group is delegated (never modified by ServiceEM), or the caller lacks the required Microsoft Graph permissions or directory roles.

**Resolution:**
1. Check the PIM for Groups policy assignments of the group:
   ```powershell
   Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '$groupId' and scopeType eq 'Group'" -OutputType PSObject
   ```

2. **For interactive users**: Ensure you connect interactively with the ServiceEM scope (includes all PIM write permissions):
   ```powershell
   Connect-EntraOps -AuthenticationType "UserInteractive" -Scope "ServiceEM" -TenantName "contoso.onmicrosoft.com"
   ```

3. **For service principals**: The app registration needs the **Application** permissions (not Delegated) listed in [Required permissions](#required-permissions) and **admin consent**. `New-EntraOpsWorkloadIdentity` does not assign them - add them manually under **App registrations > API permissions**, then grant **admin consent**.

4. Manually configure PIM policies in the Microsoft Entra admin center as a fallback

### Verification Checklist

After deployment, verify the following:

#### Entra ID Objects
- [ ] All expected groups created (check count, see [Parameter Impact Matrix](#parameter-impact-matrix))
- [ ] WorkloadPlane groups have the expected owners (only with `-GroupOwnership`); no other group has an owner set by ServiceEM
- [ ] Catalogs created
- [ ] Access packages created
- [ ] Assignment policies configured (or manually created if failed)
- [ ] PIM for Groups policies applied to ControlPlane-/ManagementPlane-Admins (only with `-EnablePimForGroups`) and WorkloadPlane-Admins (only with `-EnableWorkloadPlanePimForGroups`)
- [ ] Access packages of these groups contain the Eligible Member role (no warning about a missing Eligible Member role)
- [ ] PIM for Groups eligible owner assignments created (only with `-GroupOwnership Eligible`)

#### Azure Resources (if not using -SkipAzureResourceGroup)
- [ ] Resource group `RG-<DeploymentPrefix>` created
- [ ] Permanent Reader and PIM eligible assignments configured on the resource group
- [ ] Constrained delegation conditions visible on the Role Based Access Control Administrator eligibilities

#### Access and Permissions
- [ ] WorkloadPlaneAdmin is assigned to the admin access package
- [ ] ServiceMembers are assigned to the WorkloadPlane-Users access package
- [ ] Approvers receive approval requests
- [ ] Elevation through PIM works correctly

## References

### Documentation

- **[ServiceEM Landing Zone Visualization](../service-em/landing-zone-visualization.html)** - Comprehensive Mermaid diagrams showing:
  - Group structure by EAM plane (ControlPlane, ManagementPlane, WorkloadPlane, CatalogPlane)
  - Access package → group resource role scopes
  - Assignment policies with requestor scopes and approvers
  - Azure Resource Group RBAC assignments
  - Catalog role assignments
  - Centralized vs. PerService governance model differences
  - Initial user/owner assignment flows

### Microsoft Documentation

- [Azure ABAC Conditions](https://learn.microsoft.com/en-us/azure/role-based-access-control/conditions-format)
- [Authentication Context in Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps#authentication-context)
- [PIM for Groups](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/concept-pim-for-groups)
- [Azure Built-in Roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles)
