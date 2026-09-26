# Service EM

**Developed in collaboration with Michael Soule**

## Introduction

ServiceEM is a submodule of EntraOps that automates the provisioning and management of tiered, service-scoped landing zones aligned with Microsoft's Enterprise Access Model. It provides a complete solution for delegated administration with least-privilege access across Azure and Entra ID.

ServiceEM creates and manages:
- **Azure Resource Groups** with tier-specific RBAC assignments
- **Entra ID Security Groups** (role-assignable) for each service and tier
- **PIM for Groups** policies with configurable authentication contexts
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
> single scope, WorkloadPlane-Admins (which approves WorkloadPlane-Users requests) in the Centralized model or the Rg scope of
> `Both`. The admin isn't added to WorkloadPlane-Users unless `-AddWorkloadPlaneAdminToUsers` is set. It doesn't make the admin a
> group owner: owners are only set with the opt-in
> switch `-AssignOwner`, because owners of role-assignable groups can manage their membership. See [Group owners](#group-owners)
> for the Microsoft 365 group exception.

**That's it!** This creates one resource group scope `Rg-MyFirstApp` (default `-DeploymentScope ResourceGroup`, see [Deployment Scopes](#deployment-scopes)):
- ✅ Role-assignable Entra ID security groups per tier (plus the optional Microsoft 365 group `Rg-MyFirstApp Members` for team collaboration with [`-CreateM365Group`](#createm365group-parameter))
- ✅ One Entitlement Management catalog `Catalog-Rg-MyFirstApp` with access packages and assignment policies
- ✅ PIM for Groups policies and eligible assignments for just-in-time elevation
- ✅ Azure Resource Group `RG-MyFirstApp` with PIM-eligible RBAC assignments

#### Step 3: Verify Deployment

```powershell
# Created groups (including the PIM staging group)
Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/groups?`$filter=startswith(mailNickname,'Rg-MyFirstApp.') or startswith(mailNickname,'PIM.Rg-MyFirstApp.')" -OutputType PSObject |
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
- **Scopes**: `New-EntraOpsSubscriptionLandingZone` runs `New-EntraOpsServiceBootstrap` once for a single scope - `Rg-<DeploymentPrefix>` with the Azure resource group `RG-<DeploymentPrefix>` (default `-DeploymentScope ResourceGroup`) or `Sub-<DeploymentPrefix>` with role assignments on the subscription (`Subscription`) - or twice with `-DeploymentScope Both` (`Sub-` governance groups without Azure resources, `Rg-` workload groups and resource group)
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

| Parameter                                                             | Description                                                                                                          |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `-DeploymentPrefix <string>`                                          | Service name prefix (default: `"Default"`); the scope is named `Rg-<Prefix>` or `Sub-<Prefix>`                       |
| `-DeploymentScope <string>`                                           | `"ResourceGroup"` (default), `"Subscription"` or `"Both"` (two scopes and catalogs), see [Deployment Scopes](#deployment-scopes) |
| `-AzureRegion <string>`                                               | Azure region of the resource group (e.g. `"westeurope"`); required unless `-SkipAzureResourceGroup` is set or `-DeploymentScope` is `Subscription` |
| `-SubscriptionId <string>`                                            | Subscription (GUID) of the resource group; required unless `-SkipAzureResourceGroup` is set. Validated before any object is created; the Azure context is switched for the RBAC step and restored afterwards |
| `-ServiceMembers <string[]>`                                          | UPNs/object IDs assigned to the WorkloadPlane-Users access package; defaults to the signed-in user (empty for app-only). The deployment stops before any object is created if a member or the admin can't be resolved |
| `-AssignOwner`                                                        | Opt-in: sets the admin as owner of created groups                                                                    |
| `-WorkloadPlaneAdmin <string>`                                        | UPN, object ID or Graph URL of the admin, assigned to the admin access package (defaults to the signed-in user only with `-AssignOwner`) |
| `-AddWorkloadPlaneAdminToUsers`                                       | Also assign the admin to the WorkloadPlane-Users access package (default: admin access package only; `ServiceEM.AddWorkloadPlaneAdminToUsers`) |
| `-GovernanceModel <string>`                                           | `"PerService"` or `"Centralized"`; parameter > `ServiceEM.GovernanceModel` in config > `"PerService"`               |
| `-ControlPlaneDelegationGroupId`, `-ManagementPlaneDelegationGroupId`, `-AdministratorGroupId` | Existing groups to use instead of per-service groups; fall back to the `ServiceEM` config values |
| `-SkipAzureResourceGroup`                                             | Entra-only: no Azure resource group and no Azure RBAC                                                                |
| `-SkipCatalogOwnerAssignment`                                         | No permanent Catalog Owner assignment for ControlPlane-Admins in the catalog(s) (recommended, see [Catalog Owner assignment](#catalog-owner-assignment-for-controlplane-admins)) |
| `-NoPimEscalation`                                                    | No PIM staging group, no PIM for Groups policies and no PIM for Groups eligibilities                                 |
| `-CreateM365Group`                                                    | Also creates the Microsoft 365 group `<Scope>-<Prefix> Members` for team collaboration; it gets no PIM for Groups eligibilities or other access (see [CreateM365Group Parameter](#createm365group-parameter)) |
| `-GroupPrefix <string>`                                               | Prefix of the security group display names (default `SG`; `ServiceEM.GroupPrefix`), see [Naming Conventions](#naming-conventions) |
| `-EnablePIMOwnerAssignment`                                           | Additionally makes the admin an eligible owner of the admin groups (requires `-AssignOwner`)                         |
| `-Smb`                                                                | Only with `-DeploymentScope Both`: creates ManagementPlane-Admins in the Rg scope instead of the Sub scope           |

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
- **Missing groups**: Centralized removes per-service ControlPlane-/ManagementPlane-Admins, ManagementPlane-Members and CatalogPlane-Members groups; `-NoPimEscalation` removes the PIM staging group; the Microsoft 365 group is only created with `-CreateM365Group`
- **Centralized silently became PerService**: A delegation group could not be resolved or created - check the `CENTRALIZED GOVERNANCE MODEL FAILED` warnings
- **Assignment policy errors**: Usually a referenced approver or requestor group does not exist in the same scope (see [Assignment Policies](#assignment-policies)) or the users are invalid
- **Azure RBAC failures**: Caller lacks Azure subscription permissions or the Azure context points to another subscription

> [!TIP]
> See the [Landing Zone Visualization](../service-em/landing-zone-visualization.html) for Mermaid diagrams of the group structure, access packages, policies, and RBAC assignments in Centralized and PerService governance models.

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

| Identity type                        | Microsoft Graph                                                                                                                                                                                                                                                  | Entra ID directory roles                                                                                                         |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| User (delegated, `-Scope ServiceEM`) | Requested automatically: `Directory.AccessAsUser.All`, `EntitlementManagement.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `RoleManagementPolicy.ReadWrite.Directory`, `RoleManagementPolicy.ReadWrite.AzureADGroup`, `PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup`, `PrivilegedAccess.ReadWrite.AzureADGroup` (plus the EntraOps read scopes) | Privileged Role Administrator (role-assignable groups, PIM for Groups) and Identity Governance Administrator (catalogs, access packages), or Global Administrator |
| Workload identity (application)      | `Group.ReadWrite.All`, `User.Read.All`, `EntitlementManagement.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `RoleManagementPolicy.ReadWrite.Directory`, `RoleManagementPolicy.ReadWrite.AzureADGroup`, `PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup`, `PrivilegedAccess.ReadWrite.AzureADGroup` - grant manually with admin consent (not assigned by `New-EntraOpsWorkloadIdentity`) | -                                                                                                                                |

All created security groups are **role-assignable** (required for PIM for Groups), therefore `RoleManagement.ReadWrite.Directory`
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
   and this group is the requestor scope, approver and reviewer fallback of the assignment policies. Without it,
   `New-EntraOpsSubscriptionLandingZone` stops before creating any object. The `-WorkloadPlaneAdmin` must be a
   member of it; ServiceEM checks this before creating any object and stops otherwise.

3. **Alternative: automatic lookup or creation**:
   - If no ID is configured, ServiceEM searches for a group with the display name `ControlPlaneGroupName` /
     `ManagementPlaneGroupName` (defaults `PRG-Tenant-ControlPlane-IdentityOps` / `PRG-Tenant-ManagementPlane-PlatformOps`)
   - If none exists and the session token contains `RoleManagement.ReadWrite.Directory` (included in `-Scope "ServiceEM"`),
     a role-assignable group is created (owned by the signed-in user only with `-AssignOwner`, otherwise without owner)
   - Found or created group IDs are persisted to `EntraOpsConfig.json` in the current directory
   - If resolution fails, ServiceEM warns and **falls back to the PerService model**

#### Governance Model Comparison

| Feature                 | PerService (Default)      | Centralized                                                         |
| ----------------------- | ------------------------- | ------------------------------------------------------------------- |
| **Pre-existing groups** | ❌ Not required            | ✅ Required or auto-created (role-assignable), plus `AdministratorGroupId` |
| **Permissions needed**  | See [Required permissions](#required-permissions) | Same                                                                |
| **Group count**         | More (per service)        | Fewer (shared)                                                      |
| **Use case**            | 5-10 services, dev/test   | 50+ services, production                                            |
| **Isolation**           | Higher (dedicated admins) | Lower (shared admins)                                               |

### Deployment Scopes

`-DeploymentScope` of `New-EntraOpsSubscriptionLandingZone` defines where the Azure permissions are assigned and how many
catalogs are created:

| `-DeploymentScope`        | Scope / catalog                            | Microsoft 365 group (only with `-CreateM365Group`) | Azure                                                                 |
| ------------------------- | ------------------------------------------ | ------------------------ | --------------------------------------------------------------------- |
| `ResourceGroup` (default) | `Rg-<Prefix>` / `Catalog-Rg-<Prefix>`      | `Rg-<Prefix> Members`    | Resource group `RG-<Prefix>`; all role assignments on the resource group |
| `Subscription`            | `Sub-<Prefix>` / `Catalog-Sub-<Prefix>`    | `Sub-<Prefix> Members`   | No resource group; the same role assignments on the subscription (`-SubscriptionId`) |
| `Both`                    | `Sub-<Prefix>` and `Rg-<Prefix>`, two catalogs | One per scope        | Resource group only; the Sub scope has governance groups but no Azure permissions |

With `ResourceGroup` and `Subscription`, all groups of the service live in **one scope and one catalog**. In the PerService
model this includes ControlPlane-Admins and ManagementPlane-Admins, so they receive their PIM eligible Azure roles on the
resource group or subscription (in `Both`, they sit in the Sub scope without Azure permissions unless `-Smb` is used).
`-Smb` and `-LandingZoneComponents` only apply to `Both`.

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

> **Existing two-scope deployments:** landing zones deployed before `-DeploymentScope` existed (now `Both`) keep their `Sub-`
> objects when redeployed with a single scope. Remove them manually, e.g.
> `Remove-EntraOpsServiceCatalog -ServiceCatalogName "Catalog-Sub-<Prefix>" -Force` (see [Cmdlet Inventory](#cmdlet-inventory)).

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
- **Rg scope** (`Rg-MyFirstApp`): all groups of the service, catalog `Catalog-Rg-MyFirstApp`, access packages, PIM for Groups policies and resource group `RG-MyFirstApp` with Azure RBAC
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
✅ **Meaning**: Sub scope of `-DeploymentScope Both` in the Centralized model with `-CreateM365Group` has no WorkloadPlane groups → zero access packages created (expected). Without `-CreateM365Group` the scope has no groups at all and is skipped:
```
VERBOSE: [New-EntraOpsServiceBootstrap] No groups left to create for Sub-MyApp (all roles delegated or skipped), skipping this scope
```

**Inherited Permission Detection:**
```
VERBOSE: [New-EntraOpsServiceAZContainer] ManagementPlane-Admins already has Contributor eligible at a higher scope — skipping assignment
VERBOSE: [New-EntraOpsServiceAZContainer] ControlPlane-Admins already has User Access Administrator eligible at a higher scope — skipping assignment
```
✅ **Meaning**: ServiceEM detected PIM eligible assignments at a parent scope (subscription, management group or root) and skipped redundant assignments (these messages only appear for ManagementPlane-Admins and ControlPlane-Admins groups that exist in the scope with Azure permissions, i.e. per-service groups of a single-scope deployment, delegated groups, or ManagementPlane-Admins with `-Smb`)

### Complete Centralized Deployment Example with Annotated Output

Here's a complete example showing how persona-based groups (IdentityOps, PlatformOps) flow through a Centralized governance deployment.
It uses `-DeploymentScope Both` and `-CreateM365Group`; with the default `ResourceGroup` scope, steps 6 to 10 (Sub scope) don't exist,
and without `-CreateM365Group` the Sub scope has no group of its own and is skipped.

**Command:**
```powershell
New-EntraOpsSubscriptionLandingZone `
    -DeploymentPrefix "MyEntraOpsApp" `
    -DeploymentScope Both `
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
VERBOSE: [New-EntraOpsSubscriptionLandingZone] Validated ManagementPlane group: prg_Lab-Tier1.Azure.1.PlatformOps (0463b6cf-de08-46c9-9fc1-48615ef75099)

# 5. Per-service ControlPlane/ManagementPlane groups removed from ServiceRoles
VERBOSE: [New-EntraOpsSubscriptionLandingZone] Removing ControlPlane/ManagementPlane/CatalogPlane from per-service groups
VERBOSE: [New-EntraOpsSubscriptionLandingZone] Removing ControlPlane components from ServiceRoles

# 6. Processing Sub scope (subscription-level)
VERBOSE: [New-EntraOpsSubscriptionLandingZone] Processing LZ Role: Sub
VERBOSE: [New-EntraOpsServiceBootstrap] WorkloadPlaneAdmin set, looking up admin@contoso.com

# 7. ControlPlane/ManagementPlane creation skipped (centralized model)
VERBOSE: [New-EntraOpsServiceBootstrap] ControlPlaneDelegationGroupId provided — enforcing SkipControlPlaneDelegation
VERBOSE: [New-EntraOpsServiceBootstrap] ManagementPlaneDelegationGroupId provided — enforcing SkipManagementPlaneDelegation

# 8. Only Members group created for Sub scope (no WorkloadPlane at subscription level)
VERBOSE: [New-EntraOpsServiceEntraGroup] Processing 1 Groups
VERBOSE: [New-EntraOpsServiceEntraGroup] {"DisplayName":"Sub-MyEntraOpsApp Members",...}

# 9. Tenant-wide delegation groups injected into service catalog
VERBOSE: [New-EntraOpsServiceBootstrap] Injecting delegated ControlPlane-Admins group (ID: a6b79e96-8a71-4b22-8946-1bbde6bbe8bd)
VERBOSE: [New-EntraOpsServiceBootstrap] Delegated ControlPlane-Admins: prg - Contoso - IdentityOps

VERBOSE: [New-EntraOpsServiceBootstrap] Injecting delegated ManagementPlane-Admins group (ID: 0463b6cf-de08-46c9-9fc1-48615ef75099)
VERBOSE: [New-EntraOpsServiceBootstrap] Delegated ManagementPlane-Admins: prg_Lab-Tier1.Azure.1.PlatformOps

VERBOSE: [New-EntraOpsServiceBootstrap] Injecting delegated CatalogPlane-Members group (ID: 7c6eb065-92e0-4c22-9908-7506d022e05b)
VERBOSE: [New-EntraOpsServiceBootstrap] Delegated CatalogPlane-Members: dug_AAD.PrivilegedAccounts

# 10. Catalog and resources created, but no access packages (Sub scope is Unified-only)
VERBOSE: [New-EntraOpsServiceBootstrap] Service Catalog ID: 812367e5-2e4a-49c8-87a8-ffdaefa823d1
VERBOSE: [New-EntraOpsServiceBootstrap] Service Catalog Resource IDs: "793dc62a-a5fc-4d7f-9182-bd46a6b1e3bc"
VERBOSE: [New-EntraOpsServiceEMAccessPackage] Processing 0 Access Package Roles
VERBOSE: [New-EntraOpsServiceBootstrap] No access packages to configure — skipping resource assignment, policies, and member assignments

# 11. Processing Rg scope (resource group level)
VERBOSE: [New-EntraOpsSubscriptionLandingZone] Processing LZ Role: Rg

# 12. WorkloadPlaneAdmin and ServiceMembers forwarded from parent cmdlet
VERBOSE: [New-EntraOpsServiceBootstrap] WorkloadPlaneAdmin set, looking up admin@contoso.com

# 13. WorkloadPlane groups created for Rg scope
VERBOSE: [New-EntraOpsServiceEntraGroup] Processing 3 Groups
VERBOSE: [New-EntraOpsServiceEntraGroup] {"DisplayName":"Rg-MyEntraOpsApp Members",...}
VERBOSE: [New-EntraOpsServiceEntraGroup] {"DisplayName":"SG-Rg-MyEntraOpsApp-WorkloadPlane-Users",...}
VERBOSE: [New-EntraOpsServiceEntraGroup] {"DisplayName":"SG-Rg-MyEntraOpsApp-WorkloadPlane-Admins",...}

# 14. Tenant-wide delegation groups injected again for Rg catalog
VERBOSE: [New-EntraOpsServiceBootstrap] Injecting delegated ControlPlane-Admins group (ID: a6b79e96-8a71-4b22-8946-1bbde6bbe8bd)
VERBOSE: [New-EntraOpsServiceBootstrap] Delegated ManagementPlane-Admins: prg_Lab-Tier1.Azure.1.PlatformOps

# 15. Access packages created for WorkloadPlane-Users and WorkloadPlane-Admins
VERBOSE: [New-EntraOpsServiceEMAccessPackage] Processing 2 Access Package Roles
VERBOSE: [New-EntraOpsServiceEMAccessPackage] Creating Access Package
VERBOSE: [New-EntraOpsServiceBootstrap] Service Access Package IDs: ["b564d5cf-2d4a-4b82-ba76-2e663687ec8d","691e8983-7ef3-47a2-ab9b-3901978dafd6"]

# 16. Assignment policies created, including the admin-only initial policies
VERBOSE: [New-EntraOpsServiceEMAssignmentPolicy] Assigning Policy for Access Package ID: b564d5cf-2d4a-4b82-ba76-2e663687ec8d
VERBOSE: [New-EntraOpsServiceEMAssignmentPolicy] Creating Initial Workload Admin Policy for Access Package ID: b564d5cf-2d4a-4b82-ba76-2e663687ec8d
VERBOSE: [New-EntraOpsServiceEMAssignmentPolicy] Assigning Policy for Access Package ID: 691e8983-7ef3-47a2-ab9b-3901978dafd6
VERBOSE: [New-EntraOpsServiceEMAssignmentPolicy] Creating Initial Workload Users Policy for Access Package ID: 691e8983-7ef3-47a2-ab9b-3901978dafd6

# 17. Service members assigned to WorkloadPlane-Users (Initial Workload Users Policy), owner to WorkloadPlane-Admins (Initial Workload Admin Policy)
VERBOSE: [New-EntraOpsServiceEMAssignment] Processing Service Member ID: alice-object-id
VERBOSE: [New-EntraOpsServiceEMAssignment] Processing Service Member ID: bob-object-id
VERBOSE: [New-EntraOpsServiceEMAssignment] Creating Assignment Request for Workload Plane Admin - {...}

# 18. PIM policies updated for WorkloadPlane groups
VERBOSE: [New-EntraOpsServicePIMPolicy] Updating PIM Policy ID: Group_baa5996e-1aee-4422-9473-1900fda1f679_707a26f7-...

# 19. Azure Resource Group created with RBAC assignments
VERBOSE: [New-EntraOpsServiceAZContainer] Azure Resource Group not found, creating
VERBOSE: Created resource group 'RG-MyEntraOpsApp' in location 'westeurope'

# 20. Inherited subscription-level eligibilities of the delegated groups detected, RG assignments skipped
VERBOSE: [New-EntraOpsServiceAZContainer] ManagementPlane-Admins already has Contributor eligible at a higher scope — skipping assignment
VERBOSE: [New-EntraOpsServiceAZContainer] ControlPlane-Admins already has User Access Administrator eligible at a higher scope — skipping assignment

# 21. RG-scoped PIM eligible assignments (e.g. Contributor and constrained RBAC Administrator for WorkloadPlane-Admins)
VERBOSE: [New-EntraOpsServiceAZContainer] Creating PIM Eligible Assignment for PrincipalId: d0daf544-dc42-4a9c-83b9-27e2d3f6c436
VERBOSE: [New-EntraOpsServiceAZContainer] Creating PIM Eligible Assignment for PrincipalId: baa5996e-1aee-4422-9473-1900fda1f679
```

**Key Takeaways:**
1. **IdentityOps group** (ControlPlane) was read from config, validated, and injected into both Sub and Rg catalogs
2. **PlatformOps group** (ManagementPlane) was read from config, validated, and injected into both catalogs
3. **No per-service ControlPlane/ManagementPlane groups** were created (Centralized model)
4. **WorkloadPlane groups** created only at Rg scope (Sub has only Unified Members group)
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
requestor scope; the delegated ManagementPlane-Admins group approves the WorkloadPlane-Admins access package (without it,
CatalogPlane-Members is used as approver). Unlike the landing zone cmdlet, `New-EntraOpsServiceBootstrap` does not read delegation group
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

| Setting                            | Description                                                                                                  |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `GovernanceModel`                  | `Centralized` or `PerService`; used when `-GovernanceModel` is not passed                                    |
| `ControlPlaneDelegationGroupId`    | Existing group used as ControlPlane-Admins (instead of a per-service group)                                  |
| `ControlPlaneGroupName`            | Display name used to look up or create the ControlPlane delegation group (Centralized, no ID configured)    |
| `ManagementPlaneDelegationGroupId` | Existing group used as ManagementPlane-Admins                                                                |
| `ManagementPlaneGroupName`         | Display name used to look up or create the ManagementPlane delegation group (Centralized, no ID configured) |
| `AdministratorGroupId`             | Existing group used as CatalogPlane-Members (catalog reader, requestor scope and approver/reviewer fallback) |
| `DefaultAzureRegion`               | Azure region used when `-AzureRegion` is not passed (e.g. `westeurope`); empty means the parameter is required |
| `SkipCatalogOwnerAssignment`       | Default of `-SkipCatalogOwnerAssignment` (see [Catalog Owner assignment](#catalog-owner-assignment-for-controlplane-admins)); an explicitly passed parameter wins |
| `CreateM365Group`                  | Default of `-CreateM365Group`: `true` also creates the Microsoft 365 group `<Scope>-<Prefix> Members` for team collaboration (see [CreateM365Group Parameter](#createm365group-parameter)); an explicitly passed parameter wins |
| `AddWorkloadPlaneAdminToUsers`     | Default of `-AddWorkloadPlaneAdminToUsers`: `true` also assigns the `-WorkloadPlaneAdmin` to the WorkloadPlane-Users access package; an explicitly passed parameter wins |
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
      "InitialManagementMembership": { "Expiration": "P365D", "ApprovalTimeout": "P2D" },
      "InitialManagementAdmins":     { "Expiration": "P365D" },
      "InitialWorkloadUsers":        { "Expiration": "P365D" },
      "InitialWorkloadAdmins":       { "Expiration": "P365D" }
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
        "ManagementPlaneAdmins":       { "ReviewerType": "Group", "Reviewers": ["ManagementPlane-Admins"] },
        "InitialWorkloadMembership":   { "ReviewerType": "Group", "Reviewers": ["ManagementPlane-Admins"] },
        "InitialManagementMembership": { "ReviewerType": "Group", "Reviewers": ["ManagementPlane-Admins"] },
        "InitialManagementAdmins":     { "ReviewerType": "Group", "Reviewers": ["ManagementPlane-Admins"] },
        "InitialWorkloadUsers":        { "ReviewerType": "Group", "Reviewers": ["WorkloadPlane-Admins"] },
        "InitialWorkloadAdmins":       { "ReviewerType": "Group", "Reviewers": ["ManagementPlane-Admins"] }
      }
    }
  }
}
```

| Setting                                                   | Description                                                                                                                  |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `PIMForGroups.MaximumActivationDuration`                  | Maximum duration of a PIM for Groups activation (ISO 8601, e.g. `PT8H`)                                                      |
| `PIMForGroups.MaximumActiveAssignmentDuration`            | Maximum duration of an active (non-eligible) PIM for Groups assignment (e.g. `P15D`); eligible assignments don't expire      |
| `AssignmentPolicies.<Policy>.Expiration`                  | "Assignments expire after": default `P365D` (365 days) for every policy; `noExpiration` or another ISO 8601 duration such as `P30D`, `P6M` or `PT12H` |
| `AssignmentPolicies.<Policy>.ApprovalTimeout`             | Time until a pending request is automatically denied, in whole days, e.g. `P2D` (Entra ID allows up to 14 days)            |
| `AssignmentPolicies.WorkloadPlaneUsers.RequestorScope`    | `AllMemberUsers` (every member user, no guests) or `CatalogPlaneMembers` (members of CatalogPlane-Members only)              |
| `AssignmentPolicies.<Policy>.AllowExtension`              | Standard request policies only (`BaselinePolicy`, `WorkloadPlaneUsers`, `WorkloadPlaneAdmins`, `ManagementPlaneAdmins`): `true` (default) lets users extend an expiring assignment ("Allow users to extend access"), always with approval by the policy's approvers; ignored with `noExpiration` |
| `AccessReviews.EnableAccessReviews`                       | `false` creates the assignment policies without recurring access reviews                                                      |
| `AccessReviews.RecurrenceIntervalInMonths`                | Months between two reviews (1 to 12, default 3 = quarterly)                                                                  |
| `AccessReviews.StartAfterDays`                            | Days between the deployment and the start of the first review                                                                |
| `AccessReviews.ReviewDuration`                            | Length of each review period in whole days (e.g. `P25D`)                                                                     |
| `AccessReviews.Policies.<Policy>.ReviewerType`            | Who reviews the assignments of the policy: `Group` (default, members of the `Reviewers` groups), `SelfReview` (users review their own access), `SpecificReviewers` (the users in `Reviewers`) or `Manager` (the user's manager, the `Reviewers` groups as fallback reviewers) |
| `AccessReviews.Policies.<Policy>.Reviewers`               | `Group` and `Manager`: service group name suffixes (e.g. `WorkloadPlane-Admins`) or group object IDs; `SpecificReviewers`: user object IDs or UPNs (required); ignored for `SelfReview`. Default `WorkloadPlane-Admins` for `WorkloadPlaneUsers` and `InitialWorkloadUsers` (the WorkloadPlane-Users access package), `ManagementPlane-Admins` for all other policies. A group suffix that doesn't exist in the scope falls back to CatalogPlane-Members |

The policy keys map to the assignment policies as follows:

| Key                           | Assignment policy                                                                   |
| ----------------------------- | ----------------------------------------------------------------------------------- |
| `BaselinePolicy`              | Baseline Policy (CatalogPlane-Members access package and the policy template)       |
| `WorkloadPlaneUsers`          | Workload Plane Users Policy (requests for WorkloadPlane-Users)                      |
| `WorkloadPlaneAdmins`         | Workload Plane Policy (requests for WorkloadPlane-Admins)                           |
| `ManagementPlaneAdmins`       | Management Plane Policy (requests for ManagementPlane-Admins)                       |
| `InitialWorkloadMembership`   | Initial Workload Membership Policy (WorkloadPlane-Members)                          |
| `InitialManagementMembership` | Initial Management Membership Policy (ManagementPlane-Members)                      |
| `InitialManagementAdmins`     | Initial Management Admin Policy (admin-assigned only)                               |
| `InitialWorkloadUsers`        | Initial Workload Users Policy (admin-assigned initial `-ServiceMembers` assignment) |
| `InitialWorkloadAdmins`       | Initial Workload Admin Policy (admin-assigned initial `-WorkloadPlaneAdmin` assignment) |

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
- **Skipped per-service groups**: ServiceEM removes the per-service ControlPlane-Admins, ManagementPlane-Admins, ManagementPlane-Members and CatalogPlane-Members groups from all scopes
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
   - Group: `dug_AAD.PrivilegedAccounts`
   - Object ID: `7c6eb065-92e0-4c22-9908-7506d022e05b`
   - Responsible for: Entitlement Management catalog governance
   - Manages: Requests for the WorkloadPlane access packages, fallback approver/reviewer

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
3. **Skips creating** per-service ControlPlane-Admins, ManagementPlane-Admins, ManagementPlane-Members and CatalogPlane-Members groups
4. **References** the tenant-wide groups in the catalog (catalog roles, policy approvers/requestors); they are not added as catalog resources and are never modified
5. Creates only the following groups for the service (default `-DeploymentScope ResourceGroup`; `Both` with `-CreateM365Group` additionally creates `Sub-MyApp Members` and its own catalog):
   - `Rg-MyApp Members` (Microsoft 365 group, only with `-CreateM365Group`)
   - `SG-Rg-MyApp-WorkloadPlane-Users` (Security group)
   - `SG-Rg-MyApp-WorkloadPlane-Admins` (Security group, PIM eligible)
6. Assigns the tenant-wide groups:
   - IdentityOps → Catalog Owner; PIM eligible User Access Administrator on `RG-MyApp` (skipped if already eligible at subscription level)
   - PlatformOps → Catalog Reader + AP Assignment Manager; approver of the WorkloadPlane-Admins access package; PIM eligible Contributor and constrained Role Based Access Control Administrator on `RG-MyApp` (Contributor skipped if already eligible at subscription level)
   - dug_AAD.PrivilegedAccounts → Catalog Reader; requestor scope of the WorkloadPlane-Admins access package (the `-WorkloadPlaneAdmin` must be a member)

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
- `SG-Rg-MyApp-ControlPlane-Admins` (Catalog Owner, approver of the ManagementPlane-Admins access package, PIM eligible User Access Administrator on `RG-MyApp`)
- `SG-Rg-MyApp-ManagementPlane-Admins` (Catalog Reader + AP Assignment Manager, approver; PIM eligible Contributor and constrained Role Based Access Control Administrator on `RG-MyApp`)
- `SG-PIM-Rg-MyApp-ManagementPlane-Admins` (PIM staging group, not created with `-NoPimEscalation`)
- `SG-Rg-MyApp-ManagementPlane-Members` (requestor scope of the ManagementPlane-Admins access package)
- `SG-Rg-MyApp-CatalogPlane-Members` (catalog readers, requestor scope and fallback approver)
- `SG-Rg-MyApp-WorkloadPlane-Users`
- `SG-Rg-MyApp-WorkloadPlane-Admins`
- `Rg-MyApp Members` (Microsoft 365 group for team collaboration, only with `-CreateM365Group`)

With `-DeploymentScope Subscription` the same groups are created with the `Sub-MyApp` prefix and the Azure roles are assigned
on the subscription.

**With `-DeploymentScope Both`:**

**Sub scope:**
- `SG-Sub-MyApp-ControlPlane-Admins` (Catalog Owner, approver of the ManagementPlane-Admins access package)
- `SG-Sub-MyApp-ManagementPlane-Admins` (Catalog Reader + AP Assignment Manager, approver)
- `SG-PIM-Sub-MyApp-ManagementPlane-Admins` (PIM staging group, not created with `-NoPimEscalation`)
- `SG-Sub-MyApp-ManagementPlane-Members` (requestor scope of the ManagementPlane-Admins access package)
- `SG-Sub-MyApp-CatalogPlane-Members` (catalog readers, requestor scope and fallback approver)
- `Sub-MyApp Members` (Microsoft 365 group for team collaboration, only with `-CreateM365Group`)

**Rg scope:**
- `SG-Rg-MyApp-CatalogPlane-Members`
- `SG-Rg-MyApp-ManagementPlane-Members`
- `SG-Rg-MyApp-WorkloadPlane-Users`
- `SG-Rg-MyApp-WorkloadPlane-Admins`
- `Rg-MyApp Members` (only with `-CreateM365Group`)

> **Note (`Both`):** The Sub scope never creates Azure resources, so the per-service ControlPlane-Admins and ManagementPlane-Admins groups
> receive **no Azure RBAC** from ServiceEM. Assign subscription-level roles to them yourself, use `-Smb` to create
> ManagementPlane-Admins in the Rg scope, or use a single-scope deployment.

### How ServiceEM Reads EntraOpsConfig.json

ServiceEM integrates deeply with the `EntraOpsConfig.json` configuration file. Here's what happens when `New-EntraOpsSubscriptionLandingZone` runs:

1. **Configuration source**: The configuration loaded by `Connect-EntraOps -ConfigFilePath` (`$Global:EntraOpsConfig`); if none is loaded, `./EntraOpsConfig.json` or `$env:ENTRAOPS_CONFIG`

2. **Delegation Group IDs**: `ControlPlaneDelegationGroupId`, `ManagementPlaneDelegationGroupId` and `AdministratorGroupId` are read from the `ServiceEM` section when the corresponding parameter is not passed

3. **Governance Model**: `-GovernanceModel` parameter > `ServiceEM.GovernanceModel` > `"PerService"`. The governance model is **not** derived from configured group IDs

4. **Delegation Group Resolution** (`Resolve-EntraOpsServiceEMDelegationGroup`):
   - Centralized: always resolves both groups - by configured ID, then by `ControlPlaneGroupName` / `ManagementPlaneGroupName`, then by creating a role-assignable group; found/created IDs are written back to `./EntraOpsConfig.json`
   - PerService: configured delegation IDs are still honored, the corresponding per-service ControlPlane-/ManagementPlane-Admins groups are then not created (ManagementPlane-Members and CatalogPlane-Members still are, unless `AdministratorGroupId` is set)
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

### Governance Model Comparison

| Aspect                     | Centralized                                  | PerService                            |
| -------------------------- | -------------------------------------------- | ------------------------------------- |
| **ControlPlane-Admins**    | Single tenant-wide group (e.g., IdentityOps) | Dedicated group per service           |
| **ManagementPlane-Admins** | Single tenant-wide group (e.g., PlatformOps) | Dedicated group per service           |
| **Use Case**               | 50+ services, dedicated operations teams     | 5-10 services, service-specific teams |
| **PIM Scope**              | One activation across all services           | Separate activation per service       |
| **Complexity**             | Low (fewer groups)                           | High (groups scale with services)     |
| **Isolation**              | Lower (shared administrators)                | Higher (dedicated administrators)     |
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

**Scope:** ManagementPlane-Admins group (PIM eligible Role Based Access Control Administrator on the resource group). Only assigned when ManagementPlane-Admins and WorkloadPlane-Admins exist in the same scope, i.e. in a single-scope PerService deployment, with a delegated ManagementPlane group (Centralized model or `ManagementPlaneDelegationGroupId`) or with `-Smb`

**Permissions:** Can assign **any** Azure role **EXCEPT** the high-privileged roles listed in `ExcludedRoleDefinitionIds`

**Target:** Can only assign roles to the WorkloadPlane-Admins group of the landing zone

**Default Excluded Roles:**
- `8e3af657-a8ff-443c-a75c-2fe8c4bcb635` - Owner
- `18d7d88d-d35e-4fb5-a5c3-7773c20a72d9` - User Access Administrator
- `f58310d9-a9f6-439a-9e8d-f62e7b41a168` - Role Based Access Control Administrator

**Use Case:** Management-tier administrators can delegate operational roles (Contributor, specific service roles) to workload teams without granting control-plane access.

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

**Scope of the policy:** The settings apply to the **PIM for Groups** member policy of every non-Members group created by the
landing zone (ControlPlane-Admins, ManagementPlane-Admins, the PIM staging group, WorkloadPlane-Users and WorkloadPlane-Admins).
The tier is derived from the group display name. Delegated groups are never modified, PIM for Azure resources (the eligible roles
on the resource group) is not affected, and nothing is configured with `-NoPimEscalation`. Changes take effect when the landing
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
5. The activated role is an Azure resource role (PIM for Azure resources) or the landing zone was deployed with `-NoPimEscalation` - authentication context is only configured for PIM for Groups

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

### NoPimEscalation Parameter

By default, ServiceEM configures **PIM for Groups** for all non-Members groups of a landing zone scope:
- A **PIM staging group** `SG-PIM-<ServiceName>-ManagementPlane-Admins` is created next to ManagementPlane-Admins (the scope of a single-scope deployment; with `Both` the Sub scope, or the Rg scope with `-Smb`)
- PIM for Groups policies (MFA + justification, 10 hours by default, no approval) are applied to ControlPlane-Admins, ManagementPlane-Admins, the staging group, WorkloadPlane-Users and WorkloadPlane-Admins
- ManagementPlane-Admins becomes an eligible member of its staging group; membership of all other groups is granted through
  access packages (the Microsoft 365 group of [`-CreateM365Group`](#createm365group-parameter) gets no eligibilities)

Use `-NoPimEscalation` when group membership should only be granted through access packages, or when PIM for Groups is managed separately:

```powershell
# -NoPimEscalation: no PIM staging group, no PIM for Groups policies/eligibilities
New-EntraOpsSubscriptionLandingZone `
    -DeploymentPrefix "ProdCritical" `
    -AzureRegion "westeurope" `
    -SubscriptionId "<subscription-id>" `
    -WorkloadPlaneAdmin "owner@contoso.com" `
    -NoPimEscalation `
    -Verbose
```

**What changes:**
- **Without** `-NoPimEscalation`:
  - Creates the staging group, e.g. `SG-PIM-Sub-MyApp-ManagementPlane-Admins`, with ManagementPlane-Admins as eligible member
  - PIM policies enforce MFA + Justification (and optionally authentication context) for activations

- **With** `-NoPimEscalation`:
  - No PIM staging group is created
  - No PIM for Groups policies and no PIM for Groups eligible assignments are configured
  - Group membership is only granted via the (time-bound, approval-based) access packages
  - Azure RBAC on the resource group is still assigned as PIM eligible (PIM for Azure resources is not affected)

> **Note:** In the default PIM-only Azure RBAC model the staging group does not receive any Azure role. It is only assigned
> permanent Owner when `New-EntraOpsServiceAZContainer` is called directly with `-rbacModel Azure|Both -pimForGroups`.

**When to use:**
- ✅ Access-package-only elevation with approvals and expiration
- ✅ PIM for Groups is managed by a separate process or tooling
- ❌ Just-in-time activation of group membership via PIM for Groups is required

### CreateM365Group Parameter

By default, a landing zone only contains security groups. With `-CreateM365Group` (or `ServiceEM.CreateM365Group` set to
`true` in `EntraOpsConfig.json`, also available in the Configuration Wizard), ServiceEM additionally creates the Microsoft 365
group `<Scope>-<Prefix> Members` in each scope. An explicitly passed `-CreateM365Group:$false` wins over the setting.

**Purpose:** the group is the collaboration space of the service team:
- **Email and ChatOps:** a group mailbox and calendar, e.g. as recipient for alerts, deployment and incident notifications
- **Knowledge:** when SharePoint Online or Microsoft Teams is used, the group's SharePoint site (documents, runbooks, wiki) or a
  Microsoft Teams team created for the group (channels for operations and ChatOps bots)

**Intended members** are the people behind the personas of the service (ServiceEM doesn't add any members):

| Persona | Privileged group of the persona | Included in the Microsoft 365 group |
| ------- | ------------------------------- | ----------------------------------- |
| Workload users (developers, data-plane operators) | `SG-<Scope>-<Prefix>-WorkloadPlane-Users` | ✅ |
| Workload admins (service owners, workload operators) | `SG-<Scope>-<Prefix>-WorkloadPlane-Admins` | ✅ |
| Management members and admins (platform operators of the service, PerService model) | `SG-<Scope>-<Prefix>-ManagementPlane-Members` / `-Admins` | ✅ (optional) |
| Control plane admins (identity and access administrators, PerService model) | `SG-<Scope>-<Prefix>-ControlPlane-Admins` | Optional; usually not part of the service team |
| Catalog readers / administrators (`CatalogPlane-Members`) | `SG-<Scope>-<Prefix>-CatalogPlane-Members` or `AdministratorGroupId` | Not required |
| Tenant-wide delegation groups (Centralized model: IdentityOps, PlatformOps) | Delegated groups | ❌ (managed outside the landing zone) |

> **Note:** the Microsoft 365 group gets no PIM for Groups eligibilities, no access package and no Azure or catalog role:
> membership only grants access to the group's collaboration resources (mailbox, calendar, SharePoint site or team). Access to
> the admin and user groups is always granted through the access packages.

```powershell
New-EntraOpsSubscriptionLandingZone `
    -DeploymentPrefix "MyApp" `
    -AzureRegion "westeurope" `
    -SubscriptionId "<subscription-id>" `
    -WorkloadPlaneAdmin "admin@contoso.com" `
    -CreateM365Group
```

**Without `-CreateM365Group` (default):**
- No Microsoft 365 group in any scope; a scope without other groups (e.g. the Sub scope of `-DeploymentScope Both` in the
  Centralized model) is skipped completely, without catalog
- A Microsoft 365 group created by an earlier run is left untouched but no longer used: it isn't added to the catalog
- Unchanged: access packages, assignment policies and the initial assignments of `-ServiceMembers` and `-WorkloadPlaneAdmin`,
  PIM for Groups policies, the PIM staging group and its eligibility for ManagementPlane-Admins, and Azure RBAC

`New-EntraOpsServiceBootstrap` uses the same switch: `Unified` entries of `-ServiceRoles` are only created with `-CreateM365Group`.

### Catalog Owner assignment for ControlPlane-Admins

By default, `New-EntraOpsServiceEMCatalogResourceRole` assigns the **Catalog Owner** role of every service catalog to the
ControlPlane-Admins group (per-service group or the `ControlPlaneDelegationGroupId`).

> **Warning:** Entitlement Management catalog roles can't be managed by PIM. This assignment is **permanent** (standing access):
> every active member of ControlPlane-Admins can modify the catalog at any time, e.g. add resources, change access packages and
> assignment policies (requestors, approvers, expiration) or assign access directly, without a separate activation of the role.

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
service catalog. Existing Catalog Owner assignments from earlier runs are not removed.

### Service Owner and Member Assignment

**Owner vs. Members** (initial `adminAdd` assignments by `New-EntraOpsServiceEMAssignment`):
- **WorkloadPlaneAdmin**: Assigned to the ManagementPlane-Admins access package ("Initial Management Admin Policy") where it exists (PerService single scope, or the Sub scope of `Both`); otherwise to the WorkloadPlane-Admins access package ("Initial Workload Admin Policy"), e.g. in the Centralized model or the Rg scope of `Both`. Both policies are admin-assigned only, without approval, and expire after 365 days by default (`ServiceEM.AssignmentPolicies`). Landing zones created before the initial policies existed fall back to the "Workload Plane Policy" (with approval). Only with `-AddWorkloadPlaneAdminToUsers` the admin is also added to the service members
- **ServiceMembers**: Assigned to the WorkloadPlane-Members access package ("Initial Workload Membership Policy", requires approval by the requestor's manager and CatalogPlane-Members, so the request waits for approval) where it exists (custom `ServiceRoles` / Bootstrap defaults); otherwise to the WorkloadPlane-Users access package ("Initial Workload Users Policy", admin-assigned only, no approval, expires after 365 days by default; fallback "Workload Plane Users Policy"). In the default landing zone this is the Rg scope WorkloadPlane-Users package

The cmdlet waits up to 5 minutes (at most 30 seconds between checks) until the submitted requests are delivered. Requests that
wait for approval or failed are reported with a warning and not awaited; requests that are still in progress after 5 minutes are
listed with their last state and completed in the background.

WorkloadPlaneAdmin is resolved when `-WorkloadPlaneAdmin` is passed (or, with `-AssignOwner` only, defaults to the signed-in
user). It is set as owner of all groups **created** in that run only with `-AssignOwner` (existing groups are not updated).

#### Group owners

Without `-AssignOwner`, ServiceEM doesn't send any owner when creating groups (including auto-created delegation groups) and
creates no PIM for Groups eligible owner assignments. Microsoft Entra ID still applies its own defaults when groups are created
without owners in a **delegated** (user) sign-in:

- **Microsoft 365 groups** (`{ServiceName} Members`, with `-CreateM365Group`): the signed-in user is automatically added as owner, and the last owner
  can't be removed afterwards. Owners manage the membership of the team's collaboration group, review them after deployment.
- **Security groups** (all `SG-*` groups): no owner is added when the signed-in user is an administrator (required for
  role-assignable groups).

With a workload identity (app-only sign-in), all groups are created without owners.

Assignments created by earlier runs with `-AssignOwner` are not removed.

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

| #   | Cmdlet                                                 | Purpose                                                                                                                                                                                             |
| --- | ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `New-EntraOpsServiceBootstrap`                         | **Orchestrator** — calls all other cmdlets in correct sequence for complete service provisioning of one scope                                                                                       |
| 2   | `New-EntraOpsServiceEntraGroup`                        | Creates role-assignable security groups, unified (M365) groups and the PIM staging group with correct naming                                                                                        |
| 3   | `New-EntraOpsServiceEMCatalog`                         | Creates Entitlement Management catalog (e.g., `Catalog-Sub-MyApp`) with idempotent lookup                                                                                                           |
| 4   | `New-EntraOpsServiceEMCatalogResource`                 | Registers the owned (non-delegated) service groups as catalog resources (required before creating access packages)                                                                                  |
| 5   | `New-EntraOpsServiceEMCatalogResourceRole`             | Assigns catalog roles: Owner (ControlPlane-Admins, skipped with `-SkipCatalogOwnerAssignment`), Reader (CatalogPlane-Members, WorkloadPlane-Admins, ManagementPlane-Admins), AP Assignment Manager (ManagementPlane-Admins)                     |
| 6   | `New-EntraOpsServiceEMAccessPackage`                   | Creates one access package per non-Unified role except ControlPlane-Admins                                                                                                                          |
| 7   | `New-EntraOpsServiceEMAccessPackageResourceAssignment` | Maps group Member roles into access packages as resource role scopes                                                                                                                                |
| 8   | `New-EntraOpsServiceEMAssignmentPolicy`                | Creates assignment policies: requestor scopes, approvers, expiration, quarterly access reviews                                                                                                      |
| 9   | `New-EntraOpsServiceEMAssignment`                      | Initial `adminAdd` assignments: service members → WorkloadPlane-Members (fallback WorkloadPlane-Users); admin → ManagementPlane-Admins (fallback WorkloadPlane-Admins)                             |
| 10  | `New-EntraOpsServicePIMPolicy`                         | Configures PIM for Groups activation policies: MFA, justification, optional authentication context, max duration (10 hours), no approval                                                           |
| 11  | `New-EntraOpsServicePIMAssignment`                     | Creates PIM for Groups eligible assignments: ManagementPlane-Admins → eligible member of its PIM staging group; optional eligible owner (`-EnablePIMOwnerAssignment`). Returned as `PimForGroupsAssignments` in the bootstrap report |
| 12  | `New-EntraOpsServiceAZContainer`                       | Creates the Azure Resource Group `RG-<Prefix>` (or, with `-AzureScope Subscription`, uses the subscription) with PIM-eligible RBAC (Contributor, UAA, constrained RBAC Administrator) and permanent Reader for WorkloadPlane-Admins                             |
| 13  | `New-EntraOpsSubscriptionLandingZone`                  | **Landing Zone** — single resource group or subscription scope (default), or the Sub + Rg split (`-DeploymentScope Both`); resolves governance model and delegation groups                                                                  |
| 14  | `Get-EntraOpsServiceEMReport`                          | Read-only report of **all** Entitlement Management catalogs in the tenant (roles, resources, access packages, policies, delivered assignments)                                                      |
| 15  | `Remove-EntraOpsServiceCatalog`                        | Cleanup cmdlet — removes assignments, access packages, the catalog and the groups of the landing zone registered as catalog resources; deletes the Azure RG only with `-RemoveAzureResourceGroup -SubscriptionId` (see note below)                              |
| 16  | `Resolve-EntraOpsServiceEMDelegationGroup`             | Resolves (by ID or display name) or creates a role-assignable ControlPlane/ManagementPlane delegation group and persists its ID to `EntraOpsConfig.json`                                           |

> **`Remove-EntraOpsServiceCatalog` and the resource group:** the resource group is **kept by default**; role assignments of the
> deleted groups remain on it as orphaned assignments. Add the opt-in switch `-RemoveAzureResourceGroup` together with
> `-SubscriptionId` to delete `RG-MyApp` (including all its resources) in that subscription when removing `Catalog-Rg-MyApp`;
> without `-SubscriptionId` the cmdlet stops before deleting anything, so a resource group with the same name in the subscription
> of the current Azure context can't be deleted by mistake. Only a resource group with the tag `EntraOpsServiceEM = {ServiceName}`
> (set when the landing zone creates it) is deleted; an existing resource group that the landing zone reused, or one created by
> an earlier version without the tag, is kept with a warning. Removing `Catalog-Sub-MyApp` never deletes a resource group
> and warns that Azure role assignments on the subscription (`-DeploymentScope Subscription`) must be removed manually.
> Only groups created by the landing zone are deleted: catalog resources whose mailNickname starts with `{ServiceName}.` or
> `PIM.{ServiceName}.`. Other groups in the catalog (e.g. shared groups added manually) are kept with a warning, delegated groups
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

| Resource Type                          | Pattern                                             | Example                                   |
| -------------------------------------- | --------------------------------------------------- | ----------------------------------------- |
| **Unified Group**                      | `{ServiceName} Members` (mailNickname `{ServiceName}.Members`), only with `-CreateM365Group` | `Rg-MyApp Members`                        |
| **Security Group**                     | `{GroupPrefix}-{ServiceName}-{AccessLevel}-{Name}` (mailNickname `{ServiceName}.{AccessLevel}.{Name}`) | `SG-Rg-MyApp-WorkloadPlane-Admins`        |
| **PIM Staging Group**                  | `{GroupPrefix}-PIM-{ServiceName}-ManagementPlane-Admins` (mailNickname `PIM.{ServiceName}.ManagementPlane.Admins`) | `SG-PIM-Sub-MyApp-ManagementPlane-Admins` |
| **Delegation Group (ControlPlane)**    | `ControlPlaneGroupName` (default)                   | `PRG-Tenant-ControlPlane-IdentityOps`     |
| **Delegation Group (ManagementPlane)** | `ManagementPlaneGroupName` (default)                | `PRG-Tenant-ManagementPlane-PlatformOps`  |
| **EM Catalog**                         | `Catalog-{ServiceName}`                             | `Catalog-Rg-MyApp`                        |
| **Access Package**                     | `AP-{ServiceName}-{AccessLevel}-{Name}`             | `AP-Rg-MyApp-WorkloadPlane-Users`         |
| **Assignment Policy**                  | Fixed names per access package: `Baseline Policy`, `Workload Plane Users Policy`, `Workload Plane Policy`, `Management Plane Policy`, `Initial Workload Membership Policy`, `Initial Management Membership Policy`, `Initial Management Admin Policy`, `Initial Workload Users Policy`, `Initial Workload Admin Policy` | `Initial Workload Admin Policy` |
| **Resource Group**                     | `RG-{ServiceName}` without `Sub-`/`Rg-` prefix      | `RG-MyApp`                                |

**Scope Prefixes:**
- `Sub-{DeploymentPrefix}` — Subscription scope (`-DeploymentScope Subscription`: role assignments on the subscription; `Both`: governance scope without Azure resources)
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

| Group                                          | Centralized | PerService | Purpose |
| ---------------------------------------------- | ----------- | ---------- | ------- |
| `{Scope}-{Prefix} Members`                     | ✅ with `-CreateM365Group` | ✅ with `-CreateM365Group` | Microsoft 365 group for team collaboration (no access to the other groups) |
| `SG-{Scope}-{Prefix}-WorkloadPlane-Users`      | ✅          | ✅         | End-user data-plane access; target group of the WorkloadPlane constrained delegation |
| `SG-{Scope}-{Prefix}-WorkloadPlane-Admins`     | ✅          | ✅         | Permanent Reader, PIM eligible Contributor + constrained RBAC Administrator |
| `SG-{Scope}-{Prefix}-CatalogPlane-Members`     | ❌ (`AdministratorGroupId`) | ✅ | Catalog Reader; requestor scope and fallback approver/reviewer |
| `SG-{Scope}-{Prefix}-ManagementPlane-Members`  | ❌          | ✅         | Requestor scope of the ManagementPlane-Admins access package |
| `SG-{Scope}-{Prefix}-ManagementPlane-Admins`   | ❌ (delegated) | ✅      | Catalog Reader + AP Assignment Manager; PIM eligible Contributor + constrained RBAC Administrator |
| `SG-PIM-{Scope}-{Prefix}-ManagementPlane-Admins` | ❌        | ✅ (not with `-NoPimEscalation`) | PIM staging group |
| `SG-{Scope}-{Prefix}-ControlPlane-Admins`      | ❌ (delegated) | ✅      | Catalog Owner (unless `-SkipCatalogOwnerAssignment`); PIM eligible User Access Administrator |

The tables below show the two scopes of `-DeploymentScope Both`.

#### Centralized Governance Model

**Sub Scope:**
| Group                  | Type           | Purpose                                             |
| ---------------------- | -------------- | --------------------------------------------------- |
| `Sub-{Prefix} Members` | Unified (M365) | Team collaboration group; only with `-CreateM365Group`, otherwise the Sub scope isn't deployed |

**Rg Scope:**
| Group                                 | Type           | Purpose                                                                                 |
| ------------------------------------- | -------------- | --------------------------------------------------------------------------------------- |
| `Rg-{Prefix} Members`                 | Unified (M365) | Team collaboration group (only with `-CreateM365Group`) |
| `SG-Rg-{Prefix}-WorkloadPlane-Users`  | Security       | End-user data-plane access; target group of the WorkloadPlane constrained delegation    |
| `SG-Rg-{Prefix}-WorkloadPlane-Admins` | Security       | Workload admin elevation; permanent Reader, PIM eligible Contributor + constrained RBAC Administrator on the RG |

**NOT Created (Centralized):**
- ❌ ControlPlane-Admins (delegated from `ServiceEM.ControlPlaneDelegationGroupId`)
- ❌ ManagementPlane-Admins (delegated from `ServiceEM.ManagementPlaneDelegationGroupId`)
- ❌ ManagementPlane-Members (removed in the Centralized model)
- ❌ CatalogPlane-Members (delegated from `ServiceEM.AdministratorGroupId`)
- ❌ WorkloadPlane-Members (not part of the landing zone roles in either model)
- ❌ PIM staging groups (only created next to an owned ManagementPlane-Admins group)

#### PerService Governance Model

**Sub Scope:**
| Group                                        | Type                | Purpose                                                                                  |
| -------------------------------------------- | ------------------- | ---------------------------------------------------------------------------------------- |
| `Sub-{Prefix} Members`                       | Unified (M365)      | Team collaboration group (only with `-CreateM365Group`) |
| `SG-Sub-{Prefix}-CatalogPlane-Members`       | Security            | Catalog Reader; requestor scope, approver and fallback approver/reviewer                 |
| `SG-Sub-{Prefix}-ManagementPlane-Members`    | Security            | Management tier membership; requestor scope of the ManagementPlane-Admins access package |
| `SG-Sub-{Prefix}-ManagementPlane-Admins`     | Security            | Management tier elevation; Catalog Reader + AP Assignment Manager; approver and reviewer (no Azure RBAC in this scope) |
| `SG-Sub-{Prefix}-ControlPlane-Admins`        | Security            | Catalog Owner; approver of the ManagementPlane-Admins access package (no Azure RBAC in this scope) |
| `SG-PIM-Sub-{Prefix}-ManagementPlane-Admins` | Security (optional) | PIM staging group; ManagementPlane-Admins is its eligible member (not created with `-NoPimEscalation`) |

**Rg Scope:**
| Group                                    | Type           | Purpose                    |
| ---------------------------------------- | -------------- | -------------------------- |
| `Rg-{Prefix} Members`                    | Unified (M365) | Team collaboration group (only with `-CreateM365Group`) |
| `SG-Rg-{Prefix}-CatalogPlane-Members`    | Security       | Catalog Reader; requestor scope and fallback approver/reviewer |
| `SG-Rg-{Prefix}-ManagementPlane-Members` | Security       | Management tier membership (no Azure RBAC) |
| `SG-Rg-{Prefix}-WorkloadPlane-Users`     | Security       | End-user data-plane access; target group of the WorkloadPlane constrained delegation |
| `SG-Rg-{Prefix}-WorkloadPlane-Admins`    | Security       | Workload admin elevation; permanent Reader, PIM eligible Contributor + constrained RBAC Administrator on the RG |

With `-Smb`, `SG-Rg-{Prefix}-ManagementPlane-Admins` and `SG-PIM-Rg-{Prefix}-ManagementPlane-Admins` are created in the Rg
scope instead of the Sub scope.

### Azure RBAC Implementation (Resource Group or Subscription Scope)

All assignments target the resource group `RG-{Prefix}` (`-DeploymentScope ResourceGroup` or the Rg scope of `Both`) or, with
`-DeploymentScope Subscription`, the subscription `-SubscriptionId` (no resource group is created). In `Both`, the Sub scope
always runs with `-SkipAzureResourceGroup`. The table shows the resource group case; the subscription case uses the same roles.

#### Assignments on `RG-{Prefix}` (or the subscription)

| Group (if present in the scope)                                     | Azure RBAC Role                                  | Type                         | Notes                                                                    |
| ------------------------------------------------------------------- | ------------------------------------------------ | ---------------------------- | ------------------------------------------------------------------------ |
| `SG-{Scope}-{Prefix}-WorkloadPlane-Admins`                          | Reader                                           | Permanent (active)           | Always assigned                                                          |
| `SG-{Scope}-{Prefix}-WorkloadPlane-Admins`                          | Contributor                                      | PIM eligible, no expiration  |                                                                          |
| `SG-{Scope}-{Prefix}-WorkloadPlane-Admins`                          | Role Based Access Control Administrator          | PIM eligible, no expiration  | ABAC: only `WorkloadPlane.AllowedRoleDefinitionIds` → WorkloadPlane-Users |
| ManagementPlane-Admins (per-service in a single scope, delegated, or with `-Smb`) | Contributor                        | PIM eligible, no expiration  | Skipped if already eligible at a parent scope                            |
| ManagementPlane-Admins (per-service in a single scope, delegated, or with `-Smb`) | Role Based Access Control Administrator | PIM eligible, no expiration | ABAC: all roles except `ManagementPlane.ExcludedRoleDefinitionIds` → WorkloadPlane-Admins |
| ControlPlane-Admins (per-service in a single scope, or delegated)   | User Access Administrator                        | PIM eligible, no expiration  | Skipped if already eligible at a parent scope                            |

ServiceEM also updates the PIM for Azure resources policy of these roles on the resource group (or subscription) so that
eligible assignments are not required to expire. ManagementPlane-Members and the PIM staging group do not receive Azure roles
in the default (PIM) RBAC model.

#### Prerequisites for Azure RBAC

To create the resource group and the Azure RBAC assignments, the calling identity requires on the subscription:
- **Owner**, or **Contributor** + **User Access Administrator** (resource group creation, role eligibility schedule requests and role management policy updates)

No additional Microsoft Graph permission is needed for the Azure part.

#### When Azure RBAC is NOT Created

Azure RBAC assignments are **skipped** when:
- `-SkipAzureResourceGroup` parameter is used
- The scope is the Sub scope of `New-EntraOpsSubscriptionLandingZone` (always)
- The caller lacks Azure subscription permissions (errors are written, the deployment continues)
- No Azure context/subscription is selected

> **Important:** When using `-SkipAzureResourceGroup`, only Entra ID objects (groups, catalogs, access packages, PIM for Groups) are created - the group and access package counts don't change. Azure RBAC assignments and resource groups are not created. This is useful for testing or when Azure resources will be managed separately.

#### PIM for Groups Integration

ServiceEM creates PIM eligible assignments that enable just-in-time elevation (unless `-NoPimEscalation` is used):

1. **PIM staging group** (eligible **member**, no expiration):
   - `SG-Sub-{Prefix}-ManagementPlane-Admins` → `SG-PIM-Sub-{Prefix}-ManagementPlane-Admins` (PerService; single scope: `{Scope}-{Prefix}`)
   - With `-AssignOwner -EnablePIMOwnerAssignment`: the admin additionally becomes eligible **owner** of the admin and user groups
   - Membership of the admin and user groups themselves is granted through the access packages; the Microsoft 365 group of
     [`-CreateM365Group`](#createm365group-parameter) gets no eligibilities

2. **PIM Policies:**
   - MFA and justification required, no approval
   - Authentication context can be enforced (if configured in EntraOpsConfig.json)
   - Maximum activation duration of 10 hours (default, `ServiceEM.PIMForGroups.MaximumActivationDuration`)

The report of `New-EntraOpsServiceBootstrap` (one per scope of `New-EntraOpsSubscriptionLandingZone`) lists these eligibilities
in `PimForGroupsAssignments`; it is empty when the scope has no PIM staging group (e.g. Centralized model, `-NoPimEscalation`)
and `-EnablePIMOwnerAssignment` isn't used.

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

#### Centralized Governance — Rg Scope Only

Same access packages for `-DeploymentScope ResourceGroup` and the Rg scope of `Both` (with `-DeploymentScope Subscription` the
names start with `AP-Sub-`).

| Access Package                        | Grants Membership To                  | Policy                      | Requestors                                  | Approver                                        | Expiration |
| ------------------------------------- | ------------------------------------- | --------------------------- | ------------------------------------------- | ----------------------------------------------- | ---------- |
| `AP-Rg-{Prefix}-WorkloadPlane-Users`  | `SG-Rg-{Prefix}-WorkloadPlane-Users`  | Workload Plane Users Policy | All member users³                           | WorkloadPlane-Admins                            | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Users`  | `SG-Rg-{Prefix}-WorkloadPlane-Users`  | Initial Workload Users Policy | Admin-assigned only (initial `-ServiceMembers`) | No approval                             | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Admins` | `SG-Rg-{Prefix}-WorkloadPlane-Admins` | Workload Plane Policy       | CatalogPlane-Members (`AdministratorGroupId`) | ManagementPlane-Admins (delegated group)        | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Admins` | `SG-Rg-{Prefix}-WorkloadPlane-Admins` | Initial Workload Admin Policy | Admin-assigned only (initial `-WorkloadPlaneAdmin`) | No approval                         | 365 days   |

**Sub Scope**: No access packages created. The Sub scope only exists with `-CreateM365Group` (its only owned group is the Microsoft 365 group).

#### PerService Governance

**Single scope (default `-DeploymentScope ResourceGroup`, 5 access packages; `Subscription` uses `AP-Sub-`):**
| Access Package                            | Grants Membership To                      | Policy                               | Requestors              | Approver                                                              | Expiration |
| ----------------------------------------- | ----------------------------------------- | ------------------------------------ | ----------------------- | --------------------------------------------------------------------- | ---------- |
| `AP-Rg-{Prefix}-CatalogPlane-Members`     | `SG-Rg-{Prefix}-CatalogPlane-Members`     | Baseline Policy                      | CatalogPlane-Members    | CatalogPlane-Members                                                  | 365 days   |
| `AP-Rg-{Prefix}-ManagementPlane-Members`  | `SG-Rg-{Prefix}-ManagementPlane-Members`  | Initial Management Membership Policy | CatalogPlane-Members¹   | ManagementPlane-Admins                                                | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Users`      | `SG-Rg-{Prefix}-WorkloadPlane-Users`      | Workload Plane Users Policy          | All member users³       | WorkloadPlane-Admins                                                  | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Users`      | `SG-Rg-{Prefix}-WorkloadPlane-Users`      | Initial Workload Users Policy        | Admin-assigned only (initial `-ServiceMembers`) | No approval                                   | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Admins`     | `SG-Rg-{Prefix}-WorkloadPlane-Admins`     | Workload Plane Policy                | CatalogPlane-Members¹   | ManagementPlane-Admins                                                | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Admins`     | `SG-Rg-{Prefix}-WorkloadPlane-Admins`     | Initial Workload Admin Policy        | Admin-assigned only     | No approval                                                           | 365 days   |
| `AP-Rg-{Prefix}-ManagementPlane-Admins`   | `SG-Rg-{Prefix}-ManagementPlane-Admins`   | Management Plane Policy              | ManagementPlane-Members | ControlPlane-Admins (escalation after 12 h, fallback CatalogPlane-Members) | 365 days   |
| `AP-Rg-{Prefix}-ManagementPlane-Admins`   | `SG-Rg-{Prefix}-ManagementPlane-Admins`   | Initial Management Admin Policy      | Admin-assigned only (initial `-WorkloadPlaneAdmin`) | No approval                               | 365 days   |

In the single scope the `-WorkloadPlaneAdmin` is initially assigned to ManagementPlane-Admins (not WorkloadPlane-Admins),
because the ManagementPlane-Admins access package exists in the scope.

**`-DeploymentScope Both` — Sub Scope (3 access packages):**
| Access Package                            | Grants Membership To                      | Policy                               | Requestors              | Approver                                                              | Expiration |
| ----------------------------------------- | ----------------------------------------- | ------------------------------------ | ----------------------- | --------------------------------------------------------------------- | ---------- |
| `AP-Sub-{Prefix}-CatalogPlane-Members`    | `SG-Sub-{Prefix}-CatalogPlane-Members`    | Baseline Policy                      | CatalogPlane-Members    | CatalogPlane-Members                                                  | 365 days   |
| `AP-Sub-{Prefix}-ManagementPlane-Members` | `SG-Sub-{Prefix}-ManagementPlane-Members` | Initial Management Membership Policy | CatalogPlane-Members¹   | ManagementPlane-Admins                                                | 365 days   |
| `AP-Sub-{Prefix}-ManagementPlane-Admins`  | `SG-Sub-{Prefix}-ManagementPlane-Admins`  | Management Plane Policy              | ManagementPlane-Members | ControlPlane-Admins (escalation after 12 h, fallback CatalogPlane-Members) | 365 days   |
| `AP-Sub-{Prefix}-ManagementPlane-Admins`  | `SG-Sub-{Prefix}-ManagementPlane-Admins`  | Initial Management Admin Policy      | Admin-assigned only     | No approval                                                           | 365 days   |

**`-DeploymentScope Both` — Rg Scope (4 access packages):**
| Access Package                           | Grants Membership To                     | Policy                               | Requestors            | Approver                  | Expiration |
| ---------------------------------------- | ---------------------------------------- | ------------------------------------ | --------------------- | ------------------------- | ---------- |
| `AP-Rg-{Prefix}-CatalogPlane-Members`    | `SG-Rg-{Prefix}-CatalogPlane-Members`    | Baseline Policy                      | CatalogPlane-Members  | CatalogPlane-Members      | 365 days   |
| `AP-Rg-{Prefix}-ManagementPlane-Members` | `SG-Rg-{Prefix}-ManagementPlane-Members` | Initial Management Membership Policy | CatalogPlane-Members¹ | ManagementPlane-Admins²   | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Users`     | `SG-Rg-{Prefix}-WorkloadPlane-Users`     | Workload Plane Users Policy          | All member users      | WorkloadPlane-Admins      | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Users`     | `SG-Rg-{Prefix}-WorkloadPlane-Users`     | Initial Workload Users Policy        | Admin-assigned only   | No approval               | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Admins`    | `SG-Rg-{Prefix}-WorkloadPlane-Admins`    | Workload Plane Policy                | CatalogPlane-Members¹ | ManagementPlane-Admins²   | 365 days   |
| `AP-Rg-{Prefix}-WorkloadPlane-Admins`    | `SG-Rg-{Prefix}-WorkloadPlane-Admins`    | Initial Workload Admin Policy        | Admin-assigned only   | No approval               | 365 days   |

¹ WorkloadPlane-Members if such a group exists in the scope (e.g. Bootstrap default roles); the landing zone roles don't include it.

² Approvers are resolved within the same scope. With `-DeploymentScope Both` (PerService), ManagementPlane-Admins exists only in the Sub scope, so CatalogPlane-Members is used as approver (and access reviewer) in the Rg scope instead. Use `-Smb`, a single scope or a `ManagementPlaneDelegationGroupId` to have ManagementPlane-Admins approve.

³ Default `ServiceEM.AssignmentPolicies.WorkloadPlaneUsers.RequestorScope` = `AllMemberUsers`; `CatalogPlaneMembers` restricts requests to CatalogPlane-Members.

The expiration ("Assignments expire after") of each policy, and therefore of each access package, is configured separately in
`ServiceEM.AssignmentPolicies.<Policy>.Expiration` or in the Configuration Wizard (default 365 days for all policies, see
[Assignment Policy, Access Review and PIM for Groups Settings](#assignment-policy-access-review-and-pim-for-groups-settings)).

> **Note**: No access packages are created for ControlPlane-Admins — membership is managed directly (or via PIM for Groups).

### Assignment Policies

Each access package has an **assignment policy** that controls who can request access, who must approve, and how long access lasts. ServiceEM automatically creates assignment policies with default configurations.

#### Default Assignment Policy Configuration

| Setting                                       | Default Value                          | Description                                                                                                                  |
| --------------------------------------------- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **Allowed Requestors** (`allowedTargetScope`) | `specificDirectoryUsers`               | Members of the requestor group listed above; `allMemberUsers` for WorkloadPlane-Members and WorkloadPlane-Users; `allMemberUsers` with all requests disabled (admin-assigned only) for the Initial Management Admin, Initial Workload Users and Initial Workload Admin policies, because administrator direct assignments are also limited to the target scope |
| **Requestor Settings**                        | Self-add, self-remove and extension    | No custom schedule, no on-behalf requests; extension ("Allow users to extend access", with approval) only for the Baseline, Workload Plane (Users) and Management Plane policies (`AllowExtension`); no requests and no extension for the admin-assigned initial policies |
| **Approval Required**                         | Yes                                    | Single stage with approver justification (two stages - requestor's manager, then CatalogPlane-Members - for WorkloadPlane-Members); not required for the admin-assigned initial policies |
| **Approvers**                                 | Tier-specific groups                   | See tables above                                                                                                              |
| **Access Duration** (`expiration`)            | 365 days                               | Assignments of all policies expire after 365 days; configurable per policy in `ServiceEM.AssignmentPolicies` (see [Assignment Policy, Access Review and PIM for Groups Settings](#assignment-policy-access-review-and-pim-for-groups-settings)). Users get reminders 14 days and 1 day before expiry and can request an extension through the standard policies; an initial assignment can't be extended, the user requests the access package again through the standard policy of the package |
| **Approval Timeout**                          | 2 days / 1 day                         | Pending requests are denied after 2 days (1 day for the Management Plane Policy); configurable in `ServiceEM.AssignmentPolicies` |
| **Access Reviews**                            | Quarterly                              | Every 3 months starting 4 days after deployment, 25-day review period; reviewers ManagementPlane-Admins (WorkloadPlane-Admins for the WorkloadPlane-Users access package, fallback CatalogPlane-Members); access is kept if not reviewed; configurable in `ServiceEM.AccessReviews`, including self-review, specific reviewers or the user's manager per policy |
| **Questions**                                 | None                                   | No custom questions configured by default                                                                                    |

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

| Module                             | Purpose                                                                                                                                  |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **Az.Accounts**                    | Azure sign-in and context (`Get-AzContext`, `Get-AzAccessToken`)                                                                         |
| **Az.Resources**                   | Resource group, Azure RBAC and PIM for Azure resources operations                                                                       |
| **Microsoft.Graph.Authentication** | Graph sign-in and `Get-MgContext` (default user/member lookup, delegation group auto-creation); not needed with `UseInvokeRestMethodOnly` and service principal/managed identity sign-in |

All Microsoft Graph calls of the ServiceEM cmdlets (groups, users, Entitlement Management, PIM for Groups) go through
`Invoke-EntraOpsMsGraphQuery`, so no further Microsoft Graph SDK modules (e.g. `Microsoft.Graph.Groups`, `Microsoft.Graph.Users`,
`Microsoft.Graph.Identity.Governance`) and no `Az.ResourceGraph` are required.

**Required Scopes:** Use `Connect-EntraOps -Scope "ServiceEM"` for delegated sign-in; see [Required permissions](#required-permissions)
for the requested delegated scopes and the application permissions of workload identities.

### Delegation Behavior Summary

When a delegation Group ID is provided (via `EntraOpsConfig.json` or parameter), the following behavior applies:

| Behavior                        | ControlPlane            | ManagementPlane                                    | CatalogPlane            |
| ------------------------------- | ----------------------- | -------------------------------------------------- | ----------------------- |
| **Group created**               | No                      | No                                                 | No                      |
| **Synthetic entry injected**    | Yes (with DisplayName)  | Yes (with DisplayName)                             | Yes (with DisplayName)  |
| **Registered as catalog resource** | No                   | No                                                 | No                      |
| **Catalog role assigned**       | Yes (Owner)             | Yes (Reader, AP Assignment Manager)                | Yes (Reader)            |
| **Referenced in AP policies**   | Approver of the ManagementPlane-Admins AP (only if ManagementPlane is not delegated) | Approver and access reviewer          | Requestor scope, approver and fallback approver/reviewer |
| **Azure RBAC assigned (RG)**    | Yes (UAA, PIM-eligible) | Yes (Contributor and constrained RBAC Administrator, PIM-eligible) | —         |
| **PIM policy applied to group** | No (managed externally) | No (managed externally)                            | No (managed externally) |
| **PIM eligibility created**     | No (managed externally) | No (managed externally)                            | No (managed externally) |
| **Access package created**      | No                      | No                                                 | No                      |

The delegated groups are **read-only** from ServiceEM's perspective — they receive role assignments and policy references but are never modified (no PIM policies, no eligibility assignments) and are not deleted by `Remove-EntraOpsServiceCatalog`.

### Parameter Impact Matrix

This matrix shows how each parameter affects the objects created during deployment:

#### New-EntraOpsSubscriptionLandingZone Parameters

| Parameter                      | Groups                      | Catalogs | Azure Resources     | Access Packages   | PIM for Groups         |
| ------------------------------ | --------------------------- | -------- | ------------------- | ----------------- | ---------------------- |
| **None (defaults: ResourceGroup, PerService)** | ✅ 7 created (incl. PIM staging group) | 1 | ✅ RG + RBAC | ✅ 5 created | ✅ Policies + staging group eligibility |
| `-DeploymentScope Subscription` | ✅ 7 created               | 1        | ⚠️ No RG; RBAC on the subscription | ✅ 5 created | ✅ Configured |
| `-DeploymentScope Both`        | ✅ 9 created (5 Sub, 4 Rg) | 2        | ✅ RG + RBAC (Rg scope groups only) | ✅ 7 created (3 Sub, 4 Rg) | ✅ Configured |
| `-SkipAzureResourceGroup`      | ✅ 7 created                 | 1        | ❌ Skipped           | ✅ 5 created       | ✅ Configured           |
| `-NoPimEscalation`             | ⚠️ 6 created (no PIM staging group) | 1 | ✅ RG + RBAC  | ✅ 5 created       | ❌ Skipped              |
| `-CreateM365Group`             | ✅ +1 per scope (Microsoft 365 group) | 1 | ✅ RG + RBAC | ✅ 5 created       | ✅ Configured (no eligibilities for the Microsoft 365 group) |
| `-GovernanceModel Centralized` | ⚠️ 2 created                 | 1        | ✅ RG + RBAC (incl. delegated groups) | ⚠️ 2 created | ✅ Policies on WorkloadPlane groups only |
| `-Smb` (only with `Both`)      | ⚠️ 9 created (3 Sub, 6 Rg incl. ManagementPlane-Admins + PIM staging group) | 2 | ✅ RG + RBAC (incl. ManagementPlane-Admins) | ✅ 7 created (2 Sub, 5 Rg) | ✅ Configured |
| `-WorkloadPlaneAdmin`          | —                           | —        | N/A                 | Admin assigned (adminAdd) | N/A              |
| `-SkipCatalogOwnerAssignment`  | —                           | —        | N/A                 | No Catalog Owner for ControlPlane-Admins | N/A |
| `-AssignOwner`                 | Owner of created groups     | —        | N/A                 | —                 | Optional eligible owner (`-EnablePIMOwnerAssignment`) |
| `-ServiceMembers`              | —                           | —        | N/A                 | Members assigned to the WorkloadPlane-Users AP (adminAdd) | N/A |

**Legend:**
- ✅ Created/Configured as expected
- ⚠️ Reduced/changed set of objects
- ❌ Not created/Skipped

#### Detailed Impact Explanations

**`-SkipAzureResourceGroup`**

When this parameter is used:

**Created:**
- All groups of the scope(s)
- The catalog (two with `-DeploymentScope Both`)
- All access packages, assignment policies and initial assignments
- PIM for Groups policies and assignments

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

With `-DeploymentScope Both` and `-CreateM365Group`, `Sub-{Prefix} Members` and a second catalog without access packages are
created additionally; without `-CreateM365Group` the Sub scope has no group of its own and is skipped.

**Delegated (Not Created):**
- ControlPlane-Admins (uses tenant-wide delegation group)
- ManagementPlane-Admins (uses tenant-wide delegation group)
- CatalogPlane-Members (uses administrator group)
- ManagementPlane-Members (not used)

**Prerequisites:**
- ControlPlaneDelegationGroupId in EntraOpsConfig.json (or resolvable/creatable via `ControlPlaneGroupName`)
- ManagementPlaneDelegationGroupId in EntraOpsConfig.json (or resolvable/creatable via `ManagementPlaneGroupName`)
- AdministratorGroupId in EntraOpsConfig.json

**`-NoPimEscalation`**

When this parameter is used:

**Impact:**
- PIM staging groups (SG-PIM-*) are NOT created
- No PIM for Groups policies and no PIM for Groups eligible assignments (incl. `-EnablePIMOwnerAssignment`)
- Group membership is only granted through access packages
- Azure RBAC on the resource group remains PIM eligible

**Use Case:** Access-package-only elevation or PIM for Groups managed outside of ServiceEM

**`-WorkloadPlaneAdmin` and `-ServiceMembers`**

**WorkloadPlaneAdmin:**
- Set as owner of all groups created in this run, only with `-AssignOwner`
- Assigned (adminAdd) to the ManagementPlane-Admins access package, or to WorkloadPlane-Admins where no ManagementPlane-Admins package exists
- Accepts a UPN, object ID or a Graph OData URL (`https://graph.microsoft.com/v1.0/users/<id>` or `.../servicePrincipals/<id>`); defaults to the signed-in user only with `-AssignOwner` (required for app-only sign-in in that case)
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
1. **Missing requestor/approver group in the scope** - e.g. no `AdministratorGroupId` in the Centralized model (CatalogPlane-Members is the requestor scope and approver fallback)
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
2. Looking at the wrong scope - ServiceEM only assigns roles on `RG-<DeploymentPrefix>` (never on the subscription) and only for groups of the Rg scope
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
Deployment used `-NoPimEscalation`, the group is delegated (never modified by ServiceEM), or the caller lacks the required Microsoft Graph permissions or directory roles.

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
- [ ] Groups have the expected owners (only with `-AssignOwner`)
- [ ] Catalogs created
- [ ] Access packages created
- [ ] Assignment policies configured (or manually created if failed)
- [ ] PIM for Groups policies applied to the non-Members groups (unless `-NoPimEscalation`)
- [ ] PIM for Groups eligibility assignments created (unless `-NoPimEscalation`)

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
