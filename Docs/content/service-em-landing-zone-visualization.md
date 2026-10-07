# ServiceEM Landing Zone - Resource & Dependency Visualization

> **Note**: Sections 1-6 show a single `New-EntraOpsServiceBootstrap` scope with **all group types** (PerService, no delegation): its default ServiceRoles plus WorkloadPlane-Members, which is only created when passed in custom `-ServiceRoles` (manager-approved access package with the Initial Workload Membership Policy). The default ServiceRoles equal the single-scope landing zone roles. `New-EntraOpsSubscriptionLandingZone` creates exactly one such scope (default `-DeploymentScope ResourceGroup` or `Subscription`) without WorkloadPlane-Members (see [Service EM → Deployment Scopes](../service-em/index.html#deployment-scopes)). To keep governance groups apart from workload groups, create them once with `New-EntraOpsServiceBootstrap -SkipAzureResourceGroup` and pass them as delegation groups to the workload landing zones (see [Separating governance and workload groups](../service-em/index.html#separating-governance-and-workload-groups)). For **Centralized governance** (using tenant-wide delegation groups), see the [Centralized Model Notes](#centralized-governance-model-notes) section below.

> Replace `{Prefix}` with the service name: `-ServiceName` of `New-EntraOpsServiceBootstrap`, or `Rg-<DeploymentPrefix>` (default `-DeploymentScope ResourceGroup`) / `Sub-<DeploymentPrefix>` (`-DeploymentScope Subscription`) for landing zones (e.g., `Rg-MyApp` or `Sub-MyApp`). The resource group is named `RG-{Prefix}` without the `Sub-`/`Rg-` prefix (e.g., `RG-MyApp`); with `-DeploymentScope Subscription` no resource group is created and the Azure roles are assigned on the subscription.  
> Nodes marked *(optional)* are skipped when using `-SkipControlPlaneDelegation`.  
> Nodes marked *(delegated)* are replaced by an existing group when a delegation Group ID is configured.

## Delegation Overview

ControlPlane-Admins, ManagementPlane-Admins and CatalogPlane-Members groups can be **delegated** to existing groups instead of
creating new ones. This is useful when a central platform team already manages these groups across multiple
landing zones.

**How to configure delegation** (pick one):

| Method | ControlPlane-Admins | ManagementPlane-Admins | CatalogPlane-Members |
| ----------------------------------------- | ------------------------------------------- | ---------------------------------------------- | ---------------------------------- |
| Parameter | `-ControlPlaneDelegationGroupId <ObjectId>` | `-ManagementPlaneDelegationGroupId <ObjectId>` | `-AdministratorGroupId <ObjectId>` |
| EntraOpsConfig (landing zone cmdlet only) | `ServiceEM.ControlPlaneDelegationGroupId` | `ServiceEM.ManagementPlaneDelegationGroupId` | `ServiceEM.AdministratorGroupId` |
| Skip flag (no delegation, no creation) | `-SkipControlPlaneDelegation` | `-SkipManagementPlaneDelegation` | — |

When a delegation Group ID is set (via parameter **or** config), the skip flag is **automatically applied**:
no new group is created, and the provided group is used for all catalog role, policy approver, and Azure RBAC
assignments that would otherwise reference the landing-zone-owned group.

**What still uses the delegated group:**
- Catalog Owner role (`ControlPlaneDelegationGroupId`), a permanent assignment unless `-SkipCatalogOwnerAssignment` is set (see [Catalog Owner assignment](../service-em/index.html#catalog-owner-assignment-for-controlplane-admins))
- Catalog Reader and AP Assignment Manager catalog roles (`ManagementPlaneDelegationGroupId`, permanent, see [Access package assignment manager](../service-em/index.html#access-package-assignment-manager-for-managementplane-admins)), Catalog Reader (`AdministratorGroupId`)
- Access package approver and access reviewer of the ManagementPlane-Admins access package, if one exists (`ControlPlaneDelegationGroupId`)
- Access package approver in Workload Plane Policy, and access reviewer of all other policies except the WorkloadPlane-Users policies (`ManagementPlaneDelegationGroupId`)
- Requestor scope (`AdministratorGroupId`)
- PIM-eligible Azure UAA on RG (`ControlPlaneDelegationGroupId`)
- PIM-eligible Azure Contributor and constrained Role Based Access Control Administrator on RG (`ManagementPlaneDelegationGroupId`)

**What is NOT applied to the delegated group:**
- Registration as catalog resource / access package (the group is not added to the catalog and not deleted on removal)
- PIM policy configuration (group is managed by its owning service)
- PIM eligibility assignments into the group

---

## 1. Full Dependency Overview

Shows all groups, the EM catalog with access packages, approver/requestor dependencies, and Azure RBAC in one picture.

```mermaid
flowchart TD
    %% ── Actors ──────────────────────────────────────────────────────────────
    SvcMembers(["👥 Service Members\n(Initial Users; + admin with\n-AddWorkloadPlaneAdminToUsers)"])
    SvcOwner(["👤 Service Owner\n(Initial Admin)"])
    CatMembers(["👥 Catalog Members\n(-CatalogPlaneMembers)"])
    CtrlAdmins(["👤 ControlPlane Admins\n(-ControlPlaneAdmins)"])

    %% ── Entra Groups ─────────────────────────────────────────────────────────
    subgraph GROUPS["Entra ID Groups"]
        G_Unified["{Prefix} Members\nUnified M365 Group\n(optional, -CreateM365Group,\ncollaboration only;\nmember via every access package)"]

        subgraph CP_PL["Catalog Plane"]
            G_CP["SG-{Prefix}-CatalogPlane-Members"]
        end

        subgraph WP_PL["Workload Plane"]
            G_WP_Mbr["SG-{Prefix}-WorkloadPlane-Members"]
            G_WP_Usr["SG-{Prefix}-WorkloadPlane-Users"]
            G_WP_Adm["SG-{Prefix}-WorkloadPlane-Admins"]
        end

        subgraph MP_PL["Management Plane"]
            G_MP_Adm["SG-{Prefix}-ManagementPlane-Admins"]
        end

        subgraph CTRL_PL["Control Plane (optional)"]
            G_Ctrl["SG-{Prefix}-ControlPlane-Admins"]
        end
    end

    %% ── EM Catalog ───────────────────────────────────────────────────────────
    subgraph CATALOG["EM Catalog · Catalog-{Prefix}"]

        subgraph CAT_ROLES["Catalog Role Assignments"]
            CR_Owner["Catalog Owner"]
            CR_Reader["Catalog Reader"]
            CR_ApMgr["AP Assignment Manager"]
        end

        subgraph AP_WP_MBR["AP-{Prefix}-WorkloadPlane-Members"]
            POL_IWP["Initial Workload Membership Policy\nRequestors: All Member Users\nStage 1 Approver: Manager L1\nFallback / Stage 2: CatalogPlane-Members\nExpiry: 365 days · Review: Quarterly"]
        end

        subgraph AP_WP_USR["AP-{Prefix}-WorkloadPlane-Users"]
            POL_WPU["Workload Plane Users Policy\nRequestors: All Member Users (configurable)\nApprover: WorkloadPlane-Admins\nExpiry: 365 days · Review: Quarterly"]
            POL_IWU["Initial Workload Users Policy\nAdmin-assigned only, no approval\nExpiry: 365 days · Review: Quarterly"]
        end

        subgraph AP_WP_ADM["AP-{Prefix}-WorkloadPlane-Admins"]
            POL_WP["Workload Plane Policy\nRequestors: WorkloadPlane-Members\n(fallback CatalogPlane-Members)\nApprover: ManagementPlane-Admins\nExpiry: 365 days · Review: Quarterly"]
            POL_IWA["Initial Workload Admin Policy\nAdmin-assigned only, no approval\nExpiry: 365 days · Review: Quarterly"]
        end

        subgraph AP_CP_MBR["AP-{Prefix}-CatalogPlane-Members"]
            POL_BASE_CP["Baseline Policy\nRequestors: CatalogPlane-Members\nApprover: CatalogPlane-Members\nExpiry: 365 days · Review: Quarterly"]
            POL_ICM["Initial Catalog Members Policy\nAdmin-assigned only, no approval\nExpiry: 365 days · Review: Quarterly"]
        end

        subgraph AP_MP_ADM["AP-{Prefix}-ManagementPlane-Admins"]
            POL_MP["Management Plane Policy\nRequestors: CatalogPlane-Members\nApprover: ControlPlane-Admins\n(no escalation, no fallback)\nExpiry: 365 days · Review: Quarterly"]
            POL_IMA["Initial Management Admin Policy\nAdmin-assigned only, no approval\nExpiry: 365 days · Review: Quarterly"]
        end

    end

    %% ── Azure ────────────────────────────────────────────────────────────────
    subgraph AZURE["Azure Resource Group"]
        AZ_RG["RG-{Prefix}"]
    end

    %% ── Catalog Role Assignments (group → catalog role) ──────────────────────
    G_Ctrl   -->|"Catalog Owner\n(EM role)"| CR_Owner
    G_CP     -->|"Catalog Reader\n(EM role)"| CR_Reader
    G_WP_Adm -->|"Catalog Reader\n(EM role)"| CR_Reader
    G_MP_Adm -->|"Catalog Reader +\nAP Assignment Manager\n(EM roles)"| CR_ApMgr

    %% ── Access Package Resource Role Scopes (AP → group membership) ──────────
    AP_CP_MBR   -->|"grants Member role"| G_CP
    AP_WP_MBR   -->|"grants Member role"| G_WP_Mbr
    AP_WP_USR   -->|"grants Member role"| G_WP_Usr
    AP_WP_ADM   -->|"grants Member role\n(Eligible Member with\n-EnableWorkloadPlanePimForGroups)"| G_WP_Adm
    AP_MP_ADM   -->|"grants Member role\n(Eligible Member with\n-EnablePimForGroups)"| G_MP_Adm
    CATALOG     -.->|"every access package grants\nMember role (-CreateM365Group)"| G_Unified

    %% ── Policy Approvers (dashed) ────────────────────────────────────────────
    G_CP -.->|"Approver / Fallback"| POL_IWP
    G_CP -.->|"Approver"| POL_BASE_CP
    G_WP_Adm -.->|"Approver"| POL_WPU
    G_MP_Adm -.->|"Approver"| POL_WP
    G_Ctrl   -.->|"Approver"| POL_MP

    %% ── Policy Requestor Scopes (dashed) ────────────────────────────────────
    G_WP_Mbr -.->|"Eligible requestors"| POL_WP
    G_CP     -.->|"Eligible requestors"| POL_MP
    G_CP     -.->|"Eligible requestors"| POL_BASE_CP

    %% ── Initial Assignments (actors → packages) ──────────────────────────────
    %% Note: Without a WorkloadPlane-Members package (landing zones, Bootstrap default roles), members → WorkloadPlane-Users via Initial Workload Users Policy;
    %%       without a ManagementPlane-Admins package (e.g. Centralized or delegated ManagementPlane), owner → WorkloadPlane-Admins via Initial Workload Admin Policy
    SvcMembers ==>|"adminAdd via\nInitial Workload Membership Policy\n(or Initial Workload Users Policy)"| AP_WP_MBR
    SvcOwner   ==>|"adminAdd via\nInitial Management Admin Policy\n(or Initial Workload Admin Policy)\nwith -WorkloadPlaneAdmin"| AP_MP_ADM
    SvcOwner   ==>|"adminAdd via\nInitial Catalog Members Policy"| AP_CP_MBR
    CatMembers ==>|"adminAdd via\nInitial Catalog Members Policy"| AP_CP_MBR
    CtrlAdmins ==>|"direct member (no access package):\nPIM eligible with -EnablePimForGroups,\notherwise permanent"| G_Ctrl

    %% ── Azure RBAC ───────────────────────────────────────────────────────────
    G_WP_Adm  -->|"Reader (permanent)\nPIM Eligible: RBAC Admin (ABAC → WorkloadPlane-Users)"| AZ_RG
    G_MP_Adm  -->|"PIM Eligible: Contributor\nPIM Eligible: RBAC Admin (ABAC → WorkloadPlane-Admins)"| AZ_RG
    G_Ctrl    -->|"PIM Eligible: User Access Administrator"| AZ_RG
```

---

## 2. Group Structure by EAM Plane

Which groups are created and how they map to the Enterprise Access Model planes.

```mermaid
flowchart LR
    subgraph UNIFIED["Unified / M365"]
        G_Unified["{Prefix} Members\nType: Unified M365 Group\nMail enabled\n(optional, -CreateM365Group)\nPurpose: Team collaboration, no access to other groups\nMembers: users of every access package"]
    end

    subgraph CP_PL["Catalog Plane"]
        G_CP["SG-{Prefix}-CatalogPlane-Members\nType: Security Group\nPurpose: Catalog governance audience"]
    end

    subgraph WP_PL["Workload Plane"]
        G_WP_Mbr["SG-{Prefix}-WorkloadPlane-Members\nType: Security Group\nPurpose: Standard service access\n(only with custom -ServiceRoles)"]
        G_WP_Usr["SG-{Prefix}-WorkloadPlane-Users\nType: Security Group\nPurpose: End-user workload access"]
        G_WP_Adm["SG-{Prefix}-WorkloadPlane-Admins\nType: Security Group\nPurpose: Workload admin elevation\n(PIM for Groups: -EnableWorkloadPlanePimForGroups)"]
    end

    subgraph MP_PL["Management Plane"]
        G_MP_Adm["SG-{Prefix}-ManagementPlane-Admins\nType: Security Group\nPurpose: Service management admin elevation\n(PIM for Groups: -EnablePimForGroups)"]
    end

    subgraph CTRL_PL["Control Plane (optional)"]
        G_Ctrl["SG-{Prefix}-ControlPlane-Admins\nType: Security Group\nPurpose: Catalog owner + Azure UAA (PIM eligible on RG)\n(PIM for Groups: -EnablePimForGroups)"]
    end
```

---

## 3. Access Package → Group Resource Role Scopes

Each access package grants membership of exactly one security group. Requesting and receiving approval for an AP automatically adds the user to the corresponding group. ControlPlane-Admins and the Unified Members group have no access package of their own. With `-EnablePimForGroups` the ManagementPlane-Admins access package (and with `-EnableWorkloadPlanePimForGroups` the WorkloadPlane-Admins access package) grants the **Eligible Member** role (PIM for Groups eligible membership) instead of the Member role. With `-CreateM365Group`, the Unified Members group is added as a resource (Member role) to **every** access package of the scope, so all users assigned to any of them also become members of the Microsoft 365 group (and lose the membership when the assignment ends).

```mermaid
flowchart LR
    subgraph APS["Access Packages\n(inside Catalog-{Prefix})"]
        AP1["AP-{Prefix}-CatalogPlane-Members"]
        AP2["AP-{Prefix}-WorkloadPlane-Members"]
        AP3["AP-{Prefix}-WorkloadPlane-Users"]
        AP4["AP-{Prefix}-WorkloadPlane-Admins"]
        AP5["AP-{Prefix}-ManagementPlane-Admins"]
    end

    subgraph GRP["Entra Groups"]
        G_CP["SG-{Prefix}-CatalogPlane-Members"]
        G_WP_Mbr["SG-{Prefix}-WorkloadPlane-Members"]
        G_WP_Usr["SG-{Prefix}-WorkloadPlane-Users"]
        G_WP_Adm["SG-{Prefix}-WorkloadPlane-Admins"]
        G_MP_Adm["SG-{Prefix}-ManagementPlane-Admins"]
        G_Unified["{Prefix} Members\n(optional, -CreateM365Group)"]
    end

    AP1 -->|"Member role"| G_CP
    AP2 -->|"Member role"| G_WP_Mbr
    AP3 -->|"Member role"| G_WP_Usr
    AP4 -->|"Member role\n(Eligible Member with\n-EnableWorkloadPlanePimForGroups)"| G_WP_Adm
    AP5 -->|"Member role\n(Eligible Member with\n-EnablePimForGroups)"| G_MP_Adm
    AP1 & AP2 & AP3 & AP4 & AP5 -.->|"Member role\n(-CreateM365Group)"| G_Unified
```

---

## 4. Assignment Policies — Requestors, Approvers & Expiry

Who can request each access package and who approves it.

```mermaid
flowchart TD
    %% Groups referenced as requestor scopes or approvers
    AllUsers(["All Member Users\n(Tenant)"])
    Manager(["Requestor's Manager\n(L1 - Graph)"])
    G_CP["SG-{Prefix}-CatalogPlane-Members"]
    G_WP_Mbr["SG-{Prefix}-WorkloadPlane-Members"]
    G_WP_Adm["SG-{Prefix}-WorkloadPlane-Admins"]
    G_MP_Adm["SG-{Prefix}-ManagementPlane-Admins"]
    G_Ctrl["SG-{Prefix}-ControlPlane-Admins"]

    %% ── AP-Members-WorkloadPlane ─────────────────────────────────────────────
    subgraph AP_WP_MBR["AP-{Prefix}-WorkloadPlane-Members"]
        POL_IWP["Initial Workload Membership Policy\nExpiry: 365 days"]
    end
    AllUsers  -->|"can request"| POL_IWP
    Manager   -->|"Stage 1 Approver"| POL_IWP
    G_CP      -->|"Fallback + Stage 2 Approver"| POL_IWP

    %% ── AP-Admins-WorkloadPlane ──────────────────────────────────────────────
    subgraph AP_WP_ADM["AP-{Prefix}-WorkloadPlane-Admins"]
        POL_WP["Workload Plane Policy\nExpiry: 365 days"]
        POL_IWA["Initial Workload Admin Policy\nAdmin-assigned only, no approval\nExpiry: 365 days"]
    end
    G_WP_Mbr  -->|"can request\n(fallback CatalogPlane-Members)"| POL_WP
    G_MP_Adm  -->|"Approver"| POL_WP

    %% ── AP-Users-WorkloadPlane ───────────────────────────────────────────────
    subgraph AP_WP_USR["AP-{Prefix}-WorkloadPlane-Users"]
        POL_WPU["Workload Plane Users Policy\nExpiry: 365 days"]
        POL_IWU["Initial Workload Users Policy\nAdmin-assigned only, no approval\nExpiry: 365 days"]
    end
    AllUsers  -->|"can request\n(RequestorScope AllMemberUsers;\nCatalogPlaneMembers: CatalogPlane-Members)"| POL_WPU
    G_WP_Adm  -->|"Approver"| POL_WPU

    %% ── AP-Admins-ManagementPlane ────────────────────────────────────────────
    subgraph AP_MP_ADM["AP-{Prefix}-ManagementPlane-Admins"]
        POL_MP["Management Plane Policy\nExpiry: 365 days"]
        POL_IMA["Initial Management Admin Policy\nAdmin-assigned only, no approval\nExpiry: 365 days"]
    end
    G_CP      -->|"can request"| POL_MP
    G_Ctrl    -->|"Approver\n(no escalation, no fallback)"| POL_MP

    %% ── Baseline Policy package ──────────────────────────────────────────────
    subgraph AP_BASELINE["AP-{Prefix}-CatalogPlane-Members"]
        POL_BASE["Baseline Policy\nExpiry: 365 days"]
        POL_ICM["Initial Catalog Members Policy\nAdmin-assigned only, no approval\n(-WorkloadPlaneAdmin, -CatalogPlaneMembers)\nExpiry: 365 days"]
    end
    G_CP      -->|"can request"| POL_BASE
    G_CP      -->|"Approver"| POL_BASE

    %% ── Access reviewers (dashed) ─────────────────────────────────────────
    %% Defaults: WorkloadPlane-Admins (WorkloadPlane-Users policies), ControlPlane-Admins (ManagementPlane-Admins policies),
    %% ManagementPlane-Admins (all others); only groups of the scope (own or delegated) are used,
    %% then a missing group falls back to a higher tier only; without one the policy gets no access review
    G_MP_Adm -.->|"Access reviewer\n(Quarterly, 25-day window)"| POL_IWP
    G_MP_Adm -.->|"Access reviewer"| POL_WP
    G_WP_Adm -.->|"Access reviewer"| POL_WPU
    G_WP_Adm -.->|"Access reviewer"| POL_IWU
    G_MP_Adm -.->|"Access reviewer"| POL_IWA
    G_Ctrl   -.->|"Access reviewer"| POL_MP
    G_Ctrl   -.->|"Access reviewer"| POL_IMA
    G_MP_Adm -.->|"Access reviewer"| POL_BASE
    G_MP_Adm -.->|"Access reviewer"| POL_ICM
```

---

## 5. Azure Resource Group RBAC

How groups are assigned to the Azure resource group created for the landing zone (default PIM RBAC model).

```mermaid
flowchart LR
    subgraph GRP["Entra Groups"]
        G_WP_Adm["SG-{Prefix}-WorkloadPlane-Admins"]
        G_WP_Usr["SG-{Prefix}-WorkloadPlane-Users"]
        G_MP_Adm["SG-{Prefix}-ManagementPlane-Admins"]
        G_Ctrl["SG-{Prefix}-ControlPlane-Admins\n(optional)"]
    end

    subgraph AZ["Azure"]
        RG["RG-{Prefix}\nResource Group"]
    end

    G_WP_Adm  -->|"Direct assignment\nReader"| RG
    G_WP_Adm  -->|"PIM Eligible\nRBAC Administrator\n(ABAC: allowed data-plane roles only)"| RG
    G_MP_Adm  -->|"PIM Eligible\nContributor\n(skipped if eligible at subscription)"| RG
    G_MP_Adm  -->|"PIM Eligible\nRBAC Administrator\n(ABAC: all except Owner/UAA/RBAC Admin)"| RG
    G_Ctrl    -->|"PIM Eligible\nUser Access Administrator\n(skipped if eligible at subscription)"| RG
    G_WP_Adm  -.->|"may assign roles to"| G_WP_Usr
    G_MP_Adm  -.->|"may assign roles to\n(e.g. Website Contributor)"| G_WP_Adm
```

> WorkloadPlane-Admins don't get Contributor: Contributor on the resource group equals ManagementPlane control (e.g. managed identities, Key Vault access policies, run command) and would be a tier breach for the WorkloadPlane. Resource-level or other roles are assigned to WorkloadPlane-Admins by ManagementPlane-Admins through their constrained RBAC Administrator. ServiceEM assigns no Owner role: unrestricted access (role assignments including Owner) remains only with ControlPlane-Admins via the PIM-eligible User Access Administrator. All groups of the scope are assigned, including delegated ControlPlane-/ManagementPlane-Admins groups.

---

## 6. Catalog Role Assignments

Which groups hold governance roles in the EM Catalog itself.

```mermaid
flowchart LR
    subgraph CAT["Catalog: Catalog-{Prefix}"]
        CR_Owner["Role: Owner\n(manages catalog resources)"]
        CR_Reader["Role: Reader\n(reads catalog content)"]
        CR_ApMgr["Role: AP Assignment Manager\n(assigns access packages on behalf of others)"]
    end

    G_Ctrl["SG-{Prefix}-ControlPlane-Admins\n(optional)"]  -->|"Catalog Owner"| CR_Owner
    G_CP["SG-{Prefix}-CatalogPlane-Members"]                -->|"Catalog Reader"| CR_Reader
    G_WP_Adm["SG-{Prefix}-WorkloadPlane-Admins"]            -->|"Catalog Reader"| CR_Reader
    G_MP_Adm["SG-{Prefix}-ManagementPlane-Admins"]          -->|"Catalog Reader"| CR_Reader
    G_MP_Adm                                                -->|"AP Assignment Manager"| CR_ApMgr
```

> **Security note:** Catalog roles can't be PIM-protected. The **Access package assignment manager** role of ManagementPlane-Admins
> is permanent: its members can directly assign every access package of the catalog without approval, including
> ManagementPlane-Admins itself, and every deployment shows a warning about it. To avoid this standing permission, make the
> membership of ManagementPlane-Admins eligible via PIM for Groups with `-EnablePimForGroups` (see
> [EnablePimForGroups and EnableWorkloadPlanePimForGroups Parameters](../service-em/index.html#enablepimforgroups-and-enableworkloadplanepimforgroups-parameters)).
> The Catalog Owner role of ControlPlane-Admins is permanent
> as well unless `-SkipCatalogOwnerAssignment` is set (with `-EnablePimForGroups`, the membership of ControlPlane-Admins is eligible too).

---

## Summary Table

| Resource | Name | Depends on |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unified Group        | `{Prefix} Members` (only with `-CreateM365Group`: team collaboration, email/ChatOps, SharePoint/Teams knowledge)                                                                                     | Resource (Member role) of every access package of the scope                                                                                                                                                                                                                                                 |
| Security Group | `SG-{Prefix}-CatalogPlane-Members` | *(delegated via `AdministratorGroupId`)* |
| Security Group       | `SG-{Prefix}-WorkloadPlane-Members`                                                                                                                                                                  | — (only with custom `-ServiceRoles`)                                                                                                                                                                                                                                                                        |
| Security Group | `SG-{Prefix}-WorkloadPlane-Users` | — |
| Security Group | `SG-{Prefix}-WorkloadPlane-Admins` | — |
| Security Group | `SG-{Prefix}-ManagementPlane-Admins` | *(delegated)* |
| Security Group       | `SG-{Prefix}-ControlPlane-Admins`                                                                                                                                                                    | *(optional / delegated)*; initial members via `-ControlPlaneAdmins` (no access package)                                                                                                                                                                                                                     |
| EM Catalog | `Catalog-{Prefix}` | All owned groups above (registered as resources; delegated groups are not) |
| Catalog Role | Owner | ControlPlane-Admins as principal (own or delegated group) |
| Catalog Role | Reader | CatalogPlane-Members, WorkloadPlane-Admins and ManagementPlane-Admins as principals |
| Catalog Role         | ApAssignmentManager                                                                                                                                                                                  | ManagementPlane-Admins as principal (own or delegated group); permanent, can assign every access package of the catalog without approval                                                                                                                                                                    |
| Access Package | `AP-{Prefix}-CatalogPlane-Members` | Catalog · CatalogPlane-Members group |
| Access Package | `AP-{Prefix}-WorkloadPlane-Members` | Catalog · WorkloadPlane-Members group |
| Access Package | `AP-{Prefix}-WorkloadPlane-Users` | Catalog · WorkloadPlane-Users group |
| Access Package | `AP-{Prefix}-WorkloadPlane-Admins` | Catalog · WorkloadPlane-Admins group |
| Access Package | `AP-{Prefix}-ManagementPlane-Admins` | Catalog · ManagementPlane-Admins group (not created when delegated) |
| Assignment Policy | Initial Workload Membership Policy | WorkloadPlane-Members AP · requestor's manager, then CatalogPlane-Members (approvers) |
| Assignment Policy    | Workload Plane Policy                                                                                                                                                                                | WorkloadPlane-Admins AP · WorkloadPlane-Members (requestors; CatalogPlane-Members if no WorkloadPlane-Members group exists) · ManagementPlane-Admins (approver, own or delegated group) — not created without a ManagementPlane-Admins approver                                 |
| Assignment Policy | Initial Workload Admin Policy | WorkloadPlane-Admins AP · admin-assigned only (targets: all member users), no approval |
| Assignment Policy    | Workload Plane Users Policy                                                                                                                                                                          | WorkloadPlane-Users AP · all member users (requestors; `ServiceEM.AssignmentPolicies.WorkloadPlaneUsers.RequestorScope` = `CatalogPlaneMembers` restricts to CatalogPlane-Members) · WorkloadPlane-Admins (approver; ManagementPlane-Admins if no WorkloadPlane-Admins group exists, otherwise not created) |
| Assignment Policy | Initial Workload Users Policy | WorkloadPlane-Users AP · admin-assigned only (targets: all member users), no approval |
| Assignment Policy    | Management Plane Policy                                                                                                                                                                              | ManagementPlane-Admins AP · CatalogPlane-Members (requestors) · ControlPlane-Admins (approver, no escalation or fallback; default access reviewer) — only if ControlPlane-Admins (own or delegated) exists in the scope                                              |
| Assignment Policy | Initial Management Admin Policy | ManagementPlane-Admins AP · admin-assigned only (targets: all member users), no approval |
| Assignment Policy | Baseline Policy | CatalogPlane-Members AP · CatalogPlane-Members (requestors & approver) |
| Assignment Policy    | Initial Catalog Members Policy                                                                                                                                                                       | CatalogPlane-Members AP · admin-assigned only (targets: all member users), no approval — not created with `AdministratorGroupId`                                                                                                                                                                            |
| Initial Assignment | Service Members (+ the Service Owner with `-AddWorkloadPlaneAdminToUsers`) → WorkloadPlane-Members AP, or WorkloadPlane-Users AP if no WorkloadPlane-Members AP exists (landing zones) | Initial Workload Membership Policy (with approval) or Initial Workload Users Policy |
| Initial Assignment | Service Owner (`-WorkloadPlaneAdmin`) → ManagementPlane-Admins AP, or WorkloadPlane-Admins AP if no ManagementPlane-Admins AP exists | Initial Management Admin Policy or Initial Workload Admin Policy |
| Initial Assignment   | Service Owner (`-WorkloadPlaneAdmin`) and `-CatalogPlaneMembers` → CatalogPlane-Members AP                                                                                                           | Initial Catalog Members Policy                                                                                                                                                                                                                                                                              |
| Initial Membership   | `-ControlPlaneAdmins` → ControlPlane-Admins group (PIM for Groups eligible with `-EnablePimForGroups`, otherwise permanent)                                                                          | PerService only                                                                                                                                                                                                                                                                                             |
| PIM for Groups       | Policy for ControlPlane-Admins and ManagementPlane-Admins; their access packages grant eligible membership (Eligible Member)                                                                         | Only with `-EnablePimForGroups` (Microsoft Entra ID Governance license); never for delegated groups                                                                                                                                                                                                         |
| PIM for Groups       | Policy for WorkloadPlane-Admins; its access package grants eligible membership (Eligible Member)                                                                                                     | Only with `-EnableWorkloadPlanePimForGroups`; WorkloadPlane-Users, CatalogPlane-Members and the `{Prefix} Members` Microsoft 365 group never get PIM for Groups                                                                                                                                             |
| PIM for Groups       | Service Owner (`-WorkloadPlaneAdmin`) → eligible owner of the WorkloadPlane-Users and WorkloadPlane-Admins groups (only with `-GroupOwnership Eligible`; `Permanent` sets a permanent owner instead) | No other group gets an owner                                                                                                                                                                                                                                                                                |
| Azure Resource Group | `RG-{Prefix}` (without `Sub-`/`Rg-`)                                                                                                                                                                 | WorkloadPlane-Admins (Reader, eligible constrained RBAC Admin), ManagementPlane-Admins / delegated group (eligible Contributor + constrained RBAC Admin), ControlPlane-Admins / delegated group (eligible UAA); no Owner assignment                                                                         |

---

## Centralized Governance Model Notes

When deploying `New-EntraOpsSubscriptionLandingZone` with `-GovernanceModel "Centralized"` (or `ServiceEM.GovernanceModel = "Centralized"` in `EntraOpsConfig.json`), the landing zone structure differs significantly. Configured delegation group IDs alone don't switch the model; in the PerService model they only replace the corresponding per-service groups.

### Key Differences

**Tenant-Wide Delegation Groups:**
- ControlPlane-Admins → Shared group (e.g., `prg - Contoso - IdentityOps`)
- ManagementPlane-Admins → Shared group (e.g., `prg - Contoso - PlatformOps`)
- AdministratorGroup (CatalogPlane-Members) → Shared group (e.g., `dug - PrivilegedAccounts`)

**Groups (default `-DeploymentScope ResourceGroup`; `Subscription` uses `Sub-`):**
| Group Created | Purpose |
| ------------------------------------- | ------------------------------------------------------------------- |
| `Rg-{Prefix} Members` | Unified M365 group for team collaboration (with `-CreateM365Group`) |
| `SG-Rg-{Prefix}-WorkloadPlane-Users` | Security group for data-plane access |
| `SG-Rg-{Prefix}-WorkloadPlane-Admins` | Security group for workload admin elevation |

**Access Packages:**
| Access Package | Grants Membership To | Policy | Initial Assignment |
| ------------------------------------- | ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `AP-Rg-{Prefix}-WorkloadPlane-Users` | `SG-Rg-{Prefix}-WorkloadPlane-Users` | Workload Plane Users Policy (requestors: all member users, approver: WorkloadPlane-Admins) and Initial Workload Users Policy (admin-assigned only) | Service Members via Initial Workload Users Policy |
| `AP-Rg-{Prefix}-WorkloadPlane-Admins` | `SG-Rg-{Prefix}-WorkloadPlane-Admins` | Workload Plane Policy (requestors: AdministratorGroup, approver: ManagementPlane delegation group) and Initial Workload Admin Policy (admin-assigned only) | Service Owner (`-WorkloadPlaneAdmin`) via Initial Workload Admin Policy |

**What's NOT Created (Centralized):**
- ❌ Per-service ControlPlane-Admins groups
- ❌ Per-service ManagementPlane-Admins groups
- ❌ Per-service CatalogPlane-Members groups
- ❌ WorkloadPlane-Members groups
- ❌ PIM for Groups for the delegated groups (WorkloadPlane-Admins only with `-EnableWorkloadPlanePimForGroups`)
- ❌ Microsoft 365 group, unless `-CreateM365Group` is used

**What STILL Happens:**
- ✅ Tenant-wide delegation groups are referenced in each service's catalog (catalog roles and policies only - they are **not** added as catalog resources)
- ✅ Catalog role assignments use the delegated groups (Owner; Reader + AP Assignment Manager; Reader)
- ✅ Azure RBAC assignments on `RG-{Prefix}` use the delegated groups (eligible UAA; eligible Contributor + constrained RBAC Administrator), skipped for Contributor/UAA if already eligible at subscription level
- ✅ Access package policies reference delegated groups as requestors, approvers and reviewers

### Centralized Model Simplified Diagram

```mermaid
flowchart TD
    %% ─── Actors ───────────────────────────────────────────────────────────
    SvcMembers(["👥 Service Members"])
    SvcOwner(["👤 Service Owner"])

    %% ─── Tenant-Wide Delegation Groups ────────────────────────────────────
    subgraph DELEGATED["Tenant-Wide Groups\n(from EntraOpsConfig.json)"]
        G_Ctrl_Global["prg - IdentityOps\n(ControlPlane delegation)"]
        G_MP_Global["prg - PlatformOps\n(ManagementPlane delegation)"]
        G_Admin_Global["dug - PrivilegedAccounts\n(Administrator / CatalogPlane)"]
    end

    %% ─── Landing zone scope ─────────────────────────────────────────────────
    subgraph RG["Scope Rg-{Prefix}"]
        G_Rg_Members["Rg-{Prefix} Members\n(Unified M365, -CreateM365Group,\ncollaboration only)"]
        G_WP_Usr["SG-Rg-{Prefix}-WorkloadPlane-Users"]
        G_WP_Adm["SG-Rg-{Prefix}-WorkloadPlane-Admins"]
        
        subgraph CAT_Rg["Catalog-Rg-{Prefix}"]
            AP_WP_Usr["AP-Rg-{Prefix}-WorkloadPlane-Users\nApprover: WorkloadPlane-Admins"]
            AP_WP_Adm["AP-Rg-{Prefix}-WorkloadPlane-Admins\nApprover: ManagementPlane (delegated)"]
        end
    end

    %% ─── Azure ────────────────────────────────────────────────────────────
    subgraph AZURE["Azure"]
        AZ_RG["RG-{Prefix}"]
    end

    %% ─── Delegation groups referenced in catalogs (roles only, not resources) ─
    G_Ctrl_Global -.->|"Catalog Owner"| CAT_Rg
    G_MP_Global -.->|"Reader + AP Assignment Manager"| CAT_Rg
    G_Admin_Global -.->|"Catalog Reader"| CAT_Rg

    %% ─── Access packages grant membership ─────────────────────────────────
    AP_WP_Usr -->|"grants Member role"| G_WP_Usr
    AP_WP_Adm -->|"grants Member role\n(Eligible Member with\n-EnableWorkloadPlanePimForGroups)"| G_WP_Adm

    %% ─── Initial assignments ──────────────────────────────────────────────
    SvcMembers ==>|"adminAdd via\nInitial Workload Users Policy"| AP_WP_Usr
    SvcOwner ==>|"adminAdd via\nInitial Workload Admin Policy"| AP_WP_Adm


    %% ─── Azure RBAC ────────────────────────────────────────────────────────
    G_Ctrl_Global -->|"PIM Eligible: UAA\n(skipped if eligible at subscription)"| AZ_RG
    G_MP_Global -->|"PIM Eligible: Contributor\n(skipped if eligible at subscription)\n+ constrained RBAC Admin"| AZ_RG
    G_WP_Adm -->|"Reader (permanent)\n+ PIM Eligible: constrained RBAC Admin"| AZ_RG
```

**Benefits of Centralized Model:**
- **Reduced group sprawl**: 3 tenant-wide groups instead of 5-7 per service
- **Consistent administrators**: Same IdentityOps team manages UAA across all services
- **Simplified PIM**: With a subscription-level eligibility (assigned outside ServiceEM), one activation for PlatformOps grants Contributor across all landing zones of that subscription
- **Clearer separation**: ControlPlane/ManagementPlane managed outside service landing zones

**When to Use Centralized:**
- ✅ 10+ services with dedicated operations teams (IdentityOps, PlatformOps)
- ✅ Organization has mature persona-based administration model
- ✅ Consistent delegation across all landing zones preferred

**When to Use PerService:**
- ✅ 1-5 services with dedicated service-specific teams
- ✅ Need full isolation between service administrative domains
- ✅ Dev/test environments where autonomy is prioritized
