<#
.SYNOPSIS
    Creates an EAM authorization structure for an Azure resource group or subscription.

.DESCRIPTION
    Provisions EAM groups, an Entitlement Management catalog, access packages,
    PIM policies and Azure role assignments for one scope. -DeploymentScope selects it:

    ResourceGroup (default) — scope "Rg-<Prefix>": catalog Catalog-Rg-<Prefix>,
      resource group RG-<Prefix> with all Azure role assignments on the resource group.

    Subscription — scope "Sub-<Prefix>": catalog Catalog-Sub-<Prefix>, no resource
      group; the same Azure role assignments are made on the subscription (-SubscriptionId).

    To share governance groups between landing zones, pass their IDs as
    -ControlPlaneDelegationGroupId / -ManagementPlaneDelegationGroupId / -AdministratorGroupId
    or use -GovernanceModel Centralized.

    Groups (PerService): SG-<Scope>-CatalogPlane-Members,
    SG-<Scope>-WorkloadPlane-Users, SG-<Scope>-WorkloadPlane-Admins,
    SG-<Scope>-ControlPlane-Admins and SG-<Scope>-ManagementPlane-Admins, and with -CreateM365Group the
    Microsoft 365 group <Scope> Members.

    Delegation and governance model behaviour:
    - When GovernanceModel = "PerService" (default), per-service groups are created
      for ControlPlane-Admins and ManagementPlane-Admins.
    - When GovernanceModel = "Centralized", ControlPlane-Admins,
      ManagementPlane-Admins and CatalogPlane-Members are resolved to tenant-wide
      shared groups via Resolve-EntraOpsServiceEMDelegationGroup.
    - Delegation group IDs are read from EntraOpsConfig.ServiceEM when not
      passed as parameters.

.PARAMETER DeploymentScope
    "ResourceGroup" (default) or "Subscription".

.PARAMETER ServiceMembers
    UPN(s) of users to add as initial WorkloadPlane-Users.
    Defaults to the signed-in identity.

.PARAMETER WorkloadPlaneAdmin
    UPN of the workload plane admin, assigned to the admin access package
    (ManagementPlane-Admins or WorkloadPlane-Admins) and to CatalogPlane-Members. Defaults to the
    signed-in identity only when -GroupOwnership is Eligible or Permanent.

.PARAMETER GroupOwnership
    Opt-in ownership of the WorkloadPlane groups (WorkloadPlane-Admins, WorkloadPlane-Users) for
    the workload plane admin: "None" (default), "Eligible" (PIM for Groups eligible owner) or "Permanent"
    (owner set when the groups are created). Owners can add members directly, bypassing access package
    approvals and access reviews, so a warning is shown. ControlPlane, ManagementPlane, CatalogPlane and
    tenant-wide delegation groups never get an owner.

.PARAMETER ControlPlaneAdmins
    UPN(s) of the initial members of the per-service ControlPlane-Admins group (PerService model only;
    in the Centralized model the tenant-wide group is managed outside ServiceEM). Added permanently, or as
    PIM for Groups eligible members with -EnablePimForGroups.
    Without this parameter an Entra administrator adds the members in the portal.

.PARAMETER CatalogPlaneMembers
    UPN(s) assigned to the CatalogPlane-Members access package, in addition to the
    WorkloadPlaneAdmin. CatalogPlane-Members (the administrator group) request WorkloadPlane-Admins and
    ManagementPlane-Admins; non-members can't request CatalogPlane-Members. Ignored with AdministratorGroupId.

.PARAMETER AddWorkloadPlaneAdminToUsers
    Also assigns the workload plane admin to the WorkloadPlane-Users access package, in addition to the
    admin access package. Not set by default, so admin accounts don't get data-plane user access.
    Defaults to EntraOpsConfig.ServiceEM.AddWorkloadPlaneAdminToUsers; an explicitly passed value wins.

.PARAMETER EnablePimForGroups
    Recommended. Manages ControlPlane-Admins and ManagementPlane-Admins with PIM for Groups:
    PIM activation policy and eligible instead of active membership through their access packages. Both
    groups hold permanent catalog roles that can't be PIM-protected otherwise. Requires Microsoft Entra ID
    Governance or Microsoft Entra Suite licenses (a warning is shown). Not set by default.

.PARAMETER EnableWorkloadPlanePimForGroups
    Manages WorkloadPlane-Admins with PIM for Groups in the same way, e.g. for multi-activation
    scenarios. Requires Microsoft Entra ID Governance or Microsoft Entra Suite licenses (a warning is shown).
    Not set by default.

.PARAMETER CreateM365Group
    Creates the Microsoft 365 group "<Scope>-<Prefix> Members". It is meant for the
    collaboration of the service team: a group mailbox and calendar for email and ChatOps notifications
    and, when SharePoint Online or Microsoft Teams is used, a SharePoint site or team as knowledge base.
    The group is added to every access package, so all users assigned to an access package
    become members. It gets no PIM for Groups eligibilities or other access. Not created by default.
    Defaults to EntraOpsConfig.ServiceEM.CreateM365Group; an explicitly passed value wins.

.PARAMETER SkipAzureResourceGroup
    When set, no Azure resource group and no Azure role assignments are created.

.PARAMETER AzureRegion
    Azure region for the resource group (e.g. "westeurope"). Required unless
    -SkipAzureResourceGroup is set or -DeploymentScope is "Subscription".

.PARAMETER SubscriptionId
    Subscription in which the resource group (or, for -DeploymentScope Subscription, the subscription
    role assignments) is created. Required unless -SkipAzureResourceGroup is set. Validated before any
    object is created; the previous Azure context is restored afterwards.

.PARAMETER DeploymentPrefix
    Prefix used in all group DisplayNames and catalog names. Defaults to
    "Default". Use the subscription or workload name
    (e.g. "Sub-Management", "Sub-Connectivity").

.PARAMETER SkipControlPlaneDelegation
    Skips creation of the per-service ControlPlane-Admins group and its Catalog
    Owner / Azure UAA PIM eligible assignments. Applied
    automatically when ControlPlaneDelegationGroupId is provided or when
    GovernanceModel is Centralized.

.PARAMETER SkipCatalogOwnerAssignment
    Do not assign the Catalog Owner role to ControlPlane-Admins. Without this switch,
    ControlPlane-Admins get a permanent (not PIM-protected) Catalog Owner assignment and can modify the
    catalog, access packages and policies. Prefer an eligible Identity Governance Administrator
    assignment via PIM instead.

.PARAMETER SkipManagementPlaneDelegation
    Skips creation of the per-service ManagementPlane-Admins group and its
    entitlement/Azure delegation. Applied automatically when
    ManagementPlaneDelegationGroupId is provided or when GovernanceModel is
    Centralized.

.PARAMETER GovernanceModel
    Governance model for the landing zone deployment. Valid values: "Centralized", "PerService".
    
    Centralized: Uses tenant-wide delegation groups (ControlPlane-Admins and 
    ManagementPlane-Admins) that are shared across all landing zones. Requires
    pre-existing groups or permissions to create them.
    
    PerService: Creates per-service admin groups for each landing zone. No
    pre-existing groups required. This is the default for simple deployments.
    
    Defaults to "PerService" unless overridden in EntraOpsConfig.json or via
    this parameter.

.PARAMETER ControlPlaneDelegationGroupId
    Object ID of an existing Entra group to use as ControlPlane-Admins instead of
    creating a per-service group, e.g. the ControlPlane-Admins of a governance landing zone shared by
    several workloads. Receives the Catalog Owner role and a PIM eligible User Access Administrator assignment.
    Falls back to EntraOpsConfig.ServiceEM.ControlPlaneDelegationGroupId.

.PARAMETER ManagementPlaneDelegationGroupId
    Object ID of an existing Entra group to use as ManagementPlane-Admins instead of
    creating a per-service group. Receives the AP Assignment Manager catalog role, approver role
    in access package policies, and a PIM eligible Contributor role.
    Falls back to EntraOpsConfig.ServiceEM.ManagementPlaneDelegationGroupId.

.PARAMETER AdministratorGroupId
    Object ID of an existing Entra group to use as CatalogPlane-Members instead of
    creating a per-service group. Controls who can request elevated access packages. Falls back to EntraOpsConfig.ServiceEM.AdministratorGroupId.
    Required with GovernanceModel "Centralized".

.PARAMETER ControlPlaneGroupName
    Display name of the tenant-wide ControlPlane delegation group to look up or
    create when GovernanceModel is Centralized. Defaults to
    "PRG-Tenant-ControlPlane-IdentityOps". Overridden by
    EntraOpsConfig.ServiceEM.ControlPlaneGroupName.

.PARAMETER ManagementPlaneGroupName
    Display name of the tenant-wide ManagementPlane delegation group to look up
    or create when GovernanceModel is Centralized. Defaults to
    "PRG-Tenant-ManagementPlane-PlatformOps". Overridden by
    EntraOpsConfig.ServiceEM.ManagementPlaneGroupName.

.PARAMETER GroupPrefix
    Prefix of the security group display names (e.g. "SG" for SG-Rg-<Prefix>-WorkloadPlane-Users).
    Defaults to EntraOpsConfig.ServiceEM.GroupPrefix, otherwise "SG"; an explicitly passed value wins.

.PARAMETER logPrefix
    Text prepended to verbose messages. Defaults to the function name.

    .EXAMPLE
    New-EntraOpsSubscriptionLandingZone -DeploymentPrefix "Management" `
        -AzureRegion "westeurope" -SubscriptionId "<subscription-id>" `
        -WorkloadPlaneAdmin "admin@contoso.com" `
        -ServiceMembers @("alice@contoso.com", "bob@contoso.com")

    Creates the Rg-Management scope with one catalog, the resource group RG-Management
    in West Europe and the Azure role assignments on it. Per-service admin groups are
    created (PerService governance model default).

.EXAMPLE
    New-EntraOpsSubscriptionLandingZone -DeploymentPrefix "Connectivity" -DeploymentScope Subscription `
        -SubscriptionId "<subscription-id>" -WorkloadPlaneAdmin "admin@contoso.com"

    Creates the Sub-Connectivity scope with one catalog and assigns the Azure roles on
    the subscription instead of a resource group.

.EXAMPLE
    $governance = New-EntraOpsServiceBootstrap -ServiceName "Sub-Connectivity" -SkipAzureResourceGroup `
        -EnablePimForGroups -ServiceRoles (@"
accessLevel,name,groupType
CatalogPlane,Members,
ControlPlane,Admins,
ManagementPlane,Admins,
"@ | ConvertFrom-Csv)
    $groupId = { param($name) ($governance.Groups | Where-Object DisplayName -like "*-$name").Id }

    New-EntraOpsSubscriptionLandingZone -DeploymentPrefix "Connectivity" `
        -AzureRegion "northeurope" -SubscriptionId "<subscription-id>" `
        -ControlPlaneDelegationGroupId (& $groupId 'ControlPlane-Admins') `
        -ManagementPlaneDelegationGroupId (& $groupId 'ManagementPlane-Admins') `
        -AdministratorGroupId (& $groupId 'CatalogPlane-Members')

    Separates governance and workload groups: a governance scope
    Sub-Connectivity without Azure resources holds ControlPlane-Admins, ManagementPlane-Admins and
    CatalogPlane-Members; the workload landing zone Rg-Connectivity uses them as delegated groups for
    its catalog roles, approvals, access reviews and Azure roles on RG-Connectivity. Repeat the second
    call for further workloads.

    .EXAMPLE
    New-EntraOpsSubscriptionLandingZone -DeploymentPrefix "Dev" `
        -SkipAzureResourceGroup

    Creates all Entra ID groups, the EM catalog and access packages for the Rg-Dev
    scope without Azure resources. Useful for development
    environments or Entra-only access structures.

#>
function New-EntraOpsSubscriptionLandingZone {
    [OutputType([System.String])]
    [cmdletbinding()]
    param(
        [string[]]$ServiceMembers,

        [string]$WorkloadPlaneAdmin,

        [switch]$AddWorkloadPlaneAdminToUsers,

        [ValidateSet("None", "Eligible", "Permanent")]
        [string]$GroupOwnership = "None",

        [string[]]$ControlPlaneAdmins,

        [string[]]$CatalogPlaneMembers,

        [switch]$EnablePimForGroups,

        [switch]$EnableWorkloadPlanePimForGroups,

        [switch]$CreateM365Group,

        [switch]$SkipAzureResourceGroup,

        [switch]$SkipControlPlaneDelegation,

        [switch]$SkipCatalogOwnerAssignment,

        [switch]$SkipManagementPlaneDelegation,

        [ValidateSet("Centralized", "PerService")]
        [string]$GovernanceModel,

        [string]$AzureRegion,

        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$SubscriptionId,

        [string]$DeploymentPrefix = "Default",

        [ValidateSet("ResourceGroup", "Subscription")]
        [string]$DeploymentScope = "ResourceGroup",

        [string]$ControlPlaneDelegationGroupId = "",

        [string]$ManagementPlaneDelegationGroupId = "",

        [string]$AdministratorGroupId = "",

        [string]$ControlPlaneGroupName = "PRG-Tenant-ControlPlane-IdentityOps",

        [string]$ManagementPlaneGroupName = "PRG-Tenant-ManagementPlane-PlatformOps",

        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]*$')]
        [string]$GroupPrefix = "SG",

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $scopeName = if ($DeploymentScope -eq "Subscription") { "Sub" } else { "Rg" }
        $serviceRoles = @(
            [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified"},
            [pscustomobject]@{accessLevel = "CatalogPlane"; name = "Members"; groupType = ""},
            [pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Users"; groupType = ""},
            [pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Admins"; groupType = ""},
            [pscustomobject]@{accessLevel = "ControlPlane"; name = "Admins"; groupType = ""}
        )
        Write-Verbose "$logPrefix Deployment scope: $DeploymentScope"

        # Load EntraOpsConfig.json if not already loaded
        if ($null -eq $Global:EntraOpsConfig) {
            $configPaths = @(
                "$PWD/EntraOpsConfig.json"
                "$PSScriptRoot/EntraOpsConfig.json"
                $env:ENTRAOPS_CONFIG
            ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            
            $configLoaded = $false
            foreach ($configPath in $configPaths) {
                if (Test-Path $configPath) {
                    try {
                        $Global:EntraOpsConfig = Get-Content -Path $configPath -Raw | ConvertFrom-Json -AsHashtable
                        Write-Verbose "$logPrefix Loaded EntraOpsConfig.json from: $configPath"
                        $configLoaded = $true
                        break
                    } catch {
                        Write-Verbose "$logPrefix Failed to load config from $configPath : $_"
                    }
                }
            }
            
            if (-not $configLoaded) {
                Write-Verbose "$logPrefix No EntraOpsConfig.json found. Using parameter defaults."
                $Global:EntraOpsConfig = @{}
            }
        } else {
            Write-Verbose "$logPrefix Using existing `$Global:EntraOpsConfig"
        }

        # Landing zone defaults from EntraOpsConfig; explicit parameters take precedence
        $configRegion = [string](Get-EntraOpsServiceEMConfigValue -Path 'DefaultAzureRegion')
        if ([string]::IsNullOrWhiteSpace($AzureRegion) -and -not [string]::IsNullOrWhiteSpace($configRegion)) {
            $AzureRegion = $configRegion
            Write-Verbose "$logPrefix Using DefaultAzureRegion '$AzureRegion' from EntraOpsConfig"
        }
        foreach ($switchName in 'SkipCatalogOwnerAssignment', 'CreateM365Group', 'AddWorkloadPlaneAdminToUsers') {
            if (-not $PSBoundParameters.ContainsKey($switchName) -and (Get-EntraOpsServiceEMConfigValue -Path $switchName) -eq $true) {
                Set-Variable -Name $switchName -Value ([switch]$true)
                Write-Verbose "$logPrefix Using $switchName from EntraOpsConfig"
            }
        }
        $configGroupPrefix = [string](Get-EntraOpsServiceEMConfigValue -Path 'GroupPrefix')
        if (-not $PSBoundParameters.ContainsKey('GroupPrefix') -and -not [string]::IsNullOrWhiteSpace($configGroupPrefix)) {
            $GroupPrefix = $configGroupPrefix
            Write-Verbose "$logPrefix Using GroupPrefix '$GroupPrefix' from EntraOpsConfig"
        }

        if (-not $SkipAzureResourceGroup -and $DeploymentScope -ne "Subscription" -and [string]::IsNullOrWhiteSpace($AzureRegion)) {
            throw "Parameter -AzureRegion (or ServiceEM.DefaultAzureRegion) is required unless -SkipAzureResourceGroup is specified or -DeploymentScope is Subscription."
        }
        if (-not $SkipAzureResourceGroup) {
            if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
                throw "Parameter -SubscriptionId is required unless -SkipAzureResourceGroup is specified."
            }
            $currentAzTenantId = (Get-AzContext).Tenant.Id
            if ([string]::IsNullOrWhiteSpace($currentAzTenantId)) {
                throw "No Azure context found. Sign in with Connect-EntraOps before creating an Azure Resource Group."
            }
            # Fail before any Entra object is created if the subscription isn't accessible in the current tenant
            Get-AzSubscription -SubscriptionId $SubscriptionId -TenantId $currentAzTenantId -ErrorAction Stop | Out-Null
        }

        # Read delegation Group IDs and group names from EntraOpsConfig when not supplied as parameters.
        # A non-empty config value also auto-activates the corresponding skip flag.
        foreach ($configName in 'ControlPlaneDelegationGroupId', 'ManagementPlaneDelegationGroupId', 'AdministratorGroupId') {
            $configValue = [string](Get-EntraOpsServiceEMConfigValue -Path $configName)
            if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $configName -ValueOnly)) -and -not [string]::IsNullOrWhiteSpace($configValue)) {
                Write-Verbose "$logPrefix Reading $configName from EntraOpsConfig"
                Set-Variable -Name $configName -Value $configValue
            }
        }

        # Read GovernanceModel from parameter > config > default (PerService)
        $governanceModelValue = "PerService"
        $governanceModelSource = "default"
        $configGovernanceModel = [string](Get-EntraOpsServiceEMConfigValue -Path 'GovernanceModel')
        if ($PSBoundParameters.ContainsKey('GovernanceModel')) {
            $governanceModelValue = $GovernanceModel
            $governanceModelSource = "parameter"
        } elseif (-not [string]::IsNullOrWhiteSpace($configGovernanceModel)) {
            $governanceModelValue = $configGovernanceModel
            $governanceModelSource = "config"
        }

        Write-Verbose "$logPrefix Using governance model '$governanceModelValue' (source: $governanceModelSource)"
        # Centralized removes CatalogPlane-Members, the requestor scope, approver and reviewer fallback of the policies
        if ($governanceModelValue -eq "Centralized" -and [string]::IsNullOrWhiteSpace($AdministratorGroupId)) {
            throw "The Centralized governance model requires -AdministratorGroupId (or ServiceEM.AdministratorGroupId in EntraOpsConfig): no per-service CatalogPlane-Members group is created. Use -GovernanceModel PerService or configure the administrator group."
        }

        # Auto-resolve or create role-assignable delegation groups.
        # Searches by config ID, then by default group name, then creates if permissions allow.
        # Group names from config take precedence over the parameter defaults.
        foreach ($configName in 'ControlPlaneGroupName', 'ManagementPlaneGroupName') {
            $configValue = [string](Get-EntraOpsServiceEMConfigValue -Path $configName)
            if (-not [string]::IsNullOrWhiteSpace($configValue)) {
                Set-Variable -Name $configName -Value $configValue
            }
        }

        if ($governanceModelValue -eq "Centralized") {
            # Centralized model: Use tenant-wide delegation groups
            Write-Verbose "$logPrefix Centralized governance model - using tenant-wide delegation groups"

            # Graceful fallback to PerService if delegation groups not found
            $centralizedFailed = $false
            $centralizedError = $null
            
            try {
                $ControlPlaneDelegationGroupId = Resolve-EntraOpsServiceEMDelegationGroup `
                    -Plane "ControlPlane" `
                    -GroupId $ControlPlaneDelegationGroupId `
                    -DefaultGroupName $ControlPlaneGroupName `
                    -ConfigKey "ControlPlaneDelegationGroupId" `
                    -logPrefix $logPrefix
                $SkipControlPlaneDelegation = $true
            } catch {
                $centralizedFailed = $true
                $centralizedError = $_
                Write-Warning "$logPrefix Failed to resolve ControlPlane delegation group: $_"
            }
            
            if (-not $centralizedFailed) {
                try {
                    $ManagementPlaneDelegationGroupId = Resolve-EntraOpsServiceEMDelegationGroup `
                        -Plane "ManagementPlane" `
                        -GroupId $ManagementPlaneDelegationGroupId `
                        -DefaultGroupName $ManagementPlaneGroupName `
                        -ConfigKey "ManagementPlaneDelegationGroupId" `
                        -logPrefix $logPrefix
                    $SkipManagementPlaneDelegation = $true
                } catch {
                    $centralizedFailed = $true
                    $centralizedError = $_
                    Write-Warning "$logPrefix Failed to resolve ManagementPlane delegation group: $_"
                }
            }
            
            if ($centralizedFailed) {
                Write-Warning "$logPrefix =========================================="
                Write-Warning "$logPrefix CENTRALIZED GOVERNANCE MODEL FAILED"
                Write-Warning "$logPrefix =========================================="
                Write-Warning "$logPrefix Falling back to PerService governance model."
                Write-Warning "$logPrefix PerService will create per-service admin groups instead."
                Write-Warning "$logPrefix "
                Write-Warning "$logPrefix To use Centralized model, either:"
                Write-Warning "$logPrefix   1. Create delegation groups manually and add IDs to EntraOpsConfig.json"
                Write-Warning "$logPrefix   2. Grant RoleManagement.ReadWrite.Directory permission for auto-creation"
                Write-Warning "$logPrefix =========================================="
                
                # Reset delegation group IDs to trigger per-service creation
                $ControlPlaneDelegationGroupId = ""
                $ManagementPlaneDelegationGroupId = ""
                $SkipControlPlaneDelegation = $false
                $SkipManagementPlaneDelegation = $false
                $governanceModelValue = "PerService"
            } else {
                # Remove per-service ControlPlane, ManagementPlane, CatalogPlane groups from ServiceRoles
                Write-Verbose "$logPrefix Removing ControlPlane/ManagementPlane/CatalogPlane from per-service groups"
                $serviceRoles = @($serviceRoles | Where-Object {
                    -not (($_.accessLevel -eq "ControlPlane" -and $_.name -eq "Admins") -or
                          ($_.accessLevel -eq "ManagementPlane" -and $_.name -eq "Admins") -or
                          ($_.accessLevel -eq "CatalogPlane" -and $_.name -eq "Members"))
                })
            }
        } else {
            # PerService model: Keep per-service groups, but still resolve delegation if IDs provided
            Write-Verbose "$logPrefix PerService governance model - creating per-service admin groups"
            
            if (-not [string]::IsNullOrWhiteSpace($ControlPlaneDelegationGroupId)) {
                $ControlPlaneDelegationGroupId = Resolve-EntraOpsServiceEMDelegationGroup `
                    -Plane "ControlPlane" `
                    -GroupId $ControlPlaneDelegationGroupId `
                    -DefaultGroupName $ControlPlaneGroupName `
                    -ConfigKey "ControlPlaneDelegationGroupId" `
                    -logPrefix $logPrefix
                $SkipControlPlaneDelegation = $true
            }

            if (-not [string]::IsNullOrWhiteSpace($ManagementPlaneDelegationGroupId)) {
                $ManagementPlaneDelegationGroupId = Resolve-EntraOpsServiceEMDelegationGroup `
                    -Plane "ManagementPlane" `
                    -GroupId $ManagementPlaneDelegationGroupId `
                    -DefaultGroupName $ManagementPlaneGroupName `
                    -ConfigKey "ManagementPlaneDelegationGroupId" `
                    -logPrefix $logPrefix
                $SkipManagementPlaneDelegation = $true
            }
        }

        # Add ManagementPlane-Admins unless it is delegated.
        if (-not $SkipManagementPlaneDelegation) {
            $serviceRoles += [pscustomobject]@{accessLevel = "ManagementPlane"; name = "Admins"; groupType = ""}
        }

        if ($SkipControlPlaneDelegation) {
            Write-Verbose "$logPrefix Removing ControlPlane components from ServiceRoles"
            $serviceRoles = @($serviceRoles | Where-Object { $_.accessLevel -ne "ControlPlane" })
        }
        
        # Log final switch states for troubleshooting
        Write-Verbose "$logPrefix =========================================="
        Write-Verbose "$logPrefix FINAL DELEGATION SWITCH STATES:"
        Write-Verbose "$logPrefix   SkipControlPlaneDelegation:    $SkipControlPlaneDelegation"
        Write-Verbose "$logPrefix   SkipManagementPlaneDelegation: $SkipManagementPlaneDelegation"
        Write-Verbose "$logPrefix   ControlPlaneDelegationGroupId: $(if ($ControlPlaneDelegationGroupId) { 'SET' } else { 'NOT SET' })"
        Write-Verbose "$logPrefix   ManagementPlaneDelegationGroupId: $(if ($ManagementPlaneDelegationGroupId) { 'SET' } else { 'NOT SET' })"
        Write-Verbose "$logPrefix   GovernanceModel: $governanceModelValue"
        Write-Verbose "$logPrefix =========================================="
    }

    process {
        Write-Verbose "$logPrefix Processing LZ"

        $splatServiceBootstrap = @{
            ServiceName                      = "$scopeName-$DeploymentPrefix"
            GroupPrefix                      = $GroupPrefix
            AddWorkloadPlaneAdminToUsers     = $AddWorkloadPlaneAdminToUsers
            EnablePimForGroups               = $EnablePimForGroups
            EnableWorkloadPlanePimForGroups  = $EnableWorkloadPlanePimForGroups
            CreateM365Group                  = $CreateM365Group
            GroupOwnership                   = $GroupOwnership
            AzureRegion                      = $AzureRegion
            ServiceRoles                     = $serviceRoles
            SkipControlPlaneDelegation       = $SkipControlPlaneDelegation
            SkipCatalogOwnerAssignment       = $SkipCatalogOwnerAssignment
            SkipManagementPlaneDelegation    = $SkipManagementPlaneDelegation
            ControlPlaneDelegationGroupId    = $ControlPlaneDelegationGroupId
            ManagementPlaneDelegationGroupId = $ManagementPlaneDelegationGroupId
            AdministratorGroupId             = $AdministratorGroupId
            SkipAzureResourceGroup           = $SkipAzureResourceGroup
            AzureScope                       = $DeploymentScope
        }
        if (-not $SkipAzureResourceGroup) {
            $splatServiceBootstrap.SubscriptionId = $SubscriptionId
        }
        foreach ($optional in 'ServiceMembers', 'CatalogPlaneMembers') {
            if ($PSBoundParameters.ContainsKey($optional)) { $splatServiceBootstrap[$optional] = Get-Variable -Name $optional -ValueOnly }
        }
        if (-not [string]::IsNullOrWhiteSpace($WorkloadPlaneAdmin)) {
            $splatServiceBootstrap.WorkloadPlaneAdmin = $WorkloadPlaneAdmin
        }
        if ($PSBoundParameters.ContainsKey('ControlPlaneAdmins')) {
            if ($serviceRoles | Where-Object { $_.accessLevel -eq "ControlPlane" -and $_.name -eq "Admins" }) {
                $splatServiceBootstrap.ControlPlaneAdmins = $ControlPlaneAdmins
            } else {
                Write-Warning "$logPrefix No per-service ControlPlane-Admins group is created (governance model '$governanceModelValue' or delegated ControlPlane); -ControlPlaneAdmins is ignored"
            }
        }

        return New-EntraOpsServiceBootstrap @splatServiceBootstrap
    }
}
