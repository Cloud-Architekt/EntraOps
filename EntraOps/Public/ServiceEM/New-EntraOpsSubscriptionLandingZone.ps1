<#
.SYNOPSIS
    Creates an EAM authorization structure for an Azure resource group or subscription.

.DESCRIPTION
    Provisions EAM groups, an Entitlement Management catalog, access packages,
    PIM policies and Azure role assignments. -DeploymentScope selects the layout:

    ResourceGroup (default) — one scope "Rg-<Prefix>": catalog Catalog-Rg-<Prefix>,
      resource group RG-<Prefix> with all Azure role assignments on the resource group.

    Subscription — one scope "Sub-<Prefix>": catalog Catalog-Sub-<Prefix>, no resource
      group; the same Azure role assignments are made on the subscription (-SubscriptionId).

    Both — the previous two-scope layout: a "Sub-<Prefix>" scope with governance
      groups and its own catalog (no Azure resources) and a "Rg-<Prefix>" scope with
      the workload groups, catalog and resource group.

    Groups per scope (PerService): SG-<Scope>-CatalogPlane-Members,
    SG-<Scope>-ManagementPlane-Members, SG-<Scope>-WorkloadPlane-Users, SG-<Scope>-WorkloadPlane-Admins,
    SG-<Scope>-ControlPlane-Admins and SG-<Scope>-ManagementPlane-Admins (+ PIM staging group), and with
    -CreateM365Group the Microsoft 365 group <Scope> Members.

    Delegation and governance model behaviour:
    - When GovernanceModel = "PerService" (default), per-service groups are created
      for ControlPlane-Admins and ManagementPlane-Admins.
    - When GovernanceModel = "Centralized", ControlPlane-Admins,
      ManagementPlane-Admins and CatalogPlane-Members are resolved to tenant-wide
      shared groups via Resolve-EntraOpsServiceEMDelegationGroup.
    - Delegation group IDs are read from EntraOpsConfig.ServiceEM when not
      passed as parameters.

.PARAMETER DeploymentScope
    "ResourceGroup" (default), "Subscription" or "Both" (previous Sub + Rg layout with two catalogs).
    -Smb and -LandingZoneComponents only apply to "Both".

.PARAMETER ServiceMembers
    UPN(s) of users to add as initial WorkloadPlane-Members in both scopes.
    Defaults to the signed-in identity.

.PARAMETER WorkloadPlaneAdmin
    UPN of the workload plane admin, assigned to the admin access package in both scopes
    (ManagementPlane-Admins or WorkloadPlane-Admins). Defaults to the signed-in identity only
    when -AssignOwner is set.

.PARAMETER AssignOwner
    By default the module does not assign an owner to objects due to the 
    potential privileged escalation concerns. Setting this switch sets the
    WorkloadPlaneAdmin as owner of created groups.

.PARAMETER AddWorkloadPlaneAdminToUsers
    Also assigns the workload plane admin to the WorkloadPlane-Users access package, in addition to the
    admin access package. Not set by default, so admin accounts don't get data-plane user access.
    Defaults to EntraOpsConfig.ServiceEM.AddWorkloadPlaneAdminToUsers; an explicitly passed value wins.

.PARAMETER NoPimEscalation
    When set, skips PIM policy configuration and PIM eligible assignment creation

.PARAMETER CreateM365Group
    Creates the Microsoft 365 group "<Scope>-<Prefix> Members" in each scope. It is meant for the
    collaboration of the service team: a group mailbox and calendar for email and ChatOps notifications
    and, when SharePoint Online or Microsoft Teams is used, a SharePoint site or team as knowledge base.
    Intended members are the people behind the service's personas: WorkloadPlane users and admins,
    ManagementPlane members and, in the PerService model, the ManagementPlane and ControlPlane admins.
    ServiceEM doesn't add members to it and the group gets no PIM for Groups eligibilities or other
    access; the admin and user groups are only granted through access packages. Not created by default.
    Defaults to EntraOpsConfig.ServiceEM.CreateM365Group; an explicitly passed value wins.

.PARAMETER EnablePIMOwnerAssignment
    When set, creates PIM for Groups eligible-owner assignments for the workload plane admin
    in addition to the default eligible-member assignments for the Members group.
    Disabled by default — use this switch to opt in.
    for all groups in both scopes.

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
    Skips creation of per-service ControlPlane-Admins groups and their Catalog
    Owner / Azure UAA PIM eligible assignments for both scopes. Applied
    automatically when ControlPlaneDelegationGroupId is provided or when
    GovernanceModel is Centralized.

.PARAMETER SkipCatalogOwnerAssignment
    Do not assign the Catalog Owner role to ControlPlane-Admins in either catalog. Without this switch,
    ControlPlane-Admins get a permanent (not PIM-protected) Catalog Owner assignment and can modify the
    catalogs, access packages and policies. Prefer an eligible Identity Governance Administrator
    assignment via PIM instead.

.PARAMETER SkipManagementPlaneDelegation
    Skips creation of per-service ManagementPlane-Admins groups and their
    entitlement/Azure delegation for both scopes. Applied automatically when
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
    Object ID of an existing Entra group to use as ControlPlane-Admins across
    both scopes instead of creating per-scope groups. Receives the Catalog Owner
    role and a PIM eligible User Access Administrator assignment.
    Falls back to EntraOpsConfig.ServiceEM.ControlPlaneDelegationGroupId.

.PARAMETER ManagementPlaneDelegationGroupId
    Object ID of an existing Entra group to use as ManagementPlane-Admins across
    both scopes. Receives the AP Assignment Manager catalog role, approver role
    in access package policies, and a PIM eligible Contributor role.
    Falls back to EntraOpsConfig.ServiceEM.ManagementPlaneDelegationGroupId.

.PARAMETER AdministratorGroupId
    Object ID of an existing Entra group to use as CatalogPlane-Members across
    both scopes. Controls who can request elevated access packages and who reviews
    expiring assignments. Falls back to EntraOpsConfig.ServiceEM.AdministratorGroupId.
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

.PARAMETER LandingZoneComponents
    Custom landing zone scope definitions for -DeploymentScope Both. Each entry must have a Role name
    ("Sub", "Rg", or any custom label) and a ServiceRole array. Defaults to
    the standard Sub + Rg split structure.

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
    New-EntraOpsSubscriptionLandingZone -DeploymentPrefix "Connectivity" -DeploymentScope Both `
        -AzureRegion "northeurope" -SubscriptionId "<subscription-id>" `
        -ControlPlaneDelegationGroupId "00000000-0000-0000-0000-000000000001" `
        -ManagementPlaneDelegationGroupId "00000000-0000-0000-0000-000000000002" `
        -AdministratorGroupId "00000000-0000-0000-0000-000000000003"

    Creates the two-scope Sub + Rg landing zone reusing explicit tenant-wide delegation
    groups for ControlPlane-Admins, ManagementPlane-Admins, and CatalogPlane-Members
    across both scopes.

    .EXAMPLE
    New-EntraOpsSubscriptionLandingZone -DeploymentPrefix "Dev" `
        -SkipAzureResourceGroup -NoPimEscalation

    Creates all Entra ID groups, the EM catalog and access packages for the Rg-Dev
    scope without Azure resources and without PIM. Useful for development
    environments or Entra-only access structures.

.EXAMPLE
    $CustomComponents = @(
        [pscustomobject]@{
            Role = "Sub"
            ServiceRole = @(
                [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified"},
                [pscustomobject]@{accessLevel = "CatalogPlane"; name = "Members"; groupType = ""},
                [pscustomobject]@{accessLevel = "ControlPlane"; name = "Admins"; groupType = ""}
            )
        },
        [pscustomobject]@{
            Role = "Rg"
            ServiceRole = @(
                [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified"},
                [pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Admins"; groupType = ""}
            )
        }
    )
    New-EntraOpsSubscriptionLandingZone -DeploymentPrefix "Sub-Shared" -DeploymentScope Both `
        -AzureRegion "westeurope" -SubscriptionId "<subscription-id>" `
        -LandingZoneComponents $CustomComponents

    Creates a reduced Sub + Rg landing zone for "Sub-Shared" with only the
    essential governance groups and no ManagementPlane separation.

#>
function New-EntraOpsSubscriptionLandingZone {
    [OutputType([System.String])]
    [cmdletbinding()]
    param(
        [string[]]$ServiceMembers,

        [string]$WorkloadPlaneAdmin,

        [switch]$AddWorkloadPlaneAdminToUsers,

        [switch]$AssignOwner,

        [switch]$NoPimEscalation,

        [switch]$CreateM365Group,

        [switch]$EnablePIMOwnerAssignment,

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

        [ValidateSet("ResourceGroup", "Subscription", "Both")]
        [string]$DeploymentScope = "ResourceGroup",

        [switch]$Smb,

        [string]$ControlPlaneDelegationGroupId = "",

        [string]$ManagementPlaneDelegationGroupId = "",

        [string]$AdministratorGroupId = "",

        [string]$ControlPlaneGroupName = "PRG-Tenant-ControlPlane-IdentityOps",

        [string]$ManagementPlaneGroupName = "PRG-Tenant-ManagementPlane-PlatformOps",

        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]*$')]
        [string]$GroupPrefix = "SG",

        [pscustomobject[]]$LandingZoneComponents = @(
            [pscustomobject]@{
                Role = "Sub"
                ServiceRole = @(
                    [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified"},
                    [pscustomobject]@{accessLevel = "CatalogPlane"; name = "Members"; groupType = ""},
                    [pscustomobject]@{accessLevel = "ManagementPlane"; name = "Members"; groupType = ""},
                    [pscustomobject]@{accessLevel = "ControlPlane"; name = "Admins"; groupType = ""}
                )
            },
            [pscustomobject]@{
                Role = "Rg"
                ServiceRole = @(
                    [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified"},
                    [pscustomobject]@{accessLevel = "CatalogPlane"; name = "Members"; groupType = ""},
                    [pscustomobject]@{accessLevel = "ManagementPlane"; name = "Members"; groupType = ""},
                    [pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Users"; groupType = ""},
                    [pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Admins"; groupType = ""}
                )
            }
        ),
        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $report = @()

        if ($PSBoundParameters.ContainsKey('LandingZoneComponents')) {
            if ($PSBoundParameters.ContainsKey('DeploymentScope') -and $DeploymentScope -ne "Both") {
                throw "-LandingZoneComponents can only be used with -DeploymentScope Both."
            }
            $DeploymentScope = "Both"
        } elseif ($DeploymentScope -ne "Both") {
            $LandingZoneComponents = @(
                [pscustomobject]@{
                    Role = if ($DeploymentScope -eq "Subscription") { "Sub" } else { "Rg" }
                    ServiceRole = @(
                        [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified"},
                        [pscustomobject]@{accessLevel = "CatalogPlane"; name = "Members"; groupType = ""},
                        [pscustomobject]@{accessLevel = "ManagementPlane"; name = "Members"; groupType = ""},
                        [pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Users"; groupType = ""},
                        [pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Admins"; groupType = ""},
                        [pscustomobject]@{accessLevel = "ControlPlane"; name = "Admins"; groupType = ""}
                    )
                }
            )
        }
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
                    -AssignOwner:$AssignOwner `
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
                        -AssignOwner:$AssignOwner `
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
                foreach ($component in $LandingZoneComponents) {
                    $component.ServiceRole = @($component.ServiceRole | Where-Object {
                        -not (($_.accessLevel -eq "ControlPlane" -and $_.name -eq "Admins") -or
                              ($_.accessLevel -eq "ManagementPlane" -and $_.name -eq "Admins") -or
                              ($_.accessLevel -eq "ManagementPlane" -and $_.name -eq "Members") -or
                              ($_.accessLevel -eq "CatalogPlane" -and $_.name -eq "Members"))
                    })
                }
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
                    -AssignOwner:$AssignOwner `
                    -logPrefix $logPrefix
                $SkipControlPlaneDelegation = $true
            }

            if (-not [string]::IsNullOrWhiteSpace($ManagementPlaneDelegationGroupId)) {
                $ManagementPlaneDelegationGroupId = Resolve-EntraOpsServiceEMDelegationGroup `
                    -Plane "ManagementPlane" `
                    -GroupId $ManagementPlaneDelegationGroupId `
                    -DefaultGroupName $ManagementPlaneGroupName `
                    -ConfigKey "ManagementPlaneDelegationGroupId" `
                    -AssignOwner:$AssignOwner `
                    -logPrefix $logPrefix
                $SkipManagementPlaneDelegation = $true
            }
        }

        # Add ManagementPlane-Admins to the appropriate component unless it is being delegated.
        if (-not $SkipManagementPlaneDelegation) {
            $mgmtAdminsRole = if ($DeploymentScope -ne "Both") { $LandingZoneComponents[0].Role } elseif ($smb) { "Rg" } else { "Sub" }
            $i = [array]::IndexOf(@($LandingZoneComponents.Role), $mgmtAdminsRole)
            if ($i -ge 0) {
                $LandingZoneComponents[$i].ServiceRole += [pscustomobject]@{accessLevel = "ManagementPlane"; name = "Admins"; groupType = ""}
            }
        }

        if ($SkipControlPlaneDelegation) {
            Write-Verbose "$logPrefix Removing ControlPlane components from ServiceRoles"
            foreach ($component in $LandingZoneComponents) {
                $component.ServiceRole = @($component.ServiceRole | Where-Object { $_.accessLevel -ne "ControlPlane" })
            }
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

        foreach ($component in $LandingZoneComponents) {
            Write-Verbose "$logPrefix Processing LZ Role: $($component.Role)"

            $splatServiceBootstrap = @{
                ServiceName                      = $component.Role + "-" + $DeploymentPrefix
                GroupPrefix                      = $GroupPrefix
                AddWorkloadPlaneAdminToUsers     = $AddWorkloadPlaneAdminToUsers
                NoPimEscalation                  = $NoPimEscalation
                CreateM365Group                  = $CreateM365Group
                EnablePIMOwnerAssignment         = $EnablePIMOwnerAssignment
                AzureRegion                      = $AzureRegion
                ServiceRoles                     = $component.ServiceRole
                SkipControlPlaneDelegation       = $SkipControlPlaneDelegation
                SkipCatalogOwnerAssignment       = $SkipCatalogOwnerAssignment
                SkipManagementPlaneDelegation    = $SkipManagementPlaneDelegation
                ControlPlaneDelegationGroupId    = $ControlPlaneDelegationGroupId
                ManagementPlaneDelegationGroupId = $ManagementPlaneDelegationGroupId
                AdministratorGroupId             = $AdministratorGroupId
            }
            if ($component.Role -eq "Sub" -and $DeploymentScope -eq "Both") {
                $splatServiceBootstrap += @{
                    SkipAzureResourceGroup = $true
                }
            } else {
                $splatServiceBootstrap += @{
                    SkipAzureResourceGroup = $SkipAzureResourceGroup
                    AzureScope             = if ($DeploymentScope -eq "Subscription") { "Subscription" } else { "ResourceGroup" }
                }
                if (-not $SkipAzureResourceGroup) {
                    $splatServiceBootstrap.SubscriptionId = $SubscriptionId
                }
            }
            # Forward ServiceMembers to every component so that all
            # scopes (Sub, Rg, etc.) use the same member list rather than
            # defaulting to the calling account for non-Sub components.
            if ($PSBoundParameters.ContainsKey('ServiceMembers')) {
                $splatServiceBootstrap.ServiceMembers = $ServiceMembers
            }

            if ($PSBoundParameters.ContainsKey('WorkloadPlaneAdmin') -and -not [string]::IsNullOrWhiteSpace($WorkloadPlaneAdmin)) {
                $splatServiceBootstrap.WorkloadPlaneAdmin = $WorkloadPlaneAdmin
            }
            if ($AssignOwner) {
                $splatServiceBootstrap.AssignOwner = $AssignOwner
            }

            $report += New-EntraOpsServiceBootstrap @splatServiceBootstrap
        }

        return $report
    }
}
