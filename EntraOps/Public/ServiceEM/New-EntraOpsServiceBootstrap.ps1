<#
.SYNOPSIS
    Creates the necessary authorization structure for a new service

.DESCRIPTION
    Creates the foundation for handling authorization of a new service
    in alignment with the Microsoft Enterprise Access Model.

.PARAMETER ServiceName
    The Name of the Service

.PARAMETER ServiceMembers
    The UserId (i.e., UPN) of the Service members
    Will default to the identity logged on to Graph

.PARAMETER GroupPrefix
    Prefix of the security group display names (e.g. "SG" for SG-<ServiceName>-WorkloadPlane-Users).
    Defaults to EntraOpsConfig.ServiceEM.GroupPrefix, otherwise "SG"; an explicitly passed value wins.

.PARAMETER WorkloadPlaneAdmin
    The UserId (i.e., UPN) of the Workload Plane Admin. Assigned to the admin access package
    (ManagementPlane-Admins, or WorkloadPlane-Admins if no ManagementPlane-Admins package exists) and to the
    CatalogPlane-Members access package. Defaults to the identity logged on to Graph only when -GroupOwnership
    is Eligible or Permanent.

.PARAMETER GroupOwnership
    Opt-in ownership of the WorkloadPlane groups (WorkloadPlane-Admins, WorkloadPlane-Users) for the
    WorkloadPlaneAdmin: "None" (default), "Eligible" (PIM for Groups eligible owner) or "Permanent" (owner set
    when the groups are created). Owners can add members directly, bypassing access package approvals and
    access reviews, so a warning is shown. ControlPlane, ManagementPlane and CatalogPlane groups never get an owner.

.PARAMETER ControlPlaneAdmins
    UserIds (i.e., UPNs) of the initial members of the per-service ControlPlane-Admins group (PerService model).
    Members are added permanently when the group's Azure roles are PIM-eligible (default); without Azure
    resources (-SkipAzureResourceGroup) they become PIM for Groups eligible members, unless -NoPimForGroups
    is set. Without this parameter an Entra administrator adds the members in the portal.

.PARAMETER CatalogPlaneMembers
    UserIds (i.e., UPNs) assigned to the CatalogPlane-Members access package (in addition to the
    WorkloadPlaneAdmin). CatalogPlane-Members is the administrator group and requestor group of the catalog
    (WorkloadPlane-Admins and ManagementPlane-Admins) and can't be requested by non-members.

.PARAMETER AddWorkloadPlaneAdminToUsers
    Also assigns the Workload Plane Admin as a service member (WorkloadPlane-Members access package, or
    WorkloadPlane-Users in landing zones) in addition to the admin access package. Not set by default,
    so admin accounts don't get data-plane user access. Defaults to
    EntraOpsConfig.ServiceEM.AddWorkloadPlaneAdminToUsers; an explicitly passed value wins.

.PARAMETER NoPimForGroups
    Set this flag to skip configuration of Entra Priviliged Identity Management for Groups (PIM policies,
    eligible owners and members, PIM staging group). Alias: NoPimEscalation.

.PARAMETER EnablePIMStagingGroup
    Creates the PIM staging group SG-PIM-<ServiceName>-ManagementPlane-Admins with a permanent Owner
    assignment on the Azure scope. ManagementPlane-Admins become eligible members, so they can activate
    unconstrained Owner via PIM for Groups as an escalation path. Not created by default.

.PARAMETER CreateM365Group
    Creates the Microsoft 365 group "<ServiceName> Members" (the Unified roles of -ServiceRoles; they are
    ignored without this switch). The group is meant for the collaboration of the service team: a group
    mailbox and calendar for email and ChatOps notifications and, when SharePoint Online or Microsoft Teams
    is used, a SharePoint site or team as knowledge base. The group is added to every access package of the
    service, so all users assigned to an access package become members. It gets no PIM for Groups
    eligibilities or other access.
    Defaults to EntraOpsConfig.ServiceEM.CreateM365Group; an explicitly passed value wins.

.PARAMETER SkipAzureResourceGroup
    Set this flag to skip all Azure configuration (no resource group and no Azure role assignments)

.PARAMETER AzureScope
    Scope of the Azure role assignments. "ResourceGroup" (default) creates RG-<ServiceName> and assigns the
    roles on it. "Subscription" creates no resource group and assigns the same roles on the subscription
    (-SubscriptionId), including the PIM role settings for these roles on the subscription.

.PARAMETER AzureRegion
    Set this to the preferred Azure Region for the Resource Group. Required for -AzureScope ResourceGroup.

.PARAMETER SubscriptionId
    Subscription in which the Resource Group and its role assignments are created. Required unless
    -SkipAzureResourceGroup is set. Must belong to the tenant of the current Azure context; the
    previous Azure context is restored afterwards.

.PARAMETER SkipControlPlaneDelegation
    Skip creation of a new ControlPlane-Admins group and its Catalog Owner / Azure UAA delegation.
    Applied automatically when ControlPlaneDelegationGroupId is provided.

.PARAMETER SkipCatalogOwnerAssignment
    Do not assign the Catalog Owner role to ControlPlane-Admins (owned or delegated group). Without this
    switch, ControlPlane-Admins get a permanent (not PIM-protected) Catalog Owner assignment and can modify
    the catalog, its access packages and policies. Prefer an eligible Identity Governance Administrator
    assignment via PIM instead.

.PARAMETER SkipManagementPlaneDelegation
    Skip creation of a new ManagementPlane-Admins group and its delegation.
    Applied automatically when ManagementPlaneDelegationGroupId is provided.

.PARAMETER ControlPlaneDelegationGroupId
    Object ID of an existing Entra group to use as ControlPlane-Admins instead of creating a new one.
    When set, SkipControlPlaneDelegation is enforced automatically and the provided group is used for
    the Catalog Owner role assignment and the PIM-eligible Azure User Access Administrator role on the
    resource group.

.PARAMETER ManagementPlaneDelegationGroupId
    Object ID of an existing Entra group to use as ManagementPlane-Admins instead of creating a new one.
    When set, SkipManagementPlaneDelegation is enforced automatically and the provided group is used for
    the AP Assignment Manager catalog role, access package approval policies, and the PIM-eligible Azure
    Contributor role on the resource group.

.PARAMETER AdministratorGroupId
    Object ID of an existing Entra group to use as CatalogPlane-Members instead of creating a new one.
    When set, the CatalogPlane-Members role is removed from group creation and the provided group is
    injected as a synthetic entry. This group controls who can request elevated access packages and
    who reviews expiring assignments.
    Falls back to EntraOpsConfig.ServiceEM.AdministratorGroupId when not provided via landing zones.

.PARAMETER ControlPlaneApproverGroupId
    Object ID of the ControlPlane-Admins group of another scope that approves and reviews ManagementPlane-Admins
    and gets the PIM eligible User Access Administrator on this Azure scope when this scope has no
    ControlPlane-Admins group (set by New-EntraOpsSubscriptionLandingZone for -DeploymentScope Both).

.PARAMETER ManagementPlaneApproverGroupId
    Object ID of the ManagementPlane-Admins group of another scope that approves and reviews WorkloadPlane-Admins
    and gets the PIM eligible Contributor and constrained RBAC Administrator on this Azure scope
    when this scope has no ManagementPlane-Admins group (set by
    New-EntraOpsSubscriptionLandingZone for the Rg scope of -DeploymentScope Both without -Smb).

.PARAMETER ServiceRoles
    Define the functional roles of the Service as an object with the columns
    accessLevel,name,groupType. Where accessLevel is the EAM plane classification (e.g., WorkloadPlane,
    ManagementPlane, ControlPlane, CatalogPlane) (an unset value is the default group), name is the functional
    purpose (e.g., Admins, Members, Users), and groupType is the Entra group type (e.g., Unified) (an unset
    value will default to a security group). The default value will create one unified members group
    (only with -CreateM365Group), the CatalogPlane-Members (administrator) group, one security user WorkloadPlane
    group, and three security admin groups (WorkloadPlane, ControlPlane, ManagementPlane).
    ManagementPlane-Members is no longer supported (ignored with a warning); CatalogPlane-Members request
    ManagementPlane-Admins.

.PARAMETER logPrefix
    Defines the text to prepend for any verbose messages

.EXAMPLE
    New-EntraOpsServiceBootstrap -ServiceName "MyService" -AzureRegion "westeurope" `
        -SubscriptionId "<subscription-id>"

    Creates the full authorization structure for "MyService" with all default EAM groups, an Entra ID
    Entitlement Management catalog and access packages, PIM policies, and an Azure resource group in
    West Europe. The currently signed-in user is assigned as service member.

.EXAMPLE
    New-EntraOpsServiceBootstrap -ServiceName "MyService" -AzureRegion "westeurope" `
        -SubscriptionId "<subscription-id>" `
        -WorkloadPlaneAdmin "admin@contoso.com" -ServiceMembers @("alice@contoso.com","bob@contoso.com")

    Creates the authorization structure for "MyService" with an explicit workload plane admin and two members.
    The admin is also added as a member only with -AddWorkloadPlaneAdminToUsers.

.EXAMPLE
    New-EntraOpsServiceBootstrap -ServiceName "MyService" -SkipAzureResourceGroup `
        -NoPimForGroups

    Creates all Entra ID groups, catalog, and access packages without an Azure resource group and
    without configuring PIM eligible assignments.

.EXAMPLE
    New-EntraOpsServiceBootstrap -ServiceName "MyService" -AzureRegion "northeurope" `
        -SubscriptionId "<subscription-id>" `
        -ControlPlaneDelegationGroupId "00000000-0000-0000-0000-000000000001" `
        -ManagementPlaneDelegationGroupId "00000000-0000-0000-0000-000000000002"

    Creates the authorization structure reusing existing Entra groups as ControlPlane-Admins and
    ManagementPlane-Admins delegates instead of creating new ones. SkipControlPlaneDelegation and
    SkipManagementPlaneDelegation are enforced automatically.

.EXAMPLE
    $CustomRoles = @"
accessLevel,name,groupType
,Members,Unified
WorkloadPlane,Members,
WorkloadPlane,Admins,
ManagementPlane,Admins,
"@ | ConvertFrom-Csv

    New-EntraOpsServiceBootstrap -ServiceName "MyService" -AzureRegion "westeurope" `
        -SubscriptionId "<subscription-id>" -ServiceRoles $CustomRoles

    Creates the authorization structure with a reduced set of custom EAM roles instead of the
    default set. Useful for services that do not require CatalogPlane or ControlPlane groups.

#>
function New-EntraOpsServiceBootstrap {
    [OutputType([System.String])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,

        [string[]]$ServiceMembers,

        [string]$GroupPrefix = "SG",
        [string]$GroupNamingDelimiter = "-",

        [AllowEmptyString()]
        [string]$WorkloadPlaneAdmin,

        [ValidateSet("None", "Eligible", "Permanent")]
        [string]$GroupOwnership = "None",

        [string[]]$ControlPlaneAdmins,

        [string[]]$CatalogPlaneMembers,

        [switch]$AddWorkloadPlaneAdminToUsers,

        [Alias('NoPimEscalation')]
        [switch]$NoPimForGroups,

        [switch]$EnablePIMStagingGroup,

        [switch]$CreateM365Group,

        [switch]$SkipAzureResourceGroup,

        [ValidateSet("ResourceGroup", "Subscription")]
        [string]$AzureScope = "ResourceGroup",

        [switch]$SkipControlPlaneDelegation,

        [switch]$SkipCatalogOwnerAssignment,

        [switch]$SkipManagementPlaneDelegation,

        [string]$ControlPlaneDelegationGroupId = "",

        [string]$ManagementPlaneDelegationGroupId = "",

        [string]$AdministratorGroupId = "",

        [string]$ControlPlaneApproverGroupId = "",

        [string]$ManagementPlaneApproverGroupId = "",

        [string]$AzureRegion,

        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$SubscriptionId,

        [psobject[]]$ServiceRoles,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {

        # Defaults from the loaded EntraOpsConfig; explicit parameters take precedence
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
        if ($GroupPrefix -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') {
            throw "GroupPrefix '$GroupPrefix' is invalid. Use letters, digits, '_', '.' or '-' (e.g. 'SG')."
        }

        if (-not $SkipAzureResourceGroup -and $AzureScope -eq "ResourceGroup" -and [string]::IsNullOrWhiteSpace($AzureRegion)) {
            throw "Parameter -AzureRegion (or ServiceEM.DefaultAzureRegion) is required for -AzureScope ResourceGroup unless -SkipAzureResourceGroup is specified."
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

        $report = @{
            ServiceName = $ServiceName
        }

        # Required lookups stop the deployment before any object is created
        $resolveDirectoryObject = {
            param([string]$Uri, [string]$Label)
            try {
                $directoryObject = Invoke-EntraOpsMsGraphQuery -Method GET -Uri $Uri -OutputType PSObject -ThrowOnFailure
            } catch {
                throw "Unable to resolve $Label ($Uri): $($_.Exception.Message)"
            }
            if (-not $directoryObject -or -not $directoryObject.Id) {
                throw "Unable to resolve $Label ($Uri): object not found"
            }
            $directoryObject
        }

        if ($GroupOwnership -ne "None") {
            Write-Warning "$logPrefix -GroupOwnership $GroupOwnership makes the WorkloadPlaneAdmin owner of the WorkloadPlane groups. Owners can add members directly, bypassing access package approvals and access reviews."
        }
        if ($GroupOwnership -eq "Eligible" -and $NoPimForGroups) {
            Write-Warning "$logPrefix -GroupOwnership Eligible is ignored with -NoPimForGroups"
        }

        #region WorkloadPlaneAdmin
        if ($GroupOwnership -ne "None" -or $PSBoundParameters.ContainsKey("WorkloadPlaneAdmin")) {
            Write-Verbose "$logPrefix Workload Plane Admin Graph API Lookup"
            if ($PSBoundParameters.ContainsKey("WorkloadPlaneAdmin")) {
                if ([string]::IsNullOrWhiteSpace($WorkloadPlaneAdmin)) {
                    throw "WorkloadPlaneAdmin was supplied but is empty. Specify a valid admin UPN, object ID, or OData URL."
                }

                Write-Verbose "$logPrefix WorkloadPlaneAdmin set, looking up $WorkloadPlaneAdmin"
                if ($WorkloadPlaneAdmin -match '^https://graph\.microsoft\.com/v1\.0/servicePrincipals/') {
                    $spId = $WorkloadPlaneAdmin -replace '^https://graph\.microsoft\.com/v1\.0/servicePrincipals/', ''
                    $graphOwner = & $resolveDirectoryObject "/v1.0/servicePrincipals/$spId" "WorkloadPlaneAdmin"
                    $owner = "https://graph.microsoft.com/v1.0/servicePrincipals/$($graphOwner.Id)"
                } elseif ($WorkloadPlaneAdmin -match '^https://graph\.microsoft\.com/v1\.0/users/') {
                    $userId = $WorkloadPlaneAdmin -replace '^https://graph\.microsoft\.com/v1\.0/users/', ''
                    $graphOwner = & $resolveDirectoryObject "/v1.0/users/$userId" "WorkloadPlaneAdmin"
                    $owner = "https://graph.microsoft.com/v1.0/users/$($graphOwner.Id)"
                } else {
                    # UPN or object ID
                    $graphOwner = & $resolveDirectoryObject "/v1.0/users/$WorkloadPlaneAdmin" "WorkloadPlaneAdmin"
                    $owner = "https://graph.microsoft.com/v1.0/users/$($graphOwner.Id)"
                }
            } else {
                $mgContext = Get-MgContext
                if ([string]::IsNullOrWhiteSpace($mgContext.Account) -or $mgContext.AuthType -eq "AppOnly") {
                    throw "WorkloadPlaneAdmin parameter is required when using service principal (AppOnly) authentication. Please specify -WorkloadPlaneAdmin with a user UPN (e.g., 'user@contoso.com') or user ID."
                }
                Write-Verbose "$logPrefix WorkloadPlaneAdmin not specified, looking up $($mgContext.Account)"
                $graphOwner = & $resolveDirectoryObject "/v1.0/users/$($mgContext.Account)" "WorkloadPlaneAdmin (signed-in user)"
                $owner = "https://graph.microsoft.com/v1.0/users/$($graphOwner.Id)"
            }
            Write-Verbose "$logPrefix Resolved workload plane admin as $owner"
        } else {
            Write-Verbose "$logPrefix Neither WorkloadPlaneAdmin nor GroupOwnership set; skipping WorkloadPlaneAdmin resolution"
            $graphOwner = $null
            $owner = $null
        }
        #endregion

        #region ServiceMembers
        Write-Verbose "$logPrefix Service Members Graph API Lookup"
        $graphMembers = @()
        if (-not $PSBoundParameters.ContainsKey("ServiceMembers")) {
            $mgContext = Get-MgContext
            if ([string]::IsNullOrWhiteSpace($mgContext.Account) -or $mgContext.AuthType -eq "AppOnly") {
                Write-Verbose "$logPrefix ServiceMembers not specified with AppOnly auth, defaulting to empty members list"
            } else {
                $graphMembers = @(& $resolveDirectoryObject "/v1.0/users/$($mgContext.Account)" "service member (signed-in user)")
            }
        } else {
            foreach ($serviceMember in $ServiceMembers) {
                $graphMembers += & $resolveDirectoryObject "/v1.0/users/$serviceMember" "service member"
            }
        }
        if ($graphOwner -and $graphOwner.Id -notin $graphMembers.Id -and $AddWorkloadPlaneAdminToUsers) {
            Write-Verbose "$logPrefix Adding workload plane admin $($graphOwner.Id) to the service members (-AddWorkloadPlaneAdminToUsers)"
            $graphMembers += $graphOwner
        }
        $graphCatalogMembers = @(foreach ($catalogMember in $CatalogPlaneMembers) {
                & $resolveDirectoryObject "/v1.0/users/$catalogMember" "CatalogPlane member"
            })
        $graphControlPlaneAdmins = @(foreach ($controlPlaneAdmin in $ControlPlaneAdmins) {
                & $resolveDirectoryObject "/v1.0/users/$controlPlaneAdmin" "ControlPlane admin"
            })
        #endregion

        #region ServiceRoles
        Write-Verbose "$logPrefix Service Roles validation"
        if (-not $PSBoundParameters.ContainsKey("ServiceRoles")) {
            $ServiceRoles = @"
accessLevel,name,groupType
,Members,Unified
CatalogPlane,Members,
WorkloadPlane,Users,
WorkloadPlane,Admins,
ControlPlane,Admins,
ManagementPlane,Admins,
"@| ConvertFrom-Csv
        } else {
            if (($ServiceRoles | Measure-Object).Count -lt 1) {
                throw "`$ServiceRoles was supplied, but did not have any objects defined"
            }

            foreach ($ServiceRole in $ServiceRoles) {
                if (@("Users", "Admins", "Members") -inotcontains $ServiceRole.name) {
                    throw "$($ServiceRole.name) is not in accepted values of 'Users', 'Admins', or 'Members'"
                }
                if (@("WorkloadPlane", "ControlPlane", "ManagementPlane", "CatalogPlane", "") -inotcontains $ServiceRole.accessLevel) {
                    throw "$($ServiceRole.accessLevel) is not in accepted values of 'WorkloadPlane', 'ControlPlane', 'ManagementPlane', 'CatalogPlane', or ''"
                }
                if (@("Unified", "Security", "") -inotcontains $ServiceRole.groupType) {
                    throw "$($ServiceRole.groupType) is not in accepted values of 'Unified' or ''"
                }
                if ($ServiceRole.name -ieq "Users" -and $ServiceRole.accessLevel -ine "WorkloadPlane") {
                    throw "Users should only be for WorkloadPlane access"
                }
            }
            if ($ServiceRoles | Where-Object { $_.accessLevel -eq "ManagementPlane" -and $_.name -eq "Members" }) {
                Write-Warning "$logPrefix ManagementPlane-Members is no longer supported and is ignored; CatalogPlane-Members (the administrator group) request ManagementPlane-Admins. Remove an existing group manually."
                $ServiceRoles = @($ServiceRoles | Where-Object { -not ($_.accessLevel -eq "ManagementPlane" -and $_.name -eq "Members") })
            }
        }
        #endregion

        #region Delegation
        # Auto-apply skip flags when delegation Group IDs are provided so that no new groups are created
        # for those planes; the external groups will be injected into $ServiceGroups after group creation.
        if (-not [string]::IsNullOrWhiteSpace($ControlPlaneDelegationGroupId)) {
            Write-Verbose "$logPrefix ControlPlaneDelegationGroupId provided — enforcing SkipControlPlaneDelegation"
            $SkipControlPlaneDelegation = $true
        }
        if (-not [string]::IsNullOrWhiteSpace($ManagementPlaneDelegationGroupId)) {
            Write-Verbose "$logPrefix ManagementPlaneDelegationGroupId provided — enforcing SkipManagementPlaneDelegation"
            $SkipManagementPlaneDelegation = $true
        }

        $SkipAdministratorGroupCreation = $false
        if (-not [string]::IsNullOrWhiteSpace($AdministratorGroupId)) {
            Write-Verbose "$logPrefix AdministratorGroupId provided — skipping CatalogPlane-Members creation"
            $SkipAdministratorGroupCreation = $true

            # Without WorkloadPlane-Members/ManagementPlane-Admins the Workload Plane Policy only allows members of AdministratorGroupId
            $hasRole = { param($level, $name) [bool]($ServiceRoles | Where-Object { $_.accessLevel -eq $level -and $_.name -eq $name }) }
            $adminScopedToAdministratorGroup = (& $hasRole 'WorkloadPlane' 'Admins') -and -not (& $hasRole 'WorkloadPlane' 'Members') -and
                ($SkipManagementPlaneDelegation -or -not (& $hasRole 'ManagementPlane' 'Admins'))
            if ($adminScopedToAdministratorGroup -and $graphOwner -and $graphOwner.Id) {
                Write-Verbose "$logPrefix Checking that workload plane admin $($graphOwner.Id) is a member of AdministratorGroupId $AdministratorGroupId"
                $checkBody = @{ groupIds = @($AdministratorGroupId) } | ConvertTo-Json
                $memberOf = @(Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/directoryObjects/$($graphOwner.Id)/checkMemberGroups" -Body $checkBody -OutputType PSObject -DisableCache -ThrowOnFailure)
                if ($AdministratorGroupId -notin $memberOf) {
                    throw "Workload plane admin '$($graphOwner.Id)' is not a member of the administrator group '$AdministratorGroupId' (CatalogPlane-Members). The Workload Plane Policy (requests for WorkloadPlane-Admins) only allows members of this group. Add the admin to the group or choose another -WorkloadPlaneAdmin."
                }
            }
        }
        #endregion
    }

    process {

        Write-Verbose "$logPrefix Beginning Bootstrap"

        Write-Verbose "$logPrefix Removing Control Plane Delegation roles if specified"
        if ($SkipControlPlaneDelegation) {
            $filteredRoles = @()
            foreach ($role in $ServiceRoles) {
                if (-not ($role.name -eq "Admins" -and $role.accessLevel -eq "ControlPlane")) {
                    $filteredRoles += $role
                }
            }
            $ServiceRoles = $filteredRoles
        }

        Write-Verbose "$logPrefix Removing Management Plane Admin roles if delegated"
        if ($SkipManagementPlaneDelegation) {
            $filteredRoles = @()
            foreach ($role in $ServiceRoles) {
                if (-not ($role.name -eq "Admins" -and $role.accessLevel -eq "ManagementPlane")) {
                    $filteredRoles += $role
                }
            }
            $ServiceRoles = $filteredRoles
        }

        Write-Verbose "$logPrefix Removing CatalogPlane-Members role if AdministratorGroupId is provided"
        if ($SkipAdministratorGroupCreation) {
            $filteredRoles = @()
            foreach ($role in $ServiceRoles) {
                if (-not ($role.name -eq "Members" -and $role.accessLevel -eq "CatalogPlane")) {
                    $filteredRoles += $role
                }
            }
            $ServiceRoles = $filteredRoles
        }

        if (-not $CreateM365Group) {
            Write-Verbose "$logPrefix Microsoft 365 group not requested (-CreateM365Group not set), removing Unified roles"
            $ServiceRoles = @($ServiceRoles | Where-Object { $_.groupType -ne "Unified" })
        }
        if (($ServiceRoles | Measure-Object).Count -eq 0) {
            Write-Verbose "$logPrefix No groups left to create for $ServiceName (all roles delegated or skipped), skipping this scope"
            return $report
        }

        Write-Verbose "$logPrefix Processing Roles to Groups"
        $ServiceEntraGroupOptions = @{
            ServiceName             = $ServiceName
            ServiceRoles            = $ServiceRoles
            GroupPrefix             = $GroupPrefix
            GroupNamingDelimiter    = $GroupNamingDelimiter
            NoPimForGroups        = $NoPimForGroups
            EnablePIMStagingGroup = $EnablePIMStagingGroup
        }
        if ($GroupOwnership -eq "Permanent" -and -not [string]::IsNullOrWhiteSpace($owner)) {
            $ServiceEntraGroupOptions.WorkloadPlaneAdmin = $owner
        }
        # Cast to [object[]] so PSCustomObject synthetic delegated entries can be appended
        # with +=. New-EntraOpsServiceEntraGroup returns typed MicrosoftGraphGroup objects;
        # PowerShell cannot use += to append a PSCustomObject to a typed array.
        [object[]]$ServiceGroups = New-EntraOpsServiceEntraGroup @ServiceEntraGroupOptions
        if (-not $CreateM365Group) {
            # The group lookup also returns a Microsoft 365 group left over from earlier runs
            [object[]]$ServiceGroups = @($ServiceGroups | Where-Object { $_.GroupTypes -notcontains "Unified" })
        }

        # Inject delegated groups as synthetic entries whose DisplayName matches the existing downstream
        # filter patterns (*-ControlPlane-Admins, *-ManagementPlane-Admins). IsDelegated = $true prevents
        # PIM policy and assignment functions from modifying groups owned by another service.
        if (-not [string]::IsNullOrWhiteSpace($ControlPlaneDelegationGroupId)) {
            Write-Verbose "$logPrefix Injecting delegated ControlPlane-Admins group (ID: $ControlPlaneDelegationGroupId)"
            try {
                $delegatedCtrlGroup = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/groups/$ControlPlaneDelegationGroupId" -OutputType PSObject
                $ServiceGroups += [PSCustomObject]@{
                    Id          = $delegatedCtrlGroup.Id
                    DisplayName = "$GroupPrefix$GroupNamingDelimiter$ServiceName$($GroupNamingDelimiter)ControlPlane$($GroupNamingDelimiter)Admins"
                    IsDelegated = $true
                }
                Write-Verbose "$logPrefix Delegated ControlPlane-Admins: $($delegatedCtrlGroup.DisplayName) ($($delegatedCtrlGroup.Id))"
            } catch {
                Write-Verbose "$logPrefix Failed to look up delegated ControlPlane-Admins group"
                Write-Error $_
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($ManagementPlaneDelegationGroupId)) {
            Write-Verbose "$logPrefix Injecting delegated ManagementPlane-Admins group (ID: $ManagementPlaneDelegationGroupId)"
            try {
                $delegatedMgmtGroup = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/groups/$ManagementPlaneDelegationGroupId" -OutputType PSObject
                $ServiceGroups += [PSCustomObject]@{
                    Id          = $delegatedMgmtGroup.Id
                    DisplayName = "$GroupPrefix$GroupNamingDelimiter$ServiceName$($GroupNamingDelimiter)ManagementPlane$($GroupNamingDelimiter)Admins"
                    IsDelegated = $true
                }
                Write-Verbose "$logPrefix Delegated ManagementPlane-Admins: $($delegatedMgmtGroup.DisplayName) ($($delegatedMgmtGroup.Id))"
            } catch {
                Write-Verbose "$logPrefix Failed to look up delegated ManagementPlane-Admins group"
                Write-Error $_
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($AdministratorGroupId)) {
            Write-Verbose "$logPrefix Injecting delegated CatalogPlane-Members group (ID: $AdministratorGroupId)"
            try {
                $delegatedAdminGroup = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/groups/$AdministratorGroupId" -OutputType PSObject
                $ServiceGroups += [PSCustomObject]@{
                    Id          = $delegatedAdminGroup.Id
                    DisplayName = "$GroupPrefix$GroupNamingDelimiter$ServiceName$($GroupNamingDelimiter)CatalogPlane$($GroupNamingDelimiter)Members"
                    IsDelegated = $true
                }
                Write-Verbose "$logPrefix Delegated CatalogPlane-Members: $($delegatedAdminGroup.DisplayName) ($($delegatedAdminGroup.Id))"
            } catch {
                Write-Verbose "$logPrefix Failed to look up delegated CatalogPlane-Members group"
                Write-Error $_
            }
        }

        $report.Groups = $ServiceGroups
        Write-Verbose "$logPrefix Service Groups IDs: $($report.Groups.Id|ConvertTo-Json -Compress)"

        # Owned (non-delegated) groups are the ones actually created by this landing zone.
        # Delegated groups are injected for downstream filter patterns but must not be added to
        # the catalog or assigned to access packages as resources.
        $ownedGroups = @($ServiceGroups | Where-Object { -not $_.IsDelegated })

        Write-Verbose "$logPrefix Processing Catalog"
        $ServiceEMCatalogOptions = @{
            ServiceName = $ServiceName
        }
        $ServiceEMCatalog = New-EntraOpsServiceEMCatalog @ServiceEMCatalogOptions
        $report.Catalog = $ServiceEMCatalog
        Write-Verbose "$logPrefix Service Catalog ID: $($report.Catalog.Id)"

        Write-Verbose "$logPrefix Processing Catalog Resources"
        $ServiceEMCatalogResourceOptions = @{
            ServiceGroups    = $ownedGroups
            ServiceCatalogId = $ServiceEMCatalog.Id
        }
        $ServiceEMCatalogResources = New-EntraOpsServiceEMCatalogResource @ServiceEMCatalogResourceOptions
        $report.CatalogResources = $ServiceEMCatalogResources
        Write-Verbose "$logPrefix Service Catalog Resource IDs: $($report.CatalogResources.Id|ConvertTo-Json -Compress)"

        Write-Verbose "$logPrefix Processing Catalog Role Assignments"
        $ServiceEMCatalogResourceRolesOptions = @{
            ServiceCatalogId           = $ServiceEMCatalog.Id
            # Pass all groups (including delegated) so delegated ControlPlane/ManagementPlane groups
            # can be matched by their synthetic DisplayName for catalog role assignment.
            ServiceGroups              = $ServiceGroups
            # When a delegation group ID is provided, SkipControlPlaneDelegation was auto-set to suppress
            # group creation but the Owner catalog role must still be assigned to the delegated group.
            SkipControlPlaneDelegation = ($SkipControlPlaneDelegation -and [string]::IsNullOrWhiteSpace($ControlPlaneDelegationGroupId))
            SkipCatalogOwnerAssignment = $SkipCatalogOwnerAssignment
        }
        $ServiceEMCatalogResourceRoles = New-EntraOpsServiceEMCatalogResourceRole @ServiceEMCatalogResourceRolesOptions
        $report.CatalogResourceRoles = $ServiceEMCatalogResourceRoles
        Write-Verbose "$logPrefix Service Catalog Resource Role IDs: $($report.CatalogResourceRoles.Id|ConvertTo-Json -Compress)"

        Write-Verbose "$logPrefix Processing Access Packages"
        $ServiceEMAccessPackagesOptions = @{
            ServiceName      = $ServiceName
            ServiceCatalogId = $ServiceEMCatalog.Id
            ServiceRoles     = $ServiceRoles
        }
        $ServiceEMAccessPackages = New-EntraOpsServiceEMAccessPackage @ServiceEMAccessPackagesOptions
        # Guard: when all roles are Unified or delegated (e.g. Sub scope in Centralized model),
        # no access packages are created. PowerShell returns $null for an empty typed array from a
        # function, so normalise to an empty array here and skip all package-dependent steps.
        if (-not $ServiceEMAccessPackages) { $ServiceEMAccessPackages = @() }
        $report.AccessPackages = $ServiceEMAccessPackages
        Write-Verbose "$logPrefix Service Access Package IDs: $($report.AccessPackages.Id|ConvertTo-Json -Compress)"

        if (($ServiceEMAccessPackages | Measure-Object).Count -gt 0) {
            Write-Verbose "$logPrefix Processing assignment of Entra Groups to Access Packages"
            $ServiceEMAccessPackageResourceAssignmentOptions = @{
                ServicePackages         = $ServiceEMAccessPackages
                # Only pass owned groups — delegated groups are not catalog resources and would break matching
                ServiceGroups           = $ownedGroups
                ServiceCatalogResources = $ServiceEMCatalogResources
                ServiceCatalogId        = $ServiceEMCatalog.Id
                ServiceName             = $ServiceName
                GroupPrefix             = $GroupPrefix
                GroupNamingDelimiter    = $GroupNamingDelimiter
            }
            $ServiceEMAccessPackageAssignments = New-EntraOpsServiceEMAccessPackageResourceAssignment @ServiceEMAccessPackageResourceAssignmentOptions
            $report.AccessPackageAssignments = $ServiceEMAccessPackageAssignments
            Write-Verbose "$logPrefix Service Access Package Resource Assignments: $($report.AccessPackageAssignments.Id|ConvertTo-Json -Compress)"

            Write-Verbose "$logPrefix Processing access package policy assignment"
            $ServiceEMAssignmentPolicyOptions = @{
                ServiceCatalogId = $ServiceEMCatalog.Id
                ServicePackages  = $ServiceEMAccessPackages
                ServiceGroups    = $ServiceGroups
                ServiceName      = $ServiceName
                ControlPlaneApproverGroupId    = $ControlPlaneApproverGroupId
                ManagementPlaneApproverGroupId = $ManagementPlaneApproverGroupId
            }
            $ServiceEMAssignmentPolicies = New-EntraOpsServiceEMAssignmentPolicy @ServiceEMAssignmentPolicyOptions
            $report.AssignmentPolicies = $ServiceEMAssignmentPolicies
            
            if ($ServiceEMAssignmentPolicies -and ($ServiceEMAssignmentPolicies | Measure-Object).Count -gt 0) {
                Write-Verbose "$logPrefix Service Access Package Assignment Policy IDs: $($report.AssignmentPolicies.Id|ConvertTo-Json -Compress)"

                Write-Verbose "$logPrefix Processing access package assignments"
                $ServiceEMAssignmentOptions = @{
                    ServiceCatalogId          = $ServiceEMCatalog.Id
                    ServiceMembers            = $graphMembers
                    WorkloadPlaneAdmin       = $graphOwner
                    CatalogPlaneMembers       = $graphCatalogMembers
                    ServiceAssignmentPolicies = $ServiceEMAssignmentPolicies
                    ServicePackages           = $ServiceEMAccessPackages
                }
                $ServiceEMAssignments = New-EntraOpsServiceEMAssignment @ServiceEMAssignmentOptions
                $report.Assignments = $ServiceEMAssignments
                Write-Verbose "$logPrefix Service Access Package Assignment IDs: $($report.Assignments.Id|ConvertTo-Json -Compress)"
            } else {
                Write-Verbose "$logPrefix No assignment policies created — skipping access package assignments"
            }
        } else {
            Write-Verbose "$logPrefix No access packages to configure — skipping resource assignment, policies, and member assignments"
        }

        if (-not $NoPimForGroups) {
            Write-Verbose "$logPrefix Processing PIM policies"
            $ServicePIMPolicyOptions = @{
                ServiceGroups = $ownedGroups
                ServiceName   = $ServiceName
            }
            $ServicePIMPolicies = New-EntraOpsServicePIMPolicy @ServicePIMPolicyOptions
            $report.PimPolicies = $ServicePIMPolicies
            Write-Verbose "$logPrefix Service PIM Policy IDs: $($report.PimPolicies.Id|ConvertTo-Json -Compress)"

            Write-Verbose "$logPrefix Processing PIM assignments"
            $ServicePIMAssignmentOptions = @{
                ServiceGroups           = $ownedGroups
                GroupPrefix             = $GroupPrefix
                GroupNamingDelimiter    = $GroupNamingDelimiter
                EnableOwnerAssignment = ($GroupOwnership -eq "Eligible")
            }
            if ($GroupOwnership -eq "Eligible" -and $graphOwner -and $graphOwner.Id) {
                $ServicePIMAssignmentOptions.WorkloadPlaneAdminPrincipalId = $graphOwner.Id
            }
            $report.PimForGroupsAssignments = New-EntraOpsServicePIMAssignment @ServicePIMAssignmentOptions
            Write-Verbose "$logPrefix Service PIM for Groups assignment IDs: $($report.PimForGroupsAssignments.Id|ConvertTo-Json -Compress)"
        }

        if (-not $SkipAzureResourceGroup) {
            Write-Verbose "$logPrefix Processing Azure Container"
            # Admin groups of another scope (-DeploymentScope Both) get their Azure roles on this scope
            $azureGroups = @($ServiceGroups)
            foreach ($crossScope in @(
                    @{ Plane = 'ControlPlane'; Id = $ControlPlaneApproverGroupId },
                    @{ Plane = 'ManagementPlane'; Id = $ManagementPlaneApproverGroupId })) {
                $hasPlaneGroup = $azureGroups | Where-Object { $_.DisplayName -like "*-$($crossScope.Plane)-Admins" -and $_.DisplayName -notlike "*-PIM-*" }
                if ($crossScope.Id -and -not $hasPlaneGroup) {
                    $azureGroups += [PSCustomObject]@{
                        Id          = $crossScope.Id
                        DisplayName = "$GroupPrefix$GroupNamingDelimiter$ServiceName$GroupNamingDelimiter$($crossScope.Plane)$($GroupNamingDelimiter)Admins"
                        IsDelegated = $true
                    }
                }
            }
            $ServiceAZContainerOptions = @{
                ServiceName                = $ServiceName
                ServiceGroups              = $azureGroups
                AzureScope                 = $AzureScope
                Location                   = $AzureRegion
                SkipControlPlaneDelegation = ($SkipControlPlaneDelegation -and [string]::IsNullOrWhiteSpace($ControlPlaneDelegationGroupId))
                pimForGroups               = ($EnablePIMStagingGroup -and -not $NoPimForGroups)
            }
            $previousAzContext = Get-AzContext
            try {
                if ($previousAzContext.Subscription.Id -ne $SubscriptionId) {
                    Write-Verbose "$logPrefix Switching Azure context to subscription $SubscriptionId"
                    Set-AzContext -Subscription $SubscriptionId -Tenant $previousAzContext.Tenant.Id -ErrorAction Stop | Out-Null
                }
                $ServiceAzContainer = New-EntraOpsServiceAZContainer @ServiceAZContainerOptions
            } finally {
                if ($previousAzContext -and (Get-AzContext).Subscription.Id -ne $previousAzContext.Subscription.Id) {
                    Write-Verbose "$logPrefix Restoring Azure context to subscription $($previousAzContext.Subscription.Id)"
                    Set-AzContext -Context $previousAzContext -ErrorAction SilentlyContinue | Out-Null
                }
            }
            $report.AzContainer = $ServiceAzContainer
            Write-Verbose "$logPrefix Service Az Container ID: $($report.AzContainer.ResourceId|ConvertTo-Json -Compress)"
        }

        if ($graphControlPlaneAdmins.Count -gt 0) {
            $controlPlaneGroup = $ownedGroups | Where-Object { $_.DisplayName -like "*-ControlPlane-Admins" } | Select-Object -First 1
            if (-not $controlPlaneGroup) {
                Write-Warning "$logPrefix No per-service ControlPlane-Admins group in $ServiceName (delegated or not created); -ControlPlaneAdmins is ignored"
            } else {
                # Permanent membership is protected by the PIM-eligible Azure roles; without them membership itself is just-in-time
                $eligibleMembership = $SkipAzureResourceGroup -and -not $NoPimForGroups
                $report.ControlPlaneAdminAssignments = @(foreach ($controlPlaneAdmin in $graphControlPlaneAdmins) {
                        try {
                            if ($eligibleMembership) {
                                $existing = @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$($controlPlaneGroup.Id)' and principalId eq '$($controlPlaneAdmin.Id)'" -OutputType PSObject -DisableCache | Where-Object { $_ -and $_.AccessId -eq 'member' })
                                if ($existing.Count -gt 0) {
                                    Write-Verbose "$logPrefix $($controlPlaneAdmin.Id) is already an eligible member of $($controlPlaneGroup.DisplayName)"
                                    continue
                                }
                                Write-Verbose "$logPrefix Making $($controlPlaneAdmin.Id) an eligible member of $($controlPlaneGroup.DisplayName)"
                                $eligibilityBody = @{
                                    accessId     = "member"
                                    principalId  = $controlPlaneAdmin.Id
                                    groupId      = $controlPlaneGroup.Id
                                    action       = "AdminAssign"
                                    scheduleInfo = @{
                                        startDateTime = (Get-Date).AddHours(-1).ToString("o")
                                        expiration    = @{ type = "noExpiration" }
                                    }
                                }
                                Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" -Body ($eligibilityBody | ConvertTo-Json -Depth 10) -OutputType PSObject -ThrowOnFailure
                            } else {
                                $existing = @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/groups/$($controlPlaneGroup.Id)/members?`$select=id" -OutputType PSObject -DisableCache)
                                if (@($existing | ForEach-Object { $_.Id }) -contains $controlPlaneAdmin.Id) {
                                    Write-Verbose "$logPrefix $($controlPlaneAdmin.Id) is already a member of $($controlPlaneGroup.DisplayName)"
                                    continue
                                }
                                Write-Verbose "$logPrefix Adding $($controlPlaneAdmin.Id) as member of $($controlPlaneGroup.DisplayName)"
                                $memberBody = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($controlPlaneAdmin.Id)" } | ConvertTo-Json
                                Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/groups/$($controlPlaneGroup.Id)/members/`$ref" -Body $memberBody -OutputType PSObject -ThrowOnFailure | Out-Null
                                [pscustomobject]@{ GroupId = $controlPlaneGroup.Id; PrincipalId = $controlPlaneAdmin.Id; AccessId = 'member' }
                            }
                        } catch {
                            Write-Warning "$logPrefix Failed to add ControlPlane admin $($controlPlaneAdmin.Id) to $($controlPlaneGroup.DisplayName): $($_.Exception.Message)"
                        }
                    })
            }
        }

        return $report
    }
}