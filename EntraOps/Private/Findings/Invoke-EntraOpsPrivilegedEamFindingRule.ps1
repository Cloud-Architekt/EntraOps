function Invoke-EntraOpsPrivilegedEamFindingRule {
    <#
    .SYNOPSIS
        Evaluates a Privileged EAM finding rule against the objects and role assignments of the export.
    .DESCRIPTION
        Pure evaluation of the context from New-EntraOpsPrivilegedEamFindingContext (no file or Graph access).
        Object rules evaluate the merged privileged objects (Inventory), assignment rules every role
        assignment of the RBAC systems the rule applies to. "Privileged access" means Control or Management
        Plane access (AccessTier); the tier of an object is the more privileged of its access and its own
        classification (RequiredTier). Returns the evaluated instances (see Invoke-EntraOpsFindingRuleSet).
    .PARAMETER Context
        Context from New-EntraOpsPrivilegedEamFindingContext.
    .PARAMETER Rule
        The Privileged EAM finding rule (from Get-EntraOpsFindingRule).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    $Objects = $Context.Inventory.Objects
    # A PIM activation (Activated) is a temporary instance of an eligible assignment that the export lists next to
    # it: evaluating both would report the same assignment twice, and an exception for the eligible assignment
    # would not cover its activation (as in EO.8001 and EO.8002).
    $Assignments = @($Context.Assignments | Where-Object { "$($_.Assignment.PIMAssignmentType)" -ne 'Activated' })
    # A standing assignment: not eligible, not a PIM activation of an eligible assignment (Activated) and not
    # time-bound (TimeBounded). Systems without PIM export Permanent.
    function Test-Permanent($Assignment) { "$($Assignment.PIMAssignmentType)" -notin 'Eligible', 'Activated', 'TimeBounded' }

    function New-ObjectInstance($Object, [bool]$Failed, [string]$Message, [System.Collections.IDictionary]$Evidence = [ordered]@{}) {
        $Evidence['TierName'] = "$($Object.tierName)"
        $Evidence['AccessTier'] = "$($Object.accessTier)"
        if ("$($Object.objectType)" -eq 'application' -and "$($Object.userPrincipalName)" -match '^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { $Evidence['AppId'] = "$($Object.userPrincipalName)" }
        [pscustomobject]@{
            Failed             = $Failed
            InstanceKey        = "$($Object.objectId)"
            ObjectId           = "$($Object.objectId)"
            ObjectType         = "$($Object.objectType)"
            DisplayName        = "$($Object.displayName)"
            AdminTierLevel     = Get-EntraOpsAdminTierLevel $Object.tierName
            AdminTierLevelName = $(if ("$($Object.tierName)") { "$($Object.tierName)" } else { 'Unclassified' })
            Message            = $Message
            Evidence           = $Evidence
        }
    }
    # Display name of a tier (Control Plane), for the messages.
    function Get-Tier($TierName) { Get-EntraOpsTierDisplayName $TierName }
    # Display names of more than one object (inventory and related objects): such an object is named with the start of
    # its ID ('Jane Doe (0e1e6c34)'), so two owners of the same name are not taken for one.
    $IdsByName = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.HashSet[string]]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $KnownObjects = @($Context.Inventory.ObjectsById.Values) + @(if ($null -ne $Context.Inventory.PSObject.Properties['RelatedObjects'] -and $null -ne $Context.Inventory.RelatedObjects) { $Context.Inventory.RelatedObjects.Values })
    foreach ($Known in $KnownObjects) {
        $KnownName = "$($Known.displayName)"
        $KnownId = "$($Known.objectId)".ToLowerInvariant()
        if (-not $KnownName -or -not $KnownId) { continue }
        if (-not $IdsByName.ContainsKey($KnownName)) { $IdsByName[$KnownName] = [System.Collections.Generic.HashSet[string]]::new() }
        $null = $IdsByName[$KnownName].Add($KnownId)
    }
    # Names of related objects (for example owners), from the inventory or the related objects of the context.
    function Get-Names($Ids) {
        @(foreach ($Id in @($Ids | Where-Object { $_ })) {
                $Key = "$Id".ToLowerInvariant()
                $Related = $Context.Inventory.ObjectsById[$Key]
                if ($null -eq $Related -and $null -ne $Context.Inventory.PSObject.Properties['RelatedObjects']) { $Related = $Context.Inventory.RelatedObjects[$Key] }
                if ($null -eq $Related -or -not "$($Related.displayName)") { "$Id"; continue }
                $Name = "$($Related.displayName)"
                if ($Key.Length -ge 8 -and $IdsByName.ContainsKey($Name) -and $IdsByName[$Name].Count -gt 1) { "$Name ($($Key.Substring(0, 8)))" } else { $Name }
            })
    }
    function Join-Limited([string[]]$Items, [int]$Max = 5) {
        $Text = @($Items | Select-Object -First $Max | ForEach-Object { "'$_'" }) -join ', '
        if ($Items.Count -gt $Max) { $Text += " and $($Items.Count - $Max) more" }
        $Text
    }
    function New-AssignmentInstance($Item, [bool]$Failed, [string]$Message, [System.Collections.IDictionary]$Evidence = [ordered]@{}) {
        $Evidence['System'] = $Item.System
        $Evidence['RoleDefinitionName'] = "$($Item.Assignment.RoleDefinitionName)"
        $Evidence['RoleAssignmentScopeId'] = "$($Item.Assignment.RoleAssignmentScopeId)"
        # The name of the scope, when the export has one: the reports show it instead of the ID.
        if ("$($Item.Assignment.RoleAssignmentScopeName)") { $Evidence['ScopeName'] = "$($Item.Assignment.RoleAssignmentScopeName)" }
        $Evidence['Tier'] = $Item.Tier
        $Evidence['RoleAssignmentType'] = "$($Item.Assignment.RoleAssignmentType)"
        # The ID of the assignment in the EAM Dashboard (#assignment=).
        $Evidence['RoleAssignmentInstanceId'] = ($Item.InstanceKey -split '\|', 3)[2]
        [pscustomobject]@{
            Failed         = $Failed
            InstanceKey    = $Item.InstanceKey
            ObjectId       = $Item.ObjectId
            ObjectType     = $Item.ObjectType
            DisplayName    = $Item.DisplayName
            AdminTierLevel = Get-EntraOpsAdminTierLevel $Item.ObjectTierName
            AdminTierLevelName = $Item.ObjectTierName
            Message        = $Message
            Evidence       = $Evidence
        }
    }
    # Roles without a name (for example an application role without a display name) are named by their ID.
    function Get-Role($Item) { "'$(if ("$($Item.Assignment.RoleDefinitionName)") { $Item.Assignment.RoleDefinitionName } elseif ("$($Item.Assignment.RoleDefinitionId)") { "unresolved $(if ("$($Item.System)" -eq 'ResourceApps') { 'app role' } else { 'role' }) $($Item.Assignment.RoleDefinitionId)$(if ("$($Item.System)" -eq 'ResourceApps' -and "$($Item.Assignment.RoleAssignmentScopeName)") { " of $($Item.Assignment.RoleAssignmentScopeName)" })" } else { '(unnamed role)' })' ($($Item.System))" }

    # The managing tenant (ManagingTenantId and ManagingTenantName of EntraOpsConfig.json, the governing tenant of Tenant
    # Governance): its principals (guests, members, groups and applications) are informational only. The rules about
    # principals of other tenants (EO.4002, EO.4011, EO.5001) let them pass and name them in a note; EO.4010 lists their
    # role assignments.
    $ManagingTenantId = "$(if ($null -ne $Rule.PSObject.Properties['ParameterValues'] -and $null -ne $Rule.ParameterValues) { $Rule.ParameterValues['ManagingTenantId'] })".Trim()
    $ManagingTenantName = "$(if ($null -ne $Rule.PSObject.Properties['ParameterValues'] -and $null -ne $Rule.ParameterValues) { $Rule.ParameterValues['ManagingTenantName'] })".Trim()
    function New-ManagingTenantNote([string[]]$Names) {
        if ($Names.Count -eq 0) { return }
        [pscustomobject]@{ NoteOnly = $true; Note = "$($Names.Count) principal(s) of the managing tenant $ManagingTenantId$(if ($ManagingTenantName) { " ($ManagingTenantName)" }) (ManagingTenantId of EntraOpsConfig.json) are not reported: $(Join-EntraOpsFindingName $Names). EO.4010 lists their role assignments." }
    }

    switch ($Rule.Key) {
        'auScopeLowerTier' {
            # Members of each administrative unit, with their tier level and restricted management.
            $Members = @{}
            foreach ($Object in $Objects) {
                foreach ($Unit in @($Object.administrativeUnits)) {
                    if ($null -eq $Unit) { continue }
                    $UnitId = "$($Unit.id)".ToLowerInvariant()
                    if (-not $Members.ContainsKey($UnitId)) { $Members[$UnitId] = [System.Collections.Generic.List[object]]::new() }
                    $Members[$UnitId].Add($Object)
                }
            }
            foreach ($Item in $Assignments) {
                # Microsoft first-party service principals (for example of Entra ID Governance) are operated by Microsoft.
                # Only roles with privileged actions (Control or Management Plane classification) can take over members.
                if ($Item.System -ne 'EntraID' -or $Item.IsMicrosoftFirstParty -or -not (Test-EntraOpsPrivilegedTier $Item.Tier) -or "$($Item.Assignment.RoleAssignmentScopeId)" -notmatch '^/administrativeUnits/([0-9a-fA-F-]{36})') { continue }
                $UnitId = $Matches[1].ToLowerInvariant()
                # The tier of the holder is the more privileged of its access and its own classification (requiredTier).
                $Holder = $Context.Inventory.ObjectsById[$Item.ObjectId]
                $HolderTier = if ($null -ne $Holder -and $Holder.requiredTier) { "$($Holder.requiredTier)" } else { $Item.ObjectTierName }
                $HolderLevel = Get-EntraOpsAdminTierLevel $HolderTier
                # Restricted management (a restricted management administrative unit, a role-assignable group or a
                # privileged role) keeps administrative-unit-scoped administrators from managing the member. The export
                # does not tell which administrative unit restricts a member: a role scoped to the restricted management
                # administrative unit itself can manage its members, which is not reported.
                $Exposed = @(@($Members[$UnitId]) | Where-Object {
                        $null -ne $_ -and -not ($_.restrictedManagementByRMAU -or $_.restrictedManagementByRAG -or $_.restrictedManagementByAadRole) -and
                        $_.requiredTier -and (Get-EntraOpsAdminTierLevel $_.requiredTier) -lt $HolderLevel
                    })
                New-AssignmentInstance $Item ($Exposed.Count -gt 0) "$(Get-Tier $HolderTier) object '$($Item.DisplayName)' holds $(Get-Role $Item) on an administrative unit with $($Exposed.Count) more privileged member(s) without restricted management." ([ordered]@{ AdministrativeUnitId = $UnitId; HolderTier = $HolderTier; MemberObjectIds = @($Exposed.objectId) })
            }
        }
        'unclassifiedAssignment' {
            # OpenID Connect sign-in scopes and user_impersonation of a resource are no privileges of their own.
            $SignInScopes = @('openid', 'profile', 'email', 'offline_access', 'user_impersonation')
            foreach ($Item in $Assignments) {
                if ("$($Item.Assignment.RoleType)" -eq 'Delegated' -and "$($Item.Assignment.RoleDefinitionName)" -in $SignInScopes) { continue }
                # An app role without a name: the resource application no longer offers it (for example an app role removed from
                # the application or an API permission retired by Microsoft), so no classification can match it. The all-zero ID is
                # the default access to an application without app roles: a valid assignment, never offered by name.
                $RoleDefinitionId = "$($Item.Assignment.RoleDefinitionId)".Trim()
                $Retired = if ("$($Item.System)" -eq 'ResourceApps' -and "$($Item.Assignment.RoleType)" -ne 'Delegated' -and -not "$($Item.Assignment.RoleDefinitionName)" -and $RoleDefinitionId -and $RoleDefinitionId -ne '00000000-0000-0000-0000-000000000000') {
                    " The resource application no longer offers this app role (for example, it was removed from the application or retired by Microsoft), so no classification can match it: remove the assignment."
                } else { '' }
                New-AssignmentInstance $Item (-not $Item.Tier) "$(Get-Role $Item) of '$($Item.DisplayName)' has no tier classification.$Retired"
            }
        }
        'customRoleControlPlane' {
            $Roles = [ordered]@{}
            foreach ($Item in $Assignments) {
                if ($Item.System -notin 'EntraID', 'Azure' -or "$($Item.Assignment.RoleType)" -ne 'CustomRole') { continue }
                $RoleKey = "$($Item.System)|$("$($Item.Assignment.RoleDefinitionId)".ToLowerInvariant())"
                if (-not $Roles.Contains($RoleKey)) { $Roles[$RoleKey] = [System.Collections.Generic.List[object]]::new() }
                $Roles[$RoleKey].Add($Item)
            }
            foreach ($RoleKey in $Roles.Keys) {
                $Items = $Roles[$RoleKey]
                # Direct assignments count the principals the role is assigned to (a group once, not each member).
                $ControlPlane = @($Items | Where-Object { $_.Tier -eq 'ControlPlane' -and "$($_.Assignment.RoleAssignmentType)" -ne 'Transitive' })
                if ($ControlPlane.Count -eq 0) { $ControlPlane = @($Items | Where-Object Tier -EQ 'ControlPlane') }
                [pscustomobject]@{
                    Failed      = $ControlPlane.Count -gt 0
                    InstanceKey = $RoleKey
                    ObjectId    = "$($Items[0].Assignment.RoleDefinitionId)"
                    ObjectType  = 'roleDefinition'
                    DisplayName = "$($Items[0].Assignment.RoleDefinitionName)"
                    Message     = "Custom role '$($Items[0].Assignment.RoleDefinitionName)' ($($Items[0].System)) grants Control Plane permissions and is assigned to $(@($ControlPlane.ObjectId | Select-Object -Unique).Count) principal(s)."
                    Evidence    = [ordered]@{ System = $Items[0].System; ObjectIds = @($ControlPlane.ObjectId | Select-Object -Unique); RoleAssignmentInstanceIds = @($ControlPlane | ForEach-Object { ($_.InstanceKey -split '\|', 3)[2] } | Select-Object -Unique) }
                }
            }
        }
        'permanentControlPlaneAssignment' {
            # Emergency access accounts (Findings.EmergencyAccessAccounts, by object ID or user principal name: display
            # names are not unique) keep their permanent assignments by design: they are not reported, and the reason names them.
            $EmergencyAccess = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($Entry in @(@($Rule.ParameterValues['EmergencyAccessAccounts']) | Where-Object { "$_" })) { $null = $EmergencyAccess.Add("$Entry".Trim()) }
            $SkippedEmergencyAccess = [System.Collections.Generic.List[string]]::new()
            foreach ($Item in $Assignments) {
                # Delegated access of Tenant Governance is granted by the managing tenant and cannot be converted to PIM here.
                if ($Item.System -notin 'EntraID', 'Azure' -or $Item.ObjectType -ne 'user' -or "$($Item.Assignment.RoleAssignmentType)" -ne 'Direct' -or $Item.Tier -ne 'ControlPlane' -or "$($Item.Assignment.RoleAssignmentSubType)" -like '*Delegated Admin*') { continue }
                if ($EmergencyAccess.Count -gt 0) {
                    $Known = $Context.Inventory.ObjectsById["$($Item.ObjectId)".ToLowerInvariant()]
                    $Keys = @("$($Item.ObjectId)", $(if ($Known) { "$($Known.userPrincipalName)" })) | Where-Object { $_ }
                    if (@($Keys | Where-Object { $EmergencyAccess.Contains($_) }).Count -gt 0) {
                        $Label = "'$($Item.DisplayName)' ($($Item.ObjectId))"
                        if (-not $SkippedEmergencyAccess.Contains($Label)) { $SkippedEmergencyAccess.Add($Label) }
                        continue
                    }
                }
                New-AssignmentInstance $Item (Test-Permanent $Item.Assignment) "User '$($Item.DisplayName)' holds the Control Plane role $(Get-Role $Item) as a permanent assignment." ([ordered]@{ PIMAssignmentType = "$($Item.Assignment.PIMAssignmentType)" })
            }
            if ($SkippedEmergencyAccess.Count -gt 0) {
                [pscustomobject]@{ NoteOnly = $true; Note = "$($SkippedEmergencyAccess.Count) emergency access account(s) of Findings.EmergencyAccessAccounts are not reported: $(Join-EntraOpsFindingName $SkippedEmergencyAccess)." }
            }
        }
        'permanentControlPlaneMembership' {
            # Role assignments of groups that are delegated access of Tenant Governance: granted by the managing tenant,
            # so the assignment of the group cannot be made eligible here (like permanentControlPlaneAssignment).
            $DelegatedGroupRoles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($Item in $Assignments) {
                if ($Item.ObjectType -eq 'group' -and "$($Item.Assignment.RoleAssignmentType)" -eq 'Direct' -and "$($Item.Assignment.RoleAssignmentSubType)" -like '*Delegated Admin*') {
                    $null = $DelegatedGroupRoles.Add("$($Item.System)|$($Item.ObjectId)|$($Item.Assignment.RoleDefinitionId)")
                }
            }
            foreach ($Item in $Assignments) {
                if ($Item.System -eq 'ResourceApps' -or $Item.ObjectType -ne 'user' -or "$($Item.Assignment.RoleAssignmentType)" -ne 'Transitive' -or $Item.Tier -ne 'ControlPlane') { continue }
                if ($DelegatedGroupRoles.Contains("$($Item.System)|$("$($Item.Assignment.TransitiveByObjectId)".ToLowerInvariant())|$($Item.Assignment.RoleDefinitionId)")) { continue }
                # Standing access needs both: a permanent membership and a standing role assignment of the group (a
                # transitive assignment carries the PIM assignment type of the group's assignment). A permanent member
                # of a group with an eligible role has to activate the role.
                $Standing = "$($Item.Assignment.RoleAssignmentSubType)" -like '*Permanent*member*' -and (Test-Permanent $Item.Assignment)
                New-AssignmentInstance $Item $Standing "User '$($Item.DisplayName)' holds the Control Plane role $(Get-Role $Item) through a permanent membership of '$($Item.Assignment.TransitiveByObjectDisplayName)', whose assignment is permanent as well." ([ordered]@{ GroupId = "$($Item.Assignment.TransitiveByObjectId)"; RoleAssignmentSubType = "$($Item.Assignment.RoleAssignmentSubType)"; PIMAssignmentType = "$($Item.Assignment.PIMAssignmentType)" })
            }
        }
        'azureRootScopeAssignment' {
            # The assignment itself (Direct): members of a group with the assignment would repeat it per member.
            # Only Control and Management Plane roles: Reader and other User Access roles do not give privileged access.
            # Microsoft first-party service principals (for example MS-PIM, which manages the PIM assignments) are not reported.
            foreach ($Item in $Assignments) {
                if ($Item.System -ne 'Azure' -or $Item.IsMicrosoftFirstParty -or "$($Item.Assignment.RoleAssignmentType)" -ne 'Direct' -or -not (Test-EntraOpsPrivilegedTier $Item.Tier)) { continue }
                $Scope = "$($Item.Assignment.RoleAssignmentScopeId)".TrimEnd('/')
                $TenantRoots = @($Item.ObjectTenantId, $Context.HomeTenantId) | Where-Object { $_ } | ForEach-Object { "/providers/Microsoft.Management/managementGroups/$_" }
                $AtRoot = $Scope -eq '' -or $TenantRoots -contains $Scope
                $ScopeLabel = if ($Scope -eq '') { "the root scope '/'" } else { 'the tenant root management group' }
                New-AssignmentInstance $Item ($AtRoot -and (Test-Permanent $Item.Assignment)) "'$($Item.DisplayName)' holds the $(Get-Tier $Item.Tier) role $(Get-Role $Item) permanently at $ScopeLabel." ([ordered]@{ PIMAssignmentType = "$($Item.Assignment.PIMAssignmentType)" })
            }
        }
        'privilegedWorkloadOwner' {
            foreach ($Object in $Objects) {
                # Microsoft first-party applications are operated by Microsoft (like workloadControlPlane).
                if ($Object.objectType -notin 'serviceprincipal', 'application' -or $Object.isMicrosoftFirstParty -or -not (Test-EntraOpsPrivilegedTier $Object.accessTier)) { continue }
                $Owners = @($Object.owners | Where-Object { $_ })
                $OwnerNames = @(Get-Names $Owners)
                New-ObjectInstance $Object ($Owners.Count -gt 0) "$(Get-Tier $Object.accessTier) workload identity '$($Object.displayName)' has $($Owners.Count) owner(s): $(Join-Limited $OwnerNames)." ([ordered]@{ OwnerIds = $Owners; OwnerNames = $OwnerNames })
            }
        }
        'privilegedGroupOwner' {
            foreach ($Object in $Objects) {
                if ($Object.objectType -ne 'group' -or -not (Test-EntraOpsPrivilegedTier $Object.accessTier)) { continue }
                $Owners = @($Object.owners | Where-Object { $_ })
                $OwnerNames = @(Get-Names $Owners)
                New-ObjectInstance $Object ($Owners.Count -gt 0) "$(Get-Tier $Object.accessTier) group '$($Object.displayName)' has $($Owners.Count) owner(s): $(Join-Limited $OwnerNames)." ([ordered]@{ OwnerIds = $Owners; OwnerNames = $OwnerNames })
            }
        }
        'guestPrivileged' {
            $OfManagingTenant = [System.Collections.Generic.List[string]]::new()
            foreach ($Object in $Objects) {
                if ($Object.objectType -ne 'user') { continue }
                $Failed = "$($Object.objectSubType)" -eq 'Guest' -and (Test-EntraOpsPrivilegedTier $Object.accessTier)
                $Evidence = [ordered]@{}
                if ($Failed -and (Test-EntraOpsFindingManagingTenant -Object $Object -ManagingTenantId $ManagingTenantId)) {
                    $Failed = $false
                    $Evidence['ManagingTenant'] = $true
                    $OfManagingTenant.Add("$($Object.displayName)")
                }
                New-ObjectInstance $Object $Failed "Guest user '$($Object.displayName)' has $(Get-Tier $Object.accessTier) access." $Evidence
            }
            New-ManagingTenantNote $OfManagingTenant
        }
        'unprotectedPrivilegedGroup' {
            # Groups of other tenants can't be protected here (like EO.4005); EO.4011 and EO.4010 report their access.
            $OfOtherTenant = [System.Collections.Generic.List[string]]::new()
            foreach ($Object in $Objects) {
                if ($Object.objectType -ne 'group' -or -not (Test-EntraOpsPrivilegedTier $Object.accessTier)) { continue }
                $Unprotected = "$($Object.objectSubType)" -ne 'Role-assignable' -and -not $Object.restrictedManagementByRMAU
                $Evidence = [ordered]@{}
                if ($Unprotected -and ($Object.isObjectOfOtherTenant -or "$($Object.originType)" -ceq 'TenantGovernance')) {
                    $Unprotected = $false
                    $Evidence['ObjectOfOtherTenant'] = $true
                    $OfOtherTenant.Add("$($Object.displayName)")
                }
                New-ObjectInstance $Object $Unprotected "$(Get-Tier $Object.accessTier) group '$($Object.displayName)' is neither role-assignable nor in a restricted management administrative unit." $Evidence
            }
            if ($OfOtherTenant.Count -gt 0) {
                [pscustomobject]@{ NoteOnly = $true; Note = "$($OfOtherTenant.Count) group(s) of other tenants are not reported: $(Join-EntraOpsFindingName $OfOtherTenant). Their membership and protection are managed in their tenant; EO.4011 and EO.4010 report their access." }
            }
        }
        'hybridManagementPlane' {
            foreach ($Object in $Objects) {
                if ($Object.requiredTier -ne 'ManagementPlane') { continue }
                New-ObjectInstance $Object ([bool]$Object.onPremSynchronized) "Management Plane object '$($Object.displayName)' ($($Object.objectType)) is synchronized from Active Directory."
            }
        }
        'foreignWorkloadControlPlane' {
            # The tenant of the application is exported since EntraOps 1.2.0: without it, no service principal can be
            # told apart from an application of the home tenant, so the rule would pass without having checked.
            if (-not @($Objects | Where-Object { $_.objectType -eq 'serviceprincipal' -and $_.originTenantId }).Count -and @($Objects | Where-Object { $_.objectType -eq 'serviceprincipal' }).Count) {
                return [pscustomobject]@{ SkipReason = 'The Privileged EAM export has no application tenant (OriginTenantId) of the service principals. Collect the Privileged EAM data again with EntraOps 1.2.0 or later.' }
            }
            $OfManagingTenant = [System.Collections.Generic.List[string]]::new()
            foreach ($Object in $Objects) {
                # Microsoft first-party applications are multi-tenant applications of Microsoft, operated by Microsoft.
                if ($Object.objectType -ne 'serviceprincipal' -or $Object.isMicrosoftFirstParty -or $Object.accessTier -ne 'ControlPlane') { continue }
                $Organization = if ($Object.originTenantId) { $Object.originTenantId } else { $Object.objectTenantId }
                $Evidence = [ordered]@{ OriginTenantId = "$($Object.originTenantId)"; ObjectTenantId = "$($Object.objectTenantId)" }
                $Failed = [bool]$Object.isForeign
                if ($Failed -and (Test-EntraOpsFindingManagingTenant -Object $Object -ManagingTenantId $ManagingTenantId)) {
                    $Failed = $false
                    $Evidence['ManagingTenant'] = $true
                    $OfManagingTenant.Add("$($Object.displayName)")
                }
                New-ObjectInstance $Object $Failed "Service principal '$($Object.displayName)' of the application of tenant $Organization has Control Plane access." $Evidence
            }
            New-ManagingTenantNote $OfManagingTenant
        }
        'foreignPrincipalControlPlane' {
            # Principals managed by another tenant: users and groups of cross-tenant synchronization, external members
            # (#EXT#, userType Member) and groups or members of a governing tenant (Tenant Governance, remote groups).
            # Guests (EO.4002) and the service principals of applications of other organizations (EO.5001) have rules of
            # their own. The principals of the managing tenant (ManagingTenantId of EntraOpsConfig.json) are informational only:
            # they pass, and a note names them.
            # Evaluated are all users and groups with Control Plane access (like EO.5001 with all Control Plane service
            # principals), so a tenant whose Control Plane principals are all its own passes instead of being skipped.
            $OfManagingTenant = [System.Collections.Generic.List[string]]::new()
            $TenantGovernanceObjects = 0
            foreach ($Object in $Objects) {
                if ($Object.isMicrosoftFirstParty -or $Object.objectType -eq 'serviceprincipal' -or $Object.accessTier -ne 'ControlPlane') { continue }
                if ($Object.objectType -eq 'user' -and "$($Object.objectSubType)" -eq 'Guest') { continue }
                $Kind = switch ("$($Object.objectType)") { 'user' { 'User' } 'group' { 'Group' } default { "Object ($($Object.objectType))" } }
                if (-not $Object.isForeign) {
                    New-ObjectInstance $Object $false "$Kind '$($Object.displayName)' of this tenant has Control Plane access."
                    continue
                }
                $Evidence = [ordered]@{}
                foreach ($Field in 'originType', 'originTenantId', 'originId', 'objectTenantId') {
                    if ("$($Object[$Field])") { $Evidence[$Field.Substring(0, 1).ToUpperInvariant() + $Field.Substring(1)] = "$($Object[$Field])" }
                }
                $Managing = Test-EntraOpsFindingManagingTenant -Object $Object -ManagingTenantId $ManagingTenantId
                if ($Managing) {
                    $Evidence['ManagingTenant'] = $true
                    $OfManagingTenant.Add("$($Object.displayName)")
                } elseif ("$($Object.originType)" -ceq 'TenantGovernance') {
                    $TenantGovernanceObjects++
                }
                $Origin = Get-EntraOpsFindingOriginText -Object $Object -HomeTenantId $Context.HomeTenantId -ManagingTenantId $ManagingTenantId -ManagingTenantName $ManagingTenantName
                New-ObjectInstance $Object (-not $Managing) "$Kind '$($Object.displayName)' is $Origin and has Control Plane access." $Evidence
            }
            if ($OfManagingTenant.Count -gt 0) {
                New-ManagingTenantNote $OfManagingTenant
            } elseif (-not "$ManagingTenantId".Trim() -and $TenantGovernanceObjects -gt 0) {
                [pscustomobject]@{ NoteOnly = $true; Note = "$TenantGovernanceObjects of the reported principals have access through Tenant Governance. If they belong to your governing tenant, set ManagingTenantId (and ManagingTenantName) in EntraOpsConfig.json to accept the access of its principals." }
            }
            # What the rule cannot see (also data gaps of findings.json): Control Plane groups whose origin is unknown (a
            # group synchronized from another tenant looks local), and groups of other tenants whose members were not collected.
            $OriginGap = Get-EntraOpsFindingGroupOriginGap -Inventory $Context.Inventory -ControlPlane
            if ($null -ne $OriginGap) { [pscustomobject]@{ NoteOnly = $true; Note = $OriginGap.Note } }
            $RemoteGap = Get-EntraOpsFindingRemoteGroupGap -Inventory $Context.Inventory -ManagingTenantId $ManagingTenantId -Tier 'ControlPlane'
            if ($null -ne $RemoteGap) { [pscustomobject]@{ NoteOnly = $true; Note = $RemoteGap.Note } }
        }
        'agentPrivileged' {
            foreach ($Object in $Objects) {
                if (-not "$($Object.objectSubType)".StartsWith('agent', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
                New-ObjectInstance $Object (Test-EntraOpsPrivilegedTier $Object.accessTier) "Agent '$($Object.displayName)' ($($Object.objectSubType)) has $(Get-Tier $Object.accessTier) access."
            }
        }
        'workloadControlPlane' {
            foreach ($Object in $Objects) {
                # Microsoft first-party service principals are operated by Microsoft, not by the tenant.
                if ($Object.objectType -ne 'serviceprincipal' -or $Object.isMicrosoftFirstParty) { continue }
                New-ObjectInstance $Object ($Object.accessTier -eq 'ControlPlane') "Service principal '$($Object.displayName)' ($($Object.objectSubType)) has Control Plane access." ([ordered]@{ RoleSystems = @($Object.roleSystems); OwnerIds = @($Object.owners | Where-Object { $_ }) })
            }
        }
        'delegatedControlPlanePermission' {
            foreach ($Item in $Assignments) {
                # Microsoft first-party clients (Azure CLI, Azure PowerShell, Office) hold delegated permissions by design.
                # Microsoft Graph Command Line Tools and Graph Explorer hold them only by consent of the tenant, which
                # the tenant controls and can revoke, so they are still reported (see Test-EntraOpsMicrosoftConsentClient).
                if ($Item.System -ne 'ResourceApps' -or ($Item.IsMicrosoftFirstParty -and -not $Item.IsMicrosoftConsentClient) -or "$($Item.Assignment.RoleType)" -ne 'Delegated') { continue }
                # The grant ID tells a grant for all users (admin consent) from the grant of one user: an application can
                # have both for the same permission, which would otherwise be two results with the same message.
                $Evidence = [ordered]@{ Resource = "$($Item.Assignment.RoleAssignmentScopeName)" }
                $Grant = ConvertFrom-EntraOpsOAuth2PermissionGrantId -GrantId "$($Item.Assignment.RoleAssignmentId)"
                $ConsentText = ''
                if ($null -ne $Grant) {
                    $Evidence['ConsentType'] = $Grant.ConsentType
                    if ($Grant.ConsentType -eq 'Principal') {
                        $Evidence['ConsentPrincipalId'] = $Grant.PrincipalId
                        $ConsentText = ", consented for the user '$(@(Get-Names @($Grant.PrincipalId))[0])' only"
                    } else {
                        $ConsentText = ', consented for all users'
                    }
                }
                New-AssignmentInstance $Item ($Item.Tier -eq 'ControlPlane') "'$($Item.DisplayName)' has the delegated Control Plane permission '$($Item.Assignment.RoleDefinitionName)' of '$($Item.Assignment.RoleAssignmentScopeName)'$ConsentText." $Evidence
            }
        }
        'unconstrainedRoleAssignmentDelegation' {
            # User Access Administrator and Role Based Access Control Administrator (built-in role IDs).
            $DelegationRoles = @('18d7d88d-d35e-4fb5-a5c3-7773c20a72d9', 'f58310d9-a9f6-439a-9e8d-f62e7b41a168')
            foreach ($Item in $Assignments) {
                # The assignment itself (Direct): a condition belongs to the assignment, not to the members of its group.
                # Microsoft first-party service principals (for example MS-PIM, which manages PIM for Azure resources) are
                # operated by Microsoft and need the delegation for their service.
                if ($Item.System -ne 'Azure' -or $Item.IsMicrosoftFirstParty -or "$($Item.Assignment.RoleAssignmentType)" -ne 'Direct') { continue }
                $RoleId = ("$($Item.Assignment.RoleDefinitionId)" -split '/')[-1].ToLowerInvariant()
                if ($RoleId -notin $DelegationRoles -and "$($Item.Assignment.RoleDefinitionName)" -notin 'User Access Administrator', 'Role Based Access Control Administrator') { continue }
                New-AssignmentInstance $Item ([string]::IsNullOrWhiteSpace("$($Item.Assignment.RoleAssignmentCondition)")) "'$($Item.DisplayName)' holds $(Get-Role $Item) at '$(if ("$($Item.Assignment.RoleAssignmentScopeName)") { $Item.Assignment.RoleAssignmentScopeName } else { $Item.Assignment.RoleAssignmentScopeId })' without a condition, so it can assign any role, including Owner." ([ordered]@{ PIMAssignmentType = "$($Item.Assignment.PIMAssignmentType)" })
            }
        }
        'nestedControlPlaneGroup' {
            # The export records the chain of groups for PIM for Groups memberships (eligible nested groups); the
            # members of other groups are read transitively with the group of the assignment as the only
            # nesting object, so their nesting is not visible here.
            foreach ($Item in $Assignments) {
                if ("$($Item.Assignment.RoleAssignmentType)" -ne 'Transitive' -or $Item.Tier -ne 'ControlPlane') { continue }
                $Chain = @(@($Item.Assignment.TransitiveByNestingObjectIds) | Where-Object { $_ })
                New-AssignmentInstance $Item ($Chain.Count -ge 2) "'$($Item.DisplayName)' holds the Control Plane role $(Get-Role $Item) through $($Chain.Count) nested groups." ([ordered]@{ GroupIds = $Chain; GroupNames = @(@($Item.Assignment.TransitiveByNestingObjectDisplayNames) | Where-Object { $_ }) })
            }
        }
        default { throw "No Privileged EAM evaluator for finding rule '$($Rule.Id)' ($($Rule.Key))." }
    }
}
