function New-EntraOpsPrivilegedAssetsFindingContext {
    <#
    .SYNOPSIS
        Builds the privileged object inventory that the Privileged Assets finding rules evaluate.
    .DESCRIPTION
        Builds one inventory record per privileged object (users, groups, service principals and
        applications incl. all object sub types) from the Privileged EAM export and merges the object
        across all RBAC systems: owners, sponsors, owned objects and devices, identity parent,
        associated work account and PAW device, administrative units, restricted management, the role
        assignments with their classification and the assignment summary (highest tier). Related object
        IDs are resolved against the export only (RelatedObjects); IDs outside the export are returned
        in UnresolvedIds.

        The records use the shape of the Privileged Assets report data, so the finding rules evaluate
        the same objects the report shows. Used by Invoke-EntraOpsFindingEvaluation and
        New-EntraOpsPrivilegedAssetsData. The checks of the Privileged Assets rules are evaluated once per
        object when the context is built (ObjectFindings, see Get-EntraOpsPrivilegedAssetsObjectFinding).
    .PARAMETER ImportPath
        Folder with the Privileged EAM export.
    .PARAMETER Export
        The export from Read-EntraOpsPrivilegedEamExport, to reuse instead of reading -ImportPath.
    .PARAMETER ReportPath
        Reports folder. When the Privileged Assets data exists (PrivilegedAssets/data/privileged-assets-data.js), the
        related objects outside the export that New-EntraOpsPrivilegedAssetsData resolved with Microsoft Graph (for
        example owners without privileged access) are taken over, so the finding results name them.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$ImportPath,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Export,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ReportPath
    )

    function ConvertTo-StringArray {
        param($Value)
        if ($null -eq $Value) { return @() }
        return @(@($Value) | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { "$_" })
    }

    if ($null -eq $Export) { $Export = Read-EntraOpsPrivilegedEamExport -ImportPath $ImportPath }
    $TierRank = $script:EntraOpsTierRank
    $GuidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    $RelationshipProperties = [ordered]@{
        owners                = 'Owners'
        sponsors              = 'Sponsors'
        ownedObjects          = 'OwnedObjects'
        ownedDevices          = 'OwnedDevices'
        associatedWorkAccount = 'AssociatedWorkAccount'
        associatedPawDevice   = 'AssociatedPawDevice'
    }

    $ObjectsById = [ordered]@{}
    # Groups of other tenants: whether the collection read their members (CrossTenantMembersExpanded of the export,
    # EntraOps 1.2.0 or later), and the groups through which members of the export hold roles (TransitiveByObjectId and
    # the nesting chain), for data without the mark (see Get-EntraOpsFindingRemoteGroupGap).
    $CrossTenantMembersExpanded = @{}
    $TransitiveGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($System in $Export.Systems) {
        $RoleSystem = $System.RoleSystem
        foreach ($Source in $System.Objects) {
            $ObjectId = "$(Get-EntraOpsPropertyValue $Source 'ObjectId')".ToLowerInvariant()
            if ($ObjectId -notmatch $GuidPattern) { continue }

            if (-not $ObjectsById.Contains($ObjectId)) {
                $TierName = "$(Get-EntraOpsPropertyValue $Source 'ObjectAdminTierLevelName')"
                if ([string]::IsNullOrWhiteSpace($TierName)) { $TierName = 'Unclassified' }
                $DisplayName = "$(Get-EntraOpsPropertyValue $Source 'ObjectDisplayName')"
                $ObjectsById[$ObjectId] = [ordered]@{
                    objectId                      = $ObjectId
                    objectType                    = "$(Get-EntraOpsPropertyValue $Source 'ObjectType')".ToLowerInvariant()
                    objectSubType                 = "$(Get-EntraOpsPropertyValue $Source 'ObjectSubType')"
                    displayName                   = $(if ($DisplayName) { $DisplayName } else { $ObjectId })
                    userPrincipalName             = "$(Get-EntraOpsPropertyValue $Source 'ObjectUserPrincipalName')"
                    objectTenantId                = "$(Get-EntraOpsPropertyValue $Source 'ObjectTenantId')"
                    # Where the object comes from (EntraOps 1.2.0 or later): OriginType, OriginTenantId and OriginId.
                    originType                    = "$(Get-EntraOpsPropertyValue $Source 'OriginType')"
                    originTenantId                = "$(Get-EntraOpsPropertyValue $Source 'OriginTenantId')".ToLowerInvariant()
                    originId                      = "$(Get-EntraOpsPropertyValue $Source 'OriginId')"
                    tierLevel                     = "$(Get-EntraOpsPropertyValue $Source 'ObjectAdminTierLevel')"
                    tierName                      = $TierName
                    onPremSynchronized            = [bool](Get-EntraOpsPropertyValue $Source 'OnPremSynchronized')
                    # Guest or external user (userType, #EXT#), as the export flags it; service principals use OriginTenantId (the tenant of their application).
                    outsideOfHomeTenant           = [bool](Get-EntraOpsPropertyValue $Source 'OutsideOfHomeTenant')
                    restrictedManagementByRAG     = [bool](Get-EntraOpsPropertyValue $Source 'RestrictedManagementByRAG')
                    restrictedManagementByAadRole = [bool](Get-EntraOpsPropertyValue $Source 'RestrictedManagementByAadRole')
                    restrictedManagementByRMAU    = [bool](Get-EntraOpsPropertyValue $Source 'RestrictedManagementByRMAU')
                    identityParent                = "$(Get-EntraOpsPropertyValue $Source 'IdentityParent')"
                    administrativeUnits           = [System.Collections.Generic.List[object]]::new()
                    roleSystems                   = [System.Collections.Generic.List[string]]::new()
                    assignments                   = [System.Collections.Generic.List[object]]::new()
                    # The PAW references as the attribute has them (device ID or object ID), to name a reference that matches no device.
                    pawReferences                 = [System.Collections.Generic.List[string]]::new()
                }
                foreach ($Key in $RelationshipProperties.Keys) {
                    $ObjectsById[$ObjectId][$Key] = [System.Collections.Generic.List[string]]::new()
                }
            }
            $Object = $ObjectsById[$ObjectId]
            if (-not $Object.roleSystems.Contains($RoleSystem)) { $Object.roleSystems.Add($RoleSystem) }
            $MembersExpanded = Get-EntraOpsPropertyValue $Source 'CrossTenantMembersExpanded'
            # One RBAC system that read the members is enough.
            if ($null -ne $MembersExpanded) { $CrossTenantMembersExpanded[$ObjectId] = [bool]$CrossTenantMembersExpanded[$ObjectId] -or [bool]$MembersExpanded }

            # RBAC systems can carry sparser records for the same object: OR flags and fill empty fields.
            foreach ($Flag in @('OnPremSynchronized', 'OutsideOfHomeTenant', 'RestrictedManagementByRAG', 'RestrictedManagementByAadRole', 'RestrictedManagementByRMAU')) {
                $Key = $Flag.Substring(0, 1).ToLowerInvariant() + $Flag.Substring(1)
                $Object[$Key] = $Object[$Key] -or [bool](Get-EntraOpsPropertyValue $Source $Flag)
            }
            $FieldMap = [ordered]@{ objectSubType = 'ObjectSubType'; userPrincipalName = 'ObjectUserPrincipalName'; objectTenantId = 'ObjectTenantId'; originType = 'OriginType'; originTenantId = 'OriginTenantId'; originId = 'OriginId'; identityParent = 'IdentityParent'; tierLevel = 'ObjectAdminTierLevel' }
            foreach ($Key in $FieldMap.Keys) {
                if ([string]::IsNullOrWhiteSpace($Object[$Key])) { $Object[$Key] = "$(Get-EntraOpsPropertyValue $Source $FieldMap[$Key])" }
            }
            $Object.originTenantId = "$($Object.originTenantId)".ToLowerInvariant()
            # An object from another tenant by its origin is outside the home tenant (also a member synchronized from
            # another tenant without #EXT# in its user principal name).
            if ($Object.originType -in 'CrossTenantSync', 'B2BInvitation', 'TenantGovernance') { $Object.outsideOfHomeTenant = $true }
            # Exports of EntraOps before 1.2.0 don't carry OutsideOfHomeTenant: like Get-EntraOpsPrivilegedEntraObject,
            # a guest (userType) or a user with an #EXT# user principal name (B2B member) is outside the home tenant.
            if ($Object.objectType -eq 'user' -and ($Object.objectSubType -eq 'Guest' -or $Object.userPrincipalName -like '*#EXT#@*')) { $Object.outsideOfHomeTenant = $true }
            if ($Object.displayName -eq $ObjectId -and "$(Get-EntraOpsPropertyValue $Source 'ObjectDisplayName')") { $Object.displayName = "$(Get-EntraOpsPropertyValue $Source 'ObjectDisplayName')" }
            $SourceTierName = "$(Get-EntraOpsPropertyValue $Source 'ObjectAdminTierLevelName')"
            if ($Object.tierName -eq 'Unclassified' -and $TierRank.ContainsKey($SourceTierName)) {
                $Object.tierName = $SourceTierName
                $Object.tierLevel = "$(Get-EntraOpsPropertyValue $Source 'ObjectAdminTierLevel')"
            }

            foreach ($Key in $RelationshipProperties.Keys) {
                # PAW devices by their object ID (AssociatedPawDeviceObjectId; AssociatedPawDevice for older exports), like the owned devices.
                $RelatedValues = if ($Key -eq 'associatedPawDevice') { Get-EntraOpsPawDeviceObjectId -Object $Source } else { ConvertTo-StringArray (Get-EntraOpsPropertyValue $Source $RelationshipProperties[$Key]) }
                foreach ($RelatedId in @($RelatedValues)) {
                    $NormalizedId = $RelatedId.ToLowerInvariant()
                    if (-not $Object[$Key].Contains($NormalizedId)) { $Object[$Key].Add($NormalizedId) }
                }
            }
            foreach ($Reference in @(ConvertTo-StringArray (Get-EntraOpsPropertyValue $Source 'AssociatedPawDevice'))) {
                $NormalizedReference = $Reference.ToLowerInvariant()
                if (-not $Object.pawReferences.Contains($NormalizedReference)) { $Object.pawReferences.Add($NormalizedReference) }
            }
            foreach ($AdministrativeUnit in @(Get-EntraOpsPropertyValue $Source 'AssignedAdministrativeUnits')) {
                $AdministrativeUnitId = "$(Get-EntraOpsPropertyValue $AdministrativeUnit 'id')".ToLowerInvariant()
                if (-not $AdministrativeUnitId -or @($Object.administrativeUnits | Where-Object { $_.id -eq $AdministrativeUnitId }).Count -gt 0) { continue }
                $Object.administrativeUnits.Add([ordered]@{ id = $AdministrativeUnitId; displayName = "$(Get-EntraOpsPropertyValue $AdministrativeUnit 'displayName')" })
            }

            foreach ($RoleAssignment in @(Get-EntraOpsPropertyValue $Source 'RoleAssignments')) {
                if ($null -eq $RoleAssignment) { continue }
                foreach ($GroupId in @(@(Get-EntraOpsPropertyValue $RoleAssignment 'TransitiveByObjectId') + @(Get-EntraOpsPropertyValue $RoleAssignment 'TransitiveByNestingObjectIds'))) {
                    if (-not [string]::IsNullOrWhiteSpace("$GroupId")) { $null = $TransitiveGroupIds.Add("$GroupId".Trim().ToLowerInvariant()) }
                }
                $AssignmentTier = Get-EntraOpsMostPrivilegedTier -TierName @(@(Get-EntraOpsPropertyValue $RoleAssignment 'Classification') | ForEach-Object { "$(Get-EntraOpsPropertyValue $_ 'AdminTierLevelName')" }) -IncludeUnclassified
                if (-not $AssignmentTier) { $AssignmentTier = 'Unclassified' }
                $InstanceId = "$(Get-EntraOpsPropertyValue $RoleAssignment 'RoleAssignmentInstanceId')"
                if (-not $InstanceId) { $InstanceId = Get-EntraOpsRoleAssignmentInstanceId -RoleSystem $RoleSystem -RoleAssignment $RoleAssignment }
                $Object.assignments.Add([ordered]@{
                        id                 = $InstanceId
                        roleSystem         = $RoleSystem
                        roleDefinitionName = "$(Get-EntraOpsPropertyValue $RoleAssignment 'RoleDefinitionName')"
                        roleDefinitionId   = "$(Get-EntraOpsPropertyValue $RoleAssignment 'RoleDefinitionId')"
                        # Delegated (an application acting within the rights of the signed-in user), Application, BuiltInRole, ...
                        roleType           = "$(Get-EntraOpsPropertyValue $RoleAssignment 'RoleType')"
                        scopeName          = "$(Get-EntraOpsPropertyValue $RoleAssignment 'RoleAssignmentScopeName')"
                        scopeId            = "$(Get-EntraOpsPropertyValue $RoleAssignment 'RoleAssignmentScopeId')"
                        assignmentType     = "$(Get-EntraOpsPropertyValue $RoleAssignment 'RoleAssignmentType')"
                        assignmentSubType  = "$(Get-EntraOpsPropertyValue $RoleAssignment 'RoleAssignmentSubType')"
                        pimAssignmentType  = "$(Get-EntraOpsPropertyValue $RoleAssignment 'PIMAssignmentType')"
                        transitiveBy       = "$(Get-EntraOpsPropertyValue $RoleAssignment 'TransitiveByObjectDisplayName')"
                        tierName           = $AssignmentTier
                        services           = @(@(Get-EntraOpsPropertyValue $RoleAssignment 'Classification') | ForEach-Object { "$(Get-EntraOpsPropertyValue $_ 'Service')" } | Where-Object { $_ } | Select-Object -Unique)
                    })
            }
        }
    }

    # Ownership from the owner's side: an owner of an app registration lists the application among its owned objects,
    # not the service principal, whose owners include the owners of its app registration (Get-EntraOpsPrivilegedEntraObject).
    # Every owner in the export owns the objects that name it as owner, so the owner side (ownsHigherTier) sees the
    # same ownership as the object side (ownerLowerTier).
    foreach ($Object in $ObjectsById.Values) {
        foreach ($OwnerId in @($Object.owners)) {
            $Owner = $ObjectsById[$OwnerId]
            if ($null -ne $Owner -and -not $Owner.ownedObjects.Contains($Object.objectId)) { $Owner.ownedObjects.Add($Object.objectId) }
        }
    }

    # The home tenant: the tenant of most objects of the export. The export writes the tenant it was taken
    # from into ObjectTenantId; only delegations of Tenant Governance and remote groups carry another tenant.
    $TenantCounts = @{}
    foreach ($Object in $ObjectsById.Values) {
        if (-not $Object.objectTenantId -or $Object.outsideOfHomeTenant -or ($Object.objectType -eq 'user' -and $Object.objectSubType -eq 'Guest')) { continue }
        $TenantCounts[$Object.objectTenantId] = [int]$TenantCounts[$Object.objectTenantId] + 1
    }
    $HomeTenantId = ($TenantCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1).Key

    $ObjectsByAppId = @{}
    foreach ($Object in $ObjectsById.Values) {
        if ($Object.objectType -in @('serviceprincipal', 'application') -and $Object.userPrincipalName -match $GuidPattern) {
            $ObjectsByAppId[$Object.userPrincipalName.ToLowerInvariant()] = $Object.objectId
        }
    }

    $Objects = [System.Collections.Generic.List[object]]::new()
    $RelatedObjects = [ordered]@{}
    $UnresolvedIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($Object in $ObjectsById.Values) {
        # highestTierName: the most privileged tier of all role assignments (the tier of the role assignments the
        # report shows). highestAccessTierName: the same without delegated permissions - the access of the object
        # itself, which the finding rules compare with its tier: a delegated permission acts within the rights of the
        # signed-in user, not with the access of the application (like the tier breach rules, EO.1001 and EO.1003).
        $Summary = [ordered]@{ total = $Object.assignments.Count; eligible = 0; active = 0; byTier = [ordered]@{}; bySystem = [ordered]@{}; highestTierName = 'Unclassified'; highestAccessTierName = 'Unclassified' }
        foreach ($TierName in $script:EntraOpsTierName) { $Summary.byTier[$TierName] = 0 }
        foreach ($Assignment in $Object.assignments) {
            $Summary.byTier[$Assignment.tierName]++
            $Summary.bySystem[$Assignment.roleSystem] = [int]$Summary.bySystem[$Assignment.roleSystem] + 1
            if ($Assignment.pimAssignmentType -eq 'Eligible') { $Summary.eligible++ } else { $Summary.active++ }
            if ($TierRank[$Assignment.tierName] -lt $TierRank[$Summary.highestTierName]) { $Summary.highestTierName = $Assignment.tierName }
            if ($Assignment.roleType -ne 'Delegated' -and $TierRank[$Assignment.tierName] -lt $TierRank[$Summary.highestAccessTierName]) { $Summary.highestAccessTierName = $Assignment.tierName }
        }
        $Object['assignmentSummary'] = $Summary
        # Service principals of Microsoft first-party applications (operated by Microsoft, not by the tenant).
        $Object['isMicrosoftFirstParty'] = $Object.objectType -eq 'serviceprincipal' -and (Test-EntraOpsMicrosoftFirstParty -AppOwnerOrganizationId $Object.originTenantId -AppId $Object.userPrincipalName)
        # Microsoft clients whose delegated permissions the tenant grants by consent (Graph CLI, Graph Explorer).
        $Object['isMicrosoftConsentClient'] = $Object.objectType -eq 'serviceprincipal' -and (Test-EntraOpsMicrosoftConsentClient -AppId $Object.userPrincipalName)
        # Outside the home tenant: a guest or external user (OutsideOfHomeTenant of the export), an object whose origin
        # is another tenant (OriginTenantId, EntraOps 1.2.0 or later: a user or group synchronized from another tenant,
        # the service principal of an application of another organization; local objects, managed identities and
        # applications of this tenant have the home tenant), or an object of another tenant (a delegation of Tenant
        # Governance, a remote group).
        $ForeignOrigin = $Object.originTenantId -and $HomeTenantId -and $Object.originTenantId -ne "$HomeTenantId".ToLowerInvariant()
        $Object['isForeign'] = [bool](($Object.objectType -eq 'user' -and $Object.outsideOfHomeTenant) -or $ForeignOrigin -or ($Object.originType -in @('CrossTenantSync', 'B2BInvitation', 'TenantGovernance')) -or ($HomeTenantId -and $Object.objectTenantId -and $Object.objectTenantId -ne $HomeTenantId))
        # The object itself is in another tenant (not a guest or the service principal of a multi-tenant application,
        # which are objects of the home tenant): the tenant can't change it, for example its custom security attributes.
        $Object['isObjectOfOtherTenant'] = [bool]($HomeTenantId -and $Object.objectTenantId -and $Object.objectTenantId -ne $HomeTenantId)
        # A directory role protects its holder only when Helpdesk, Password, Authentication or User Administrators can't
        # manage it (Test-EntraOpsDirectoryRoleRestrictsManagement). Exports of EntraOps before 1.2.0 count every
        # directory role, so an object whose Entra ID roles are all manageable by these administrators is not protected.
        $DirectoryRoles = @($Object.assignments | Where-Object { $_.roleSystem -eq 'EntraID' })
        if ($Object.restrictedManagementByAadRole -and $DirectoryRoles.Count -gt 0 -and
            @($DirectoryRoles | Where-Object { Test-EntraOpsDirectoryRoleRestrictsManagement -RoleDefinitionId $_.roleDefinitionId }).Count -eq 0) {
            $Object.restrictedManagementByAadRole = $false
        }
        $Object['restrictedManagement'] = if ($Object.objectType -in @('serviceprincipal', 'application')) {
            'Not available'
        } elseif ($Object.objectType -eq 'group' -and $Object.objectSubType -eq 'Role-assignable' -and $Object.restrictedManagementByRMAU) {
            'Conflict'
        } elseif ($Object.restrictedManagementByAadRole -or $Object.restrictedManagementByRAG -or $Object.restrictedManagementByRMAU) {
            'Applied'
        } else {
            'Not applied'
        }

        $RelatedIds = @($RelationshipProperties.Keys | ForEach-Object { $Object[$_] })
        if ($Object.identityParent) {
            $ParentKey = $Object.identityParent.ToLowerInvariant()
            $Object.identityParent = $ParentKey
            if ($ObjectsByAppId.ContainsKey($ParentKey) -and -not $RelatedObjects.Contains($ParentKey)) {
                $ParentObject = $ObjectsById[$ObjectsByAppId[$ParentKey]]
                $RelatedObjects[$ParentKey] = [ordered]@{ objectId = $ParentObject.objectId; displayName = $ParentObject.displayName; objectType = $ParentObject.objectType; objectSubType = $ParentObject.objectSubType; tierName = $ParentObject.tierName; source = 'PrivilegedEAM' }
            } else {
                $RelatedIds += $ParentKey
            }
        }
        foreach ($RelatedId in $RelatedIds) {
            if ($RelatedObjects.Contains($RelatedId)) { continue }
            if ($ObjectsById.Contains($RelatedId)) {
                $RelatedObject = $ObjectsById[$RelatedId]
                $RelatedObjects[$RelatedId] = [ordered]@{ objectId = $RelatedId; displayName = $RelatedObject.displayName; objectType = $RelatedObject.objectType; objectSubType = $RelatedObject.objectSubType; tierName = $RelatedObject.tierName; source = 'PrivilegedEAM' }
            } elseif ($RelatedId -match $GuidPattern) {
                $UnresolvedIds.Add($RelatedId) | Out-Null
            }
        }
        $Objects.Add($Object)
    }

    # Names of related objects outside the export, resolved by the Privileged Assets data (Microsoft Graph).
    if ($ReportPath) {
        try {
            $ReportData = Read-EntraOpsReportDataFile -Path (Join-Path $ReportPath 'PrivilegedAssets/data/privileged-assets-data.js')
            $Resolved = if ($null -ne $ReportData -and $ReportData.Data -is [System.Collections.IDictionary]) { $ReportData.Data['relatedObjects'] }
            if ($Resolved -is [System.Collections.IDictionary]) {
                foreach ($Key in @($Resolved.Keys)) {
                    $Entry = $Resolved[$Key]
                    $Id = "$Key".ToLowerInvariant()
                    if ($RelatedObjects.Contains($Id) -or $Entry -isnot [System.Collections.IDictionary] -or -not "$($Entry['displayName'])") { continue }
                    $RelatedObjects[$Id] = [ordered]@{ objectId = $(if ($Entry['objectId']) { "$($Entry['objectId'])" } else { $Id }); displayName = "$($Entry['displayName'])"; objectType = "$($Entry['objectType'])"; objectSubType = "$($Entry['objectSubType'])"; tierName = "$($Entry['tierName'])"; source = $(if ($Entry['source']) { "$($Entry['source'])" } else { 'Microsoft Graph' }) }
                }
            }
        } catch {
            Write-Verbose "The related objects of the Privileged Assets data in $ReportPath could not be read: $($_.Exception.Message)"
        }
    }

    $Context = [pscustomobject]@{
        Area           = 'PrivilegedAssets'
        Files          = $Export.Files
        ObjectsById    = $ObjectsById
        Objects        = $Objects
        RelatedObjects = $RelatedObjects
        UnresolvedIds  = $UnresolvedIds
        HomeTenantId   = $HomeTenantId
        ObjectFindings = $null
        CrossTenantMembersExpanded = $CrossTenantMembersExpanded
        TransitiveGroupIds         = $TransitiveGroupIds
    }
    $Context.ObjectFindings = Get-EntraOpsPrivilegedAssetsObjectFinding -Context $Context
    $Context
}
