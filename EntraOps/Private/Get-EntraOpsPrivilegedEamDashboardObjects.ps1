<#
.SYNOPSIS
    Transform a Privileged EAM export folder into the EAM Dashboard object schema.

.DESCRIPTION
    Shared transform used by New-EntraOpsPrivilegedEamDashboardData (current/live
    dataset) and New-EntraOpsPrivilegedEamPrivilegeHistoryData (historic snapshots read
    from git history), so both generators compute identical columns
    (EligibilityBy, RestrictedManagement, SyncSource, PrivilegedType, ...) from
    the same PrivilegedEAM/<RbacSystem>/<RbacSystem>.json export shape.

    Only JSON files directly in an RBAC system folder are read (not the
    per-object subfolders user/, group/, serviceprincipal/, ...), matching
    Save-EntraOpsPrivilegedEAMJson.

.PARAMETER ImportPath
    Folder with the Privileged EAM export (contains one subfolder per RBAC
    system, each with a <RbacSystem>.json file).

.PARAMETER TenantId
    Home tenant id used to detect foreign objects for the PrivilegedType column
    (Multi-Tenant Apps, B2B Collaboration, Tenant Governance). Defaults to the
    most common ObjectTenantId in the export among objects that are neither
    guest users nor Tenant Governance delegated admins.

.PARAMETER ScopeReasoningDetails
    Scope reasoning loaded from ScopeReasoning_Azure.json,
    ScopeReasoning_EntraID.json and ScopeReasoning_IdentityGovernance.json.

.PARAMETER ControlPlaneReasoningDetails
    Object classification reasoning loaded from ScopeReasoning_ControlPlane.json.

.OUTPUTS
    System.Collections.Generic.List[object] of [ordered] hashtables (one per
    privileged object) plus the list of source files read is available via
    -SourceFiles (out parameter pattern using a ref variable).
#>

function Get-EntraOpsPrivilegedEamDashboardObjects {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$ImportPath,

        [Parameter(Mandatory = $false)]
        [System.String]$TenantId,

        [Parameter(Mandatory = $false)]
        [object[]]$ScopeReasoningDetails = @(),

        [Parameter(Mandatory = $false)]
        [object[]]$ControlPlaneReasoningDetails = @(),

        [Parameter(Mandatory = $false)]
        [ref]$SourceFiles
    )

    function Get-PropValue {
        # Safe property access for objects from ConvertFrom-Json whose schema can
        # vary between RBAC systems (also strict-mode proof).
        param($Object, [string] $Name)
        if ($null -eq $Object) { return $null }
        if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name)) {
            return $Object[$Name]
        }
        $p = $Object.PSObject.Properties[$Name]
        if ($null -ne $p) { return $p.Value }
        return $null
    }

    function ConvertTo-StringArray {
        # Normalize $null / scalar / array values to a flat string array.
        param($Value)
        if ($null -eq $Value) { return @() }
        return @(@($Value) | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { "$_" })
    }

    function ConvertTo-ScopedObjects {
        param($Value)
        return @(@($Value) | Where-Object { $null -ne $_ } | ForEach-Object {
                [ordered]@{
                    id          = "$(Get-PropValue $_ 'id')"
                    displayName = "$(Get-PropValue $_ 'displayName')"
                }
            })
    }

    function ConvertTo-ClassifiedResources {
        param($Value)
        return @(@($Value) | Where-Object { $null -ne $_ } | ForEach-Object {
                [ordered]@{
                    resourceName = "$(Get-PropValue $_ 'ResourceName')"
                    resourceId   = "$(Get-PropValue $_ 'ResourceId')"
                    originSystem = "$(Get-PropValue $_ 'OriginSystem')"
                    source       = "$(Get-PropValue $_ 'Source')"
                    eamTier      = "$(Get-PropValue $_ 'EAMTier')"
                    reason       = "$(Get-PropValue $_ 'Reason')"
                }
            })
    }

    function ConvertTo-AzureScopeEvidence {
        param($Value)
        return @(@($Value) | Where-Object { $null -ne $_ } | ForEach-Object {
                [ordered]@{
                    subscriptionScope = "$(Get-PropValue $_ 'SubscriptionScope')"
                    resultingScope    = "$(Get-PropValue $_ 'ResultingScope')"
                    scopeDetails      = @(ConvertTo-ClassifiedResources (Get-PropValue $_ 'ScopeDetails'))
                }
            })
    }

    function ConvertTo-ConditionEvaluation {
        param($Value)
        if ($null -eq $Value) { return $null }
        return [ordered]@{
            status      = "$(Get-PropValue $Value 'Status')"
            summary     = "$(Get-PropValue $Value 'Summary')"
            constraints = @(@(Get-PropValue $Value 'Constraints') | Where-Object { $null -ne $_ } | ForEach-Object {
                    [ordered]@{
                        source            = "$(Get-PropValue $_ 'Source')"
                        operator          = "$(Get-PropValue $_ 'Operator')"
                        roleDefinitionIds = @(ConvertTo-StringArray (Get-PropValue $_ 'RoleDefinitionIds'))
                    }
                })
        }
    }

    function Test-AzureControlPlaneRoleAppliesToScopeResource {
        param(
            [object[]]$Classification,
            [string]$ScopeResourceId,
            [string]$RoleDefinitionId
        )

        $broadResourceRoleIds = @(
            '8e3af657-a8ff-443c-a75c-2fe8c4bcb635', # Owner
            'b24988ac-6180-42a0-ab88-20f7382dd24c'  # Contributor
        )
        if ($broadResourceRoleIds -contains $RoleDefinitionId) { return $true }

        # A broad assignment can cover many classified descendants, but only
        # provider-specific Control Plane actions explain why this role reaches one.
        $resourceProviderMatch = [regex]::Match($ScopeResourceId, '(?i)/providers/([^/]+)')
        if (-not $resourceProviderMatch.Success) { return $true }

        $resourceProvider = $resourceProviderMatch.Groups[1].Value
        $actionProviders = foreach ($entry in @($Classification)) {
            if ("$(Get-PropValue $entry 'AdminTierLevelName')" -ne 'ControlPlane') { continue }
            foreach ($action in @(Get-PropValue $entry 'MatchedActions')) {
                $actionProviderMatch = [regex]::Match("$action", '^(?i)([^/*]+)(?:/|$)')
                if ($actionProviderMatch.Success) { $actionProviderMatch.Groups[1].Value }
            }
        }

        return @($actionProviders | Where-Object { $_ -ieq $resourceProvider }).Count -gt 0
    }

    function ConvertTo-ControlPlaneReasons {
        param($Value)
        return @(@($Value) | Where-Object { $null -ne $_ } | ForEach-Object {
                if ($_ -is [string]) {
                    return [ordered]@{ value = "$_" }
                }
                [ordered]@{
                    roleSystem     = "$(Get-PropValue $_ 'RoleSystem')"
                    roleName       = "$(Get-PropValue $_ 'RoleName')"
                    roleScope      = "$(Get-PropValue $_ 'RoleScope')"
                    edgeLabel      = "$(Get-PropValue $_ 'EdgeLabel')"
                    targetNodeName = "$(Get-PropValue $_ 'TargetNodeName')"
                }
            })
    }

    function Get-EligibilityBy {
        # Same case logic as the PrivilegedEAM_WatchLists / PrivilegedEAM_CustomTable
        # parsers (EligibilityBy computed column).
        param([string]$RoleSystem, [string]$PIMAssignmentType, [string]$RoleAssignmentSubType)
        if ($RoleSystem -eq 'EntraID' -and $PIMAssignmentType -eq 'Eligible' -and
            $RoleAssignmentSubType -in @('Nested Eligible member', 'Eligible member')) {
            return 'PIM for Entra ID Roles and Groups'
        }
        if ($RoleSystem -eq 'EntraID' -and $PIMAssignmentType -eq 'Eligible') { return 'PIM for Entra ID Roles' }
        if ($RoleSystem -eq 'Azure' -and $PIMAssignmentType -eq 'Eligible') { return 'PIM for Azure Roles' }
        if ($RoleAssignmentSubType -in @('Nested Eligible group member', 'Eligible member')) { return 'PIM for Groups' }
        return 'N/A'
    }

    function Get-RestrictedManagement {
        # Same case logic as the "List of Privileged Assets" grid in the
        # EntraOps Privileged EAM - Overview workbook.
        param(
            [string]$ObjectType,
            [string]$ObjectSubType,
            [bool]$ByAadRole,
            [bool]$ByRAG,
            [bool]$ByRMAU
        )
        if ($ObjectType -eq 'serviceprincipal') { return 'Not available' }
        if ($ObjectType -eq 'group') {
            if ($ObjectSubType -eq 'Role-assignable' -and $ByRMAU) { return 'Conflict' }
            if ($ByRMAU) { return 'Applied' }
            if ($ByRAG) { return 'Applied' }
            return 'Not applied'
        }
        if ($ObjectType -eq 'user') {
            if ($ByAadRole -or $ByRAG -or $ByRMAU) { return 'Applied' }
            return 'Not applied'
        }
        return 'Not applied'
    }

    # Match PrivilegedEAM/<System>/<System>.json only (one level deep), not the
    # per-object subfolders (user/, group/, serviceprincipal/ ...).
    $files = Get-ChildItem -Path $ImportPath -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ChildItem -Path $_.FullName -Filter '*.json' -File } |
    Sort-Object FullName

    if ($SourceFiles) { $SourceFiles.Value = @($files) }

    $objects = [System.Collections.Generic.List[object]]::new()

    foreach ($file in @($files)) {
        $roleSystem = Split-Path -Leaf (Split-Path -Parent $file.FullName)

        try {
            $data = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 |
            ConvertFrom-Json
        } catch {
            # Fail closed: an export file that exists but cannot be read/parsed must abort the
            # generation - silently dropping a whole RBAC system would produce a plausible but
            # truncated dataset downstream. A legitimately absent file is simply not enumerated.
            throw "Failed to read or parse Privileged EAM export file '$($file.FullName)' (RBAC system '$roleSystem'): $($_.Exception.Message)"
        }

        foreach ($o in @($data)) {
            if ($null -eq $o) { continue }

            $objType = "$(Get-PropValue $o 'ObjectType')"
            $objSubType = "$(Get-PropValue $o 'ObjectSubType')"
            $objectId = "$(Get-PropValue $o 'ObjectId')"
            $display = "$(Get-PropValue $o 'ObjectDisplayName')"
            if (-not $display) { $display = $objectId }

            $onPremSync = [bool](Get-PropValue $o 'OnPremSynchronized')
            $outsideOfHomeTenant = [bool](Get-PropValue $o 'OutsideOfHomeTenant')
            $byRAG = [bool](Get-PropValue $o 'RestrictedManagementByRAG')
            $byAadRole = [bool](Get-PropValue $o 'RestrictedManagementByAadRole')
            $byRMAU = [bool](Get-PropValue $o 'RestrictedManagementByRMAU')

            $objTierName = "$(Get-PropValue $o 'ObjectAdminTierLevelName')"
            if (-not $objTierName) { $objTierName = 'Unclassified' }

            # Object-level classification (aggregated tier/service pairs).
            $objClassification = [System.Collections.Generic.List[object]]::new()
            foreach ($c in @(Get-PropValue $o 'Classification')) {
                if ($null -eq $c) { continue }
                $tierName = "$(Get-PropValue $c 'AdminTierLevelName')"
                if (-not $tierName) { $tierName = 'Unclassified' }
                $objClassification.Add([ordered]@{
                        adminTierLevel     = "$(Get-PropValue $c 'AdminTierLevel')"
                        adminTierLevelName = $tierName
                        service            = "$(Get-PropValue $c 'Service')"
                    })
            }

            # Administrative units (id + displayName pairs).
            $adminUnits = [System.Collections.Generic.List[object]]::new()
            foreach ($au in @(Get-PropValue $o 'AssignedAdministrativeUnits')) {
                if ($null -eq $au) { continue }
                $adminUnits.Add([ordered]@{
                        id          = "$(Get-PropValue $au 'id')"
                        displayName = "$(Get-PropValue $au 'displayName')"
                    })
            }

            # Role assignments incl. per-assignment classification.
            $assignments = [System.Collections.Generic.List[object]]::new()
            foreach ($ra in @(Get-PropValue $o 'RoleAssignments')) {
                if ($null -eq $ra) { continue }

                $pimType = "$(Get-PropValue $ra 'PIMAssignmentType')"
                $assignSub = "$(Get-PropValue $ra 'RoleAssignmentSubType')"

                $raClassification = [System.Collections.Generic.List[object]]::new()
                foreach ($c in @(Get-PropValue $ra 'Classification')) {
                    if ($null -eq $c) { continue }
                    $tierName = "$(Get-PropValue $c 'AdminTierLevelName')"
                    if (-not $tierName) { $tierName = 'Unclassified' }
                    $raClassification.Add([ordered]@{
                            adminTierLevel             = "$(Get-PropValue $c 'AdminTierLevel')"
                            adminTierLevelName         = $tierName
                            service                    = "$(Get-PropValue $c 'Service')"
                            taggedBy                   = "$(Get-PropValue $c 'TaggedBy')"
                            taggedByObjectIds          = @(ConvertTo-StringArray (Get-PropValue $c 'TaggedByObjectIds'))
                            taggedByObjectDisplayNames = @(ConvertTo-StringArray (Get-PropValue $c 'TaggedByObjectDisplayNames'))
                            taggedByRoleSystem         = "$(Get-PropValue $c 'TaggedByRoleSystem')"
                            matchedActions             = @(ConvertTo-StringArray (Get-PropValue $c 'MatchedActions'))
                            scopedObjects              = @(ConvertTo-ScopedObjects (Get-PropValue $c 'ScopedObjects'))
                        })
                }

                $scopeReasoning = [System.Collections.Generic.List[object]]::new()
                if ($ScopeReasoningDetails.Count -gt 0) {
                    $scopeId = "$(Get-PropValue $ra 'RoleAssignmentScopeId')"
                    $normalizedScopeId = $scopeId.Trim().TrimEnd('/')
                    $classificationTaggedObjectIds = @($raClassification | ForEach-Object { @(Get-PropValue $_ 'taggedByObjectIds') } | Where-Object { $_ })
                    $classificationTiers = @($raClassification | ForEach-Object { "$(Get-PropValue $_ 'adminTierLevelName')" } | Where-Object { $_ } | Select-Object -Unique)
                    $matchedScopeReasons = @($ScopeReasoningDetails | Where-Object {
                            $reasoningRoleSystem = "$(Get-PropValue $_ 'RoleSystem')"
                            $reasoningScopeId = "$(Get-PropValue $_ 'ScopeId')".Trim().TrimEnd('/')
                            if (-not $reasoningScopeId) { return $false }
                            if ($roleSystem -eq 'DeviceManagement') {
                                return $reasoningRoleSystem -eq 'DeviceManagement' -and
                                $classificationTaggedObjectIds -contains $reasoningScopeId -and
                                (-not (Get-PropValue $_ 'EAMTier') -or $classificationTiers -contains "$(Get-PropValue $_ 'EAMTier')")
                            }
                            if ($roleSystem -eq 'Defender' -and $reasoningRoleSystem -eq 'Azure') {
                                $isArmScope = $normalizedScopeId -match '^/(subscriptions|providers/microsoft\.management)/'
                                return $isArmScope -and ($reasoningScopeId -ieq $normalizedScopeId -or $reasoningScopeId.StartsWith("$normalizedScopeId/", [System.StringComparison]::OrdinalIgnoreCase))
                            }
                            if ($reasoningRoleSystem -ne $roleSystem) { return $false }
                            if ($roleSystem -eq 'Azure') {
                                $expandedScopePaths = @(Get-PropValue $_ 'ExpandedScopePaths' | ForEach-Object { "$_".Trim().TrimEnd('/') })
                                return $reasoningScopeId -eq $normalizedScopeId -or $reasoningScopeId.StartsWith("$normalizedScopeId/", [System.StringComparison]::OrdinalIgnoreCase) -or $expandedScopePaths -contains $normalizedScopeId
                            }
                            return $reasoningScopeId -ieq $normalizedScopeId
                        })
                    foreach ($scopeReason in $matchedScopeReasons) {
                        $scopeResourceId = "$(Get-PropValue $scopeReason 'ScopeId')"
                        if ($roleSystem -eq 'Azure' -and -not (Test-AzureControlPlaneRoleAppliesToScopeResource -Classification $raClassification -ScopeResourceId $scopeResourceId -RoleDefinitionId "$(Get-PropValue $ra 'RoleDefinitionId')")) {
                            continue
                        }
                        $scopeReasoning.Add([ordered]@{
                                resourceName            = "$(Get-PropValue $scopeReason 'ScopeName')"
                                resourceId              = $scopeResourceId
                                roleSystem              = $roleSystem
                                source                  = "$(Get-PropValue $scopeReason 'Source')"
                                eamTier                 = "$(Get-PropValue $scopeReason 'EAMTier')"
                                resultingScope          = "$(Get-PropValue $scopeReason 'ResultingScope')"
                                tierSource              = "$(Get-PropValue $scopeReason 'TierSource')"
                                tierEvidence            = @(ConvertTo-StringArray (Get-PropValue $scopeReason 'TierEvidence'))
                                reason                  = "$(Get-PropValue $scopeReason 'Reason')"
                                criticalityLevel        = "$(Get-PropValue $scopeReason 'CriticalityLevel')"
                                criticalityRules        = "$(Get-PropValue $scopeReason 'CriticalityRules')"
                                managedIdentityObjectId = "$(Get-PropValue $scopeReason 'ManagedIdentityObjectId')"
                                scopeCategory           = "$(Get-PropValue $scopeReason 'ScopeCategory')"
                                scopeType               = "$(Get-PropValue $scopeReason 'ScopeType')"
                                catalogDisplayName      = "$(Get-PropValue $scopeReason 'CatalogDisplayName')"
                                classifiedResources     = @(ConvertTo-ClassifiedResources (Get-PropValue $scopeReason 'ClassifiedResources'))
                                expandedScopePaths      = @(ConvertTo-StringArray (Get-PropValue $scopeReason 'ExpandedScopePaths'))
                                affectedObjects         = @(ConvertTo-ScopedObjects (Get-PropValue $scopeReason 'AffectedObjects'))
                                resolutionStatus        = "$(Get-PropValue $scopeReason 'ResolutionStatus')"
                                subscriptionScopes      = @(ConvertTo-StringArray (Get-PropValue $scopeReason 'SubscriptionScopes'))
                                tier0SubscriptionScopes = @(ConvertTo-StringArray (Get-PropValue $scopeReason 'Tier0SubscriptionScopes'))
                                tier1SubscriptionScopes = @(ConvertTo-StringArray (Get-PropValue $scopeReason 'Tier1SubscriptionScopes'))
                                azureScopeEvidence      = @(ConvertTo-AzureScopeEvidence (Get-PropValue $scopeReason 'AzureScopeEvidence'))
                                scopeRelation           = $(if ($roleSystem -eq 'DeviceManagement') { 'Assigned scope group' } elseif ("$(Get-PropValue $scopeReason 'ScopeId')".TrimEnd('/') -ieq $scopeId.TrimEnd('/')) { 'Exact' } else { 'Descendant resource' })
                            })
                    }
                }

                $assignments.Add([ordered]@{
                    roleAssignmentInstanceId              = if (Get-PropValue $ra 'RoleAssignmentInstanceId') { "$(Get-PropValue $ra 'RoleAssignmentInstanceId')" } else { Get-EntraOpsRoleAssignmentInstanceId -RoleSystem $roleSystem -RoleAssignment $ra }
                        roleAssignmentId                      = "$(Get-PropValue $ra 'RoleAssignmentId')"
                        roleAssignmentScopeId                 = "$(Get-PropValue $ra 'RoleAssignmentScopeId')"
                        roleAssignmentScopeName               = "$(Get-PropValue $ra 'RoleAssignmentScopeName')"
                        applicationScopes                     = @(ConvertTo-StringArray (Get-PropValue $ra 'AppScopeName'))
                        roleAssignmentType                    = "$(Get-PropValue $ra 'RoleAssignmentType')"
                        roleAssignmentSubType                 = $assignSub
                        roleAssignmentCondition               = "$(Get-PropValue $ra 'RoleAssignmentCondition')"
                        roleAssignmentConditionVersion        = "$(Get-PropValue $ra 'RoleAssignmentConditionVersion')"
                        roleDefinitionConditions              = @(@(Get-PropValue $ra 'RoleDefinitionConditions') | Where-Object { $null -ne $_ } | ForEach-Object {
                                [ordered]@{
                                    condition        = "$(Get-PropValue $_ 'Condition')"
                                    conditionVersion = "$(Get-PropValue $_ 'ConditionVersion')"
                                }
                            })
                        conditionEvaluation                   = ConvertTo-ConditionEvaluation (Get-PropValue $ra 'ConditionEvaluation')
                        pimManagedRole                        = [bool](Get-PropValue $ra 'PIMManagedRole')
                        pimAssignmentType                     = $pimType
                        roleDefinitionName                    = "$(Get-PropValue $ra 'RoleDefinitionName')"
                        roleDefinitionId                      = "$(Get-PropValue $ra 'RoleDefinitionId')"
                        roleType                              = "$(Get-PropValue $ra 'RoleType')"
                        roleIsPrivileged                      = [bool](Get-PropValue $ra 'RoleIsPrivileged')
                        eligibilityBy                         = Get-EligibilityBy -RoleSystem $roleSystem -PIMAssignmentType $pimType -RoleAssignmentSubType $assignSub
                        transitiveByObjectDisplayName         = "$(Get-PropValue $ra 'TransitiveByObjectDisplayName')"
                        transitiveByObjectId                  = "$(Get-PropValue $ra 'TransitiveByObjectId')"
                        transitiveByNestingObjectDisplayNames = @(ConvertTo-StringArray (Get-PropValue $ra 'TransitiveByNestingObjectDisplayNames'))
                        cloudSetSubscriptionScopes            = @(ConvertTo-StringArray (Get-PropValue $ra 'CloudSetSubscriptionScopes'))
                        scopeResolutionStatus                 = "$(Get-PropValue $ra 'ScopeResolutionStatus')"
                        classification                        = $raClassification
                        scopeReasoning                        = $scopeReasoning
                    })
            }

            $controlPlaneReasoning = [System.Collections.Generic.List[object]]::new()
            foreach ($reasoningObject in (Find-EntraOpsControlPlaneReasoning -ReasoningObjects $ControlPlaneReasoningDetails -ObjectId $objectId)) {
                $controlPlaneReasoning.Add([ordered]@{
                        classificationSources = @(ConvertTo-StringArray (Get-PropValue $reasoningObject 'ClassificationSource'))
                        classificationReasons = @(ConvertTo-ControlPlaneReasons (Get-PropValue $reasoningObject 'ClassificationReason'))
                    })
            }

            $objects.Add([ordered]@{
                    objectId                      = $objectId
                    objectTenantId                = "$(Get-PropValue $o 'ObjectTenantId')"
                    objectType                    = $objType
                    objectSubType                 = $objSubType
                    objectDisplayName             = $display
                    objectUserPrincipalName       = "$(Get-PropValue $o 'ObjectUserPrincipalName')"
                    # Where the object comes from (EntraOps 1.2.0 or later): for example CrossTenantSync, OnPremises or
                    # FirstPartyApplication, the tenant (of the application of a service principal, for Microsoft
                    # first-party apps) and the ID there.
                    originType                    = "$(Get-PropValue $o 'OriginType')"
                    originTenantId                = "$(Get-PropValue $o 'OriginTenantId')"
                    originId                      = "$(Get-PropValue $o 'OriginId')"
                    objectAdminTierLevel          = "$(Get-PropValue $o 'ObjectAdminTierLevel')"
                    objectAdminTierLevelName      = $objTierName
                    onPremSynchronized            = $onPremSync
                    syncSource                    = $(if ($onPremSync) { 'Hybrid' } else { 'Cloud-Only' })
                    outsideOfHomeTenant           = $outsideOfHomeTenant
                    restrictedManagementByAadRole = $byAadRole
                    restrictedManagementByRAG     = $byRAG
                    restrictedManagementByRMAU    = $byRMAU
                    restrictedManagement          = Get-RestrictedManagement -ObjectType $objType -ObjectSubType $objSubType -ByAadRole $byAadRole -ByRAG $byRAG -ByRMAU $byRMAU
                    roleSystem                    = $roleSystem
                    assignedAdministrativeUnits   = $adminUnits
                    associatedWorkAccount         = @(ConvertTo-StringArray (Get-PropValue $o 'AssociatedWorkAccount'))
                    ownedDevices                  = @(ConvertTo-StringArray (Get-PropValue $o 'OwnedDevices'))
                    # The object IDs of the PAW devices (AssociatedPawDeviceObjectId; AssociatedPawDevice for older exports).
                    associatedPawDevice           = @(Get-EntraOpsPawDeviceObjectId -Object $o)
                    controlPlaneReasoning         = $controlPlaneReasoning
                    classification                = $objClassification
                    roleAssignments               = $assignments
                })
        }
    }

    # PrivilegedType (workbook-style "origin" category of the privileged object):
    #   * Tenant Governance - foreign object whose role assignments ALL originate from a
    #                         Tenant Governance delegation (RoleAssignmentSubType
    #                         "Tenant Governance Delegated Admin"), or any other foreign
    #                         object that is neither a service principal nor a user.
    #   * Multi-Tenant Apps - service principal whose ObjectTenantId differs from the
    #                         home tenant (owning application lives in another tenant).
    #   * B2B Collaboration - external (guest) user whose ObjectTenantId differs from the
    #                         home tenant and who holds at least one role assignment that
    #                         is not a Tenant Governance delegation.
    #   * Local Identities  - everything else: local user, group, single-tenant application.
    # The home tenant is -TenantId when given, otherwise derived from the export itself:
    # the most common ObjectTenantId among objects that are neither guest users nor
    # Tenant Governance delegated admins (the OutsideOfHomeTenant flag of
    # Get-EntraOpsPrivilegedEntraObject is not part of the Save-EntraOpsPrivilegedEAMJson
    # export, so ObjectTenantId is the reliable signal for foreign objects).
    $tgSubType = 'Tenant Governance Delegated Admin'
    $homeTenantId = $TenantId
    if ([string]::IsNullOrWhiteSpace($homeTenantId)) {
        $tenantCounts = @{}
        foreach ($obj in $objects) {
            if (-not $obj.objectTenantId) { continue }
            if ($obj.objectType -eq 'user' -and $obj.objectSubType -eq 'Guest') { continue }
            if (@($obj.roleAssignments | Where-Object { $_.roleAssignmentSubType -eq $tgSubType }).Count -gt 0) { continue }
            $tenantCounts[$obj.objectTenantId] = [int]$tenantCounts[$obj.objectTenantId] + 1
        }
        $homeTenantId = ($tenantCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1).Key
    }
    foreach ($obj in $objects) {
        $isForeign = [bool]$obj.outsideOfHomeTenant -or
        ($homeTenantId -and $obj.objectTenantId -and $obj.objectTenantId -ne $homeTenantId)
        $privilegedType = 'Local Identities'
        if ($isForeign) {
            $nonTgAssignments = @($obj.roleAssignments | Where-Object { $_.roleAssignmentSubType -ne $tgSubType })
            if (@($obj.roleAssignments).Count -gt 0 -and $nonTgAssignments.Count -eq 0) {
                $privilegedType = 'Tenant Governance'
            } elseif ($obj.objectType -eq 'serviceprincipal') {
                $privilegedType = 'Multi-Tenant Apps'
            } elseif ($obj.objectType -eq 'user') {
                $privilegedType = 'B2B Collaboration'
            } else {
                $privilegedType = 'Tenant Governance'
            }
        }
        $obj['outsideOfHomeTenant'] = [bool]$isForeign
        $obj['privilegedType'] = $privilegedType
    }

    return , $objects
}
