<#
.SYNOPSIS
    Classify a list of Identity Governance access package resource role scopes (resources actually
    included in one or more access packages) against the classified RBAC systems and API permission
    definitions.

.DESCRIPTION
    Shared by Get-EntraOpsPrivilegedEamIdGov for scopes narrower than a full catalog resource
    inventory - a single access package, or the union of resource role scopes across every access
    package of a catalog for the Access package assignment manager role, which can only assign users
    to existing access packages and never gains access to catalog resources outside of them.

.PARAMETER ResourceRoleScopes
    Array of accessPackageResourceRoleScopes objects (expanded with accessPackageResourceRole and
    accessPackageResourceScope) to classify.

.PARAMETER FilterClassifiedRbacs
    RBAC systems (e.g. Azure, EntraID, DeviceManagement) whose pre-loaded classification cache should
    be used to classify AadGroup resource scopes.

.PARAMETER ClassificationCache
    Hashtable of pre-loaded classified objects, keyed by RBAC system name.

.PARAMETER ApiPermissionsClassLookup
    Hashtable lookup ("<originId>|<app role display name>" -> classification) for Graph API app roles.

.PARAMETER ApiResourceAppCategoryLookup
    Optional hashtable lookup (resource app id -> Category, e.g. "Microsoft.Graph") from the same
    Classification_ApiPermissions.json definitions, used to label OAuthApplication resource role
    scopes with a readable API name instead of the access package resource scope's own displayName
    (often just "Root"). Falls back to that displayName when not provided or the resource app id
    isn't found.

.PARAMETER EntraIdRolesClassification
    Classified EntraID role assignments (flattened RoleAssignments of the classified EntraID EAM
    data) used to classify DirectoryRole resource scopes at directory level.

.PARAMETER EntraRolesDefaultClassification
    Default classification of Entra ID directory roles (AzurePrivilegedIAM community repository)
    used as fallback when a directory role is not found in EntraIdRolesClassification.

.PARAMETER AzureScopeReasoning
    Parsed payload of ScopeReasoning_Azure.json (Tier0Scope/Tier1Scope), written by
    Update-EntraOpsClassificationControlPlaneScope, used to classify AzureResources resource
    scopes. Without it, Azure resources fail closed to ControlPlane (conservative) with a
    warning - the same fail-closed convention used by the IdGov-side scope classifier
    (Get-EntraOpsIdGovScopeClassification), so both outputs agree for the same catalog.

.PARAMETER ContextLabel
    Human-readable label of the scope being classified (access package or catalog id), used in
    warning messages only.

.PARAMETER WarningMessages
    Optional list to collect warning messages raised during classification.

.EXAMPLE
    Get-EntraOpsPrivilegedEamAccessPackageResourceRoleScopeClassification -ResourceRoleScopes $Scopes -FilterClassifiedRbacs $FilterClassifiedRbacs -ClassificationCache $ClassificationCache -ApiPermissionsClassLookup $ApiPermissionsClassLookup -ContextLabel "access package aaaaaaaa-0000-0000-0000-000000000000"
#>

function Get-EntraOpsPrivilegedEamAccessPackageResourceRoleScopeClassification {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$ResourceRoleScopes
        ,
        [Parameter(Mandatory = $true)]
        [array]$FilterClassifiedRbacs
        ,
        [Parameter(Mandatory = $true)]
        [hashtable]$ClassificationCache
        ,
        [Parameter(Mandatory = $true)]
        [hashtable]$ApiPermissionsClassLookup
        ,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [hashtable]$ApiResourceAppCategoryLookup
        ,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [array]$EntraIdRolesClassification
        ,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [array]$EntraRolesDefaultClassification
        ,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [psobject]$AzureScopeReasoning
        ,
        [Parameter(Mandatory = $true)]
        [string]$ContextLabel
        ,
        [Parameter(Mandatory = $false)]
        [System.Collections.Generic.List[psobject]]$WarningMessages
    )

    $MatchedClassification = New-Object System.Collections.Generic.List[psobject]

    foreach ($AssignedResourceRoleScope in $ResourceRoleScopes) {
        $ResourceRole = $AssignedResourceRoleScope.accessPackageResourceRole
        $ResourceScope = $AssignedResourceRoleScope.accessPackageResourceScope
        # A resource role added to an access package but not yet approved (e.g. by an Access package
        # assignment manager pending catalog owner approval) is still potential access - classify it,
        # but annotate the tagging so the pending state stays visible.
        $IsPending = ($null -ne $AssignedResourceRoleScope.PSObject.Properties['isPending'] -and $AssignedResourceRoleScope.isPending -eq $true)
        $PendingSuffix = if ($IsPending) { " [pending approval]" } else { "" }

        switch ($ResourceScope.originSystem) {

            'AadGroup' {
                Write-Verbose -Message "Classifying resource role scope $($ResourceScope.displayName) from origin system $($ResourceScope.originSystem) by $FilterClassifiedRbacs"
                foreach ($RbacSystem in $FilterClassifiedRbacs) {
                    if ($ClassificationCache.ContainsKey($RbacSystem)) {
                        $ObjectIndexKey = "${RbacSystem}:ByObjectId"
                        $ClassifiedObject = if ($ClassificationCache.ContainsKey($ObjectIndexKey)) {
                            @($ClassificationCache[$ObjectIndexKey][$ResourceScope.originId])
                        } else {
                            @($ClassificationCache[$RbacSystem] | Where-Object { $_.ObjectId -eq $ResourceScope.originId })
                        }
                        if ($null -ne $($ClassifiedObject.Classification)) {
                            $TaggedObjectDisplayName = $ClassifiedObject.ObjectDisplayName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
                            if ([string]::IsNullOrWhiteSpace($TaggedObjectDisplayName)) { $TaggedObjectDisplayName = $ResourceScope.displayName }
                            $MatchedRbacClassification = $ClassifiedObject.Classification
                            foreach ($ClassItem in $MatchedRbacClassification) {
                                # Clone before tagging - $ClassItem is a live reference into $ClassificationCache,
                                # which is loaded once and reused for every catalog/access package scope in this
                                # run. Mutating it in place would permanently rewrite the same cached object every
                                # time any other scope's resource happens to match it.
                                $TaggedClassItem = $ClassItem.PSObject.Copy()
                                $TaggedClassItem | Add-Member -NotePropertyName "TaggedBy"                   -NotePropertyValue "AssignedAadGroup"          -Force
                                $TaggedClassItem | Add-Member -NotePropertyName "TaggedByObjectIds"          -NotePropertyValue @($ResourceScope.originId)      -Force
                                $TaggedClassItem | Add-Member -NotePropertyName "TaggedByObjectDisplayNames" -NotePropertyValue @("$TaggedObjectDisplayName$PendingSuffix") -Force
                                $TaggedClassItem | Add-Member -NotePropertyName "TaggedByRoleSystem"         -NotePropertyValue $RbacSystem                    -Force
                                $MatchedClassification.Add($TaggedClassItem) | Out-Null
                            }
                        } else {
                            Write-Verbose "No classification for $($ResourceScope.displayName) $($ResourceScope.id) found in $RbacSystem"
                        }
                    }
                }
            } 'OAuthApplication' {
                Write-Verbose -Message "Classifying resource role $($ResourceRole.displayName) of resource $($ResourceScope.displayName) by Graph API App roles"
                $lookupKey = "$($ResourceScope.originId)|$($ResourceRole.displayName)"
                $AppRoleMatch = $ApiPermissionsClassLookup[$lookupKey]

                # $ResourceScope.displayName is the access package resource SCOPE's name (e.g. "Root"
                # for the root scope of the resource application), not the resource application
                # itself - resolve the resource app's Category from the same classification
                # definitions (Classification_ApiPermissions.json) instead, falling back to the
                # scope's own displayName if the resource app id isn't in there.
                $ResourceAppDisplayName = $null
                if ($null -ne $ApiResourceAppCategoryLookup) {
                    $ResourceAppDisplayName = $ApiResourceAppCategoryLookup[$ResourceScope.originId]
                }
                if ([string]::IsNullOrEmpty($ResourceAppDisplayName)) {
                    $ResourceAppDisplayName = $ResourceScope.displayName
                }

                if ($null -ne $AppRoleMatch) {
                    $Classification = [PSCustomObject]@{
                        'AdminTierLevel'             = $AppRoleMatch.EAMTierLevelTagValue
                        'AdminTierLevelName'         = $AppRoleMatch.EAMTierLevelName
                        'Service'                    = $AppRoleMatch.Service
                        'TaggedBy'                   = "AssignedOAuthApplicationResource"
                        'TaggedByObjectIds'          = @($ResourceRole.originId)
                        'TaggedByObjectDisplayNames' = @("$($ResourceRole.displayName)$PendingSuffix")
                        'TaggedByRoleSystem'         = $ResourceAppDisplayName
                    }
                } else {
                    if ($null -ne $WarningMessages) {
                        $WarningMessages.Add([PSCustomObject]@{
                                Type    = "Unclassified App Role"
                                Message = "No classification for app role $($ResourceRole.displayName) assigned to resource $($ResourceScope.displayName) in $ContextLabel"
                                Target  = $ContextLabel
                            })
                    }
                    $Classification = [PSCustomObject]@{
                        'AdminTierLevel'             = "Unclassified"
                        'AdminTierLevelName'         = "Unclassified"
                        'Service'                    = "Unclassified"
                        'TaggedBy'                   = "AssignedOAuthApplicationResource"
                        'TaggedByObjectIds'          = @($ResourceRole.originId)
                        'TaggedByObjectDisplayNames' = @("$($ResourceRole.displayName)$PendingSuffix")
                        'TaggedByRoleSystem'         = $ResourceAppDisplayName
                    }
                }
                $MatchedClassification.Add($Classification) | Out-Null
            } 'AadApplication' {
                $Classifications = @(Get-EntraOpsAadApplicationClassification -ServicePrincipalObjectId $ResourceScope.originId -ClassificationCache $ClassificationCache -DisplayName $ResourceScope.displayName -ContextLabel $ContextLabel -WarningMessages $WarningMessages)
                foreach ($ClassItem in $Classifications) {
                    $TaggedClassItem = $ClassItem.PSObject.Copy()
                    $TaggedClassItem | Add-Member -NotePropertyName "TaggedBy"                   -NotePropertyValue "AssignedAadApplicationResource" -Force
                    $TaggedClassItem | Add-Member -NotePropertyName "TaggedByObjectIds"          -NotePropertyValue @($ResourceScope.originId)         -Force
                    $TaggedClassItem | Add-Member -NotePropertyName "TaggedByObjectDisplayNames" -NotePropertyValue @("$($ResourceScope.displayName) ($($ResourceRole.displayName))$PendingSuffix") -Force
                    # ClassificationSource is internal to Get-EntraOpsAadApplicationClassification and is not saved.
                    $ClassItemSource = if ($null -ne $ClassItem.PSObject.Properties['ClassificationSource']) { "$($ClassItem.ClassificationSource)" } else { '' }
                    $TaggedClassItem.PSObject.Properties.Remove('ClassificationSource')
                    $TaggedClassItem | Add-Member -NotePropertyName "TaggedByRoleSystem" -NotePropertyValue $(if ($ClassItemSource -and $ClassItemSource -notin 'NoPermissions', 'ResourceAppsMissing') { $ClassItemSource } else { 'ResourceApps' }) -Force
                    $MatchedClassification.Add($TaggedClassItem) | Out-Null
                }
            } 'SharePointOnline' {
                $SharePointTier = Resolve-EntraOpsSharePointOnlineRoleTier -RoleDisplayName $ResourceRole.displayName -RoleOriginId "$($ResourceRole.originId)"
                if ($SharePointTier.IsFallback -and $null -ne $WarningMessages) {
                    $WarningMessages.Add([pscustomobject]@{
                            Type    = "Unknown SharePoint Role"
                            Message = "SharePoint role '$($ResourceRole.displayName)' (originId '$($ResourceRole.originId)') in $ContextLabel is not recognized - treated as ManagementPlane (conservative)."
                            Target  = $ContextLabel
                        })
                }
                $MatchedClassification.Add([pscustomobject]@{
                        AdminTierLevel             = $SharePointTier.AdminTierLevel
                        AdminTierLevelName         = $SharePointTier.AdminTierLevelName
                        Service                    = "SharePoint Online"
                        TaggedBy                   = "AssignedSharePointOnlineResource"
                        TaggedByObjectIds          = @($ResourceScope.originId)
                        TaggedByObjectDisplayNames = @("$($ResourceScope.displayName) ($($ResourceRole.displayName))$PendingSuffix")
                        TaggedByRoleSystem         = "SharePointOnline"
                    }) | Out-Null
            } 'DirectoryRole' {
                # Directory role delegated via an access package: the resource scope's originId is the
                # role definition id (the expanded role object only carries the membership type, e.g.
                # "Active Member"). Classified like catalog-level directory roles - EntraID EAM data at
                # directory scope first, then the community default classification.
                Write-Verbose -Message "Classifying resource role scope $($ResourceScope.displayName) ($($ResourceScope.originId)) from origin system DirectoryRole by EntraID"
                $RoleDisplayName = $ResourceScope.displayName
                $Classification = $null
                $MatchedRole = if ($ClassificationCache.ContainsKey("EntraIDRoles:ByDefinitionId")) {
                    $ClassificationCache["EntraIDRoles:ByDefinitionId"][$ResourceScope.originId]
                } else {
                    @($EntraIdRolesClassification) | Where-Object { $_.RoleAssignmentScopeId -eq "/" -and $_.RoleDefinitionId -eq $ResourceScope.originId } | Select-Object -First 1
                }
                if ($null -ne $MatchedRole) {
                    if (-not [string]::IsNullOrEmpty($MatchedRole.RoleDefinitionName)) { $RoleDisplayName = $MatchedRole.RoleDefinitionName }
                    $Classification = $MatchedRole.Classification
                }

                if ($null -eq $Classification) {
                    if ($null -ne $WarningMessages) {
                        $WarningMessages.Add([PSCustomObject]@{
                                Type    = "Default Classification Fallback"
                                Message = "No classification for directory role $($ResourceScope.originId) assigned in $ContextLabel found in EntraID! Fallback to default."
                                Target  = $ContextLabel
                            })
                    }
                    $MatchedDefaultRole = @($EntraRolesDefaultClassification) | Where-Object { $_.RoleId -eq $ResourceScope.originId } | Select-Object -First 1
                    if ($null -ne $MatchedDefaultRole -and $null -ne $MatchedDefaultRole.RolePermissions) {
                        if (-not [string]::IsNullOrEmpty($MatchedDefaultRole.RoleName)) { $RoleDisplayName = $MatchedDefaultRole.RoleName }
                        $DefaultRoleClassification = $MatchedDefaultRole.RolePermissions | Select-Object -Unique EAMTierLevelTagValue, EAMTierLevelName, Category
                        $Classification = $DefaultRoleClassification | ForEach-Object {
                            [PSCustomObject]@{
                                'AdminTierLevel'     = $_.EAMTierLevelTagValue
                                'AdminTierLevelName' = $_.EAMTierLevelName
                                'Service'            = $_.Category | Select-Object -First 1
                            }
                        }
                    }
                }
                if ($null -eq $Classification.AdminTierLevel) {
                    if ($null -ne $WarningMessages) {
                        $WarningMessages.Add([PSCustomObject]@{
                                Type    = "Unclassified Resource"
                                Message = "No default classification for directory role $($ResourceScope.originId) assigned in $ContextLabel found!"
                                Target  = $ContextLabel
                            })
                    }
                    $Classification = [PSCustomObject]@{
                        'AdminTierLevel'     = "Unclassified"
                        'AdminTierLevelName' = "Unclassified"
                        'Service'            = "Unclassified"
                    }
                }
                foreach ($ClassItem in @($Classification)) {
                    $TaggedClassItem = $ClassItem.PSObject.Copy()
                    $TaggedClassItem | Add-Member -NotePropertyName "TaggedBy"                   -NotePropertyValue "AssignedDirectoryRoleResource" -Force
                    $TaggedClassItem | Add-Member -NotePropertyName "TaggedByObjectIds"          -NotePropertyValue @($ResourceScope.originId)      -Force
                    $TaggedClassItem | Add-Member -NotePropertyName "TaggedByObjectDisplayNames" -NotePropertyValue @("$RoleDisplayName$PendingSuffix") -Force
                    $TaggedClassItem | Add-Member -NotePropertyName "TaggedByRoleSystem"         -NotePropertyValue "EntraID"                       -Force
                    $MatchedClassification.Add($TaggedClassItem) | Out-Null
                }
            } 'AzureResources' {
                # Azure resource (subscription, resource group, resource) delegated via an access
                # package: classified by the Tier0/Tier1 resource scope buckets from
                # ScopeReasoning_Azure.json (a role at the onboarded ARM scope reaches every resource
                # beneath it). The specific Azure role is kept visible in the tagging display name.
                Write-Verbose -Message "Classifying resource role scope $($ResourceScope.displayName) ($($ResourceScope.originId)) from origin system AzureResources by Azure resource scope reasoning"
                $AzureScopeTier = Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId $ResourceScope.originId -AzureScopeReasoning $AzureScopeReasoning
                if ($null -eq $AzureScopeTier) {
                    if ($null -ne $WarningMessages) {
                        $WarningMessages.Add([PSCustomObject]@{
                                Type    = "Unresolved Azure Scope"
                                Message = "Azure scope $($ResourceScope.originId) assigned in $ContextLabel could not be evaluated - ScopeReasoning_Azure.json not available. Run Update-EntraOpsClassificationControlPlaneScope for Azure first. Treated as ControlPlane (conservative)."
                                Target  = $ContextLabel
                            })
                    }
                    $AzureScopeTier = [PSCustomObject]@{ AdminTierLevel = "0"; AdminTierLevelName = "ControlPlane"; MatchedScope = $null }
                }
                $RoleLabel = if ([string]::IsNullOrEmpty($ResourceRole.displayName)) { "" } else { " ($($ResourceRole.displayName))" }
                $Classification = [PSCustomObject]@{
                    'AdminTierLevel'             = $AzureScopeTier.AdminTierLevel
                    'AdminTierLevelName'         = $AzureScopeTier.AdminTierLevelName
                    'Service'                    = "Azure Resources"
                    'TaggedBy'                   = "AssignedAzureResourcesResource"
                    'TaggedByObjectIds'          = @($ResourceScope.originId)
                    'TaggedByObjectDisplayNames' = @("$($ResourceScope.displayName)$RoleLabel$PendingSuffix")
                    'TaggedByRoleSystem'         = "Azure"
                }
                $MatchedClassification.Add($Classification) | Out-Null
            } default {
                if ($null -ne $WarningMessages) {
                    $WarningMessages.Add([PSCustomObject]@{
                            Type    = "Unknown Origin System"
                            Message = "Origin system $($ResourceScope.originSystem) not supported for access package classification!"
                            Target  = $ResourceScope.originSystem
                        })
                }
            }
        }
    }

    return $MatchedClassification
}
