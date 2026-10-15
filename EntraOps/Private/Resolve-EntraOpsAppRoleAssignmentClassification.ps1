function Resolve-EntraOpsAppRoleAssignmentClassification {
    <#
    .SYNOPSIS
        Attaches the classification from Classification_ApiPermissions.json to app role and delegated permission assignments.
    .DESCRIPTION
        Matches every distinct permission (RoleDefinitionId, RoleAssignmentScopeId, RoleDefinitionName, RoleType,
        ResourceAppId) against the expanded classification definitions and attaches the result to each assignment.
        The lookup uses the same full key as the matching step: delegated permissions can have no RoleDefinitionId,
        and an app role and a delegated scope can share an ID, so RoleDefinitionId and scope alone are not unique.
    .PARAMETER AppRoleAssignments
        App role / delegated permission assignments from Get-EntraOpsPrivilegedAppRoles.
    .PARAMETER ClassificationDefinitions
        Flattened classification entries from Expand-EntraOpsPrivilegedEAMJsonFile.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$AppRoleAssignments,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$ClassificationDefinitions
    )

    $GetClassificationKey = {
        param($Assignment)
        @(
            "$($Assignment.RoleAssignmentScopeId)"
            "$($Assignment.RoleDefinitionId)"
            (@($Assignment.RoleDefinitionName) -join ',')
            "$($Assignment.RoleType)"
            "$($Assignment.ResourceAppId)"
        ) -join '|'
    }

    $AppRoleClassificationsByJSON = @()
    $AppRoleClassificationsByJSON += foreach ($AppRoleAssignment in $AppRoleAssignments | Select-Object -Unique RoleDefinitionId, RoleAssignmentScopeId, RoleDefinitionName, RoleType, ResourceAppId) {
        # Check if role action and scope exists in JSON classification, filtered by ResourceAppId and ResourceScope
        $ClassifiedWithMatchedActions = @()
        foreach ($RoleDefinitionName in $AppRoleAssignment.RoleDefinitionName) {
            $ClassifiedWithMatchedActions += $ClassificationDefinitions | Where-Object {
                ($_.RoleDefinitionActions -eq $RoleDefinitionName -or $RoleDefinitionName -like $_.RoleDefinitionActions) -and
                $_.ExcludedRoleDefinitionActions -ne $RoleDefinitionName -and
                (-not $_.ResourceAppId -or $_.ResourceAppId -eq $AppRoleAssignment.ResourceAppId) -and
                ($_.ResourceScope -eq "All" -or
                ($AppRoleAssignment.RoleType -eq "Application" -and $_.ResourceScope -eq "Application") -or
                ($AppRoleAssignment.RoleType -eq "Delegated" -and $_.ResourceScope -eq "Delegation"))
            } | ForEach-Object {
                [PSCustomObject]@{
                    EAMTierLevelName     = $_.EAMTierLevelName
                    EAMTierLevelTagValue = $_.EAMTierLevelTagValue
                    Service              = $_.Service
                    MatchedAction        = $RoleDefinitionName
                }
            }
        }
        $Classification = @()
        if ($ClassifiedWithMatchedActions.Count -gt 0) {
            $UniqueClassifications = $ClassifiedWithMatchedActions | Select-Object -Unique EAMTierLevelName, EAMTierLevelTagValue, Service
            $Classification += $UniqueClassifications | ForEach-Object {
                $UniqueClass = $_
                $MatchedEntries = @($ClassifiedWithMatchedActions | Where-Object {
                        $_.EAMTierLevelName -eq $UniqueClass.EAMTierLevelName -and
                        $_.EAMTierLevelTagValue -eq $UniqueClass.EAMTierLevelTagValue -and
                        $_.Service -eq $UniqueClass.Service
                    })
                [array]$MatchedActions = @($MatchedEntries | Select-Object -ExpandProperty MatchedAction | Select-Object -Unique)
                [PSCustomObject]@{
                    'AdminTierLevel'             = $UniqueClass.EAMTierLevelTagValue
                    'AdminTierLevelName'         = $UniqueClass.EAMTierLevelName
                    'Service'                    = $UniqueClass.Service
                    'MatchedActions'             = if ($MatchedActions.Count -gt 0) { , @($MatchedActions) } else { $null }
                    'ScopedObjects'              = $null
                    'TaggedBy'                   = "JSONwithAction"
                    'TaggedByObjectIds'          = $null
                    'TaggedByObjectDisplayNames' = $null
                    'TaggedByRoleSystem'         = "ResourceApps"
                }
            }
        } else {
            $Classification += [PSCustomObject]@{
                'AdminTierLevel'             = "Unclassified"
                'AdminTierLevelName'         = "Unclassified"
                'Service'                    = "Unclassified"
                'MatchedActions'             = $null
                'ScopedObjects'              = $null
                'TaggedBy'                   = "JSONwithAction"
                'TaggedByObjectIds'          = $null
                'TaggedByObjectDisplayNames' = $null
                'TaggedByRoleSystem'         = "ResourceApps"
            }
        }

        [PSCustomObject]@{
            'ClassificationKey' = & $GetClassificationKey $AppRoleAssignment
            'Classification'    = $Classification
        }
    }

    $ClassificationsByKey = @{}
    foreach ($ClassifiedPermission in $AppRoleClassificationsByJSON) {
        if (-not $ClassificationsByKey.ContainsKey($ClassifiedPermission.ClassificationKey)) {
            $ClassificationsByKey[$ClassifiedPermission.ClassificationKey] = [System.Collections.Generic.List[object]]::new()
        }
        foreach ($ClassItem in @($ClassifiedPermission.Classification)) {
            $ClassificationsByKey[$ClassifiedPermission.ClassificationKey].Add($ClassItem)
        }
    }

    foreach ($AppRoleAssignment in $AppRoleAssignments) {
        $AppRoleAssignment = $AppRoleAssignment | Select-Object -ExcludeProperty Classification
        $Classification = @()
        $ClassificationCollection = $ClassificationsByKey[(& $GetClassificationKey $AppRoleAssignment)]
        if (@($ClassificationCollection).Count -gt 0) {
            $Classification += $ClassificationCollection | Sort-Object AdminTierLevel, AdminTierLevelName, Service, TaggedBy | Select-Object -Unique AdminTierLevel, AdminTierLevelName, MatchedActions, ScopedObjects, Service, TaggedBy, TaggedByObjectIds, TaggedByObjectDisplayNames, TaggedByRoleSystem, Justification
        }
        $AppRoleAssignment | Add-Member -NotePropertyName "Classification" -NotePropertyValue $Classification -Force
        $AppRoleAssignment
    }
}
