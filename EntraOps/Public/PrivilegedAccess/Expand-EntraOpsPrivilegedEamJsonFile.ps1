<#
.SYNOPSIS
    Expand JSON classification file to object

.DESCRIPTION
    Read JSON classification file and expand them to a object with all role actions from role definition (including tiering).

.PARAMETER FilePath
    Path to the JSON file which should be expanded.

.EXAMPLE
    Expand classification of Entra ID roles to get a list of all role actions and their classification
    Expand-EntraOpsPrivilegedEAMJsonFile -FilePath ".\Classification\EntraID\Classification_AadResources.json"

#>

function Expand-EntraOpsPrivilegedEAMJsonFile {

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $True)]
        [System.String]$FilePath
    )

    $JSON = Get-Content -Path $FilePath -Raw | ConvertFrom-Json -Depth 10

    # 1) Expand TierLevelDefinition
    $TierLevelDefinitions = [System.Collections.Generic.List[object]]::new()
    foreach ($EAMTierLevel in $JSON) {
        foreach ($Definition in $EAMTierLevel.TierLevelDefinition) {
            $null = $TierLevelDefinitions.Add(
                [PSCustomObject]@{
                    'EAMTierLevelName'                = $EAMTierLevel.EAMTierLevelName
                    'EAMTierLevelTagValue'            = $EAMTierLevel.EAMTierLevelTagValue
                    'Category'                        = $Definition.Category
                    'Service'                         = $Definition.Service
                    'RoleAssignmentScopeName'         = $Definition.RoleAssignmentScopeName
                    'ExcludedRoleAssignmentScopeName' = $Definition.ExcludedRoleAssignmentScopeName
                    'RoleDefinitionActions'           = $Definition.RoleDefinitionActions
                    'ExcludedRoleDefinitionActions'   = $Definition.ExcludedRoleDefinitionActions
                }
            )
        }
    }

    # 2) Expand RoleAssignmentScopeName
    $TierLevelRoleScopes = [System.Collections.Generic.List[object]]::new()
    foreach ($TierLevelDefinition in $TierLevelDefinitions) {
        foreach ($ScopeName in $TierLevelDefinition.RoleAssignmentScopeName) {
            $null = $TierLevelRoleScopes.Add(
                [PSCustomObject]@{
                    'EAMTierLevelName'                = $TierLevelDefinition.EAMTierLevelName
                    'EAMTierLevelTagValue'            = $TierLevelDefinition.EAMTierLevelTagValue
                    'Category'                        = $TierLevelDefinition.Category
                    'Service'                         = $TierLevelDefinition.Service
                    'RoleAssignmentScopeName'         = $ScopeName
                    'ExcludedRoleAssignmentScopeName' = $TierLevelDefinition.ExcludedRoleAssignmentScopeName
                    'RoleDefinitionActions'           = $TierLevelDefinition.RoleDefinitionActions
                    'ExcludedRoleDefinitionActions'   = $TierLevelDefinition.ExcludedRoleDefinitionActions
                }
            )
        }
    }

    # 3) Expand RoleDefinitionActions
    $TierLevelRoleScopesWithRoleActions = [System.Collections.Generic.List[object]]::new()
    foreach ($TierLevelRoleScope in $TierLevelRoleScopes) {
        foreach ($RoleAction in $TierLevelRoleScope.RoleDefinitionActions) {
            $null = $TierLevelRoleScopesWithRoleActions.Add(
                [PSCustomObject]@{
                    'EAMTierLevelName'                = $TierLevelRoleScope.EAMTierLevelName
                    'EAMTierLevelTagValue'            = $TierLevelRoleScope.EAMTierLevelTagValue
                    'Category'                        = $TierLevelRoleScope.Category
                    'Service'                         = $TierLevelRoleScope.Service
                    'RoleAssignmentScopeName'         = $TierLevelRoleScope.RoleAssignmentScopeName
                    'ExcludedRoleAssignmentScopeName' = $TierLevelRoleScope.ExcludedRoleAssignmentScopeName
                    'RoleDefinitionActions'           = $RoleAction
                    'ExcludedRoleDefinitionActions'   = $TierLevelRoleScope.ExcludedRoleDefinitionActions
                }
            )
        }
    }

    $TierLevelRoleScopesWithRoleActions
}