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

    $JSON = Get-Content -Path $FilePath | ConvertFrom-Json -Depth 10
    $TierLevelDefinitions = @()
    foreach ($EAMTierLevel in $JSON) {
        $TierLevelDefinitions += $EAMTierLevel | ForEach-Object {
            $_.TierLevelDefinition | ForEach-Object {
                [PSCustomObject]@{
                    'EAMTierLevelName'                = $EAMTierLevel.EAMTierLevelName
                    'EAMTierLevelTagValue'            = $EAMTierLevel.EAMTierLevelTagValue
                    'Category'                        = $_.Category
                    'Service'                         = $_.Service
                    'RoleAssignmentScopeName'         = $_.RoleAssignmentScopeName
                    'ExcludedRoleAssignmentScopeName' = $_.ExcludedRoleAssignmentScopeName
                    'RoleDefinitionActions'           = $_.RoleDefinitionActions
                    'ExcludedRoleDefinitionActions'   = $_.ExcludedRoleDefinitionActions
                }
            }
        }
    }

    $TierLevelRoleScopes = @()
    foreach ($TierLevelDefinition in $TierLevelDefinitions) {
        $TierLevelRoleScopes += $TierLevelDefinition.RoleAssignmentScopeName | ForEach-Object {
            [PSCustomObject]@{
                'EAMTierLevelName'                = $TierLevelDefinition.EAMTierLevelName
                'EAMTierLevelTagValue'            = $TierLevelDefinition.EAMTierLevelTagValue
                'Category'                        = $TierLevelDefinition.Category
                'Service'                         = $TierLevelDefinition.Service
                'RoleAssignmentScopeName'         = $_
                'ExcludedRoleAssignmentScopeName' = $TierLevelDefinition.ExcludedRoleAssignmentScopeName
                'RoleDefinitionActions'           = $TierLevelDefinition.RoleDefinitionActions
                'ExcludedRoleDefinitionActions'   = $TierLevelDefinition.ExcludedRoleDefinitionActions
            }
        }
    }

    $TierLevelRoleScopesWithRoleActions = $null
    foreach ($TierLevelRoleScope in $TierLevelRoleScopes) {
        $TierLevelRoleScopesWithRoleActions += $TierLevelRoleScope.RoleDefinitionActions | ForEach-Object {
            [PSCustomObject]@{
                'EAMTierLevelName'                = $TierLevelRoleScope.EAMTierLevelName
                'EAMTierLevelTagValue'            = $TierLevelRoleScope.EAMTierLevelTagValue
                'Category'                        = $TierLevelRoleScope.Category
                'Service'                         = $TierLevelRoleScope.Service
                'RoleAssignmentScopeName'         = $TierLevelRoleScope.RoleAssignmentScopeName
                'ExcludedRoleAssignmentScopeName' = $TierLevelRoleScope.ExcludedRoleAssignmentScopeName
                'RoleDefinitionActions'           = $_
                'ExcludedRoleDefinitionActions'   = $TierLevelRoleScope.ExcludedRoleDefinitionActions
            }
        }
    }
    $TierLevelRoleScopesWithRoleActions
}