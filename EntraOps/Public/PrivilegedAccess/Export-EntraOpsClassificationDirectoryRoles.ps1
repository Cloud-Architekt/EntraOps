<#
.SYNOPSIS
    Get a JSON file with all classified Directory in Entra ID.

.DESCRIPTION
    Read JSON classification file and match directory roles in Entra ID tenant to export it as JSON.

.PARAMETER SingleClassification
    Export only the highest tier level classification for each directory role.

.PARAMETER FilteredConditions
    Filtered conditions to exclude from the classification. Default is '$ResourceIsSelf', '$SubjectIsOwner' which are additional permissions as object owner or resource self and not part of the Enterprise Access Model.

.PARAMETER IncludeCustomRoles
    Include custom directory roles in the export. Default is $False.

.PARAMETER ShowOnly
    Show the output in the console instead of exporting it to a file.

.PARAMETER ExportFile
    Path to the JSON file which should be exported.

.EXAMPLE
    Export all classified built-in and custom Directory Roles with a single classification based on Enterprise Access Model
    to the file path ".\Classification\Classification_EntraIdDirectoryRoles.json".
    By default, additional permissions as object owner or resource self will be excluded.
    Export-EntraOpsClassificationAppRoles -IncludeCustomRoles $True
#>

function Export-EntraOpsClassificationDirectoryRoles {

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        $SingleClassification = $True
        ,
        [Parameter(Mandatory = $false)]
        $FilteredConditions = @('$ResourceIsSelf', '$SubjectIsOwner')
        ,
        [Parameter(Mandatory = $false)]
        $IncludeCustomRoles = $False
        ,
        [Parameter(Mandatory = $false)]
        $Exportfile = ".\Classification\Classification_EntraIdDirectoryRoles.json"
        ,
        [Parameter(Mandatory = $false)]
        [bool]$ShowOnly = $false           
    )

    # Get EntraOps Classification
    # Check if classification file custom and/or template file exists, choose custom template for tenant if available
    $ClassificationFileName = "Classification_AadResources.json"
    if (Test-Path -Path "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)") {
        $AadClassificationFilePath = "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)"
    }
    elseif (Test-Path -Path "$($DefaultFolderClassification)/Templates/$($ClassificationFileName)") {
        $AadClassificationFilePath = "$($DefaultFolderClassification)/Templates/$($ClassificationFileName)"
    }
    else {
        Write-Error "Classification file $($ClassificationFileName) not found in $($DefaultFolderClassification). Please run Update-EntraOpsClassificationFiles to download the latest classification files from AzurePrivilegedIAM repository."
    }
    $Classification = Get-Content -Path $($AadClassificationFilePath) | ConvertFrom-Json -Depth 10

    # Single Classification (highest tier level only)
    Write-Output "Query directory role templates for mapping ID to name and further details"
    $DirectoryRoleDefinitions = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions").value | select-object displayName, templateId, isBuiltin, isPrivileged, rolePermissions

    if ($IncludeCustomRoles -eq $False) {
        $DirectoryRoleDefinitions = $DirectoryRoleDefinitions | where-object { $_.isBuiltin -eq "True" }
    }

    $DirectoryRoles = $DirectoryRoleDefinitions | foreach-object {

        $DirectoryRolePermissions = ($_.RolePermissions | Where-Object { $_.condition -notin $FilteredConditions }).allowedResourceActions
        $ClassifiedDirectoryRolePermissions = foreach ($RolePermission in $DirectoryRolePermissions) {
            # Apply Classification
            $EntraRolePermissionTierLevelClassification = $Classification | where-object { $_.TierLevelDefinition.RoleDefinitionActions -contains $($RolePermission) } | select-object EAMTierLevelName, EAMTierLevelTagValue
            $EntraRolePermissionServiceClassification = $Classification | select-object -ExpandProperty TierLevelDefinition | where-object { $_.RoleDefinitionActions -contains $($RolePermission) } | select-object Service

            if ($EntraRolePermissionTierLevelClassification.Count -gt 1 -and $EntraRolePermissionServiceClassification.Count -gt 1) {
                Write-Warning "Multiple Tier Level Classification found for $($RolePermission)"
            }

            if ($null -eq $EntraRolePermissionTierLevelClassification) {
                $EntraRolePermissionTierLevelClassification = [PSCustomObject]@{
                    "EAMTierLevelName"     = "Unclassified"
                    "EAMTierLevelTagValue" = "Unclassified"
                }
            }

            if ($null -eq $EntraRolePermissionServiceClassification) {
                $EntraRolePermissionServiceClassification = [PSCustomObject]@{
                    "Service" = "Unclassified"
                }
            }

            [PSCustomObject]@{
                "AuthorizedResourceAction" = $RolePermission
                "Category"                 = $EntraRolePermissionServiceClassification.Service
                "EAMTierLevelName"         = $EntraRolePermissionTierLevelClassification.EAMTierLevelName
                "EAMTierLevelTagValue"     = $EntraRolePermissionTierLevelClassification.EAMTierLevelTagValue
            }
        }
        $ClassifiedDirectoryRolePermissions = $ClassifiedDirectoryRolePermissions | sort-object EAMTierLevelTagValue, Category, AuthorizedResourceAction

        if ($SingleClassification -eq $True) {
            $RoleDefinitionClassification = ($ClassifiedDirectoryRolePermissions | select-object -ExcludeProperty AuthorizedResourceAction, Category -Unique | Sort-Object EAMTierLevelTagValue | select-object -First 1)
        }
        else {
            $FilteredRoleClassifications = ($ClassifiedDirectoryRolePermissions | select-object -ExcludeProperty AuthorizedResourceAction -Unique | Sort-Object EAMTierLevelTagValue )
            $RoleDefinitionClassification = [System.Collections.Generic.List[object]]::new()
            $RoleDefinitionClassification.Add($FilteredRoleClassifications)
        }

        [PSCustomObject]@{
            "RoleId"          = $_.templateId
            "RoleName"        = $_.displayName
            "isPrivileged"    = $_.isPrivileged
            "RolePermissions" = $ClassifiedDirectoryRolePermissions
            "Classification"  = $RoleDefinitionClassification
        }
    }

    $DirectoryRoles = $DirectoryRoles | sort-object RoleName
    
    if ($ShowOnly -eq $true) {
        $DirectoryRoles
    }
    else {
        $DirectoryRoles | ConvertTo-Json -Depth 10 | Out-File $ExportFile -Force
    }    
}
