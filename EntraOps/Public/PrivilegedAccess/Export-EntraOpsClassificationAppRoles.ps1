<#
.SYNOPSIS
    Get a JSON file with all classified App Roles in Entra ID.

.DESCRIPTION
    Read JSON classification file and match app roles in Entra ID tenant to export it as JSON.

.PARAMETER IncludeAuthorizedApiCalls
    Include authorized Graph API calls for each App Role.

.PARAMETER ExportFile
    Path to the JSON file which should be exported.

.EXAMPLE
    Export all classified App Roles with list of authorized Graph API calls to the path "Classification\Classification_AppRoles.json"
    Export-EntraOpsClassificationAppRoles -IncludeAuthorizedApiCalls $true
#>

function Export-EntraOpsClassificationAppRoles {

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        $IncludeAuthorizedApiCalls = $False
        ,
        [Parameter(Mandatory = $false)]
        $ExportFile = ".\Classification\Classification_AppRoles.json"
    )

    # Get EntraOps Classification
    # Check if classification file custom and/or template file exists, choose custom template for tenant if available
    $ClassificationFileName = "Classification_AppRoles.json"
    if (Test-Path -Path "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)") {
        $AppRolesClassificationFilePath = "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)"
    }
    elseif (Test-Path -Path "$($DefaultFolderClassification)/Templates/$($ClassificationFileName)") {
        $AppRolesClassificationFilePath = "$($DefaultFolderClassification)/Templates/$($ClassificationFileName)"
    }
    else {
        Write-Error "Classification file $($ClassificationFileName) not found in $($DefaultFolderClassification). Please run Update-EntraOpsClassificationFiles to download the latest classification files from AzurePrivilegedIAM repository."
    }
    $Classification = Get-Content -Path $(AppRolesClassificationFilePath) | ConvertFrom-Json -Depth 10

    # Get Graph API actions
    if ($IncludeAuthorizedApiCalls -eq $true) {
        $AllAuthorizedApiCalls = Invoke-WebRequest -Method GET -Uri "https://raw.githubusercontent.com/merill/graphpermissions.github.io/main/permissions.csv" | ConvertFrom-Csv
    }

    # Get information about App Role Provider
    $AppRoleProviderIds = @("00000003-0000-0000-c000-000000000000")
    $AppRoleProviders = foreach ($AppRoleProviderId in $AppRoleProviderIds) {
        (Invoke-EntraOpsMsGraphQuery -Uri "/beta/servicePrincipals?`$filter=appId eq '$AppRoleProviderId'" -OutputType PSObject) | select-object appId, appRoles
    }

    $AppRoles = $AppRoleProviders | foreach-object {

        foreach ($AppRole in $_.AppRoles) {

            # Apply Classification
            $AppRoleTierLevelClassification = $Classification | where-object { $_.TierLevelDefinition.RoleDefinitionActions -contains $($AppRole.value) } | select-object EAMTierLevelName, EAMTierLevelTagValue
            $AppRoleServiceClassification = $Classification | select-object -ExpandProperty TierLevelDefinition | where-object { $_.RoleDefinitionActions -contains $($AppRole.value) } | select-object Service
            if ($IncludeAuthorizedApiCalls -eq $True -and $_.appId -eq "00000003-0000-0000-c000-000000000000") {
                # Apply Autorized Graph Calls if AppRoleProvider is Microsoft Graph
                $AppRoleAuthorizedApiCalls = $AllAuthorizedApiCalls | where-object { $_.PermissionName -contains $($AppRole.value) } | select-object -ExpandProperty API
            }

            if ($AppRoleTierLevelClassification.Count -gt 1 -and $AppRoleServiceClassification.Count -gt 1) {
                Write-Warning "Multiple Tier Level Classification found for $($AppRole.value)"
            }

            if ($null -eq $AppRoleTierLevelClassification) {
                $AppRoleTierLevelClassification = [PSCustomObject]@{
                    "EAMTierLevelName"     = "Unclassified"
                    "EAMTierLevelTagValue" = "Unclassified"
                }
            }

            if ($null -eq $AppRoleServiceClassification) {
                $AppRoleServiceClassification = [PSCustomObject]@{
                    "Service" = "Unclassified"
                }
            }

            if ($IncludeAuthorizedApiCalls -eq $True) {
                [PSCustomObject]@{
                    "AppId"                = $_.appId
                    "AppRoleId"            = $AppRole.id
                    "AppRoleDisplayName"   = $AppRole.value
                    "AuthorizedApiCalls"   = $AppRoleAuthorizedApiCalls
                    "Category"             = $AppRoleServiceClassification.Service
                    "EAMTierLevelName"     = $AppRoleTierLevelClassification.EAMTierLevelName
                    "EAMTierLevelTagValue" = $AppRoleTierLevelClassification.EAMTierLevelTagValue
                }
            }
            else {
                [PSCustomObject]@{
                    "AppId"                = $_.appId
                    "AppRoleId"            = $AppRole.id
                    "AppRoleDisplayName"   = $AppRole.value
                    "Category"             = $AppRoleServiceClassification.Service
                    "EAMTierLevelName"     = $AppRoleTierLevelClassification.EAMTierLevelName
                    "EAMTierLevelTagValue" = $AppRoleTierLevelClassification.EAMTierLevelTagValue
                }
            }
        }
    }

    $AppRoles = $AppRoles | sort-object AppRoleDisplayName
    $AppRoles | ConvertTo-Json -Depth 10 | Out-File $ExportFile -Force
}