function Export-EntraOpsClassificationDirectoryRoles {

    <#
    .SYNOPSIS
        Get a JSON file with all classified Entra ID Directory roles.

    .DESCRIPTION
        Read JSON classification file and match Entra ID directory role definitions to export it as JSON.

    .PARAMETER SingleClassification
        Use the highest tier level classification only for each role definition. Default is $True.

    .PARAMETER FilteredConditions
        List of role permission conditions to exclude from classification. Default filters out '$ResourceIsSelf'.
        '$SubjectIsOwner' is always excluded because owner-scoped actions are not tenant-wide privileges.

    .PARAMETER IncludeCustomRoles
        Include custom role definitions in addition to built-in roles.

    .PARAMETER IncludeInheritedPermissions
        When a role definition has "inheritsPermissionsFrom" set (e.g. a custom role based on a built-in role
        template), also resolve and include all role actions of the referenced role definition(s) for classification
        and as role actions of the inheriting role. Resolution is recursive (inherited roles may themselves inherit
        from another role) and protected against circular references. Default is $True.

    .PARAMETER RoleDefinitionOverwritesFilePath
        Path to the EntraOps role definition overwrites file. Roles listed there (RbacSystem "EntraID") are pinned
        to the overwrite tier because their sensitivity is not visible in their role actions.
        Default is "./EntraOps_Classification/Classification_RoleDefinitionOverwrites.json".

    .EXAMPLE
        Export all classified Entra ID Directory roles to "Classification\Classification_EntraIdDirectoryRoles.json".
        Export-EntraOpsClassificationDirectoryRoles

    .EXAMPLE
        Export all classified Entra ID Directory roles including custom roles.
        Export-EntraOpsClassificationDirectoryRoles -IncludeCustomRoles $true
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        $SingleClassification = $True
        ,
        [Parameter(Mandatory = $false)]
        $FilteredConditions = @('$ResourceIsSelf')
        ,
        [Parameter(Mandatory = $false)]
        $IncludeCustomRoles = $False
        ,
        [Parameter(Mandatory = $false)]
        $IncludeInheritedPermissions = $false
        ,
        [Parameter(Mandatory = $false)]
        [string]$RoleDefinitionOverwritesFilePath = "./EntraOps_Classification/Classification_RoleDefinitionOverwrites.json"
    )

    # Keep the owner-only exclusion mandatory even when a caller supplies a custom filter list.
    $FilteredConditions = @(
        @($FilteredConditions) + '$SubjectIsOwner' |
        ForEach-Object { "$($_)".Trim() } |
        Where-Object { -not [string]::IsNullOrEmpty($_) } |
        Select-Object -Unique
    )

    # Resolve role actions inherited via "inheritsPermissionsFrom" (e.g. a custom role based on a built-in role
    # template). Recursively follows nested inheritance and guards against circular references.
    function Resolve-EntraOpsInheritedRoleActions {
        param
        (
            [Parameter(Mandatory = $true)] [string[]] $InheritedRoleIds,
            [Parameter(Mandatory = $true)] $RoleActionsLookup,
            [Parameter(Mandatory = $true)] [System.Collections.Generic.HashSet[string]] $VisitedRoleIds
        )

        $InheritedActions = New-Object System.Collections.Generic.List[string]
        foreach ($InheritedRoleId in $InheritedRoleIds) {
            if (-not $VisitedRoleIds.Add($InheritedRoleId)) {
                continue # already visited, avoid circular inheritance
            }

            if (-not $RoleActionsLookup.ContainsKey($InheritedRoleId)) {
                Write-Warning "inheritsPermissionsFrom references unknown role template ID '$InheritedRoleId'; unable to resolve inherited permissions."
                continue
            }

            $InheritedActions.AddRange([string[]]$RoleActionsLookup[$InheritedRoleId].Actions)

            if (@($RoleActionsLookup[$InheritedRoleId].InheritsFrom).Count -gt 0) {
                $NestedActions = Resolve-EntraOpsInheritedRoleActions -InheritedRoleIds $RoleActionsLookup[$InheritedRoleId].InheritsFrom -RoleActionsLookup $RoleActionsLookup -VisitedRoleIds $VisitedRoleIds
                $InheritedActions.AddRange($NestedActions)
            }
        }

        return $InheritedActions
    }

    # Roles whose sensitivity is not visible in their role actions (same source EntraOps applies at runtime)
    $RoleDefinitionOverwrites = Get-EntraOpsRoleDefinitionOverwrites -Path $RoleDefinitionOverwritesFilePath -RbacSystem 'EntraID'

    # Get EntraOps Classification
    $Classification = Get-Content -Path ./EntraOps_Classification/Classification_AadResources.json -Encoding UTF8 | ConvertFrom-Json -Depth 10

    # Single classifcation (highest tier level only)
    Write-Output "Query directory role templates for mapping ID to name and further details"
    $DirectoryRoleDefinitions = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions" -OutputType PSObject | select-object displayName, templateId, isBuiltin, isPrivileged, rolePermissions, categories, richDescription, inheritsPermissionsFrom, assignmentMode

    # Build a lookup of role actions (and further inheritance) by templateId from the full, unfiltered role
    # definitions list so inherited permissions can be resolved even when IncludeCustomRoles is $False.
    $RoleActionsLookup = @{}
    foreach ($RoleDef in $DirectoryRoleDefinitions) {
        $RoleActionsLookup[$RoleDef.templateId] = [PSCustomObject]@{
            Actions      = @(($RoleDef.RolePermissions | Where-Object { "$($_.condition)".Trim() -notin $FilteredConditions }).allowedResourceActions)
            InheritsFrom = @($RoleDef.inheritsPermissionsFrom | Select-Object -ExpandProperty id)
        }
    }

    if ($IncludeCustomRoles -eq $False) {
        $DirectoryRoleDefinitions = $DirectoryRoleDefinitions | where-object { $_.isBuiltin -eq "True" }
    }

    $DirectoryRoles = $DirectoryRoleDefinitions | foreach-object {

        # Roles without role actions (e.g. Device Join) would otherwise yield a single $null action
        $DirectoryRolePermissions = @(($_.RolePermissions | Where-Object { "$($_.condition)".Trim() -notin $FilteredConditions }).allowedResourceActions | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

        # Include role actions inherited via inheritsPermissionsFrom (e.g. custom roles based on a built-in template)
        $InheritsPermissionsFromIds = @($_.inheritsPermissionsFrom | Select-Object -ExpandProperty id | Sort-Object -Unique)
        if ($IncludeInheritedPermissions -eq $True -and $InheritsPermissionsFromIds.Count -gt 0) {
            $VisitedRoleIds = [System.Collections.Generic.HashSet[string]]::new()
            $VisitedRoleIds.Add($_.templateId) | Out-Null
            $InheritedActions = Resolve-EntraOpsInheritedRoleActions -InheritedRoleIds $InheritsPermissionsFromIds -RoleActionsLookup $RoleActionsLookup -VisitedRoleIds $VisitedRoleIds
            $DirectoryRolePermissions = @($DirectoryRolePermissions + $InheritedActions | Select-Object -Unique)
        }

        $ClassifiedDirectoryRolePermissions = New-Object System.Collections.ArrayList
        foreach ($RolePermission in $DirectoryRolePermissions) {
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

            $ClassifiedDirectoryRolePermission = (
                [PSCustomObject]@{
                    "AuthorizedResourceAction" = $RolePermission
                    "Category"                 = $EntraRolePermissionServiceClassification.Service
                    "EAMTierLevelName"         = $EntraRolePermissionTierLevelClassification.EAMTierLevelName
                    "EAMTierLevelTagValue"     = $EntraRolePermissionTierLevelClassification.EAMTierLevelTagValue
                }
            )
            $ClassifiedDirectoryRolePermissions.Add($ClassifiedDirectoryRolePermission) | Out-Null
        }
        $ClassifiedDirectoryRolePermissions = $ClassifiedDirectoryRolePermissions | sort-object EAMTierLevelTagValue, Category, AuthorizedResourceAction

        # Keep one Unclassified placeholder for roles without role actions: KQL mv-expand drops rows with empty arrays
        if (@($ClassifiedDirectoryRolePermissions).Count -eq 0) {
            $ClassifiedDirectoryRolePermissions = @(
                [PSCustomObject]@{
                    "AuthorizedResourceAction" = $null
                    "Category"                 = "Unclassified"
                    "EAMTierLevelName"         = "Unclassified"
                    "EAMTierLevelTagValue"     = "Unclassified"
                }
            )
        }

        if ($SingleClassification -eq $True) {
            $RoleDefinitionClassification = ($ClassifiedDirectoryRolePermissions | select-object -ExcludeProperty AuthorizedResourceAction, Category -Unique | Sort-Object EAMTierLevelTagValue | select-object -First 1)
        } else {
            $FilteredRoleClassifications = ($ClassifiedDirectoryRolePermissions | select-object -ExcludeProperty AuthorizedResourceAction -Unique | Sort-Object EAMTierLevelTagValue, Category)
            $RoleDefinitionClassification = [System.Collections.Generic.List[object]]::new()
            $RoleDefinitionClassification.Add($FilteredRoleClassifications)        
        }

        if ($RoleDefinitionOverwrites.ContainsKey([string]$_.templateId)) {
            $RoleDefinitionClassification = $RoleDefinitionOverwrites[[string]$_.templateId]
        }

        [PSCustomObject]@{
            "RoleId"                  = $_.templateId
            "RoleName"                = $_.displayName
            "isPrivileged"            = $_.isPrivileged
            "AssignmentMode"          = $_.assignmentMode
            "InheritsPermissionsFrom" = $InheritsPermissionsFromIds
            # Preserve the Microsoft Graph representation: Categories is a scalar string, and Graph
            # exposes multiple category values as one comma-delimited string (for example, "Collaboration,Identity").
            "Categories"              = $_.categories
            "RichDescription"         = $_.richDescription
            "RolePermissions"         = @($ClassifiedDirectoryRolePermissions) 
            "Classification"          = $RoleDefinitionClassification
        }    
    }

    $DirectoryRoles = $DirectoryRoles | Sort-Object RoleName, RoleId
    $DirectoryRoles | ConvertTo-Json -Depth 10 | Out-File .\Classification\Classification_EntraIdDirectoryRoles.json -Force
}
