<#
.SYNOPSIS
    Get a list in schema of EntraOps with all privileged principals in Resource Apps and assigned app roles and classifications.

.DESCRIPTION
    Get a list in schema of EntraOps with all privileged principals in Resource Apps and assigned app roles and classifications.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER FolderClassification
    Folder path to the classification definition files. Default is "./Classification".

.PARAMETER SampleMode
    Use sample data for testing or offline mode. Default is $False. Default sample data is stored in "./Samples"

.PARAMETER GlobalExclusion
    Use global exclusion list for classification. Default is $true. Global exclusion list is stored in "./Classification/Global.json".
#>

function Get-EntraOpsPrivilegedEamResourceApps {

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$TenantId = (Get-AzContext).Tenant.Id
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$FolderClassification = "$DefaultFolderClassification"
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$SampleMode = $False
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$GlobalExclusion = $true
    )

    # Check if classification file custom and/or template file exists, choose custom template for tenant if available
    $ClassificationFileName = "Classification_AppRoles.json"
    if (Test-Path -Path "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)") {
        $ResourceAppsClassificationFilePath = "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)"
    } elseif (Test-Path -Path "$($DefaultFolderClassification)/Templates/$($ClassificationFileName)") {
        $ResourceAppsClassificationFilePath = "$($DefaultFolderClassification)/Templates/$($ClassificationFileName)"
    } else {
        Write-Error "Classification file $($ClassificationFileName) not found in $($DefaultFolderClassification). Please run Update-EntraOpsClassificationFiles to download the latest classification files from AzurePrivilegedIAM repository."
    }

    Write-Host "Getting App Roles from Entra ID Service Principals..."

    # Get all role assignments and global exclusions
    if ($SampleMode -ne $True) {
        $AppRoleAssignments = Get-EntraOpsPrivilegedAppRoles -TenantId $TenantId
    } else {
        Write-Warning "Currently not supported!"
    }
    if ($GlobalExclusion -eq $true) {
        $GlobalExclusionList = (Get-Content -Path "$DefaultFolderClassification/Global.json" | ConvertFrom-Json -Depth 10).ExcludedPrincipalId
    } else {
        $GlobalExclusionList = $null
    }
    #endregion

    #region Check if App Role Assignment and scope is defined in JSON classification
    Write-Host "Checking if App role and scope is defined in JSON classification..."
    $AppRoleByClassificationJSON = Expand-EntraOpsPrivilegedEAMJsonFile -FilePath $ResourceAppsClassificationFilePath | select-object EAMTierLevelName, EAMTierLevelTagValue, Category, Service, RoleAssignmentScopeName, ExcludedRoleAssignmentScopeName, RoleDefinitionActions, ExcludedRoleDefinitionActions
    $AppRoleClassificationsByJSON = @()
    $AppRoleClassificationsByJSON += foreach ($AppRoleAssignment in $AppRoleAssignments | Select-Object -Unique RoleDefinitionId, RoleAssignmentScopeId, RoleDefinitionName) {
        # Check if role action and scope exists in JSON definition
        $AppRoleInJsonDefinition = @()
        $AppRoleInJsonDefinition = foreach ($RoleDefinitionName in $AppRoleAssignment.RoleDefinitionName) {
            $AppRoleByClassificationJSON | Where-Object { ($_.RoleDefinitionActions -eq $RoleDefinitionName -or $RoleDefinitionName -like $_.RoleDefinitionActions) -and $Classification.ExcludedRoleDefinitionActions -ne $RoleDefinitionName }
        }

        $Classification = @()
        if (($AppRoleInJsonDefinition.Count -gt 0)) {
            $ClassifiedAppRole = @()
            $ClassifiedAppRole += $AppRoleInJsonDefinition | select-object -Unique EAMTierLevelName, EAMTierLevelTagValue, Service | Sort-Object EAMTierLevelTagValue, EAMTierLevelName, Service
            $Classification += $ClassifiedAppRole | ForEach-Object {
                [PSCustomObject]@{
                    'AdminTierLevel'     = $_.EAMTierLevelTagValue
                    'AdminTierLevelName' = $_.EAMTierLevelName
                    'Service'            = $_.Service
                    'TaggedBy'           = "JSONwithAction"
                }
            }
        } else {
            $Classification += [PSCustomObject]@{
                'AdminTierLevel'     = "Unclassified"
                'AdminTierLevelName' = "Unclassified"
                'Service'            = "Unclassified"
            }
        }

        [PSCustomObject]@{
            'RoleDefinitionId'      = $AppRoleAssignment.RoleDefinitionId
            'RoleAssignmentScopeId' = $AppRoleAssignment.RoleAssignmentScopeId
            'Classification'        = $Classification
        }
    }
    $AppRoleClassificationsByJSON = $AppRoleClassificationsByJSON | sort-object -property @{e = { $_.Classification.AdminTierLevel } }
    #endregion

    #region Classify App Role Assignments
    $AppRoleClassifications = foreach ($AppRoleAssignment in $AppRoleAssignments) {
        $AppRoleAssignment = $AppRoleAssignment | Select-Object -ExcludeProperty Classification
        $Classification = @()
        $ClassificationCollection = ($AppRoleClassificationsByJSON | Where-Object { $_.RoleAssignmentScope -eq $AppRoleAssignment.RoleAssignmentScope -and $_.RoleDefinitionId -eq $AppRoleAssignment.RoleDefinitionId })
        if ($ClassificationCollection.Classification.Count -gt 0) {
            $Classification += $ClassificationCollection.Classification | Sort-Object AdminTierLevel, AdminTierLevelName, Service
            $Classification += $ClassificationCollection.Classification | select-object -Unique AdminTierLevel, AdminTierLevelName, Service, TaggedBy
        }
        $AppRoleAssignment | Add-Member -NotePropertyName "Classification" -NotePropertyValue $Classification -Force
        $AppRoleAssignment
    }
    #endregion
    $AppRoleClassifications = $AppRoleClassifications | sort-object -property @{e = { $_.Classification.AdminTierLevel } }, RoleDefinitionName

    #region Add classification and details of Service Principals to output
    Write-Host "Classifiying of all assigned privileged app roles to service principals..."
    $AppRoleClassifiedObjects = $AppRoleAssignments | select-object -Unique ObjectId, ObjectType | ForEach-Object {
        if ($_.ObjectId -ne $null) {

            # Object types
            $ObjectId = $_.ObjectId
            $ObjectDetails = Get-EntraOpsPrivilegedEntraObject -AadObjectId $ObjectId -TenantId $TenantId

            # RBAC Assignments
            $AppRoleClassifiedAssignments = @()
            $AppRoleClassifiedAssignments += ($AppRoleClassifications | Where-Object { $_.ObjectId -eq "$ObjectId" })
            $AppRoleClassification = $($AppRoleClassifiedAssignments).Classification | select-object -Unique AdminTierLevel, AdminTierLevelName, Service | Sort-Object AdminTierLevel, AdminTierLevelName, Service

            # Classification
            $Classification = @()
            $Classification += $AppRoleClassification | Sort-Object AdminTierLevel, AdminTierLevelName, Service
            if ($Classification.Count -eq 0) {
                $Classification += [PSCustomObject]@{
                    'AdminTierLevel'     = "Unclassified"
                    'AdminTierLevelName' = "Unclassified"
                    'Service'            = "Unclassified"
                }
            }

            [PSCustomObject]@{
                'ObjectId'                      = $ObjectId
                'ObjectType'                    = $ObjectDetails.ObjectType.toLower()
                'ObjectSubType'                 = $ObjectDetails.ObjectSubType
                'ObjectDisplayName'             = $ObjectDetails.ObjectDisplayName
                'ObjectUserPrincipalName'       = $ObjectDetails.ObjectSignInName
                'ObjectAdminTierLevel'          = $ObjectDetails.AdminTierLevel
                'ObjectAdminTierLevelName'      = $ObjectDetails.AdminTierLevelName
                'OnPremSynchronized'            = $ObjectDetails.OnPremSynchronized
                'AssignedAdministrativeUnits'   = $ObjectDetails.AssignedAdministrativeUnits
                'RestrictedManagementByRAG'     = $ObjectDetails.RestrictedManagementByRAG
                'RestrictedManagementByAadRole' = $ObjectDetails.RestrictedManagementByAadRole
                'RestrictedManagementByRMAU'    = $ObjectDetails.RestrictedManagementByRMAU
                'RoleSystem'                    = "ResourceApp"
                'Classification'                = $Classification
                'RoleAssignments'               = $AppRoleClassifiedAssignments
                'Owners'                        = $ObjectDetails.Owners
                'OwnedObjects'                  = $ObjectDetails.OwnedObjects
                'OwnedDevices'                  = $ObjectDetails.OwnedDevices
                'AssociatedWorkAccount'         = $ObjectDetails.AssociatedWorkAccount
                'AssociatedPawDevice'           = $ObjectDetails.AssociatedPawDevice
            }
        }
    }
    #endregion

    $AppRoleClassifiedObjects = $AppRoleClassifiedObjects | Where-Object { $GlobalExclusionList -notcontains $_.ObjectId }
    $AppRoleClassifiedObjects | Sort-Object ObjectAdminTierLevel, ObjectDisplayName
}