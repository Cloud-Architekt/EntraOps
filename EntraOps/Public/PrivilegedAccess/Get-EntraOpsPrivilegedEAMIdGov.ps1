<#
.SYNOPSIS
    Get a list in schema of EntraOps with all privileged principals in Identity Governance and assigned roles and classifications.

.DESCRIPTION
    Get a list in schema of EntraOps with all privileged principals in Identity Governance and assigned roles and classifications.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER FolderClassification
    Folder path to the classification definition files. Default is "./Classification".

.PARAMETER FolderClassifiedObjects
    Folder path to the JSON files of classified objects which will be used to identify privileged objects in access packages or catalogs.
    Default is "./PrivilegedEAM".

.PARAMETER FilterClassifiedRbacs
    Filter classified objects by selected RBAC system. Default is "Azure", "EntraID", "DeviceManagement".
    All classified objects will be used to apply classification to to the access package or catalog if a group object is assigned.

.PARAMETER SampleMode
    Use sample data for testing or offline mode. Default is $False. Default sample data is stored in "./Samples"

.PARAMETER GlobalExclusion
    Use global exclusion list for classification. Default is $true. Global exclusion list is stored in "./Classification/Global.json".
#>

function Get-EntraOpsPrivilegedEamIdGov {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$TenantId = (Get-AzContext).Tenant.Id
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$FolderClassification = "$DefaultFolderClassification"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$FolderClassifiedObjects = "$DefaultFolderClassifiedEam"
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Azure", "EntraID", "DeviceManagement")]
        [Array]$FilterClassifiedRbacs = ("Azure", "EntraID", "DeviceManagement")
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$SampleMode = $False
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$GlobalExclusion = $true
    )

    # Check if classification file custom and/or template file exists, choose custom template for tenant if available
    $ClassificationFileName = "Classification_IdentityGovernance.json"
    if (Test-Path -Path "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)") {
        $IdGovClassificationFilePath = "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)"
    }
    elseif (Test-Path -Path "$($DefaultFolderClassification)/Templates/$($ClassificationFileName)") {
        $IdGovClassificationFilePath = "$($DefaultFolderClassification)/Templates/$($ClassificationFileName)"
    }
    else {
        Write-Error "Classification file $($ClassificationFileName) not found in $($DefaultFolderClassification). Please run Update-EntraOpsClassificationFiles to download the latest classification files from AzurePrivilegedIAM repository."
    }    

    # Get all role assignments and global exclusions
    Write-Host "Getting Microsoft Entra ID Governance information..."

    if ($SampleMode -ne $True) {
        $IdGovRbacAssignments = Get-EntraOpsPrivilegedIdGovRoles -TenantId $TenantId
    }
    else {
        Write-Warning "Currently not supported!"
    }

    if ($GlobalExclusion -eq $true) {
        $GlobalExclusionList = (Get-Content -Path "$DefaultFolderClassification/Global.json" | ConvertFrom-Json -Depth 10).ExcludedPrincipalId
    }
    else {
        $GlobalExclusionList = $null
    }
    #endregion

    #region Classification of assignments
    Write-Host "Classifiying of all Identity Governance assignments by classification of assigned and classified catalog objects"
    $IdGovRbacClassificationsByAssignedObjects = foreach ($IdGovRbacScope in $IdGovRbacAssignments | Select-Object -Unique RoleAssignmentScopeId) {
        $CurrentRoleAssignmentScope = $IdGovRbacScope.RoleAssignmentScopeId
        Write-Verbose -Message "Classify assignment scope $($CurrentRoleAssignmentScope)"

        if ($CurrentRoleAssignmentScope -like "/AccessPackageCatalog/*") {
            # Get all objects assigned to Access Package Catalog
            $AccessPackageCatalogId = $CurrentRoleAssignmentScope.Replace("/AccessPackageCatalog/", "")
            $AssignedCatalogObjects = Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/entitlementManagement/accessPackageCatalogs/$AccessPackageCatalogId/accessPackageResources" -ConsistencyLevel "eventual"
            $ClassificationOfAssignedCatalogObjects = @()
            $ClassificationOfAssignedCatalogObjects += foreach ($AssignedCatalogObject in $AssignedCatalogObjects) {
                # Get classification object of the object from all or filtered RBAC system
                $MatchedClassificationToCatalogObject = @()
                $MatchedClassificationToCatalogObject += foreach ($RbacSystem in $FilterClassifiedRbacs) {
                    $ClassificationSource = $FolderClassifiedObjects + "/" + $RbacSystem + "/" + $RbacSystem + ".json"
                    $MatchedRbacClassification = Get-Content -Path $ClassificationSource -ErrorAction SilentlyContinue | ConvertFrom-Json -Depth 10 | Where-Object { $_.ObjectId -eq $AssignedCatalogObject.originId }
                    if ($Null -ne $MatchedRbacClassification) {
                        $MatchedRbacClassification
                    }
                    else {
                        Write-Output "No classification for $($AssignedCatalogObject.displayName) $($AssignedCatalogObject.id) found in $RbacSystem or file $ClassificationSource is missing!"
                    }
                }
                # Return classification object of the object as summary
                $MatchedClassificationToCatalogObject
            }
            if ($Null -ne $ClassificationOfAssignedCatalogObjects.Classification) {
                $ClassificationOfAssignedCatalogObjects.Classification | Add-Member -NotePropertyName "TaggedBy" -NotePropertyValue "AssignedCatalogObjects" -Force
                $Classification = (($ClassificationOfAssignedCatalogObjects).Classification | select-object -Unique *)
                [PSCustomObject]@{
                    'RoleAssignmentScopeId' = $CurrentRoleAssignmentScope
                    'Classification'        = $Classification
                }
            }
        }
        else {
            Write-Error "Invalid scope $CurrentRoleAssignmentScopeId"
        }
    }
    #endregion

    Write-Host "Checking if RBAC role action and scope is defined in JSON classification..."
    $IdGovResourcesByClassificationJSON = Expand-EntraOpsPrivilegedEAMJsonFile -FilePath "$($IdGovClassificationFilePath)" | select-object EAMTierLevelName, EAMTierLevelTagValue, Category, Service, RoleAssignmentScopeName, ExcludedRoleAssignmentScopeName, RoleDefinitionActions, ExcludedRoleDefinitionActions
    $IdGovRbacClassificationsByJSON = @()
    $IdGovRbacClassificationsByJSON += foreach ($IdGovRbacAssignment in $IdGovRbacAssignments | Select-Object -Unique RoleDefinitionId, RoleAssignmentScopeId) {

        # Role actions are defined for scope and role definition contains an action of the role, otherwise all role actions within role assignment scope will be applied
        if ($SampleMode -eq $True) {
            Write-Warning "Currently not supported!"
        }
        else {
            $IdGovRoleActions = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/EntitlementManagement/roleDefinitions" | Where-Object { $_.Id -eq "$($IdGovRbacAssignment.RoleDefinitionId)" }
        }

        $MatchedClassificationByScope = @()
        # Check if RBAC scope is listed in JSON by wildcard in RoleAssignmentScope (e.g. /azops-rg/*)
        $MatchedClassificationByScope += $IdGovResourcesByClassificationJSON | foreach-object {
            $Classification = $_
            $Classification | where-object { $IdGovRbacAssignment.RoleAssignmentScopeId -like $Classification.RoleAssignmentScopeName -and $IdGovRbacAssignment.RoleAssignmentScopeId -notin $Classification.ExcludedRoleAssignmentScopeName }
        }

        # Check if role action and scope exists in JSON definition
        $IdGovRoleActionsInJsonDefinition = @()
        $IdGovRoleActionsInJsonDefinition = foreach ($Action in $IdGovRoleActions.rolePermissions.allowedResourceActions) {
            $MatchedClassificationByScope | Where-Object { $_.RoleDefinitionActions -Contains $Action -and $Classification.ExcludedRoleDefinitionActions -notcontains $_.RoleDefinitionActions }
        }


        if (($IdGovRoleActionsInJsonDefinition.Count -gt 0)) {
            $ClassifiedIdGovRbacRoleWithActions = @()
            foreach ($IdGovRoleAction in $IdGovRoleActions.rolePermissions.allowedResourceActions) {
                $ClassifiedIdGovRbacRoleWithActions += $IdGovResourcesByClassificationJSON | Where-Object { $IdGovRoleAction -in $_.RoleDefinitionActions }
            }
            $ClassifiedIdGovRbacRoleWithActions = $ClassifiedIdGovRbacRoleWithActions | select-object -Unique EAMTierLevelName, EAMTierLevelTagValue, Service
            $Classification = $ClassifiedIdGovRbacRoleWithActions | ForEach-Object {
                [PSCustomObject]@{
                    'AdminTierLevel'     = $_.EAMTierLevelTagValue
                    'AdminTierLevelName' = $_.EAMTierLevelName
                    'Service'            = $_.Service
                    'TaggedBy'           = "JSONwithAction"
                }
            }

            [PSCustomObject]@{
                'RoleDefinitionId'      = $IdGovRbacAssignment.RoleDefinitionId
                'RoleAssignmentScopeId' = $IdGovRbacAssignment.RoleAssignmentScopeId
                'Classification'        = $Classification
            }
        }
        else {
            $ClassifiedIdGovRbacRoleWithActions = @()
        }
    }

    $IdGovRbacClassifications = foreach ($IdGovRbacAssignment in $IdGovRbacAssignments) {
        $IdGovRbacAssignment = $IdGovRbacAssignment | Select-Object -ExcludeProperty Classification
        $ClassificationCollection = @()
        $ClassificationCollection += ($IdGovRbacClassificationsByAssignedObjects | Where-Object { $_.RoleAssignmentScopeId -eq $IdGovRbacAssignment.RoleAssignmentScopeId }).Classification
        $ClassificationCollection += ($IdGovRbacClassificationsByJSON | Where-Object { $_.RoleAssignmentScope -eq $IdGovRbacAssignment.RoleAssignmentScope -and $_.RoleDefinitionId -eq $IdGovRbacAssignment.RoleDefinitionId }).Classification
        $Classification = @()
        $Classification += $ClassificationCollection | select-object -Unique AdminTierLevel, AdminTierLevelName, Service, TaggedBy | Sort-Object -Unique AdminTierLevel, AdminTierLevelName, Service, TaggedBy
        $IdGovRbacAssignment | Add-Member -NotePropertyName "Classification" -NotePropertyValue $Classification -Force
        $IdGovRbacAssignment
    }

    Write-Host "Classifiying of all assigned privileged users and groups in Identity Governance..."
    $IdGovRbacClassifiedObjects = $IdGovRbacAssignments | select-object -Unique ObjectId, ObjectType | ForEach-Object {
        if ($_.ObjectId -ne $null) {

            # Object types
            $ObjectId = $_.ObjectId
            $ObjectDetails = Get-EntraOpsPrivilegedEntraObject -AadObjectId $ObjectId -TenantId $TenantId

            # RBAC Assignments
            $IdGovRbacClassifiedAssignments = @()
            $IdGovRbacClassifiedAssignments += ($IdGovRbacClassifications | Where-Object { $_.ObjectId -eq "$ObjectId" })
            $IdGovRbacClassification = $($IdGovRbacClassifiedAssignments).Classification | select-object -Unique AdminTierLevel, AdminTierLevelName, Service | Sort-Object AdminTierLevel, AdminTierLevelName, Service

            # Classification
            $Classification = @()
            $Classification += $IdGovRbacClassification
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
                'RoleSystem'                    = "IdentityGovernance"
                'Classification'                = $Classification
                'RoleAssignments'               = $IdGovRbacClassifiedAssignments
                'Owners'                        = $ObjectDetails.Owners
                'OwnedObjects'                  = $ObjectDetails.OwnedObjects
                'OwnedDevices'                  = $ObjectDetails.OwnedDevices
                'AssociatedWorkAccount'         = $ObjectDetails.AssociatedWorkAccount
                'AssociatedPawDevice'           = $ObjectDetails.AssociatedPawDevice
            }
        }
    }
    $IdGovRbacClassifiedObjects = $IdGovRbacClassifiedObjects | Where-Object { $GlobalExclusionList -notcontains $_.ObjectId }
    $IdGovRbacClassifiedObjects | Sort-Object ObjectAdminTierLevel, ObjectDisplayName
}