<#
.SYNOPSIS
    Get a list in schema of EntraOps with all privileged principals in Entra ID and assigned roles and classifications.

.DESCRIPTION
    Get a list in schema of EntraOps with all privileged principals in Entra ID and assigned roles and classifications.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER FolderClassification
    Folder path to the classification definition files. Default is "./Classification".

.PARAMETER SampleMode
    Use sample data for testing or offline mode. Default is $False. Default sample data is stored in "./Samples"

.PARAMETER GlobalExclusion
    Use global exclusion list for classification. Default is $true. Global exclusion list is stored in "./Classification/Global.json".
#>

function Get-EntraOpsPrivilegedEamEntraId {

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

    Write-Host "Get Entra ID role assignments..."

    #region Define sensitive role definitions without actions to classify
    $ControlPlaneRolesWithoutRoleActions = @()
    $ControlPlaneRolesWithoutRoleActions += New-Object PSObject -Property @{
        "RoleId"  = 'd29b2b05-8046-44ba-8758-1e26182fcf32' # Directory Synchronization Accounts
        "Service" = 'Hybrid Identity Synchronization'
    }
    $ControlPlaneRolesWithoutRoleActions += New-Object PSObject -Property @{
        "RoleId"  = "a92aed5d-d78a-4d16-b381-09adb37eb3b0" # On Premises Directory Sync Account
        "Service" = 'Hybrid Identity Synchronization'
    }
    $ControlPlaneRolesWithoutRoleActions += New-Object PSObject -Property @{
        "RoleId"  = "9f06204d-73c1-4d4c-880a-6edb90606fd8" # Azure AD Joined Device Local Administrator
        "Service" = 'Global Endpoint Management'
    }

    #endregion

    #region Check if classification file custom and/or template file exists, choose custom template for tenant if available
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
    #endregion

    #region Get all role assignments and global exclusions
    if ($SampleMode -eq $True) {
        $AadRbacAssignments = get-content -Path "$EntraOpsBaseFolder/Samples/AadRoleManagementAssignments.json" | ConvertFrom-Json -Depth 10
    }
    else {
        $AadRbacAssignments = Get-EntraOpsPrivilegedEntraIdRoles -TenantId $TenantId
    }

    if ($GlobalExclusion -eq $true) {
        $GlobalExclusionList = (Get-Content -Path "$DefaultFolderClassification/Global.json" | ConvertFrom-Json -Depth 10).ExcludedPrincipalId
    }
    else {
        $GlobalExclusionList = $null
    }
    #endregion

    #region Classification of assignments by JSON
    Write-Host "Classifiying of all Entra ID RBAC assignments by classification in JSON"
    $AadRbacClassifications = foreach ($AadRbacAssignment in $AadRbacAssignments) {
        $Classification = $AadRbacEamScope | Where-Object { $_.ResourceId -eq $CurrentRoleAssignmentScope } | select-object AdminTierLevel, AdminTierLevelName, Service, TaggedBy | Sort-Object AdminTierLevel, AdminTierLevelName, Service

        if ($ControlPlaneRolesWithoutRoleActions.RoleId -contains $AadRbacAssignment.RoleId) {
            $Classification = $ControlPlaneRolesWithoutRoleActions | Where-Object { $_.RoleId -contains $AadRbacAssignment.RoleId }
            $Classification = [PSCustomObject]@{
                'AdminTierLevel'     = "ControlPlane"
                'AdminTierLevelName' = "0"
                'Service'            = $Classification.Service
                'TaggedBy'           = "ControlPlaneRolesWithoutRoleActions"
            }
        }

        [PSCustomObject]@{
            'RoleAssignmentId'              = $AadRbacAssignment.RoleAssignmentId
            'RoleAssignmentScopeId'         = $AadRbacAssignment.RoleAssignmentScopeId
            'RoleAssignmentScopeName'       = $AadRbacAssignment.RoleAssignmentScopeName
            'RoleAssignmentType'            = $AadRbacAssignment.RoleAssignmentType
            'RoleAssignmentSubType'         = $AadRbacAssignment.RoleAssignmentSubType
            'PIMManagedRole'                = $AadRbacAssignment.RoleAssignmentPIMRelated
            'PIMAssignmentType'             = $AadRbacAssignment.RoleAssignmentPIMAssignmentType
            'RoleDefinitionName'            = $AadRbacAssignment.RoleName
            'RoleDefinitionId'              = $AadRbacAssignment.RoleId
            'RoleType'                      = $AadRbacAssignment.RoleType
            'RoleIsPrivileged'              = if ($null -eq $AadRbacAssignment.IsPrivileged) { $false } else { $AadRbacAssignment.IsPrivileged }
            'Classification'                = $Classification | Sort-Object AdminTierLevel, AdminTierLevelName, Service
            'ObjectId'                      = $AadRbacAssignment.ObjectId
            'ObjectType'                    = $AadRbacAssignment.ObjectType
            'TransitiveByObjectId'          = $AadRbacAssignment.TransitiveByObjectId
            'TransitiveByObjectDisplayName' = $AadRbacAssignment.TransitiveByObjectDisplayName
        }
    }

    Write-Host "Checking if RBAC role action and scope is defined in JSON classification..."
    $AadResourcesByClassificationJSON = Expand-EntraOpsPrivilegedEAMJsonFile -FilePath "$($AadClassificationFilePath)" | select-object EAMTierLevelName, EAMTierLevelTagValue, Category, Service, RoleAssignmentScopeName, ExcludedRoleAssignmentScopeName, RoleDefinitionActions, ExcludedRoleDefinitionActions

    # Get all role actions for Entra ID roles, role actions are defined tenant wide
    if ($SampleMode -eq $True) {
        $AllAadRoleActions = get-content -Path "$EntraOpsBaseFolder/Samples/AadRoleManagementRoleDefinitions.json" | ConvertFrom-Json -Depth 10
    }
    else {
        $AllAadRoleActions = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions" -OutputType PSObject)
    }
    #endregion

    #region Apply classification for all role definitions
    $AadRbacClassification = foreach ($CurrentAadRbacClassification in $AadRbacClassifications) {
        $CurrentRoleDefinitionName = $CurrentAadRbacClassification.RoleDefinitionName
        $AadRoleScope = $CurrentAadRbacClassification.RoleAssignmentScopeId

        # Get role actions for role definition
        $AadRoleActions = $AllAadRoleActions | Where-Object { $_.DisplayName -eq "$($CurrentRoleDefinitionName)" }

        $MatchedClassificationByScope = @()
        # Check if RBAC scope is listed in JSON by wildcard in RoleAssignmentScopeName (e.g. /azops-rg/*)
        $MatchedClassificationByScope += $AadResourcesByClassificationJSON | foreach-object {
            $Classification = $_
            $Classification | where-object { $AadRoleScope -like $Classification.RoleAssignmentScopeName -and $AadRoleScope -notin $Classification.ExcludedRoleAssignmentScopeName }
        }

        # Check if role action and scope exists in JSON definition
        $AadRoleActionsInJsonDefinition = @()
        $AadRoleActionsInJsonDefinition = foreach ($Action in $AadRoleActions.rolePermissions.allowedResourceActions) {
            $MatchedClassificationByScope | Where-Object { $_.RoleDefinitionActions -Contains $Action -and $Classification.ExcludedRoleDefinitionActions -notcontains $_.RoleDefinitionActions }
        }

        if (($AadRoleActionsInJsonDefinition.Count -gt 0)) {
            $ClassifiedAadRbacRoleWithActions = @()
            foreach ($AadRoleAction in $AadRoleActions.rolePermissions.allowedResourceActions) {
                $ClassifiedAadRbacRoleWithActions += $AadRoleActionsInJsonDefinition | Where-Object { $AadRoleAction -in $_.RoleDefinitionActions }
            }
            $ClassifiedAadRbacRoleWithActions = $ClassifiedAadRbacRoleWithActions | select-object -Unique EAMTierLevelName, EAMTierLevelTagValue, Service | Sort-Object EAMTierLevelTagValue, Service
            $CurrentAadRbacClassification.Classification = New-Object System.Collections.ArrayList
            $ClassifiedAadRbacRoleWithActions | ForEach-Object {
                $ClassifiedRoleAction = [PSCustomObject]@{
                    'AdminTierLevel'     = $_.EAMTierLevelTagValue
                    'AdminTierLevelName' = $_.EAMTierLevelName
                    'Service'            = $_.Service
                    'TaggedBy'           = "JSONwithAction"
                }
                $CurrentAadRbacClassification.Classification.Add( $ClassifiedRoleAction ) | Out-Null
            }
        }
        $CurrentAadRbacClassification | sort-object AdminTierLevel, AdminTierLevelName, Service
    }
    #endregion

    #region Apply classification on all principals
    Write-Host "Classifiying of all assigned privileged users and groups to Entra ID roles..."
    $AadRbacClassifiedObjects = $AadRbacClassification | select-object -Unique ObjectId, ObjectType | ForEach-Object {
        if ($null -ne $_.ObjectId) {
            Write-Verbose -Message "Get details for privileged user $($AadRbacClassification.ObjectId)..."
            # Object types
            $ObjectId = $_.ObjectId
            $ObjectType = $_.ObjectType
            $ObjectDetails = Get-EntraOpsPrivilegedEntraObject -AadObjectId $ObjectId -TenantId $TenantId

            # RBAC Assignments
            $AllAadRbacEntriesOfObject = @()
            $AllAadRbacEntriesOfObject += ($AadRbacClassification | Where-Object { $_.ObjectId -eq "$ObjectId" })

            # Classification
            $Classification = @()
            $Classification += (($AllAadRbacEntriesOfObject).Classification | select-object -Unique AdminTierLevel, AdminTierLevelName, Service) | Sort-Object AdminTierLevel, AdminTierLevelName, Service

            if ($Classification.Count -eq 0) {
                $Classification = @()
                $Classification += [PSCustomObject]@{
                    'AdminTierLevel'     = "Unclassified"
                    'AdminTierLevelName' = "Unclassified"
                    'Service'            = "Unclassified"
                }
            }

            [PSCustomObject]@{
                'ObjectId'                      = $ObjectId
                'ObjectType'                    = $ObjectType.ToLower()
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
                'RoleSystem'                    = "EntraID"
                'Classification'                = $Classification
                'RoleAssignments'               = $AllAadRbacEntriesOfObject
                'Owners'                        = $ObjectDetails.Owners
                'OwnedObjects'                  = $ObjectDetails.OwnedObjects
                'OwnedDevices'                  = $ObjectDetails.OwnedDevices
                'AssociatedWorkAccount'         = $ObjectDetails.AssociatedWorkAccount
                'AssociatedPawDevice'           = $ObjectDetails.AssociatedPawDevice
            }
        }
    }
    #endregion
    $EamEntraId = $AadRbacClassifiedObjects | Where-Object { $GlobalExclusionList -notcontains $_.ObjectId }
    $EamEntraId | Sort-Object ObjectAdminTierLevel, ObjectDisplayName
}
