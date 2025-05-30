<#
.SYNOPSIS
    Get a list in schema of EntraOps with all privileged principals in Microsoft Intune and assigned roles and classifications.

.DESCRIPTION
    Get a list in schema of EntraOps with all privileged principals in Microsoft Intune and assigned roles and classifications.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER FolderClassification
    Folder path to the classification definition files. Default is "./Classification".

.PARAMETER SampleMode
    Use sample data for testing or offline mode. Default is $False. Default sample data is stored in "./Samples"

.PARAMETER GlobalExclusion
    Use global exclusion list for classification. Default is $true. Global exclusion list is stored in "./Classification/Global.json".
#>

function Get-EntraOpsPrivilegedEamDefender {
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
        [System.String]$ApplyClassificationByAssignedObjects = $false
        ,        
        [Parameter(Mandatory = $false)]
        [System.Boolean]$SampleMode = $False
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$GlobalExclusion = $true
    )

    # Check if classification file custom and/or template file exists, choose custom template for tenant if available
    $ClassificationFileName = "Classification_Defender.json"
    if (Test-Path -Path "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)") {
        $DefenderClassificationFilePath = "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)"
    } elseif (Test-Path -Path "$DefaultFolderClassification/Templates/$($ClassificationFileName)") {
        $DefenderClassificationFilePath = "$($DefaultFolderClassification)/Templates/$($ClassificationFileName)"
    } else {
        Write-Error "Classification file $($ClassificationFileName) not found in $($DefaultFolderClassification). Please run Update-EntraOpsClassificationFiles to download the latest classification files from AzurePrivilegedIAM repository."
    }

    #region Get all role assignments and global exclusions
    Write-Host "Getting Defender Roles..."

    if ($SampleMode -ne $True) {
        $DefenderRbacAssignments = EntraOps\Get-EntraOpsPrivilegedDefenderRoles -TenantId $TenantId
    } else {
        Write-Warning "Currently not supported!"
    }

    if ($GlobalExclusion -eq $true) {
        $GlobalExclusionList = (Get-Content -Path "$DefaultFolderClassification/Global.json" | ConvertFrom-Json -Depth 10).ExcludedPrincipalId
    } else {
        $GlobalExclusionList = $null
    }
    #endregion

    #region Check if RBAC role action and scope is defined in JSON classification
    Write-Host "Checking if RBAC role action and scope is defined in JSON classification..."
    $DefenderResourcesByClassificationJSON = Expand-EntraOpsPrivilegedEAMJsonFile -FilePath $DefenderClassificationFilePath | select-object EAMTierLevelName, EAMTierLevelTagValue, Category, Service, RoleAssignmentScopeName, ExcludedRoleAssignmentScopeName, RoleDefinitionActions, ExcludedRoleDefinitionActions
    $DefenderRbacClassificationsByJSON = @()
    $DefenderRbacClassificationsByJSON += foreach ($DefenderRbacAssignment in $DefenderRbacAssignments | Select-Object -Unique RoleDefinitionId, RoleAssignmentScopeId) {
        if ($DefenderRbacAssignment.RoleAssignmentScopeId -ne "/") {
            $DefenderRbacAssignment.RoleAssignmentScopeId = "$($DefenderRbacAssignment.RoleAssignmentScopeId)"
        }
        # Role actions are defined for scope and role definition contains an action of the role, otherwise all role actions within role assignment scope will be applied
        if ($SampleMode -eq $True) {
            Write-Warning "Currently not supported!"
        } else {
            $DefenderRoleActions = (Invoke-EntraOpsMsGraphQuery -Method GET -Uri https://graph.microsoft.com/beta/roleManagement/defender/roleDefinitions -OutputType PSObject) | Where-Object { $_.Id -eq "$($DefenderRbacAssignment.RoleDefinitionId)" }
        }

        $MatchedClassificationByScope = @()
        # Check if RBAC scope is listed in JSON by wildcard in RoleAssignmentScope (e.g. /azops-rg/*)
        $MatchedClassificationByScope += $DefenderResourcesByClassificationJSON | foreach-object {
            $Classification = $_
            $Classification | where-object { $DefenderRbacAssignment.RoleAssignmentScopeId -like $Classification.RoleAssignmentScopeName -and $DefenderRbacAssignment.RoleAssignmentScopeId -notcontains $Classification.ExcludedRoleAssignmentScopeName }
        }

        # Check if role action and scope exists in JSON definition
        $DefenderRoleActionsInJsonDefinition = @()
        $DefenderRoleActionsInJsonDefinition = foreach ($Action in $DefenderRoleActions.rolePermissions.allowedResourceActions) {
            $MatchedClassificationByScope | Where-Object { $_.RoleDefinitionActions -Contains $Action -and $Classification.ExcludedRoleDefinitionActions -notcontains $_.RoleDefinitionActions }
        }

        if (($DefenderRoleActionsInJsonDefinition.Count -gt 0)) {
            $ClassifiedDefenderMgmtRbacRoleWithActions = @()
            foreach ($DefenderRoleAction in $DefenderRoleActions.rolePermissions.allowedResourceActions) {
                $ClassifiedDefenderMgmtRbacRoleWithActions += $DefenderResourcesByClassificationJSON | Where-Object { $DefenderRoleAction -in $_.RoleDefinitionActions -and $_.RoleAssignmentScopeName -contains $DefenderRbacAssignment.RoleAssignmentScopeId -and $_.ExcludedRoleAssignmentScopeName -notcontains $DefenderRbacAssignment.RoleAssignmentScopeId }
            }
            $ClassifiedDefenderMgmtRbacRoleWithActions = $ClassifiedDefenderMgmtRbacRoleWithActions | select-object -Unique EAMTierLevelName, EAMTierLevelTagValue, Service
            $Classification = $ClassifiedDefenderMgmtRbacRoleWithActions | ForEach-Object {
                [PSCustomObject]@{
                    'AdminTierLevel'     = $_.EAMTierLevelTagValue
                    'AdminTierLevelName' = $_.EAMTierLevelName
                    'Service'            = $_.Service
                    'TaggedBy'           = "JSONwithAction"
                }
            }

            [PSCustomObject]@{
                'RoleDefinitionId'      = $DefenderRbacAssignment.RoleDefinitionId
                'RoleAssignmentScopeId' = $DefenderRbacAssignment.RoleAssignmentScopeId
                'Classification'        = $Classification
            }
        } else {
            $ClassifiedDefenderMgmtRbacRoleWithActions = @()
        }
    }
    #endregion

    #region Classify all assigned privileged users and groups in Device Management
    $DefenderRbacClassifications = foreach ($DefenderRbacAssignment in $DefenderRbacAssignments) {
        $DefenderRbacAssignment = $DefenderRbacAssignment | Select-Object -ExcludeProperty Classification
        $Classification = @()
        $Classification += ($DefenderRbacClassificationsByAssignedObjects | Where-Object { $_.RoleAssignmentScopeId -contains $DefenderRbacAssignment.RoleAssignmentScopeId }).Classification
        $Classification += ($DefenderRbacClassificationsByJSON | Where-Object { $_.RoleAssignmentScopeId -contains $DefenderRbacAssignment.RoleAssignmentScopeId -and $_.RoleDefinitionId -eq $DefenderRbacAssignment.RoleDefinitionId }).Classification
        $Classification = $Classification | select-object -Unique AdminTierLevel, AdminTierLevelName, Service, TaggedBy | Sort-Object AdminTierLevel, AdminTierLevelName, Service, TaggedBy
        $DefenderRbacAssignment | Add-Member -NotePropertyName "Classification" -NotePropertyValue $Classification -Force
        $DefenderRbacAssignment
    }
    #endregion

    #region Apply classification to all assigned privileged users and groups in Device Management
    Write-Host "Classifiying of all assigned privileged users and groups in Device Management..."
    $DefenderRbacClassifiedObjects = $DefenderRbacAssignments | select-object -Unique ObjectId, ObjectType | ForEach-Object {
        if ($null -ne $_.ObjectId) {

            # Object types
            $ObjectId = $_.ObjectId
            $ObjectDetails = Get-EntraOpsPrivilegedEntraObject -AadObjectId $ObjectId -TenantId $TenantId

            # RBAC Assignments
            $DefenderRbacClassifiedAssignments = @()
            $DefenderRbacClassifiedAssignments += ($DefenderRbacClassifications | Where-Object { $_.ObjectId -eq "$ObjectId" })

            # Classification
            $Classification = @()
            $Classification += (($DefenderRbacClassifiedAssignments).Classification | select-object -Unique AdminTierLevel, AdminTierLevelName, Service) | Sort-Object AdminTierLevel, AdminTierLevelName, Service
            if ($Classification.Count -eq 0) {
                $Classification += [PSCustomObject]@{
                    'AdminTierLevel'     = "Unclassified"
                    'AdminTierLevelName' = "Unclassified"
                    'Service'            = "Unclassified"
                }
            }

            [PSCustomObject]@{
                'ObjectId'                      = $ObjectId
                'ObjectType'                    = $ObjectDetails.ObjectType.ToLower()
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
                'RoleSystem'                    = "Defender"
                'Classification'                = $Classification
                'RoleAssignments'               = $DefenderRbacClassifiedAssignments
                'Owners'                        = $ObjectDetails.Owners
                'OwnedObjects'                  = $ObjectDetails.OwnedObjects
                'OwnedDevices'                  = $ObjectDetails.OwnedDevices
                'AssociatedWorkAccount'         = $ObjectDetails.AssociatedWorkAccount
                'AssociatedPawDevice'           = $ObjectDetails.AssociatedPawDevice
            }
        }
    }
    #endregion
    $DefenderRbacClassifiedObjects | Where-Object { $GlobalExclusionList -notcontains $_.ObjectId } | Sort-Object ObjectAdminTierLevel, ObjectDisplayName
}