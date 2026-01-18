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

    # Configuration for batch processing
    $BatchSize = 100  # Number of objects to process before showing progress

    Write-Host "Get Entra ID role assignments..."

    #region Define sensitive role definitions without actions to classify
    $ControlPlaneRolesWithoutRoleActions = [System.Collections.Generic.List[object]]::new()
    $ControlPlaneRolesWithoutRoleActions.Add([PSCustomObject]@{
            "RoleId"  = 'd29b2b05-8046-44ba-8758-1e26182fcf32' # Directory Synchronization Accounts
            "Service" = 'Hybrid Identity Synchronization'
        }) | Out-Null
    $ControlPlaneRolesWithoutRoleActions.Add([PSCustomObject]@{
            "RoleId"  = "a92aed5d-d78a-4d16-b381-09adb37eb3b0" # On Premises Directory Sync Account
            "Service" = 'Hybrid Identity Synchronization'
        }) | Out-Null
    $ControlPlaneRolesWithoutRoleActions.Add([PSCustomObject]@{
            "RoleId"  = "9f06204d-73c1-4d4c-880a-6edb90606fd8" # Azure AD Joined Device Local Administrator
            "Service" = 'Global Endpoint Management'
        }) | Out-Null
    $ControlPlaneRolesWithoutRoleActions.Add([PSCustomObject]@{
            "RoleId"  = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" # Privileged Authentication Administrator
            "Service" = 'Privileged User Management'
        }) | Out-Null
    $ControlPlaneRolesWithoutRoleActions.Add([PSCustomObject]@{
            "RoleId"  = 'db506228-d27e-4b7d-95e5-295956d6615f' # Agent ID Administrator
            "Service" = 'Agent Identity'
        }) | Out-Null
    
    # Create hashtable lookup for faster access
    $ControlPlaneRolesLookup = @{}
    foreach ($Role in $ControlPlaneRolesWithoutRoleActions) {
        $ControlPlaneRolesLookup[$Role.RoleId] = $Role
    }

    #endregion

    #region Check if classification file custom and/or template file exists, choose custom template for tenant if available
    $ClassificationFileName = "Classification_AadResources.json"
    if (Test-Path -Path "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)") {
        $AadClassificationFilePath = "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)"
    } elseif (Test-Path -Path "$($DefaultFolderClassification)/Templates/$($ClassificationFileName)") {
        $AadClassificationFilePath = "$($DefaultFolderClassification)/Templates/$($ClassificationFileName)"
    } else {
        Write-Error "Classification file $($ClassificationFileName) not found in $($DefaultFolderClassification). Please run Update-EntraOpsClassificationFiles to download the latest classification files from AzurePrivilegedIAM repository."
    }
    #endregion

    #region Get all role assignments and global exclusions
    if ($SampleMode -eq $True) {
        $AadRbacAssignments = get-content -Path "$EntraOpsBaseFolder/Samples/AadRoleManagementAssignments.json" | ConvertFrom-Json -Depth 10
    } else {
        $AadRbacAssignments = Get-EntraOpsPrivilegedEntraIdRoles -TenantId $TenantId
    }

    if ($GlobalExclusion -eq $true) {
        $GlobalExclusionList = (Get-Content -Path "$DefaultFolderClassification/Global.json" | ConvertFrom-Json -Depth 10).ExcludedPrincipalId
    } else {
        $GlobalExclusionList = $null
    }
    #endregion

    #region Classification of assignments by JSON
    Write-Host "Classifiying of all Entra ID RBAC assignments by classification in JSON"
    $AadRbacClassifications = foreach ($AadRbacAssignment in $AadRbacAssignments) {

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
            'Classification'                = $null  # Will be set during classification processing
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
    } else {
        $AllAadRoleActions = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions" -OutputType PSObject)
    }

    # Optimization: Create lookup hashtables for role actions and classifications
    $RoleActionsLookup = @{}
    foreach ($RoleAction in $AllAadRoleActions) {
        if ($null -ne $RoleAction.DisplayName) {
            $RoleActionsLookup[$RoleAction.DisplayName] = $RoleAction
        }
    }
    
    # Create hashtable for action-to-classification mapping for O(1) lookups
    $ActionClassificationLookup = @{}
    foreach ($ClassificationItem in $AadResourcesByClassificationJSON) {
        $key = "$($ClassificationItem.RoleAssignmentScopeName)|$($ClassificationItem.RoleDefinitionActions)"
        if (-not $ActionClassificationLookup.ContainsKey($key)) {
            $ActionClassificationLookup[$key] = [System.Collections.Generic.List[object]]::new()
        }
        $ActionClassificationLookup[$key].Add($ClassificationItem)
    }
    #endregion

    #region Apply classification for all role definitions
    $AadRbacClassification = foreach ($CurrentAadRbacClassification in $AadRbacClassifications) {
        $CurrentRoleDefinitionName = $CurrentAadRbacClassification.RoleDefinitionName
        $AadRoleScope = $CurrentAadRbacClassification.RoleAssignmentScopeId

        # Get role actions for role definition using hashtable lookup
        $AadRoleActions = $RoleActionsLookup["$($CurrentRoleDefinitionName)"]

        # Check if RBAC scope is listed in JSON by wildcard in RoleAssignmentScopeName
        $MatchedClassificationByScope = [System.Collections.Generic.List[object]]::new()
        foreach ($Classification in $AadResourcesByClassificationJSON) {
            if ($AadRoleScope -like $Classification.RoleAssignmentScopeName -and $AadRoleScope -notin $Classification.ExcludedRoleAssignmentScopeName) {
                $MatchedClassificationByScope.Add($Classification)
            }
        }

        # Check if role action and scope exists in JSON definition using optimized lookup
        $AadRoleActionsInJsonDefinition = [System.Collections.Generic.List[object]]::new()
        if ($null -ne $AadRoleActions -and $null -ne $AadRoleActions.rolePermissions) {
            foreach ($Action in $AadRoleActions.rolePermissions.allowedResourceActions) {
                # Use hashtable lookup for faster matching when possible
                foreach ($MatchedClassification in $MatchedClassificationByScope) {
                    if ($MatchedClassification.RoleDefinitionActions -Contains $Action -and $MatchedClassification.ExcludedRoleDefinitionActions -notcontains $Action) {
                        $AadRoleActionsInJsonDefinition.Add($MatchedClassification)
                    }
                }
            }
        }

        $CurrentAadRbacClassification.Classification = [System.Collections.Generic.List[object]]::new()

        if ($ControlPlaneRolesLookup.ContainsKey($CurrentAadRbacClassification.RoleDefinitionId)) {
            Write-Warning "Apply classification for role $($CurrentAadRbacClassification.RoleDefinitionName) without role actions..."
            $ControlPlaneRole = $ControlPlaneRolesLookup[$CurrentAadRbacClassification.RoleDefinitionId]
            $ClassifiedAadRbacRoleWithoutActions = [PSCustomObject]@{
                'AdminTierLevel'     = "0"
                'AdminTierLevelName' = "ControlPlane"
                'Service'            = $ControlPlaneRole.Service
                'TaggedBy'           = "ControlPlaneWithoutRoleActions"
            }
            $CurrentAadRbacClassification.Classification.Add($ClassifiedAadRbacRoleWithoutActions) | Out-Null
        }        

        if ($AadRoleActionsInJsonDefinition.Count -gt 0) {
            # Use hashtable to track unique combinations for better performance
            $UniqueClassifications = @{}
            foreach ($Item in $AadRoleActionsInJsonDefinition) {
                $key = "$($Item.EAMTierLevelTagValue)|$($Item.EAMTierLevelName)|$($Item.Service)"
                if (-not $UniqueClassifications.ContainsKey($key)) {
                    $UniqueClassifications[$key] = [PSCustomObject]@{
                        'EAMTierLevelTagValue' = $Item.EAMTierLevelTagValue
                        'EAMTierLevelName'     = $Item.EAMTierLevelName
                        'Service'              = $Item.Service
                    }
                }
            }
            
            # Sort and add to classification
            $SortedClassifications = $UniqueClassifications.Values | Sort-Object EAMTierLevelTagValue, Service
            foreach ($Item in $SortedClassifications) {
                $ClassifiedRoleAction = [PSCustomObject]@{
                    'AdminTierLevel'     = $Item.EAMTierLevelTagValue
                    'AdminTierLevelName' = $Item.EAMTierLevelName
                    'Service'            = $Item.Service
                    'TaggedBy'           = "JSONwithAction"
                }
                $CurrentAadRbacClassification.Classification.Add($ClassifiedRoleAction) | Out-Null
            }
        }     

        $CurrentAadRbacClassification 
    }
    #endregion

    #region Apply classification on all principals
    Write-Host "Classifying of all assigned privileged users and groups to Entra ID roles..."

    # Optimization: Group assignments by ObjectId to avoid O(N^2) filtering in loop
    $RbacAssignmentsByObject = $AadRbacClassification | Group-Object ObjectId -AsHashTable -AsString

    # Optimization: Collect all unique ObjectIds and batch resolve details
    $UniqueObjects = $AadRbacClassification | Select-Object -Unique ObjectId, ObjectType | Where-Object { $null -ne $_.ObjectId }
    $UniqueObjectIds = $UniqueObjects.ObjectId
    
    Write-Host "Resolving details for $($UniqueObjectIds.Count) unique objects..."
    $ObjectDetailsCache = @{}
    
    # Batch resolution with progress reporting
    for ($i = 0; $i -lt $UniqueObjectIds.Count; $i++) {
        $ObjectId = $UniqueObjectIds[$i]
        
        # Update progress more frequently for better UX (every 10 items or 5%, whichever is less frequent)
        $ProgressInterval = [Math]::Max(10, [Math]::Floor($UniqueObjectIds.Count / 20))
        if (($i % $ProgressInterval) -eq 0 -or $i -eq ($UniqueObjectIds.Count - 1)) {
            $PercentComplete = [math]::Round(($i / $UniqueObjectIds.Count) * 100, 0)
            Write-Progress -Activity "Resolving Object Details" -Status "Processing object $($i + 1) of $($UniqueObjectIds.Count)" -PercentComplete $PercentComplete
            if ($VerbosePreference -ne 'SilentlyContinue') {
                Write-Verbose "Processing object $($i + 1) of $($UniqueObjectIds.Count)..."
            }
        }
        
        try {
            $ObjectDetailsCache[$ObjectId] = Get-EntraOpsPrivilegedEntraObject -AadObjectId $ObjectId -TenantId $TenantId
        } catch {
            Write-Warning "Failed to get details for object $($ObjectId): $_"
            $ObjectDetailsCache[$ObjectId] = $null
        }
    }
    Write-Progress -Activity "Resolving Object Details" -Completed

    $AadRbacClassifiedObjects = $UniqueObjects | ForEach-Object {
        if ($null -ne $_.ObjectId) {
            $ObjectId = $_.ObjectId
            if ($VerbosePreference -ne 'SilentlyContinue') {
                Write-Verbose -Message "Processing classifications for $($ObjectId)..."
            }
            # Object types
            $ObjectType = $_.ObjectType
            $ObjectDetails = $ObjectDetailsCache[$ObjectId]
            
            # Skip if object details couldn't be retrieved
            if ($null -eq $ObjectDetails) {
                Write-Warning "Skipping object $ObjectId - failed to retrieve details"
                return
            }

            # RBAC Assignments
            $AllAadRbacEntriesOfObject = $RbacAssignmentsByObject[$ObjectId]

            # Classification - use hashtable for unique aggregation
            $UniqueClassificationsHash = @{}
            foreach ($Entry in $AllAadRbacEntriesOfObject) {
                if ($null -ne $Entry.Classification) {
                    foreach ($ClassItem in $Entry.Classification) {
                        $key = "$($ClassItem.AdminTierLevel)|$($ClassItem.AdminTierLevelName)|$($ClassItem.Service)"
                        if (-not $UniqueClassificationsHash.ContainsKey($key)) {
                            $UniqueClassificationsHash[$key] = $ClassItem
                        }
                    }
                }
            }
            
            $Classification = @($UniqueClassificationsHash.Values | Sort-Object AdminTierLevel, AdminTierLevelName, Service)
            
            if ($Classification.Count -eq 0) {
                $Classification = @([PSCustomObject]@{
                        'AdminTierLevel'     = "Unclassified"
                        'AdminTierLevelName' = "Unclassified"
                        'Service'            = "Unclassified"
                    })
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
                'Sponsors'                      = $ObjectDetails.Sponsors
                'Owners'                        = $ObjectDetails.Owners
                'OwnedObjects'                  = $ObjectDetails.OwnedObjects
                'OwnedDevices'                  = $ObjectDetails.OwnedDevices
                'IdentityParent'                = $ObjectDetails.IdentityParent                
                'AssociatedWorkAccount'         = $ObjectDetails.AssociatedWorkAccount
                'AssociatedPawDevice'           = $ObjectDetails.AssociatedPawDevice
            }
        }
    }
    #endregion
    
    Write-Host "Applying global exclusions and finalizing results..."
    $EamEntraId = $AadRbacClassifiedObjects | Where-Object { $GlobalExclusionList -notcontains $_.ObjectId }
    
    Write-Host "Completed processing $($EamEntraId.Count) privileged objects."
    $EamEntraId | Where-Object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId } | Sort-Object ObjectAdminTierLevel, ObjectDisplayName
}
