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

    # Configuration for batch processing
    $BatchSize = 100  # Number of objects to process before showing progress

    # Check if classification file custom and/or template file exists, choose custom template for tenant if available
    $ClassificationFileName = "Classification_IdentityGovernance.json"
    if (Test-Path -Path "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)") {
        $IdGovClassificationFilePath = "$($DefaultFolderClassification)/$($TenantNameContext)/$($ClassificationFileName)"
    } elseif (Test-Path -Path "$($DefaultFolderClassification)/Templates/$($ClassificationFileName)") {
        $IdGovClassificationFilePath = "$($DefaultFolderClassification)/Templates/$($ClassificationFileName)"
    } else {
        Write-Error "Classification file $($ClassificationFileName) not found in $($DefaultFolderClassification). Please run Update-EntraOpsClassificationFiles to download the latest classification files from AzurePrivilegedIAM repository."
    }

    # Default classification for Entra ID roles if no classified role definition found
    $EntraRolesDefaultClassification = Invoke-RestMethod -Method Get -Uri "https://raw.githubusercontent.com/Cloud-Architekt/AzurePrivilegedIAM/refs/heads/main/Classification/Classification_EntraIdDirectoryRoles.json"

    # Classification for API permissions
    $AppRolesClassification = Get-Content -Path $($FolderClassification + "Templates/Classification_AppRoles.json") | ConvertFrom-Json -Depth 10

    # Get all role assignments and global exclusions
    Write-Host "Getting Microsoft Entra ID Governance information..."

    if ($SampleMode -ne $True) {
        $IdGovRbacAssignments = Get-EntraOpsPrivilegedIdGovRoles -TenantId $TenantId
    } else {
        Write-Warning "Currently not supported!"
    }

    if ($GlobalExclusion -eq $true) {
        $GlobalExclusionList = (Get-Content -Path "$DefaultFolderClassification/Global.json" | ConvertFrom-Json -Depth 10).ExcludedPrincipalId
    } else {
        $GlobalExclusionList = $null
    }
    #endregion

    #region Classification of assignments
    Write-Host "Classifiying of all Identity Governance assignments by classification of assigned and classified catalog objects"
    $IdGovRbacScopes = $IdGovRbacAssignments | Select-Object -Unique RoleAssignmentScopeId
    $IdGovRbacClassificationsByAssignedObjects = New-Object System.Collections.Generic.List[psobject]
    foreach ($IdGovRbacScope in $IdGovRbacScopes) {
        $CurrentRoleAssignmentScope = $IdGovRbacScope.RoleAssignmentScopeId
        Write-Verbose -Message "Classify assignment scope $($CurrentRoleAssignmentScope)"

        if ($CurrentRoleAssignmentScope -like "/AccessPackageCatalog/*") {
            # Get all objects assigned to Access Package Catalog
            $AccessPackageCatalogId = $CurrentRoleAssignmentScope.Replace("/AccessPackageCatalog/", "")
            $AssignedCatalogResources = Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/entitlementManagement/accessPackageCatalogs/$($AccessPackageCatalogId)/accessPackageResources?`$expand=accessPackageResourceScopes,accessPackageResourceRoles" -ConsistencyLevel "eventual" | Where-Object { $null -ne $_.originId }
            Write-Verbose -Message "Found $($AssignedCatalogResources.Count) assigned catalog resources in catalog $($AccessPackageCatalogId)"
            $MatchedClassificationToCatalogResources = New-Object System.Collections.Generic.List[psobject]
            foreach ($AssignedCatalogResource in $AssignedCatalogResources) {
                # Get classification object of the object from all or filtered RBAC system
                switch ($AssignedCatalogResource.originSystem) {

                    'AadGroup' {
                        Write-Verbose -Message "Classifying assigned catalog object $($AssignedCatalogResource.displayName) from origin system $($AssignedCatalogResource.originSystem) by $FilterClassifiedRbacs"
                        foreach ($RbacSystem in $FilterClassifiedRbacs) {
                            $ClassificationSource = $FolderClassifiedObjects + $RbacSystem + "/" + $RbacSystem + ".json"
                            $ClassifiedObject = Get-Content -Path $ClassificationSource -ErrorAction SilentlyContinue | ConvertFrom-Json -Depth 10 | Where-Object { $_.ObjectId -eq $AssignedCatalogResource.originId }
                            if ($null -ne $($ClassifiedObject.Classification)) {
                                $MatchedRbacClassification = $ClassifiedObject.Classification
                                $MatchedRbacClassification | Add-Member -NotePropertyName "TaggedBy" -NotePropertyValue "Assigned$($AssignedCatalogResource.originSystem)" -Force
                                $MatchedClassificationToCatalogResources.Add($MatchedRbacClassification) | Out-Null
                            } else {
                                Write-Verbose "No classification for $($AssignedCatalogResource.displayName) $($AssignedCatalogResource.id) found in $RbacSystem or file $ClassificationSource is missing!"
                            }
                        }
                    } 'DirectoryRole' {
                        Write-Verbose -Message "Classifying assigned catalog object $($AssignedCatalogResource.displayName) from origin system $($AssignedCatalogResource.originSystem) by EntraID"
                        $ClassificationSource = $FolderClassifiedObjects + "EntraID/EntraID.json"
                        # Get classification from EntraID roles only on root scope, as directory roles can be only assigned in Entitlement Management on root scope
                        if ($AssignedCatalogResource.accessPackageResourceScopes.isRootScope -ne $true) {
                            Write-Verbose -Message "Assigned catalog resource scope is root scope, get classification from EntraID roles"
                        } else {
                            Write-Warning "Assigned catalog resource scope is not root scope, directory roles are currently only supported on root scope!"
                        }
                        $AllRbacClassification = (Get-Content -Path $ClassificationSource -ErrorAction SilentlyContinue | ConvertFrom-Json -Depth 10).RoleAssignments
                        $Classification = ($AllRbacClassification | Where-Object { $_.RoleAssignmentScopeId -eq "/" -and $_.RoleDefinitionId -eq $AssignedCatalogResource.originId } | Select-Object -First 1).Classification
                        if ($Null -eq $Classification) {
                            Write-Warning "No classification for $($AssignedCatalogResource.displayName) $($AssignedCatalogResource.id) found in EntraID or file $ClassificationSource is missing! Fallback to default classification from AzurePrivilegedIAM repository."
                            $DefaultRoleClassification = ($EntraRolesDefaultClassification | Where-Object { $_.RoleId -eq $AssignedCatalogResource.originId } | Select-Object -First 1).RolePermissions | Select-Object -Unique EAMTierLevelTagValue, EAMTierLevelName, Category
                            $Classification = $DefaultRoleClassification | foreach-object {
                                [PSCustomObject]@{
                                    'AdminTierLevel'     = $_.EAMTierLevelTagValue
                                    'AdminTierLevelName' = $_.EAMTierLevelName
                                    'Service'            = $_.Category | Select-Object -First 1
                                }
                            }
                        }
                        if ($Null -eq $Classification.AdminTierLevel) {
                            Write-Warning "No default classification for $($AssignedCatalogResource.displayName) $($AssignedCatalogResource.id) found in AzurePrivilegedIAM repository!"
                            $Classification = [PSCustomObject]@{
                                'AdminTierLevel'     = "Unclassified"
                                'AdminTierLevelName' = "Unclassified"
                                'Service'            = "Unclassified"
                            }
                        }
                        $Classification | Add-Member -NotePropertyName "TaggedBy" -NotePropertyValue "Assigned$($AssignedCatalogResource.originSystem)Resource" -Force
                        $MatchedClassificationToCatalogResources.Add($Classification) | Out-Null
                    } 'OAuthApplication' {
                        Write-Verbose -Message "Classifying assigned catalog object $($AssignedCatalogResource.displayName) from origin system $($AssignedCatalogResource.originSystem) by Graph API App roles"
                        $Classification = foreach ($AppRoleScope in $AssignedCatalogResource.accessPackageResourceRoles) {
                            $AppRoleClassification = ($AppRolesClassification | Where-Object { $_.TierLevelDefinition.RoleDefinitionActions -eq $AppRoleScope.displayName -and $_.TierLevelDefinition.ResourceAppId -eq $AssignedCatalogResource.originId }) | Select-Object EAMTierLevelName, EAMTierLevelTagValue
                            $AppRoleService = ($AppRolesClassification.TierLevelDefinition | Where-Object { $_.RoleDefinitionActions -eq $AppRoleScope.displayName -and $_.ResourceAppId -eq $AssignedCatalogResource.originId }) | Select-Object Service
                            if ($Null -ne $AppRoleClassification) {
                                [PSCustomObject]@{
                                    'AdminTierLevel'     = $AppRoleClassification.EAMTierLevelTagValue
                                    'AdminTierLevelName' = $AppRoleClassification.EAMTierLevelName
                                    'Service'            = $AppRoleService.Service
                                    'TaggedBy'           = "Assigned$($AssignedCatalogResource.originSystem)Resource"
                                }
                            } else {
                                Write-Warning "No classification for app role $($AppRoleScope.displayName) of application $($AssignedCatalogResource.displayName) $($AssignedCatalogResource.id) found in App Roles classification!"
                                [PSCustomObject]@{
                                    'AdminTierLevel'     = "Unclassified"
                                    'AdminTierLevelName' = "Unclassified"
                                    'Service'            = "Unclassified"
                                    'TaggedBy'           = "Assigned$($AssignedCatalogResource.originSystem)Resource"
                                }
                            }
                        }
                        $MatchedClassificationToCatalogResources.Add($Classification) | Out-Null
                    } default { Write-Warning "Origin system $($AssignedCatalogResource.originSystem) not supported for classification!" }
                }                
            }
        } elseif ($CurrentRoleAssignmentScope -eq "/") {
            Write-Warning "Skipping root scope, currently only delegated roles of catalog creator and connected organization admin available."
        } else {
            Write-Error "Invalid scope $CurrentRoleAssignmentScopeId"
        }

        if ([string]::IsNullOrEmpty -ne $MatchedClassificationToCatalogResources -and [string]::IsNullOrEmpty -ne $CurrentRoleAssignmentScope) {
            $Classification = $($MatchedClassificationToCatalogResources | ForEach-Object { $_ }) | Sort-Object AdminTierLevel, AdminTierLevelName, Service, TaggedBy | Select-Object -Unique *
            $IdGovRbacClassificationsByAssignedObject = [PSCustomObject]@{
                'RoleAssignmentScopeId' = $CurrentRoleAssignmentScope
                'Classification'        = $Classification
            }
            $IdGovRbacClassificationsByAssignedObjects.Add($IdGovRbacClassificationsByAssignedObject) | Out-Null
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
        } else {
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
        } else {
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

    Write-Host "Classifying of all assigned privileged users and groups in Identity Governance..."

    # Optimization: Group assignments by ObjectId to avoid O(N^2) filtering
    $IdGovRbacByObject = $IdGovRbacClassifications | Group-Object ObjectId -AsHashTable -AsString

    # Optimization: Collect all unique ObjectIds and batch resolve details
    $UniqueObjects = $IdGovRbacAssignments | Select-Object -Unique ObjectId, ObjectType | Where-Object { $null -ne $_.ObjectId }
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

    $IdGovRbacClassifiedObjects = $UniqueObjects | ForEach-Object {
        if ($null -ne $_.ObjectId) {
            $ObjectId = $_.ObjectId
            if ($VerbosePreference -ne 'SilentlyContinue') {
                Write-Verbose -Message "Processing classifications for $($ObjectId)..."
            }
            
            # Object types
            $ObjectDetails = $ObjectDetailsCache[$ObjectId]
            
            # Skip if object details couldn't be retrieved
            if ($null -eq $ObjectDetails) {
                Write-Warning "Skipping object $ObjectId - failed to retrieve details"
                return
            }

            # RBAC Assignments
            $IdGovRbacClassifiedAssignments = $IdGovRbacByObject[$ObjectId]
            
            # Classification - use hashtable for unique aggregation
            $UniqueClassificationsHash = @{}
            foreach ($Assignment in $IdGovRbacClassifiedAssignments) {
                if ($null -ne $Assignment.Classification) {
                    foreach ($ClassItem in $Assignment.Classification) {
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
    
    Write-Host "Applying global exclusions and finalizing results..."
    $IdGovRbacClassifiedObjects = $IdGovRbacClassifiedObjects | Where-Object { $GlobalExclusionList -notcontains $_.ObjectId }
    
    Write-Host "Completed processing $($IdGovRbacClassifiedObjects.Count) privileged objects."
    $IdGovRbacClassifiedObjects | Where-Object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId } | Sort-Object ObjectAdminTierLevel, ObjectDisplayName
}