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
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$EnableParallelProcessing = $true
        ,
        [Parameter(Mandatory = $false)]
        [System.Int32]$ParallelThrottleLimit = 10
    )

    # Configuration for batch processing
    $BatchSize = 100  # Number of objects to process before showing progress
    $WarningMessages = New-Object -TypeName "System.Collections.Generic.List[psobject]"

    # Check if classification file custom and/or template file exists, choose custom template for tenant if available
    $IdGovClassificationFilePath = Resolve-EntraOpsClassificationPath -ClassificationFileName "Classification_IdentityGovernance.json"

    # Default classification for Entra ID roles if no classified role definition found
    $EntraRolesDefaultClassification = Invoke-RestMethod -Method Get -Uri "https://raw.githubusercontent.com/Cloud-Architekt/AzurePrivilegedIAM/refs/heads/main/Classification/Classification_EntraIdDirectoryRoles.json"

    # Classification for API permissions
    $AppRolesClassification = Get-Content -Path $($FolderClassification + "/Templates/Classification_AppRoles.json") | ConvertFrom-Json -Depth 10

    # Get all role assignments and global exclusions
    #region Stage 1: Fetch Identity Governance Assignments
    $Stage1Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 1/4: Fetching Identity Governance Assignments" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Retrieving Identity Governance role assignments, catalogs, and access packages..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 1/4: Fetching Identity Governance" -Status "Loading role assignments and global exclusions..." -PercentComplete 10

    if ($SampleMode -ne $True) {
        $IdGovRbacAssignments = Get-EntraOpsPrivilegedIdGovRoles -TenantId $TenantId -WarningMessages $WarningMessages
    } else {
        $WarningMessages.Add([PSCustomObject]@{Type = "Stage1"; Message = "SampleMode currently not supported!" })
    }

    $GlobalExclusionList = Import-EntraOpsGlobalExclusions -Enabled $GlobalExclusion
    
    $Stage1Duration = ((Get-Date) - $Stage1Start).TotalSeconds
    Write-Host "✓ Stage 1 completed in $([Math]::Round($Stage1Duration, 2)) seconds ($($IdGovRbacAssignments.Count) role assignments retrieved)" -ForegroundColor Green
    Write-Progress -Activity "Stage 1/4: Fetching Identity Governance" -Completed
    #endregion

    # Return early if no role assignments found to prevent null index errors
    if ($null -eq $IdGovRbacAssignments -or @($IdGovRbacAssignments).Count -eq 0) {
        Write-Warning "No Identity Governance role assignments found. Returning empty result."
        return @()
    }

    #region Classification of assignments
    #region Stage 2: Classify Catalog Objects
    $Stage2Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 2/4: Classifying Catalog Objects" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Analyzing assigned catalog resources (groups, directory roles, app roles) and matching classifications..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 2/4: Classifying Catalog Objects" -Status "Processing catalog resources..." -PercentComplete 25
    
    # Optimization: Pre-load classification files into memory to avoid N+1 File I/O
    $ClassificationCache = @{}
    foreach ($RbacSystem in $FilterClassifiedRbacs) {
        $ClassificationSource = $FolderClassifiedObjects + $RbacSystem + "/" + $RbacSystem + ".json"
        if (Test-Path $ClassificationSource) {
            Write-Verbose "Pre-loading classification file from $ClassificationSource..."
            try {
                $ClassificationCache[$RbacSystem] = Get-Content -Path $ClassificationSource -ErrorAction SilentlyContinue | ConvertFrom-Json -Depth 10
            } catch {
                $WarningMessages.Add([PSCustomObject]@{Type = "Stage2"; Message = "Failed to load classification file $($ClassificationSource): $_" })
            }
        }
    }
    # Pre-load EntraID roles specifically for DirectoryRole lookups
    $EntraIdClassificationSource = $FolderClassifiedObjects + "EntraID/EntraID.json"
    if (Test-Path $EntraIdClassificationSource) {
        try {
            $ClassificationCache["EntraIDRoles"] = (Get-Content -Path $EntraIdClassificationSource | ConvertFrom-Json -Depth 10).RoleAssignments
        } catch {
            $WarningMessages.Add([PSCustomObject]@{Type = "Stage2"; Message = "Failed to load EntraID classification: $_" })
        }
    }

    # Optimization: Build hashtable lookup for App Role classifications
    $AppRoleClassLookup = @{}
    foreach ($AppRoleClass in $AppRolesClassification) {
        foreach ($RoleDef in $AppRoleClass.TierLevelDefinition) {
            foreach ($RoleAction in $RoleDef.RoleDefinitionActions) {
                $key = "$($RoleDef.ResourceAppId)|$($RoleAction)"
                if (-not $AppRoleClassLookup.ContainsKey($key)) {
                    $AppRoleClassLookup[$key] = @{
                        EAMTierLevelName     = $AppRoleClass.EAMTierLevelName
                        EAMTierLevelTagValue = $AppRoleClass.EAMTierLevelTagValue
                        Service              = $RoleDef.Service
                    }
                }
            }
        }
    }

    # Warning Collection (continued from earlier stages)
    # Note: Do not reinitialize $WarningMessages here to preserve Stage 1 warnings

    $IdGovRbacScopes = $IdGovRbacAssignments | Select-Object -Unique RoleAssignmentScopeId
    $IdGovRbacClassificationsByAssignedObjects = New-Object System.Collections.Generic.List[psobject]
    foreach ($IdGovRbacScope in $IdGovRbacScopes) {
        $CurrentRoleAssignmentScope = $IdGovRbacScope.RoleAssignmentScopeId
        Write-Verbose -Message "Classify assignment scope $($CurrentRoleAssignmentScope)"

        if ($CurrentRoleAssignmentScope -like "/AccessPackageCatalog/*") {
            # Get all objects assigned to Access Package Catalog
            $AccessPackageCatalogId = $CurrentRoleAssignmentScope.Replace("/AccessPackageCatalog/", "")
            
            # Suppress warnings for expected 404s (Deleted Catalogs)
            try {
                $RawCatalogResources = Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/entitlementManagement/accessPackageCatalogs/$($AccessPackageCatalogId)/accessPackageResources?`$expand=accessPackageResourceScopes,accessPackageResourceRoles" -ConsistencyLevel "eventual" -WarningAction SilentlyContinue
                
                if ($null -eq $RawCatalogResources) {
                    # Log warning if catalog not found (Invoke-EntraOpsMsGraphQuery returns null on failure)
                    $WarningMessages.Add([PSCustomObject]@{
                            Type    = "CatalogResolution"
                            Message = "Access Package Catalog $AccessPackageCatalogId not found (likely deleted)."
                            Target  = $AccessPackageCatalogId
                        })
                    $AssignedCatalogResources = @()
                } else {
                    $AssignedCatalogResources = $RawCatalogResources | Where-Object { $null -ne $_.originId }
                }
            } catch {
                # Catch script errors
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "CatalogResolutionError"
                        Message = "Error resolving catalog ${AccessPackageCatalogId}: $($_.Exception.Message)"
                        Target  = $AccessPackageCatalogId
                    })
                $AssignedCatalogResources = @()
            }
            
            Write-Verbose -Message "Found $($AssignedCatalogResources.Count) assigned catalog resources in catalog $($AccessPackageCatalogId)"
            $MatchedClassificationToCatalogResources = New-Object System.Collections.Generic.List[psobject]
            foreach ($AssignedCatalogResource in $AssignedCatalogResources) {
                # Get classification object of the object from all or filtered RBAC system
                switch ($AssignedCatalogResource.originSystem) {

                    'AadGroup' {
                        Write-Verbose -Message "Classifying assigned catalog object $($AssignedCatalogResource.displayName) from origin system $($AssignedCatalogResource.originSystem) by $FilterClassifiedRbacs"
                        foreach ($RbacSystem in $FilterClassifiedRbacs) {
                            # Optimization: Use In-Memory Cache
                            if ($ClassificationCache.ContainsKey($RbacSystem)) {
                                $ClassifiedObject = $ClassificationCache[$RbacSystem] | Where-Object { $_.ObjectId -eq $AssignedCatalogResource.originId }
                                if ($null -ne $($ClassifiedObject.Classification)) {
                                    $MatchedRbacClassification = $ClassifiedObject.Classification
                                    foreach ($ClassItem in $MatchedRbacClassification) {
                                        $ClassItem | Add-Member -NotePropertyName "TaggedBy"                   -NotePropertyValue "Assigned$($AssignedCatalogResource.originSystem)" -Force
                                        $ClassItem | Add-Member -NotePropertyName "TaggedByObjectIds"          -NotePropertyValue @($AssignedCatalogResource.originId)               -Force
                                        $ClassItem | Add-Member -NotePropertyName "TaggedByObjectDisplayNames" -NotePropertyValue @($AssignedCatalogResource.displayName)            -Force
                                        $MatchedClassificationToCatalogResources.Add($ClassItem) | Out-Null
                                    }
                                } else {
                                    Write-Verbose "No classification for $($AssignedCatalogResource.displayName) $($AssignedCatalogResource.id) found in $RbacSystem"
                                }
                            }
                        }
                    } 'DirectoryRole' {
                        Write-Verbose -Message "Classifying assigned catalog object $($AssignedCatalogResource.displayName) from origin system $($AssignedCatalogResource.originSystem) by EntraID"
                        # Get classification from EntraID roles only on root scope
                        if ($AssignedCatalogResource.accessPackageResourceScopes.isRootScope -eq $true) {
                            Write-Verbose -Message "Assigned catalog resource scope is root scope, get classification from EntraID roles"
                        } else {
                            $WarningMessages.Add([PSCustomObject]@{
                                    Type    = "Scope Limitation"
                                    Message = "Assigned catalog resource scope is not root scope, directory roles are currently only supported on root scope!"
                                    Target  = $AssignedCatalogResource.displayName
                                })
                        }
                        
                        # Optimization: Use In-Memory Cache for Directory Roles
                        $Classification = $null
                        if ($ClassificationCache.ContainsKey("EntraIDRoles")) {
                            $MatchedRole = $ClassificationCache["EntraIDRoles"] | Where-Object { $_.RoleAssignmentScopeId -eq "/" -and $_.RoleDefinitionId -eq $AssignedCatalogResource.originId } | Select-Object -First 1
                            if ($null -ne $MatchedRole) {
                                $Classification = $MatchedRole.Classification
                            }
                        }

                        if ($Null -eq $Classification) {
                            $WarningMessages.Add([PSCustomObject]@{
                                    Type    = "Default Classification Fallback"
                                    Message = "No classification for $($AssignedCatalogResource.displayName) ($($AssignedCatalogResource.id)) found in EntraID! Fallback to default."
                                    Target  = $AssignedCatalogResource.displayName
                                })
                            $MatchedDefaultRole = $EntraRolesDefaultClassification | Where-Object { $_.RoleId -eq $AssignedCatalogResource.originId } | Select-Object -First 1
                            if ($null -ne $MatchedDefaultRole -and $null -ne $MatchedDefaultRole.RolePermissions) {
                                $DefaultRoleClassification = $MatchedDefaultRole.RolePermissions | Select-Object -Unique EAMTierLevelTagValue, EAMTierLevelName, Category
                                $Classification = $DefaultRoleClassification | foreach-object {
                                    [PSCustomObject]@{
                                        'AdminTierLevel'     = $_.EAMTierLevelTagValue
                                        'AdminTierLevelName' = $_.EAMTierLevelName
                                        'Service'            = $_.Category | Select-Object -First 1
                                    }
                                }
                            }
                        }
                        if ($Null -eq $Classification.AdminTierLevel) {
                            $WarningMessages.Add([PSCustomObject]@{
                                    Type    = "Unclassified Resource"
                                    Message = "No default classification for $($AssignedCatalogResource.displayName) ($($AssignedCatalogResource.id)) found!"
                                    Target  = $AssignedCatalogResource.displayName
                                })
                            $Classification = [PSCustomObject]@{
                                'AdminTierLevel'     = "Unclassified"
                                'AdminTierLevelName' = "Unclassified"
                                'Service'            = "Unclassified"
                            }
                        }
                        $Classification | Add-Member -NotePropertyName "TaggedBy"                   -NotePropertyValue "Assigned$($AssignedCatalogResource.originSystem)Resource" -Force
                        $Classification | Add-Member -NotePropertyName "TaggedByObjectIds"          -NotePropertyValue @($AssignedCatalogResource.originId)                       -Force
                        $Classification | Add-Member -NotePropertyName "TaggedByObjectDisplayNames" -NotePropertyValue @($AssignedCatalogResource.displayName)                    -Force
                        $MatchedClassificationToCatalogResources.Add($Classification) | Out-Null
                    } 'OAuthApplication' {
                        Write-Verbose -Message "Classifying assigned catalog object $($AssignedCatalogResource.displayName) from origin system $($AssignedCatalogResource.originSystem) by Graph API App roles"
                        # Optimization: Already implemented lookups in previous step
                        
                        foreach ($AppRoleScope in $AssignedCatalogResource.accessPackageResourceRoles) {
                            $lookupKey = "$($AssignedCatalogResource.originId)|$($AppRoleScope.displayName)"
                            $AppRoleMatch = $AppRoleClassLookup[$lookupKey]
                            
                            if ($null -ne $AppRoleMatch) {
                                $Classification = [PSCustomObject]@{
                                    'AdminTierLevel'             = $AppRoleMatch.EAMTierLevelTagValue
                                    'AdminTierLevelName'         = $AppRoleMatch.EAMTierLevelName
                                    'Service'                    = $AppRoleMatch.Service
                                    'TaggedBy'                   = "Assigned$($AssignedCatalogResource.originSystem)Resource"
                                    'TaggedByObjectIds'          = @($AssignedCatalogResource.originId)
                                    'TaggedByObjectDisplayNames' = @($AssignedCatalogResource.displayName)
                                }
                                $MatchedClassificationToCatalogResources.Add($Classification) | Out-Null
                            } else {
                                $WarningMessages.Add([PSCustomObject]@{
                                        Type    = "Unclassified App Role"
                                        Message = "No classification for app role $($AppRoleScope.displayName) of application $($AssignedCatalogResource.displayName)"
                                        Target  = $AssignedCatalogResource.displayName
                                    })
                                $Classification = [PSCustomObject]@{
                                    'AdminTierLevel'             = "Unclassified"
                                    'AdminTierLevelName'         = "Unclassified"
                                    'Service'                    = "Unclassified"
                                    'TaggedBy'                   = "Assigned$($AssignedCatalogResource.originSystem)Resource"
                                    'TaggedByObjectIds'          = @($AssignedCatalogResource.originId)
                                    'TaggedByObjectDisplayNames' = @($AssignedCatalogResource.displayName)
                                }
                                $MatchedClassificationToCatalogResources.Add($Classification) | Out-Null
                            }
                        }
                    } default { 
                        $WarningMessages.Add([PSCustomObject]@{
                                Type    = "Unknown Origin System"
                                Message = "Origin system $($AssignedCatalogResource.originSystem) not supported for classification!"
                                Target  = $AssignedCatalogResource.originSystem
                            })
                    }
                }                
            }
        } elseif ($CurrentRoleAssignmentScope -eq "/") {
            $WarningMessages.Add([PSCustomObject]@{
                    Type    = "Scope Limitation"
                    Message = "Skipping root scope, currently only delegated roles of catalog creator and connected organization admin available."
                    Target  = "Root Scope"
                })
        } else {
            Write-Error "Invalid scope $CurrentRoleAssignmentScope"
        }

        if ($null -ne $MatchedClassificationToCatalogResources -and $null -ne $CurrentRoleAssignmentScope) {
            $Classification = $($MatchedClassificationToCatalogResources | ForEach-Object { $_ }) | Sort-Object AdminTierLevel, AdminTierLevelName, Service, TaggedBy | Select-Object -Unique *
            $IdGovRbacClassificationsByAssignedObject = [PSCustomObject]@{
                'RoleAssignmentScopeId' = $CurrentRoleAssignmentScope
                'Classification'        = $Classification
            }
            $IdGovRbacClassificationsByAssignedObjects.Add($IdGovRbacClassificationsByAssignedObject) | Out-Null
        }
    }
    
    $Stage2Duration = ((Get-Date) - $Stage2Start).TotalSeconds
    Write-Host "✓ Stage 2 completed in $([Math]::Round($Stage2Duration, 2)) seconds ($($IdGovRbacClassificationsByAssignedObjects.Count) catalog scopes classified)" -ForegroundColor Green
    Write-Progress -Activity "Stage 2/4: Classifying Catalog Objects" -Completed
    #endregion

    #region Stage 3: Classify Role Actions
    $Stage3Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 3/4: Classifying Role Actions" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Matching role definitions and actions against JSON classification rules..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 3/4: Classifying Role Actions" -Status "Reading classification file and matching role actions..." -PercentComplete 50
    $IdGovResourcesByClassificationJSON = Expand-EntraOpsPrivilegedEAMJsonFile -FilePath "$($IdGovClassificationFilePath)" | select-object EAMTierLevelName, EAMTierLevelTagValue, Category, Service, RoleAssignmentScopeName, ExcludedRoleAssignmentScopeName, RoleDefinitionActions, ExcludedRoleDefinitionActions
    $IdGovRbacClassificationsByJSON = @()

    # Optimization: Pre-fetch all Entitlement Management role definitions
    $IdGovRoleDefinitionsCache = @{}
    try {
        if ($SampleMode -ne $True) {
            Write-Verbose "Pre-fetching all Identity Governance role definitions..."
            $AllIdGovRoles = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/EntitlementManagement/roleDefinitions" -OutputType PSObject
            foreach ($Role in $AllIdGovRoles) {
                $IdGovRoleDefinitionsCache[$Role.Id] = $Role
            }
        }
    } catch {
        $WarningMessages.Add([PSCustomObject]@{
                Type    = "Pre-fetch Failure"
                Message = "Failed to pre-fetch Identity Governance role definitions: $_"
                Target  = "Role Definitions"
            })
    }

    $UniqueRoleDefs = $IdGovRbacAssignments | Select-Object -Unique RoleDefinitionId, RoleAssignmentScopeId
    $ProcessedCount = 0
    $TotalCount = $UniqueRoleDefs.Count

    $IdGovRbacClassificationsByJSON += foreach ($IdGovRbacAssignment in $UniqueRoleDefs) {
        $ProcessedCount++
        if ($ProcessedCount % 10 -eq 0) {
            Write-Progress -Activity "Stage 3/4: Classifying Role Actions" -Status "Classifying role definition $ProcessedCount of $TotalCount" -PercentComplete (50 + ($ProcessedCount / $TotalCount * 20))
        }

        # Role actions are defined for scope and role definition contains an action of the role, otherwise all role actions within role assignment scope will be applied
        if ($SampleMode -eq $True) {
            # Removed redundant warning
        } else {
            # Optimization: Use In-Memory Cache
            if ($IdGovRoleDefinitionsCache.ContainsKey("$($IdGovRbacAssignment.RoleDefinitionId)")) {
                $IdGovRoleActions = $IdGovRoleDefinitionsCache["$($IdGovRbacAssignment.RoleDefinitionId)"]
            } else {
                $IdGovRoleActions = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/EntitlementManagement/roleDefinitions" | Where-Object { $_.Id -eq "$($IdGovRbacAssignment.RoleDefinitionId)" }
            }
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
            $MatchedClassificationByScope | Where-Object { $_.RoleDefinitionActions -Contains $Action -and $_.ExcludedRoleDefinitionActions -notcontains $Action }
        }


        if (($IdGovRoleActionsInJsonDefinition.Count -gt 0)) {
            $ClassifiedIdGovRbacRoleWithActions = @()
            foreach ($IdGovRoleAction in $IdGovRoleActions.rolePermissions.allowedResourceActions) {
                $ClassifiedIdGovRbacRoleWithActions += $IdGovResourcesByClassificationJSON | Where-Object { $IdGovRoleAction -in $_.RoleDefinitionActions }
            }
            $ClassifiedIdGovRbacRoleWithActions = $ClassifiedIdGovRbacRoleWithActions | select-object -Unique EAMTierLevelName, EAMTierLevelTagValue, Service
            $Classification = $ClassifiedIdGovRbacRoleWithActions | ForEach-Object {
                [PSCustomObject]@{
                    'AdminTierLevel'             = $_.EAMTierLevelTagValue
                    'AdminTierLevelName'         = $_.EAMTierLevelName
                    'Service'                    = $_.Service
                    'TaggedBy'                   = "JSONwithAction"
                    'TaggedByObjectIds'          = $null
                    'TaggedByObjectDisplayNames' = $null
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
        $ClassificationCollection += ($IdGovRbacClassificationsByJSON | Where-Object { $_.RoleAssignmentScopeId -eq $IdGovRbacAssignment.RoleAssignmentScopeId -and $_.RoleDefinitionId -eq $IdGovRbacAssignment.RoleDefinitionId }).Classification
        $Classification = @()
        $Classification += $ClassificationCollection | select-object -Unique AdminTierLevel, AdminTierLevelName, Service, TaggedBy, TaggedByObjectIds, TaggedByObjectDisplayNames | Sort-Object -Unique AdminTierLevel, AdminTierLevelName, Service, TaggedBy
        $IdGovRbacAssignment | Add-Member -NotePropertyName "Classification" -NotePropertyValue $Classification -Force
        $IdGovRbacAssignment
    }
    
    $Stage3Duration = ((Get-Date) - $Stage3Start).TotalSeconds
    Write-Host "✓ Stage 3 completed in $([Math]::Round($Stage3Duration, 2)) seconds ($($IdGovRbacClassifications.Count) role assignments classified)" -ForegroundColor Green
    Write-Progress -Activity "Stage 3/4: Classifying Role Actions" -Completed
    #endregion

    #region Stage 4: Resolve and Finalize Objects
    $Stage4Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 4/4: Resolving Object Details and Finalizing" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Enriching principals with detailed attributes and applying exclusions..." -ForegroundColor Gray

    # Optimization: Group assignments by ObjectId to avoid O(N^2) filtering
    $IdGovRbacByObject = $IdGovRbacClassifications | Group-Object ObjectId -AsHashTable -AsString

    # Optimization: Collect all unique ObjectIds and batch resolve details
    $UniqueObjects = $IdGovRbacAssignments | Select-Object -Unique ObjectId, ObjectType | Where-Object { $null -ne $_.ObjectId }
    $ObjectDetailsCache = Invoke-EntraOpsParallelObjectResolution `
        -UniqueObjects $UniqueObjects `
        -TenantId $TenantId `
        -EnableParallelProcessing $EnableParallelProcessing `
        -ParallelThrottleLimit $ParallelThrottleLimit

    # Aggregate classifications and build output objects
    $IdGovRbacClassifiedObjects = Invoke-EntraOpsEAMClassificationAggregation `
        -UniqueObjects $UniqueObjects `
        -ObjectDetailsCache $ObjectDetailsCache `
        -RbacClassificationsByObject $IdGovRbacByObject `
        -RoleSystem "IdentityGovernance" `
        -EnableParallelProcessing $EnableParallelProcessing `
        -ParallelThrottleLimit $ParallelThrottleLimit `
        -WarningMessages $WarningMessages
    
    Write-Progress -Activity "Stage 4/4: Finalizing Results" -Status "Applying global exclusions and sorting..." -PercentComplete 90
    $IdGovRbacClassifiedObjects = $IdGovRbacClassifiedObjects | Where-Object { $GlobalExclusionList -notcontains $_.ObjectId }

    $Stage4Duration = ((Get-Date) - $Stage4Start).TotalSeconds
    $TotalDuration = ((Get-Date) - $Stage1Start).TotalSeconds
    
    Write-Progress -Activity "Stage 4/4: Finalizing Results" -Completed
    Write-Host "✓ Stage 4 completed in $([Math]::Round($Stage4Duration, 2)) seconds ($($IdGovRbacClassifiedObjects.Count) privileged objects after exclusions)" -ForegroundColor Green

    Show-EntraOpsWarningSummary -WarningMessages $WarningMessages

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✓ All Stages Completed Successfully" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "Total execution time: $([Math]::Round($TotalDuration, 2)) seconds" -ForegroundColor Gray
    Write-Host "Final result: $($IdGovRbacClassifiedObjects.Count) privileged objects ready for export" -ForegroundColor Gray
    #endregion
    
    $IdGovRbacClassifiedObjects | Where-Object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId } | Sort-Object ObjectAdminTierLevel, ObjectDisplayName
}