<#
.SYNOPSIS
    Get a list in schema of EntraOps with all privileged principals in Entra ID and assigned roles and classifications.

.DESCRIPTION
    Get a list in schema of EntraOps with all privileged principals in Entra ID and assigned roles and classifications.
    Supports parallel processing (PowerShell 7+) using Microsoft Graph SDK's process-level authentication context.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER FolderClassification
    Folder path to the classification definition files. Default is "./Classification".

.PARAMETER SampleMode
    Use sample data for testing or offline mode. Default is $False. Default sample data is stored in "./Samples"

.PARAMETER GlobalExclusion
    Use global exclusion list for classification. Default is $true. Global exclusion list is stored in "./Classification/Global.json".

.PARAMETER EnableParallelProcessing
    Enable parallel processing for object detail resolution. Default is $true. 
    Requires PowerShell 7+ and Microsoft Graph SDK authentication (not UseAzPwshOnly mode).
    Leverages MgGraph's process-level authentication context - no re-authentication needed in parallel threads.

.PARAMETER ParallelThrottleLimit
    Maximum number of parallel threads. Default is 10. Adjust based on API rate limits and system resources.

.EXAMPLE
    Get privileged principals with automatic parallel processing (PowerShell 7+)
    Get-EntraOpsPrivilegedEamEntraId

.EXAMPLE
    Disable parallel processing for sequential execution
    Get-EntraOpsPrivilegedEamEntraId -EnableParallelProcessing $false

.EXAMPLE
    Use parallel processing with reduced throttle limit to avoid API throttling
    Get-EntraOpsPrivilegedEamEntraId -ParallelThrottleLimit 5
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
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$EnableParallelProcessing = $true
        ,
        [Parameter(Mandatory = $false)]
        [System.Int32]$ParallelThrottleLimit = 20
    )

    # Configuration for batch processing
    $BatchSize = 100  # Number of objects to process before showing progress
    $WarningMessages = New-Object -TypeName "System.Collections.Generic.List[psobject]"

    #region Stage 1: Fetch Entra ID Role Assignments
    $Stage1Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 1/6: Fetching Entra ID Role Assignments" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Retrieving active and eligible role assignments and definitions from Microsoft Graph..." -ForegroundColor Gray

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
    Write-Progress -Activity "Stage 1/6: Fetching Role Assignments" -Status "Loading role assignments and global exclusions..." -PercentComplete 10
    
    if ($SampleMode -eq $True) {
        $AadRbacAssignments = get-content -Path "$EntraOpsBaseFolder/Samples/AadRoleManagementAssignments.json" | ConvertFrom-Json -Depth 10
    } else {
        $AadRbacAssignments = Get-EntraOpsPrivilegedEntraIdRoles -TenantId $TenantId -WarningMessages $WarningMessages
    }

    if ($GlobalExclusion -eq $true) {
        $GlobalExclusionList = (Get-Content -Path "$DefaultFolderClassification/Global.json" | ConvertFrom-Json -Depth 10).ExcludedPrincipalId
    } else {
        $GlobalExclusionList = $null
    }
    
    $Stage1Duration = ((Get-Date) - $Stage1Start).TotalSeconds
    Write-Host "✓ Stage 1 completed in $([Math]::Round($Stage1Duration, 2)) seconds ($($AadRbacAssignments.Count) role assignments retrieved)" -ForegroundColor Green
    Write-Progress -Activity "Stage 1/6: Fetching Role Assignments" -Completed
    #endregion

    #region Classification of assignments by JSON
    #region Stage 2: Load and Validate Classification Rules
    $Stage2Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 2/6: Loading Classification Rules" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Loading role action classifications from JSON file and preparing rule set..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 2/6: Loading Classification Rules" -Status "Reading classification file..." -PercentComplete 15
    
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

    # Build scope pattern lookup hashtables for O(1) lookups
    $ScopePatternLookup = @{}
    $ExactScopeLookup = @{}
    foreach ($ClassificationItem in $AadResourcesByClassificationJSON) {
        $ScopeName = $ClassificationItem.RoleAssignmentScopeName
        if ($null -ne $ScopeName) {
            # Check if scope contains wildcards
            if ($ScopeName -match '[*?\[\]]') {
                # Pattern-based scope (needs -like matching)
                if (-not $ScopePatternLookup.ContainsKey($ScopeName)) {
                    $ScopePatternLookup[$ScopeName] = [System.Collections.Generic.List[object]]::new()
                }
                $ScopePatternLookup[$ScopeName].Add($ClassificationItem)
            } else {
                # Exact match scope (faster hashtable lookup)
                if (-not $ExactScopeLookup.ContainsKey($ScopeName)) {
                    $ExactScopeLookup[$ScopeName] = [System.Collections.Generic.List[object]]::new()
                }
                $ExactScopeLookup[$ScopeName].Add($ClassificationItem)
            }
        }
    }

    # Get all role actions for Entra ID roles, role actions are defined tenant wide
    # Recommendation: Implement Persistent Disk Caching for role definitions (matching module cache pattern)
    $PersistentCachePath = $__EntraOpsSession.PersistentCachePath
    if (-not (Test-Path $PersistentCachePath)) {
        New-Item -ItemType Directory -Path $PersistentCachePath -Force | Out-Null
    }
    
    $RoleDefCacheKey = "EntraOps_RoleDefinitions_$($TenantId)"
    $RoleDefCacheFileName = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($RoleDefCacheKey)) + ".json"
    $RoleDefCacheFile = Join-Path $PersistentCachePath $RoleDefCacheFileName
    $RoleDefCacheValid = $false
    $RoleDefCacheTTL = $__EntraOpsSession.StaticDataCacheTTL  # Use configurable TTL for static data
    
    if (Test-Path $RoleDefCacheFile) {
        try {
            $RoleDefCachedObject = Get-Content $RoleDefCacheFile -Raw | ConvertFrom-Json
            $CurrentTime = [DateTime]::UtcNow
            $ExpiryTime = [DateTime]::Parse($RoleDefCachedObject.ExpiryTime)
            
            if ($CurrentTime -lt $ExpiryTime) {
                $RoleDefCacheValid = $true
                $TimeRemaining = ($ExpiryTime - $CurrentTime).TotalSeconds
                Write-Verbose "Using persistent disk cache for role definitions: $RoleDefCacheFileName (expires in $([Math]::Round($TimeRemaining, 0))s)"
            } else {
                Write-Verbose "Role definitions cache expired, fetching fresh data"
            }
        } catch {
            Write-Verbose "Failed to read role definitions cache metadata: $_"
        }
    }

    if ($SampleMode -eq $True) {
        $AllAadRoleActions = get-content -Path "$EntraOpsBaseFolder/Samples/AadRoleManagementRoleDefinitions.json" | ConvertFrom-Json -Depth 10
    } elseif ($RoleDefCacheValid) {
        $RoleDefCachedObject = Get-Content $RoleDefCacheFile -Raw | ConvertFrom-Json
        $AllAadRoleActions = $RoleDefCachedObject.Data
    } else {
        # Recommendation: Optimize Payload (Minimal Select)
        $AllAadRoleActions = (Invoke-EntraOpsMsGraphQuery -Method Get -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$select=id,displayName,rolePermissions" -OutputType PSObject)
        
        if ($AllAadRoleActions.Count -gt 0) {
            try {
                $CurrentTime = [DateTime]::UtcNow
                $ExpiryTime = $CurrentTime.AddSeconds($RoleDefCacheTTL)
                
                $RoleDefPersistentCacheObject = @{
                    CacheKey   = $RoleDefCacheKey
                    CachedTime = $CurrentTime.ToString("o")
                    ExpiryTime = $ExpiryTime.ToString("o")
                    TTLSeconds = $RoleDefCacheTTL
                    Data       = $AllAadRoleActions
                }
                
                $RoleDefPersistentCacheObject | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $RoleDefCacheFile -Force
                Write-Verbose "Persisted role definitions cache: $RoleDefCacheFileName (TTL: $($RoleDefCacheTTL)s)"
            } catch {
                Write-Verbose "Failed to persist role definitions cache to disk: $_"
            }
        }
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

        # Check if RBAC scope is listed in JSON using optimized hashtable lookups
        $MatchedClassificationByScope = [System.Collections.Generic.List[object]]::new()
        
        if ($null -ne $AadRoleScope) {
            # First, try exact match lookup (fastest - O(1))
            if ($ExactScopeLookup.ContainsKey($AadRoleScope)) {
                foreach ($Classification in $ExactScopeLookup[$AadRoleScope]) {
                    # Check exclusions
                    $ScopeExcluded = $false
                    if ($null -ne $Classification.ExcludedRoleAssignmentScopeName) {
                        foreach ($ExcludedScope in $Classification.ExcludedRoleAssignmentScopeName) {
                            if (($AadRoleScope -like $ExcludedScope) -or ($ExcludedScope -like $AadRoleScope)) {
                                $ScopeExcluded = $true
                                break
                            }
                        }
                    }
                    if (-not $ScopeExcluded) {
                        $MatchedClassificationByScope.Add($Classification)
                    }
                }
            }
            
            # Then check pattern-based scopes (requires -like matching)
            foreach ($Pattern in $ScopePatternLookup.Keys) {
                if ($AadRoleScope -like $Pattern) {
                    foreach ($Classification in $ScopePatternLookup[$Pattern]) {
                        # Check exclusions
                        $ScopeExcluded = $false
                        if ($null -ne $Classification.ExcludedRoleAssignmentScopeName) {
                            foreach ($ExcludedScope in $Classification.ExcludedRoleAssignmentScopeName) {
                                if (($AadRoleScope -like $ExcludedScope) -or ($ExcludedScope -like $AadRoleScope)) {
                                    $ScopeExcluded = $true
                                    break
                                }
                            }
                        }
                        if (-not $ScopeExcluded) {
                            $MatchedClassificationByScope.Add($Classification)
                        }
                    }
                }
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
            $WarningMessages.Add([PSCustomObject]@{Type = "Stage3"; Message = "Apply classification for role $($CurrentAadRbacClassification.RoleDefinitionName) without role actions..." })
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
    
    $Stage2Duration = ((Get-Date) - $Stage2Start).TotalSeconds
    Write-Host "✓ Stage 2 completed in $([Math]::Round($Stage2Duration, 2)) seconds ($($AadRbacClassification.Count) assignments classified)" -ForegroundColor Green
    Write-Progress -Activity "Stage 2/6: Loading Classification Rules" -Completed
    #endregion

    #region Apply classification on all principals
    #region Stage 3: Classify Role Assignments
    $Stage3Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 3/6: Classifying Role Assignments" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Matching role assignments against classification rules and applying tier levels..." -ForegroundColor Gray

    # Optimization: Group assignments by ObjectId to avoid O(N^2) filtering in loop
    $RbacAssignmentsByObject = $AadRbacClassification | Group-Object ObjectId -AsHashTable -AsString

    # Optimization: Collect all unique ObjectIds and batch resolve details
    $UniqueObjects = $AadRbacClassification | Select-Object -Unique ObjectId, ObjectType | Where-Object { $null -ne $_.ObjectId }
    $UniqueObjectIds = @($UniqueObjects.ObjectId)
    
    $Stage3Duration = ((Get-Date) - $Stage3Start).TotalSeconds
    Write-Host "✓ Stage 3 completed in $([Math]::Round($Stage3Duration, 2)) seconds ($($UniqueObjects.Count) unique principals identified)" -ForegroundColor Green
    #endregion
    
    #region Stage 4: Pre-Fetch Principal Details
    $Stage4Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 4/6: Pre-Fetching Principal Details" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Batch loading user, group, and service principal details to populate cache ($($UniqueObjectIds.Count) objects)..." -ForegroundColor Gray
    
    #region Pre-fetch objects by type for massive performance improvement
    # Pre-fetching all objects in type-specific batches reduces API calls from N to ~3-5
    # This eliminates API throttling and improves performance by 80-90%
    $ObjectsByType = $UniqueObjects | Group-Object ObjectType
    $PreFetchStats = @{
        TotalObjects    = $UniqueObjectIds.Count
        PreFetchedCount = 0
        FailedCount     = 0
    }
    
    # store pre-fetched objects in hashtable for O(1) lookup during resolution
    $PreFetchedObjectLookup = @{}

    $TypeIndex = 0
    $TotalTypes = $ObjectsByType.Count
    foreach ($TypeGroup in $ObjectsByType) {
        $ObjectType = $TypeGroup.Name
        $ObjectIds = @($TypeGroup.Group.ObjectId)
        $TypeIndex++
        
        # Determine endpoint and select fields based on type
        # UPGRADE: Switched to /beta/ to retrieve 'isManagementRestricted' and other advanced properties
        # This allows Stage 5 to skip the initial API call entirely
        $EndpointInfo = switch ($ObjectType) {
            'user' { 
                @{ 
                    Endpoint = '/beta/users/getByIds'
                    Select   = 'id,displayName,userPrincipalName,mail,accountEnabled,userType,onPremisesSyncEnabled,assignedLicenses,isManagementRestricted,isAssignableToRole,passwordPolicies'
                }
            }
            'group' { 
                @{ 
                    Endpoint = '/beta/groups/getByIds'
                    Select   = 'id,displayName,mailEnabled,securityEnabled,groupTypes,onPremisesSyncEnabled,membershipRule,isManagementRestricted,isAssignableToRole'
                }
            }
            'servicePrincipal' { 
                @{ 
                    Endpoint = '/beta/servicePrincipals/getByIds'
                    Select   = 'id,displayName,appId,servicePrincipalType,accountEnabled,appOwnerOrganizationId,isManagementRestricted,isAssignableToRole'
                }
            }
            default { $null }
        }
        
        if ($EndpointInfo) {
            Write-Progress -Activity "Stage 4/6: Pre-Fetching Principal Details" -Status "Loading $ObjectType objects ($TypeIndex of $TotalTypes types, $($ObjectIds.Count) objects)..." -PercentComplete (($TypeIndex / $TotalTypes) * 100)
            Write-Verbose "Pre-fetching $($ObjectIds.Count) $ObjectType objects..."
            
            try {
                # Batch in chunks of 1000 (API limit for getByIds)
                for ($i = 0; $i -lt $ObjectIds.Count; $i += 1000) {
                    $Batch = $ObjectIds[$i..([Math]::Min($i + 999, $ObjectIds.Count - 1))]
                    $BatchNumber = [Math]::Floor($i / 1000) + 1
                    $TotalBatches = [Math]::Ceiling($ObjectIds.Count / 1000)
                    
                    Write-Progress -Activity "Stage 4/6: Pre-Fetching Principal Details" -Status "Loading $ObjectType objects - Batch $BatchNumber of $TotalBatches ($($Batch.Count) objects)..." -PercentComplete (($TypeIndex / $TotalTypes) * 100)
                    
                    $Body = @{ ids = $Batch } | ConvertTo-Json
                    
                    # Use $select to minimize payload size
                    $Uri = "$($EndpointInfo.Endpoint)?`$select=$($EndpointInfo.Select)"
                    $PreFetchedObjects = Invoke-EntraOpsMsGraphQuery -Method POST -Uri $Uri -Body $Body -OutputType PSObject
                    
                    if ($PreFetchedObjects) {
                        $PreFetchedObjects | ForEach-Object {
                            if ($_.id) { $PreFetchedObjectLookup[$_.id] = $_ }
                        }
                        $PreFetchStats.PreFetchedCount += $PreFetchedObjects.Count
                        Write-Verbose "Pre-fetched batch of $($PreFetchedObjects.Count) $ObjectType objects (batch $BatchNumber of $TotalBatches)"
                    }
                    
                    # Brief delay between batches to avoid throttling
                    if ($i + 1000 -lt $ObjectIds.Count) {
                        Start-Sleep -Milliseconds 200
                    }
                }
            } catch {
                $WarningMessages.Add([PSCustomObject]@{Type = "Stage5-PreFetch"; Message = "Pre-fetch failed for $ObjectType objects: $($_.Exception.Message)" })
                $PreFetchStats.FailedCount += $ObjectIds.Count
            }
        } else {
            Write-Verbose "Skipping pre-fetch for unknown object type: $ObjectType"
        }
    }
    
    $Stage4Duration = ((Get-Date) - $Stage4Start).TotalSeconds
    Write-Host "✓ Stage 4 completed in $([Math]::Round($Stage4Duration, 2)) seconds ($($PreFetchStats.PreFetchedCount) objects cached, $($PreFetchStats.FailedCount) failed)" -ForegroundColor Green
    Write-Progress -Activity "Stage 4/6: Pre-Fetching Principal Details" -Completed
    #endregion
    
    $ObjectDetailsCache = @{}
    
    #region Stage 5: Resolve Object Details (Parallel or Sequential)
    $Stage5Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 5/6: Resolving Object Details" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Enriching principals with detailed attributes, group memberships, and ownership data..." -ForegroundColor Gray
    
    # Determine if parallel processing is viable
    # Requirements: PowerShell 7+, dataset >= 20 objects, NOT using UseAzPwshOnly mode
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
    $HasSufficientObjects = $UniqueObjectIds.Count -ge 20
    $IsUsingMgGraphSDK = -not $Global:UseAzPwshOnly
    $UseParallel = $EnableParallelProcessing -and $IsPowerShell7 -and $HasSufficientObjects -and $IsUsingMgGraphSDK
    
    # Create thread-safe synchronized hashtables for cache sharing across parallel runspaces
    if ($UseParallel) {
        # Convert existing cache to synchronized (thread-safe) hashtables
        $SyncGraphCache = [System.Collections.Hashtable]::Synchronized(@{})
        $SyncCacheMetadata = [System.Collections.Hashtable]::Synchronized(@{})
        $SyncPreFetchedObjectLookup = [System.Collections.Hashtable]::Synchronized(@{})
        
        # Copy existing cache entries to synchronized hashtables
        if ($__EntraOpsSession.GraphCache) {
            foreach ($key in $__EntraOpsSession.GraphCache.Keys) {
                $SyncGraphCache[$key] = $__EntraOpsSession.GraphCache[$key]
            }
        }
        if ($__EntraOpsSession.CacheMetadata) {
            foreach ($key in $__EntraOpsSession.CacheMetadata.Keys) {
                $SyncCacheMetadata[$key] = $__EntraOpsSession.CacheMetadata[$key]
            }
        }
        
        # Share pre-fetched objects
        foreach ($key in $PreFetchedObjectLookup.Keys) {
            $SyncPreFetchedObjectLookup[$key] = $PreFetchedObjectLookup[$key]
        }
        
        Write-Verbose "Initialized synchronized cache for parallel processing: $($SyncGraphCache.Count) cached entries"
    }
    
    if ($UseParallel) {
        # Optimize throttle limit based on dataset size (Balanced Mode)
        # With pre-fetch optimization, most API calls hit cache, allowing higher thread counts
        # Adaptive throttling will adjust based on actual API response
        $OptimalThrottleLimit = switch ($UniqueObjectIds.Count) {
            { $_ -lt 50 } { 10; break }
            { $_ -lt 100 } { 20; break }
            { $_ -lt 500 } { 30; break }
            { $_ -lt 1000 } { 40; break }
            default { 50 }  # Balanced cap with pre-fetch optimization
        }
        
        # Use user-specified limit if lower (respects user's throttling preference)
        $EffectiveThrottleLimit = [Math]::Min($ParallelThrottleLimit, $OptimalThrottleLimit)
        
        Write-Host "Using parallel processing with $EffectiveThrottleLimit threads for $($UniqueObjectIds.Count) objects..." -ForegroundColor Yellow
        if ($EffectiveThrottleLimit -ne $ParallelThrottleLimit) {
            Write-Verbose "Throttle limit adjusted from $ParallelThrottleLimit to $EffectiveThrottleLimit for optimal performance"
        }
        Write-Verbose "MgGraph authentication context is process-scoped and will be accessible in parallel runspaces"
        
        # Verify MgGraph connection exists before starting parallel processing
        $MgContext = Get-MgContext
        if ($null -eq $MgContext) {
            $WarningMessages.Add([PSCustomObject]@{Type = "Stage5-Parallel"; Message = "Microsoft Graph is not connected. Falling back to sequential processing." })
            $UseParallel = $false
        } else {
            Write-Verbose "MgGraph Context: TenantId=$($MgContext.TenantId), Scopes=$($MgContext.Scopes -join ', ')"
            
            # Import module in current scope to ensure it's available
            Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
            
            # Prepare module paths for parallel runspaces
            $EntraOpsModulePath = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $MgGraphModulePath = (Get-Module Microsoft.Graph.Authentication).Path
            
            # Capture global variables and synchronized caches for parallel runspaces
            $LocalEntraOpsConfig = $Global:EntraOpsConfig
            $LocalEntraOpsBaseFolder = $Global:EntraOpsBaseFolder
            $SharedGraphCache = $SyncGraphCache
            $SharedCacheMetadata = $SyncCacheMetadata
            $SharedPreFetchedLookup = $SyncPreFetchedObjectLookup
            $CacheTTLDefault = $__EntraOpsSession.DefaultCacheTTL
            $CacheTTLStatic = $__EntraOpsSession.StaticDataCacheTTL
            $CachePath = $__EntraOpsSession.PersistentCachePath
            
            # Create thread-safe progress counter for parallel processing
            $ProgressCounter = [System.Collections.Concurrent.ConcurrentBag[int]]::new()
            $TotalObjects = $UniqueObjects.Count
            
            try {
                # Execute parallel processing with shared cache
                # Key insight: Synchronized hashtables allow thread-safe cache sharing!
                # All threads read/write to same cache = massive performance improvement
                $ParallelResults = $UniqueObjects | ForEach-Object -ThrottleLimit $EffectiveThrottleLimit -Parallel {
                    $obj = $_
                    $ObjectId = $obj.ObjectId
                    $LocalTenantId = $using:TenantId
                    $LocalEntraOpsPath = $using:EntraOpsModulePath
                    $LocalMgGraphPath = $using:MgGraphModulePath
                    $LocalVerbosePref = $using:VerbosePreference
                    
                    # Set verbose preference in parallel runspace
                    $VerbosePreference = $LocalVerbosePref
                    
                    try {
                        # Import Microsoft.Graph.Authentication in parallel runspace
                        # This gives access to Get-MgContext and Invoke-MgGraphRequest
                        Import-Module $LocalMgGraphPath -ErrorAction Stop
                        
                        # Verify MgGraph context is accessible (it should be - process-scoped!)
                        $ThreadMgContext = Get-MgContext
                        if ($null -eq $ThreadMgContext) {
                            throw "MgGraph context not available in parallel runspace"
                        }
                        
                        # CRITICAL: Set cache BEFORE importing module
                        # Module functions will look for $__EntraOpsSession in global scope if not found in module scope
                        $global:__EntraOpsSession = @{
                            GraphCache          = $using:SharedGraphCache
                            CacheMetadata       = $using:SharedCacheMetadata
                            DefaultCacheTTL     = $using:CacheTTLDefault
                            StaticDataCacheTTL  = $using:CacheTTLStatic
                            PersistentCachePath = $using:CachePath
                        }
                        
                        Write-Verbose "[Thread $([System.Threading.Thread]::CurrentThread.ManagedThreadId)] Pre-import: Global cache set with $($global:__EntraOpsSession.GraphCache.Count) entries"
                        
                        # Import EntraOps module to get all functions - Optimized to avoid reload on reused runspaces
                        $EntraOpsModuleManifest = Join-Path $LocalEntraOpsPath "EntraOps.psd1"
                        if (Test-Path $EntraOpsModuleManifest) {
                            $env:ENTRAOPS_NOWELCOME = $true
                            if (-not (Get-Module -Name EntraOps)) {
                                Import-Module $EntraOpsModuleManifest -ErrorAction Stop -WarningAction SilentlyContinue
                            }
                        } else {
                            throw "EntraOps module manifest not found at $EntraOpsModuleManifest"
                        }
                        
                        Write-Verbose "[Thread $([System.Threading.Thread]::CurrentThread.ManagedThreadId)] Post-import: Cache has $($global:__EntraOpsSession.GraphCache.Count) entries"
                        
                        # Restore global variables in parallel runspace
                        $global:UseAzPwshOnly = $false
                        $global:EntraOpsConfig = $using:LocalEntraOpsConfig
                        $global:EntraOpsBaseFolder = $using:LocalEntraOpsBaseFolder
                        
                        # Retrieve pre-fetched object if available
                        $SharedLookup = $using:SharedPreFetchedLookup
                        $PreFetchedObj = if ($SharedLookup.ContainsKey($ObjectId)) { $SharedLookup[$ObjectId] } else { $null }

                        # Get object details using MgGraph SDK - authentication already in place!
                        # Optimized: Passes pre-fetched InputObject to avoid redundant API calls
                        $ObjectDetails = Get-EntraOpsPrivilegedEntraObject -AadObjectId $ObjectId -TenantId $LocalTenantId -InputObject $PreFetchedObj
                        
                        # Update progress (thread-safe)
                        $LocalCounter = $using:ProgressCounter
                        $LocalCounter.Add(1)
                        $Completed = $LocalCounter.Count
                        $LocalTotal = $using:TotalObjects
                        
                        # Progress reporting every 5% or every 10 items (whichever is more frequent)
                        if (($Completed % [Math]::Max(10, [Math]::Floor($LocalTotal / 20))) -eq 0 -or $Completed -eq $LocalTotal) {
                            $PercentComplete = [Math]::Round(($Completed / $LocalTotal) * 100, 1)
                            Write-Progress -Id 1 -Activity "Parallel Object Resolution" -Status "Processed $Completed of $LocalTotal objects ($PercentComplete%)" -PercentComplete $PercentComplete
                        }
                        
                        [PSCustomObject]@{
                            ObjectId = $ObjectId
                            Details  = $ObjectDetails
                            Success  = $true
                            ThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
                        }
                    } catch {
                        # Update progress even on failure
                        $LocalCounter = $using:ProgressCounter
                        $LocalCounter.Add(1)
                        
                        [PSCustomObject]@{
                            ObjectId = $ObjectId
                            Details  = $null
                            Success  = $false
                            Error    = $_.Exception.Message
                            ThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
                        }
                    }
                }
                
                Write-Progress -Id 1 -Activity "Parallel Object Resolution" -Completed
                
                # Process parallel results and build cache
                $SuccessCount = 0
                $FailureCount = 0
                $UsedThreads = @()
                
                foreach ($Result in $ParallelResults) {
                    if ($Result.Success) {
                        $ObjectDetailsCache[$Result.ObjectId] = $Result.Details
                        $SuccessCount++
                        if ($Result.ThreadId -notin $UsedThreads) { $UsedThreads += $Result.ThreadId }
                    } else {
                        $WarningMessages.Add([PSCustomObject]@{Type = "Stage5-ObjectDetails"; Message = "Failed to get details for object $($Result.ObjectId): $($Result.Error)"; Target = $Result.ObjectId })
                        $ObjectDetailsCache[$Result.ObjectId] = $null
                        $FailureCount++
                    }
                }
                
                Write-Host "Parallel processing completed: $SuccessCount successful, $FailureCount failed (used $($UsedThreads.Count) threads)"
                
                # Copy synchronized cache back to main session for persistence
                # This ensures cache is available for subsequent calls
                Write-Verbose "Before copy-back: Main cache has $($__EntraOpsSession.GraphCache.Count) entries, Sync cache has $($SyncGraphCache.Count) entries"
                
                foreach ($key in $SyncGraphCache.Keys) {
                    if ($__EntraOpsSession.GraphCache.ContainsKey($key)) {
                        $__EntraOpsSession.GraphCache[$key] = $SyncGraphCache[$key]
                    } else {
                        $__EntraOpsSession.GraphCache.Add($key, $SyncGraphCache[$key])
                    }
                }
                foreach ($key in $SyncCacheMetadata.Keys) {
                    if ($__EntraOpsSession.CacheMetadata.ContainsKey($key)) {
                        $__EntraOpsSession.CacheMetadata[$key] = $SyncCacheMetadata[$key]
                    } else {
                        $__EntraOpsSession.CacheMetadata.Add($key, $SyncCacheMetadata[$key])
                    }
                }
                Write-Verbose "After copy-back: Main cache has $($__EntraOpsSession.GraphCache.Count) total entries"
                Write-Host "Cache updated with $($SyncGraphCache.Count) entries from parallel processing"
                
            } catch {
                $WarningMessages.Add([PSCustomObject]@{Type = "Stage5-ParallelFallback"; Message = "Parallel processing failed: $($_.Exception.Message). Falling back to sequential processing." })
                $UseParallel = $false
            }
        }
        
        if ($UseParallel) {
            $Stage5Duration = ((Get-Date) - $Stage5Start).TotalSeconds
            Write-Host "✓ Stage 5 completed in $([Math]::Round($Stage5Duration, 2)) seconds (parallel: $SuccessCount successful, $FailureCount failed, $($UsedThreads.Count) threads)" -ForegroundColor Green
        }
    }
    
    # Sequential processing (fallback or when parallel is not viable)
    if (-not $UseParallel) {
        # Provide informative reason for sequential processing
        if ($EnableParallelProcessing) {
            $Reasons = @()
            if (-not $IsPowerShell7) { $Reasons += "PowerShell 7+ required" }
            if (-not $HasSufficientObjects) { $Reasons += "dataset too small (<20 objects)" }
            if (-not $IsUsingMgGraphSDK) { $Reasons += "UseAzPwshOnly mode enabled (use MgGraph SDK for parallel support)" }
            if ($Reasons.Count -gt 0) {
                Write-Host "Using sequential processing: $($Reasons -join ', ')" -ForegroundColor Yellow
            }
        } else {
            Write-Host "Using sequential processing (parallel disabled)..." -ForegroundColor Yellow
        }
        
        # Batch resolution with progress reporting
        for ($i = 0; $i -lt $UniqueObjectIds.Count; $i++) {
            $ObjectId = $UniqueObjectIds[$i]
            
            # Update progress more frequently for better UX (every 10 items or 5%, whichever is less frequent)
            $ProgressInterval = [Math]::Max(10, [Math]::Floor($UniqueObjectIds.Count / 20))
            if (($i % $ProgressInterval) -eq 0 -or $i -eq ($UniqueObjectIds.Count - 1)) {
                $PercentComplete = [math]::Round(($i / $UniqueObjectIds.Count) * 100, 0)
                Write-Progress -Activity "Stage 5/6: Resolving Object Details" -Status "Processing object $($i + 1) of $($UniqueObjectIds.Count)" -PercentComplete $PercentComplete
                if ($VerbosePreference -ne 'SilentlyContinue') {
                    Write-Verbose "Processing object $($i + 1) of $($UniqueObjectIds.Count)..."
                }
            }
            
            try {
                # Use pre-fetched object if available
                $PreFetchedObj = if ($PreFetchedObjectLookup.ContainsKey($ObjectId)) { $PreFetchedObjectLookup[$ObjectId] } else { $null }

                $ObjectDetailsCache[$ObjectId] = Get-EntraOpsPrivilegedEntraObject -AadObjectId $ObjectId -TenantId $TenantId -InputObject $PreFetchedObj
            } catch {
                $WarningMessages.Add([PSCustomObject]@{Type = "Stage5-Sequential"; Message = "Failed to get details for object $($ObjectId): $_"; Target = $ObjectId })
                $ObjectDetailsCache[$ObjectId] = $null
            }
        }
        Write-Progress -Activity "Stage 5/6: Resolving Object Details" -Completed
        
        $Stage5Duration = ((Get-Date) - $Stage5Start).TotalSeconds
        Write-Host "✓ Stage 5 completed in $([Math]::Round($Stage5Duration, 2)) seconds (sequential: $($ObjectDetailsCache.Count) objects processed)" -ForegroundColor Green
    }
    #endregion
    
    #region Stage 6: Apply Global Exclusions and Finalize
    $Stage6Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 6/6: Finalizing Results" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Building final object collection, applying exclusions, and sorting results..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 6/6: Finalizing Results" -Status "Processing classifications and building final dataset..." -PercentComplete 50

    $AadRbacClassifiedObjects = $UniqueObjects | ForEach-Object {
        if ($null -ne $_.ObjectId) {
            $ObjectId = $_.ObjectId
            if ($VerbosePreference -ne 'SilentlyContinue') {
                Write-Verbose -Message "Processing classifications for $($ObjectId)..."
            }
            # Object types
            $ObjectType = $_.ObjectType
            $ObjectTypeLower = $ObjectType.ToLower()
            $ObjectDetails = $ObjectDetailsCache[$ObjectId]
            
            # Skip if object details couldn't be retrieved
            if ($null -eq $ObjectDetails) {
                $WarningMessages.Add([PSCustomObject]@{Type = "Stage6-SkippedObject"; Message = "Skipping object $ObjectId - failed to retrieve details"; Target = $ObjectId })
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
            
            $Classification = @($UniqueClassificationsHash.Values | Select-Object -ExcludeProperty TaggedBy | Sort-Object AdminTierLevel, AdminTierLevelName, Service)
            
            if ($Classification.Count -eq 0) {
                $Classification = @([PSCustomObject]@{
                        'AdminTierLevel'     = "Unclassified"
                        'AdminTierLevelName' = "Unclassified"
                        'Service'            = "Unclassified"
                    })
            }

            [PSCustomObject]@{
                'ObjectId'                      = $ObjectId
                'ObjectType'                    = $ObjectTypeLower
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
                'RoleAssignments'               = @($AllAadRbacEntriesOfObject | Sort-Object RoleAssignmentId)
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
    
    Write-Progress -Activity "Stage 6/6: Finalizing Results" -Status "Applying global exclusions and sorting..." -PercentComplete 90
    $EamEntraId = $AadRbacClassifiedObjects | Where-Object { $GlobalExclusionList -notcontains $_.ObjectId }
    
    $Stage6Duration = ((Get-Date) - $Stage6Start).TotalSeconds
    $TotalDuration = ((Get-Date) - $Stage1Start).TotalSeconds
    
    Write-Progress -Activity "Stage 6/6: Finalizing Results" -Completed
    Write-Host "✓ Stage 6 completed in $([Math]::Round($Stage6Duration, 2)) seconds ($($EamEntraId.Count) privileged objects after exclusions)" -ForegroundColor Green

    # Display Warning Summary
    if ($WarningMessages.Count -gt 0) {
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
        Write-Host "  ⚠ Warnings Summary" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
        
        # Group by Type first, then by distinct message within each type
        $GroupedByType = $WarningMessages | Group-Object Type
        foreach ($TypeGroup in $GroupedByType) {
            Write-Host "  $($TypeGroup.Name):" -ForegroundColor Yellow
            
            # Group messages by distinct message pattern to avoid duplicates
            $GroupedByMessage = $TypeGroup.Group | Group-Object Message
            foreach ($MessageGroup in $GroupedByMessage) {
                if ($MessageGroup.Count -eq 1) {
                    Write-Host "    - $($MessageGroup.Name)" -ForegroundColor DarkYellow
                } else {
                    Write-Host "    - $($MessageGroup.Name) [$($MessageGroup.Count) occurrences]" -ForegroundColor DarkYellow
                }
            }
        }
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✓ All Stages Completed Successfully" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "Total execution time: $([Math]::Round($TotalDuration, 2)) seconds" -ForegroundColor Gray
    Write-Host "Cache statistics: $($__EntraOpsSession.GraphCache.Count) cached entries, $($__EntraOpsSession.CacheMetadata.Count) metadata entries" -ForegroundColor Gray
    Write-Host "Final result: $($EamEntraId.Count) privileged objects ready for export" -ForegroundColor Gray
    #endregion
    
    $EamEntraId | Where-Object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId } | Sort-Object ObjectAdminTierLevel, ObjectDisplayName
}
