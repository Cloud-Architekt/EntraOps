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
        [System.Int32]$ParallelThrottleLimit = 10
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

        # Check if RBAC scope is listed in JSON by wildcard or exact match in RoleAssignmentScopeName
        $MatchedClassificationByScope = [System.Collections.Generic.List[object]]::new()
        foreach ($Classification in $AadResourcesByClassificationJSON) {
            # Skip if either scope is null
            if ($null -eq $AadRoleScope -or $null -eq $Classification.RoleAssignmentScopeName) {
                continue
            }
            
            # Test if scope matches using -like for wildcard support
            $ScopeMatches = $AadRoleScope -like $Classification.RoleAssignmentScopeName
            
            if (-not $ScopeMatches) {
                continue
            }
            
            # Check exclusions using -like for wildcard/pattern matching in exclusions
            $ScopeExcluded = $false
            if ($null -ne $Classification.ExcludedRoleAssignmentScopeName) {
                foreach ($ExcludedScope in $Classification.ExcludedRoleAssignmentScopeName) {
                    # Use -like to support wildcards in exclusions AND exact matches
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
    $UniqueObjectIds = @($UniqueObjects.ObjectId)
    
    Write-Host "Resolving details for $($UniqueObjectIds.Count) unique objects..."
    $ObjectDetailsCache = @{}
    
    # Determine if parallel processing is viable
    # Requirements: PowerShell 7+, dataset >= 20 objects, NOT using UseAzPwshOnly mode
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
    $HasSufficientObjects = $UniqueObjectIds.Count -ge 20
    $IsUsingMgGraphSDK = -not $Global:UseAzPwshOnly
    $UseParallel = $EnableParallelProcessing -and $IsPowerShell7 -and $HasSufficientObjects -and $IsUsingMgGraphSDK
    
    if ($UseParallel) {
        Write-Host "Using parallel processing with $ParallelThrottleLimit threads (Microsoft Graph SDK authentication)..."
        Write-Verbose "MgGraph authentication context is process-scoped and will be accessible in parallel runspaces"
        
        # Verify MgGraph connection exists before starting parallel processing
        $MgContext = Get-MgContext
        if ($null -eq $MgContext) {
            Write-Warning "Microsoft Graph is not connected. Falling back to sequential processing."
            $UseParallel = $false
        } else {
            Write-Verbose "MgGraph Context: TenantId=$($MgContext.TenantId), Scopes=$($MgContext.Scopes -join ', ')"
            
            # Import module in current scope to ensure it's available
            Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
            
            # Prepare module paths for parallel runspaces
            $EntraOpsModulePath = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $MgGraphModulePath = (Get-Module Microsoft.Graph.Authentication).Path
            
            # Capture global variables needed by Get-EntraOpsPrivilegedEntraObject
            $LocalEntraOpsConfig = $Global:EntraOpsConfig
            $LocalEntraOpsBaseFolder = $Global:EntraOpsBaseFolder
            
            try {
                # Execute parallel processing
                # Key insight: MgGraph SDK maintains process-level auth that parallel runspaces inherit
                # No re-authentication needed - Get-MgContext works in parallel threads!
                $ParallelResults = $UniqueObjects | ForEach-Object -ThrottleLimit $ParallelThrottleLimit -Parallel {
                    $obj = $_
                    $ObjectId = $obj.ObjectId
                    $LocalTenantId = $using:TenantId
                    $LocalEntraOpsPath = $using:EntraOpsModulePath
                    $LocalMgGraphPath = $using:MgGraphModulePath
                    
                    try {
                        # Import Microsoft.Graph.Authentication in parallel runspace
                        # This gives access to Get-MgContext and Invoke-MgGraphRequest
                        Import-Module $LocalMgGraphPath -ErrorAction Stop
                        
                        # Verify MgGraph context is accessible (it should be - process-scoped!)
                        $ThreadMgContext = Get-MgContext
                        if ($null -eq $ThreadMgContext) {
                            throw "MgGraph context not available in parallel runspace"
                        }
                        
                        # Import EntraOps module to get all functions
                        $EntraOpsModuleManifest = Join-Path $LocalEntraOpsPath "EntraOps.psd1"
                        if (Test-Path $EntraOpsModuleManifest) {
                            $env:ENTRAOPS_NOWELCOME = $true
                            Import-Module $EntraOpsModuleManifest -Force -ErrorAction Stop -WarningAction SilentlyContinue
                        } else {
                            throw "EntraOps module manifest not found at $EntraOpsModuleManifest"
                        }
                        
                        # Initialize module session variable for caching in this runspace
                        if (-not (Get-Variable -Name __EntraOpsSession -Scope Script -ErrorAction SilentlyContinue)) {
                            $script:__EntraOpsSession = @{
                                GraphCache = @{}
                                CacheMetadata = @{}
                            }
                        }
                        
                        # Restore global variables in parallel runspace
                        New-Variable -Name UseAzPwshOnly -Value $false -Scope Global -Force -ErrorAction SilentlyContinue
                        New-Variable -Name EntraOpsConfig -Value $using:LocalEntraOpsConfig -Scope Global -Force -ErrorAction SilentlyContinue
                        New-Variable -Name EntraOpsBaseFolder -Value $using:LocalEntraOpsBaseFolder -Scope Global -Force -ErrorAction SilentlyContinue
                        
                        # Get object details using MgGraph SDK - authentication already in place!
                        $ObjectDetails = Get-EntraOpsPrivilegedEntraObject -AadObjectId $ObjectId -TenantId $LocalTenantId
                        
                        [PSCustomObject]@{
                            ObjectId = $ObjectId
                            Details = $ObjectDetails
                            Success = $true
                            ThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
                        }
                    } catch {
                        [PSCustomObject]@{
                            ObjectId = $ObjectId
                            Details = $null
                            Success = $false
                            Error = $_.Exception.Message
                            ThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
                        }
                    }
                }
                
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
                        Write-Warning "Failed to get details for object $($Result.ObjectId): $($Result.Error)"
                        $ObjectDetailsCache[$Result.ObjectId] = $null
                        $FailureCount++
                    }
                }
                
                Write-Host "Parallel processing completed: $SuccessCount successful, $FailureCount failed (used $($UsedThreads.Count) threads)"
                
            } catch {
                Write-Warning "Parallel processing failed: $($_.Exception.Message). Falling back to sequential processing."
                $UseParallel = $false
            }
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
                Write-Host "Using sequential processing: $($Reasons -join ', ')"
            }
        } else {
            Write-Host "Using sequential processing (parallel disabled)..."
        }
        
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
    }

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
            
            $Classification = @($UniqueClassificationsHash.Values | Select-Object -Unique -ExcludeProperty TaggedBy | Sort-Object AdminTierLevel, AdminTierLevelName, Service)
            
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
