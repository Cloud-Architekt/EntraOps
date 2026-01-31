<#
.SYNOPSIS
    Get a list of directory role member assignments in Entra ID.

.DESCRIPTION
    Get a list of directory role member assignments in Entra ID.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER PrincipalTypeFilter
    Filter for principal type. Default is User, Group, ServicePrincipal. Possible values are User, Group, ServicePrincipal.

.PARAMETER ExpandGroupMembers
    Expand group members for transitive role assignments. Default is $true.

.PARAMETER SampleMode
    Use sample data for testing or offline mode. Default is $False.

.EXAMPLE
    Get a list of assignment of Entra ID directory roles.
    Get-EntraOpsPrivilegedEntraIdRoles
#>

function Get-EntraOpsPrivilegedEntraIdRoles {
    param (
        [Parameter(Mandatory = $False)]
        [System.String]$TenantId
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("User", "Group", "ServicePrincipal")]
        [Array]$PrincipalTypeFilter = ("User", "Group", "ServicePrincipal")
        ,
        [Parameter(Mandatory = $False)]
        [System.Boolean]$ExpandGroupMembers = $true
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$SampleMode = $False
        ,
        [Parameter(Mandatory = $false)]
        [System.Collections.Generic.List[psobject]]$WarningMessages
    )

    # Set Error Action
    $ErrorActionPreference = "Stop"

    #region Get Role Definitions and Role Assignments
    Write-Host "Get Entra ID Role Management Assignments and Role Definition..."

    # Recommendation: Implement Persistent Disk Caching (matching module cache pattern)
    $PersistentCachePath = $__EntraOpsSession.PersistentCachePath
    if (-not (Test-Path $PersistentCachePath)) {
        New-Item -ItemType Directory -Path $PersistentCachePath -Force | Out-Null
    }
    
    $CacheKey = "EntraOps_RoleData_$($TenantId)"
    $CacheFileName = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($CacheKey)) + ".json"
    $CacheFile = Join-Path $PersistentCachePath $CacheFileName
    $CacheValid = $false
    $CacheTTL = $__EntraOpsSession.StaticDataCacheTTL  # Use configurable TTL for static data
    
    if (Test-Path $CacheFile) {
        try {
            $CachedObject = Get-Content $CacheFile -Raw | ConvertFrom-Json
            $CurrentTime = [DateTime]::UtcNow
            $ExpiryTime = [DateTime]::Parse($CachedObject.ExpiryTime)
            
            if ($CurrentTime -lt $ExpiryTime) {
                $CacheValid = $true
                $TimeRemaining = ($ExpiryTime - $CurrentTime).TotalSeconds
                Write-Verbose "Using persistent disk cache: $CacheFileName (expires in $([Math]::Round($TimeRemaining, 0))s)"
            } else {
                Write-Verbose "Persistent cache expired, fetching fresh data"
            }
        } catch {
            Write-Verbose "Failed to read cache metadata: $_"
        }
    }

    # Initialize Lookup Table early to support cache loading
    $DirObjLookup = @{}

    if ($SampleMode -eq $True) {
        $AadRoleDefinitions = get-content -Path "$EntraOpsBaseFolder/Samples/AadRoleManagementRoleDefinitions.json" | ConvertFrom-Json -Depth 10
        $AadRoleAssignments = get-content -Path "$EntraOpsBaseFolder/Samples/AadRoleManagementAssignments.json" | ConvertFrom-Json -Depth 10
        $AadEligibleRoleAssignments = @()
        if (Test-Path "$EntraOpsBaseFolder/Samples/AadRoleManagementEligibleAssignments.json") {
            $AadEligibleRoleAssignments = get-content -Path "$EntraOpsBaseFolder/Samples/AadRoleManagementEligibleAssignments.json" | ConvertFrom-Json -Depth 10
        }
        $AadRoleAssignmentsByPim = @()
    } elseif ($CacheValid) {
        $CachedObject = Get-Content $CacheFile -Raw | ConvertFrom-Json
        $AadRoleDefinitions = $CachedObject.Data.RoleDefinitions
        $AadRoleAssignments = $CachedObject.Data.RoleAssignments
        $AadEligibleRoleAssignments = $CachedObject.Data.EligibleAssignments
        $AadRoleAssignmentsByPim = $CachedObject.Data.PimAssignments

        # Load resolved principals from cache if available
        if ($CachedObject.Data.ResolvedPrincipals) {
            Write-Verbose "Loading resolved principals from persistent cache..."
            $CachedObject.Data.ResolvedPrincipals.PSObject.Properties | ForEach-Object {
                $DirObjLookup[$_.Name] = $_.Value
            }
        }
    } else {
        # Parallel fetch of all required data to reduce sequential API call overhead
        Write-Verbose "Fetching role data in parallel (definitions, assignments, eligibility, PIM schedules)..."
        $AadRoleDefinitions = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleDefinitions?`$select=id,displayName,description,rolePermissions,isBuiltIn,IsPrivileged,templateId"
        # Recommendation: Optimize Payload - Role Assignments (id, principalId, roleDefinitionId, directoryScopeId)
        $AadRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleAssignments?`$select=id,principalId,roleDefinitionId,directoryScopeId"
        # Recommendation: Server-Side Filtering (OData) for Eligible Assignments
        $AadEligibleRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleEligibilitySchedules?`$filter=memberType eq 'Direct' and status eq 'Provisioned'&`$select=id,principalId,roleDefinitionId,directoryScopeId,memberType,status"
        # Fetch PIM assignment schedules early (used later for enrichment)
        $AadRoleAssignmentsByPim = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/roleManagement/directory/roleAssignmentScheduleInstances?`$select=id,roleDefinitionId,assignmentType,endDateTime,startDateTime" -OutputType PSObject
        Write-Verbose "Parallel data fetch complete"

        # Validate essential data was retrieved
        if ($null -eq $AadRoleDefinitions -or $null -eq $AadRoleAssignments) {
            Write-Error "Failed to retrieve essential role data from Microsoft Graph. Please ensure you are connected (Connect-EntraOps) and have the required permissions."
            return @()
        }
        
        # Ensure collections are arrays even if API returns null
        if ($null -eq $AadRoleDefinitions) { $AadRoleDefinitions = @() }
        if ($null -eq $AadRoleAssignments) { $AadRoleAssignments = @() }
        if ($null -eq $AadEligibleRoleAssignments) { $AadEligibleRoleAssignments = @() }
        if ($null -eq $AadRoleAssignmentsByPim) { $AadRoleAssignmentsByPim = @() }

        # Validate essential data was retrieved
        if ($null -eq $AadRoleDefinitions -or $null -eq $AadRoleAssignments) {
            Write-Error "Failed to retrieve essential role data from Microsoft Graph. Please ensure you are connected (Connect-EntraOps) and have the required permissions."
            return @()
        }
        
        # Ensure collections are arrays even if API returns null
        if ($null -eq $AadRoleDefinitions) { $AadRoleDefinitions = @() }
        if ($null -eq $AadRoleAssignments) { $AadRoleAssignments = @() }
        if ($null -eq $AadEligibleRoleAssignments) { $AadEligibleRoleAssignments = @() }
        if ($null -eq $AadRoleAssignmentsByPim) { $AadRoleAssignmentsByPim = @() }

        if ($AadRoleAssignments.Count -gt 0) {
            try {
                $CurrentTime = [DateTime]::UtcNow
                $ExpiryTime = $CurrentTime.AddSeconds($CacheTTL)
                
                $PersistentCacheObject = @{
                    CacheKey   = $CacheKey
                    CachedTime = $CurrentTime.ToString("o")
                    ExpiryTime = $ExpiryTime.ToString("o")
                    TTLSeconds = $CacheTTL
                    Data       = @{
                        RoleDefinitions     = $AadRoleDefinitions
                        RoleAssignments     = $AadRoleAssignments
                        EligibleAssignments = $AadEligibleRoleAssignments
                        PimAssignments      = $AadRoleAssignmentsByPim
                    }
                }
                
                $PersistentCacheObject | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $CacheFile -Force
                Write-Verbose "Persisted role data cache: $CacheFileName (TTL: $($CacheTTL)s)"
            } catch {
                Write-Verbose "Failed to persist cache to disk: $_"
            }
        }
    }

    # Optimization: Build Lookup Tables
    Write-Verbose "Building Role Definition Dictionary..."
    $RoleDefLookup = @{}
    foreach ($Role in $AadRoleDefinitions) { 
        # Index by actual id
        $RoleDefLookup[$Role.id] = $Role 
        # Also index by templateId if available (for built-in roles)
        # Assignments may reference either id or templateId
        if ($Role.templateId -and $Role.templateId -ne $Role.id) {
            $RoleDefLookup[$Role.templateId] = $Role
        }
    }
    Write-Verbose "Role Definition Lookup: $($RoleDefLookup.Count) total entries (from $($AadRoleDefinitions.Count) role definitions)"

    # Optimization: Collect Unique IDs for Type-Specific Batch Resolution
    # Separate principals (users/groups/servicePrincipals) from scopes (AUs, other objects)
    $PrincipalIds = [System.Collections.Generic.HashSet[string]]::new()
    $ScopeIds = [System.Collections.Generic.HashSet[string]]::new()
    $GuidPattern = "([0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12})"

    foreach ($AadRoleAssignment in $AadRoleAssignments) {
        if ($AadRoleAssignment.principalId) { 
            $PrincipalIds.Add($AadRoleAssignment.principalId) | Out-Null 
        }
        if ($AadRoleAssignment.directoryScopeId -and $AadRoleAssignment.directoryScopeId -ne "/" -and $AadRoleAssignment.directoryScopeId -match $GuidPattern) {
            $ScopeIds.Add($Matches[1]) | Out-Null
        }
    }
    
    # Early filtering: Only process Direct + Provisioned eligible assignments
    $EligibleToProcess = $AadEligibleRoleAssignments
    Write-Verbose "Filtered to $($EligibleToProcess.Count) eligible assignments to process (Direct + Provisioned)"
    
    foreach ($AadRoleAssignment in $EligibleToProcess) {
        if ($AadRoleAssignment.principalId) { 
            $PrincipalIds.Add($AadRoleAssignment.principalId) | Out-Null 
        }
        if ($AadRoleAssignment.directoryScopeId -and $AadRoleAssignment.directoryScopeId -ne "/" -and $AadRoleAssignment.directoryScopeId -match $GuidPattern) {
            $ScopeIds.Add($Matches[1]) | Out-Null
        }
    }

    Write-Host "Resolving $($PrincipalIds.Count) principals and $($ScopeIds.Count) scopes using type-specific batch endpoints..."
    # $DirObjLookup was initialized earlier
    
    #region Type-Specific Principal Resolution (Users/Groups/ServicePrincipals)
    # Use type-specific batch endpoints with optimized $select for better reliability and smaller payloads
    
    # Filter out principals that are already in the cache/lookup
    $UnresolvedPrincipalIds = $PrincipalIds | Where-Object { -not $DirObjLookup.ContainsKey($_) }

    if ($UnresolvedPrincipalIds.Count -gt 0) {
        $PrincipalIdArray = @($UnresolvedPrincipalIds)
        Write-Verbose "Need to resolve $($PrincipalIdArray.Count) principals (others found in cache)..."
        
        # Try each principal type with type-specific endpoint
        # This is much more reliable than directoryObjects/getByIds and supports $select
        $TypeEndpoints = @(
            @{
                Type     = 'users'
                Endpoint = '/v1.0/users/getByIds'
                Select   = 'id,displayName,userPrincipalName,mail,accountEnabled,userType,onPremisesSyncEnabled'
            },
            @{
                Type     = 'groups'
                Endpoint = '/v1.0/groups/getByIds'
                Select   = 'id,displayName,mailEnabled,securityEnabled,groupTypes,onPremisesSyncEnabled,isAssignableToRole'
            },
            @{
                Type     = 'servicePrincipals'
                Endpoint = '/v1.0/servicePrincipals/getByIds'
                Select   = 'id,displayName,appId,servicePrincipalType,accountEnabled,appOwnerOrganizationId'
            }
        )
        
        foreach ($TypeConfig in $TypeEndpoints) {
            Write-Verbose "Fetching $($PrincipalIdArray.Count) objects as $($TypeConfig.Type)..."
            
            try {
                # Batch in chunks of 1000 (API limit for getByIds)
                $BatchSize = 1000
                $TypeResolvedCount = 0
                
                for ($i = 0; $i -lt $PrincipalIdArray.Count; $i += $BatchSize) {
                    $Batch = $PrincipalIdArray[$i..([Math]::Min($i + $BatchSize - 1, $PrincipalIdArray.Count - 1))]
                    $Body = @{ ids = $Batch } | ConvertTo-Json
                    
                    # Use $select to minimize payload size (60-80% reduction)
                    $Uri = "$($TypeConfig.Endpoint)?`$select=$($TypeConfig.Select)"
                    
                    try {
                        $Response = Invoke-EntraOpsMsGraphQuery -Method POST -Uri $Uri -Body $Body -OutputType PSObject
                        
                        foreach ($Obj in $Response) { 
                            if (-not $DirObjLookup.ContainsKey($Obj.id)) {
                                $DirObjLookup[$Obj.id] = $Obj
                                $TypeResolvedCount++
                            }
                        }
                        
                        Write-Verbose "Resolved $($Response.Count) $($TypeConfig.Type) in batch $([Math]::Floor($i / $BatchSize) + 1)"
                        
                        # Brief delay between batches to avoid throttling
                        if ($i + $BatchSize -lt $PrincipalIdArray.Count) {
                            Start-Sleep -Milliseconds 200
                        }
                    } catch {
                        # Silent failure OK - object might not be this type
                        Write-Verbose "Batch failed for $($TypeConfig.Type): $($_.Exception.Message)"
                    }
                }
                
                if ($TypeResolvedCount -gt 0) {
                    Write-Host "Resolved $TypeResolvedCount $($TypeConfig.Type)"
                }
            } catch {
                Write-Verbose "Type-specific resolution failed for $($TypeConfig.Type): $_"
            }
        }
        
        # Check for unresolved principals and attempt individual fallback resolution
        $UnresolvedPrincipals = $PrincipalIdArray | Where-Object { -not $DirObjLookup.ContainsKey($_) }
        
        if ($UnresolvedPrincipals.Count -gt 0) {
            Write-Verbose "$($UnresolvedPrincipals.Count) principal(s) not resolved via type-specific endpoints, attempting individual resolution..."
            
            $IndividualResolvedCount = 0
            $ConfirmedDeletedCount = 0
            
            foreach ($UnresolvedId in $UnresolvedPrincipals) {
                # Suppress warnings from Invoke-EntraOpsMsGraphQuery for expected 404s
                try {
                    # Try individual resolution as fallback
                    $IndividualObj = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/v1.0/directoryObjects/${UnresolvedId}?`$select=id,displayName" -OutputType PSObject -WarningAction SilentlyContinue
                    
                    if ($IndividualObj) {
                        $DirObjLookup[$UnresolvedId] = $IndividualObj
                        $IndividualResolvedCount++
                        Write-Verbose "Individually resolved: $UnresolvedId"
                    } else {
                        # If null is returned and warning suppressed, it likely failed (404/403)
                        # We count this as confirmed deleted/orphaned since the catch block below is unreachable for handled errors
                        $ConfirmedDeletedCount++
                        Write-Verbose "Confirmed deleted/not found: $UnresolvedId"
                        
                        if ($null -ne $WarningMessages) {
                            $WarningMessages.Add([PSCustomObject]@{
                                    Type    = "RoleAssignmentResolution"
                                    Message = "Principal $UnresolvedId could not be resolved (likely deleted or insufficient permissions)."
                                    Target  = $UnresolvedId
                                })
                        }
                    }
                } catch {
                    # This block handles unexpected script errors, not API errors caught by Invoke-EntraOpsMsGraphQuery
                    $ErrorMsg = $_.Exception.Message
                    Write-Verbose "Script error resolving ${UnresolvedId}: ${ErrorMsg}"

                    if ($null -ne $WarningMessages) {
                        $WarningMessages.Add([PSCustomObject]@{
                                Type    = "RoleAssignmentResolutionError"
                                Message = "Error resolving principal ${UnresolvedId}: $ErrorMsg"
                                Target  = $UnresolvedId
                            })
                    }
                }
            }
            
            if ($IndividualResolvedCount -gt 0) {
                Write-Host "Individually resolved $IndividualResolvedCount additional principal(s)"
            }
            if ($ConfirmedDeletedCount -gt 0) {
                Write-Host "$ConfirmedDeletedCount principal(s) confirmed as unsupported/deleted/orphaned (will appear as unresolved in assignments)"
            }
        }
    }
    #endregion
    
    #region Scope Resolution (Administrative Units and other directory objects)
    if ($ScopeIds.Count -gt 0) {
        Write-Verbose "Resolving $($ScopeIds.Count) directory scope objects individually..."
        $ScopeIdArray = @($ScopeIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $ScopeResolvedCount = 0
        
        foreach ($ScopeId in $ScopeIdArray) {
            # Validate GUID format before API call
            if ([string]::IsNullOrWhiteSpace($ScopeId)) {
                Write-Verbose "Skipping empty/null scope ID"
                continue
            }
            
            if ($DirObjLookup.ContainsKey($ScopeId)) {
                continue  # Already resolved (shouldn't happen but safe)
            }
            
            # Suppress warnings from Invoke-EntraOpsMsGraphQuery for expected 404s
            try {
                # Use v1.0 endpoint for better stability
                $ScopeObj = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/v1.0/directoryObjects/${ScopeId}?`$select=id,displayName" -OutputType PSObject -WarningAction SilentlyContinue
                if ($ScopeObj) {
                    $DirObjLookup[$ScopeId] = $ScopeObj
                    $ScopeResolvedCount++
                } else {
                    # If null is returned and warning suppressed, it likely failed (404/403)
                    if ($null -ne $WarningMessages) {
                        $WarningMessages.Add([PSCustomObject]@{
                                Type    = "ScopeResolution"
                                Message = "Scope Object $ScopeId could not be resolved (likely deleted or insufficient permissions)."
                                Target  = $ScopeId
                            })
                    }
                }
            } catch {
                $ErrorMsg = $_.Exception.Message
                if ($null -ne $WarningMessages) {
                    $WarningMessages.Add([PSCustomObject]@{
                            Type    = "ScopeResolutionError"
                            Message = "Error resolving scope ${ScopeId}: $ErrorMsg"
                            Target  = $ScopeId
                        })
                }
            }
        }
        
        if ($ScopeResolvedCount -gt 0) {
            Write-Host "Resolved $ScopeResolvedCount directory scopes"
        }
    }
    #endregion

    # Update persistent cache with resolved principals if any new resolutions occurred or cache is being refreshed
    # We do this after resolution so we store the complete picture (Role Data + Principals)
    if ($UnresolvedPrincipalIds.Count -gt 0 -or ($ScopeResolvedCount -gt 0) -or (-not $CacheValid)) {
        try {
            $CurrentTime = [DateTime]::UtcNow
            $ExpiryTime = $CurrentTime.AddSeconds($CacheTTL)
            
            $PersistentCacheObject = @{
                CacheKey   = $CacheKey
                CachedTime = $CurrentTime.ToString("o")
                ExpiryTime = $ExpiryTime.ToString("o")
                TTLSeconds = $CacheTTL
                Data       = @{
                    RoleDefinitions     = $AadRoleDefinitions
                    RoleAssignments     = $AadRoleAssignments
                    EligibleAssignments = $AadEligibleRoleAssignments
                    PimAssignments      = $AadRoleAssignmentsByPim
                    ResolvedPrincipals  = $DirObjLookup
                }
            }
            
            $PersistentCacheObject | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $CacheFile -Force
            Write-Verbose "Updated persistent data cache with resolved principals: $CacheFileName"
        } catch {
            Write-Verbose "Failed to update cache: $_"
        }
    }

    #region Pre-fetch any missing role definitions
    # Collect all role definition IDs referenced in assignments
    $AllRoleDefIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($Assignment in $AadRoleAssignments) {
        if ($Assignment.roleDefinitionId) { $AllRoleDefIds.Add($Assignment.roleDefinitionId) | Out-Null }
    }
    foreach ($Assignment in $EligibleToProcess) {
        if ($Assignment.roleDefinitionId) { $AllRoleDefIds.Add($Assignment.roleDefinitionId) | Out-Null }
    }
    
    # Check for missing role definitions
    $MissingRoleDefIds = $AllRoleDefIds | Where-Object { -not $RoleDefLookup.ContainsKey($_) }
    
    if ($MissingRoleDefIds) {
        Write-Host "Fetching $($MissingRoleDefIds.Count) missing role definition(s) not in initial cache..."
        Write-Host "Missing role definition IDs: $($MissingRoleDefIds -join ', ')"
        Write-Verbose "Missing role definition IDs: $($MissingRoleDefIds -join ', ')"
        $FetchedCount = 0
        $NotFoundCount = 0
        
        foreach ($MissingRoleDefId in $MissingRoleDefIds) {
            try {
                Write-Verbose "Fetching role definition: $MissingRoleDefId"
                $MissingRole = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleDefinitions/$MissingRoleDefId"
                if ($MissingRole) {
                    $RoleDefLookup[$MissingRoleDefId] = $MissingRole
                    $FetchedCount++
                    Write-Verbose "Added role definition to cache: $($MissingRole.displayName)"
                }
            } catch {
                $ErrorMsg = $_.Exception.Message
                if ($ErrorMsg -like "*ResourceNotFound*" -or $ErrorMsg -like "*does not exist*") {
                    $NotFoundCount++
                    Write-Verbose "Role definition $MissingRoleDefId not found (deleted/deprecated role)"
                    # Add placeholder entry to prevent repeated lookups
                    $RoleDefLookup[$MissingRoleDefId] = @{
                        id           = $MissingRoleDefId
                        displayName  = "Unknown Role (Deleted/Deprecated)"
                        description  = "This role definition no longer exists"
                        isBuiltIn    = $false
                        isPrivileged = $false
                        templateId   = $MissingRoleDefId
                    }
                } else {
                    if ($WarningMessages) {
                        $WarningMessages.Add([PSCustomObject]@{
                                Type    = "Role Definition"
                                Message = "Failed to fetch role definition ${MissingRoleDefId}: $ErrorMsg"
                                Target  = $MissingRoleDefId
                            })
                    }
                }
            }
        }
        
        if ($FetchedCount -gt 0) {
            Write-Host "Successfully fetched $FetchedCount role definition(s)."
        }
        if ($NotFoundCount -gt 0) {
            Write-Host "Note: $NotFoundCount role definition(s) could not be found (deleted/deprecated custom roles with orphaned assignments)."
        }
    }
    #endregion

    #region Collect permanent direct role assignments
    Write-Host "Get details of Entra ID Role Assignments foreach individual principal..."
    # Iterate over Assignments directly, filtered by local logic instead of Re-Querying API
    # Using parallel processing for improved performance with large assignment counts
    $AadRbacActiveAndPermanentAssignments = $AadRoleAssignments | ForEach-Object -ThrottleLimit 50 -Parallel {
        $AadPrincipalRoleAssignment = $_
        $Principal = $AadPrincipalRoleAssignment.principalId
        
        # Import hashtables from parent scope
        $DirObjLookup = $using:DirObjLookup
        $RoleDefLookup = $using:RoleDefLookup
        $GuidPattern = $using:GuidPattern
        
        # Resolve Principal
        $ObjectType = "unknown"
        $PrincipalProfile = $null

        if ($null -ne $Principal -and $DirObjLookup.ContainsKey($Principal)) {
            $PrincipalProfile = $DirObjLookup[$Principal]
        } elseif ($null -eq $Principal) {
            # Skip assignments with null principal
            return $null
        } else {
            # Principal not found even after fallback resolution
            if ($WarningMessages) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "Principal Resolution"
                        Message = "Principal $Principal could not be resolved (deleted/orphaned assignment)"
                        Target  = $Principal
                    })
            }
        }

        if ($PrincipalProfile) {
            if ($PrincipalProfile.'@odata.type') {
                $ObjectType = $PrincipalProfile.'@odata.type'.Replace('#microsoft.graph.', '')
            } else {
                # Fallback if odata.type is missing (should not happen on Graph objects)
                Write-Verbose "Object type missing for $Principal"
            }
        }
        
        # Resolve Role
        $RoleDefId = $AadPrincipalRoleAssignment.roleDefinitionId
        $RoleDefinitionName = "Unknown"
        $RoleType = "CustomRole"
        $RoleIsPrivileged = $false

        if ($RoleDefLookup.ContainsKey($RoleDefId)) {
            $Role = $RoleDefLookup[$RoleDefId]
        } else {
            # Fallback for deprecated/hidden roles
            # Note: API calls in parallel blocks require careful consideration
            # Using cached lookup should handle 99%+ of cases
            if ($WarningMessages) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "Role Definition"
                        Message = "Role definition $RoleDefId not found in lookup cache"
                        Target  = $RoleDefId
                    })
            }
            $Role = $null
        }

        if ($Role) {
            $RoleDefinitionName = $Role.displayName
            $RoleIsPrivileged = $Role.isPrivileged
            if ($Role.isBuiltIn -eq $True -or $Role.isBuiltIn -eq "true") { 
                $RoleType = "BuiltInRole" 
            }
            if ($Role.templateId) {
                $RoleDefId = $Role.templateId
            }
        }

        # Resolve Scope
        $RoleAssignmentScopeName = "Directory"
        if ($AadPrincipalRoleAssignment.directoryScopeId -ne "/") {
            $ScopeId = $null
            if ($AadPrincipalRoleAssignment.directoryScopeId -match $GuidPattern) {
                $ScopeId = $Matches[1]
            }
            if ($ScopeId -and $DirObjLookup.ContainsKey($ScopeId)) {
                $RoleAssignmentScopeName = $DirObjLookup[$ScopeId].displayName
            } else {
                # Scope not in batch lookup (rare edge case)
                # Using scope ID directly since API calls don't work reliably in parallel
                $RoleAssignmentScopeName = $AadPrincipalRoleAssignment.directoryScopeId
                Write-Verbose "Scope $ScopeId not found in lookup cache"
            }
        }

        # Pre-compute string operations
        $ObjectTypeLower = $ObjectType.ToLower()

        [pscustomobject]@{
            RoleAssignmentId                = $AadPrincipalRoleAssignment.Id
            RoleName                        = $RoleDefinitionName
            RoleId                          = $RoleDefId
            RoleType                        = $RoleType
            IsPrivileged                    = $RoleIsPrivileged
            RoleAssignmentPIMRelated        = $False
            RoleAssignmentPIMAssignmentType = "Permanent"
            RoleAssignmentScopeId           = $AadPrincipalRoleAssignment.directoryScopeId
            RoleAssignmentScopeName         = $RoleAssignmentScopeName
            RoleAssignmentType              = "Direct"
            RoleAssignmentSubType           = ""
            ObjectDisplayName               = if ($PrincipalProfile) { $PrincipalProfile.displayName } else { $Principal }
            ObjectId                        = $Principal
            ObjectType                      = $ObjectTypeLower
            TransitiveByObjectId            = $null
            TransitiveByObjectDisplayName   = $null
        }
    }
    #endregion

    #region Collect eligible direct role assignments
    Write-Host "Get details of Entra ID Eligible Role Assignments..."
    Write-Host "Processing $($EligibleToProcess.Count) eligible assignments..." -ForegroundColor Gray
    
    # Track progress for user feedback
    $ProcessedCount = 0
    $TotalCount = $EligibleToProcess.Count
    $ProgressInterval = [Math]::Max(1, [Math]::Floor($TotalCount / 20))  # Update every 5%
    
    # Already filtered in EligibleToProcess (from top block)
    # Using parallel processing for improved performance with large assignment counts
    $AadEligibleUserRoleAssignments = $EligibleToProcess | ForEach-Object -ThrottleLimit 50 -Parallel {
        $EligiblePrincipalRoleAssignment = $_
        $Principal = $EligiblePrincipalRoleAssignment.principalId
        
        # Import hashtables from parent scope
        $DirObjLookup = $using:DirObjLookup
        $RoleDefLookup = $using:RoleDefLookup
        $GuidPattern = $using:GuidPattern
        
        # Thread-safe progress tracking
        $CurrentCount = $using:ProcessedCount
        $Total = $using:TotalCount
        $Interval = $using:ProgressInterval
        
        # Increment and check if we should report progress
        $LocalCount = [System.Threading.Interlocked]::Increment([ref]$using:ProcessedCount)
        if (($LocalCount % $Interval) -eq 0 -or $LocalCount -eq $Total) {
            $PercentComplete = [Math]::Round(($LocalCount / $Total) * 100, 0)
            Write-Progress -Activity "Processing Eligible Assignments" -Status "Processing $LocalCount of $Total eligible assignments" -PercentComplete $PercentComplete -Id 100
        }
        
        # Resolve Principal
        $ObjectType = "unknown"
        $PrincipalProfile = $null

        if ($null -ne $Principal -and $DirObjLookup.ContainsKey($Principal)) {
            $PrincipalProfile = $DirObjLookup[$Principal]
        } elseif ($null -eq $Principal) {
            # Skip eligible assignments with null principal
            return $null
        } else {
            # Principal not found even after fallback resolution  
            if ($WarningMessages) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "Principal Resolution"
                        Message = "Principal $Principal could not be resolved for eligible assignment (deleted/orphaned)"
                        Target  = $Principal
                    })
            }
        }

        if ($PrincipalProfile) {
            if ($PrincipalProfile.'@odata.type') {
                $ObjectType = $PrincipalProfile.'@odata.type'.Replace('#microsoft.graph.', '')
            }
        }

        # Resolve Role
        $RoleDefId = $EligiblePrincipalRoleAssignment.roleDefinitionId
        $RoleDefinitionName = "Unknown"
        $RoleType = "CustomRole"
        $RoleIsPrivileged = $false

        if ($RoleDefLookup.ContainsKey($RoleDefId)) {
            $Role = $RoleDefLookup[$RoleDefId]
        } else {
            # Fallback for deprecated/hidden roles
            # Note: API calls in parallel blocks require careful consideration
            # Using cached lookup should handle 99%+ of cases
            if ($WarningMessages) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "Role Definition"
                        Message = "Role definition $RoleDefId not found in lookup cache for eligible assignment"
                        Target  = $RoleDefId
                    })
            }
            $Role = $null
        }

        if ($Role) {
            $RoleDefinitionName = $Role.displayName
            $RoleIsPrivileged = $Role.isPrivileged
            if ($Role.isBuiltIn -eq $True -or $Role.isBuiltIn -eq "true") { 
                $RoleType = "BuiltInRole" 
            }
            if ($Role.templateId) {
                $RoleDefId = $Role.templateId
            }
        }

        # Resolve Scope
        $RoleAssignmentScopeName = "Directory"
        if ($EligiblePrincipalRoleAssignment.directoryScopeId -ne "/") {
            $ScopeId = $null
            if ($EligiblePrincipalRoleAssignment.directoryScopeId -match $GuidPattern) {
                $ScopeId = $Matches[1]
            }
            if ($ScopeId -and $DirObjLookup.ContainsKey($ScopeId)) {
                $RoleAssignmentScopeName = $DirObjLookup[$ScopeId].displayName
            } else {
                # Scope not in batch lookup (rare edge case)
                # Using scope ID directly since API calls don't work reliably in parallel
                $RoleAssignmentScopeName = $EligiblePrincipalRoleAssignment.directoryScopeId
                Write-Verbose "Scope $ScopeId not found in lookup cache for eligible assignment"
            }
        }

        # Pre-compute string operations
        $ObjectTypeLower = $ObjectType.ToLower()

        [pscustomobject]@{
            RoleAssignmentId                = $EligiblePrincipalRoleAssignment.Id
            RoleName                        = $RoleDefinitionName
            RoleId                          = $RoleDefId
            RoleType                        = $RoleType
            IsPrivileged                    = $RoleIsPrivileged
            RoleAssignmentPIMRelated        = $True
            RoleAssignmentPIMAssignmentType = "Eligible"
            RoleAssignmentScopeId           = $EligiblePrincipalRoleAssignment.directoryScopeId
            RoleAssignmentScopeName         = $RoleAssignmentScopeName
            RoleAssignmentType              = "Direct"
            RoleAssignmentSubType           = ""
            ObjectDisplayName               = if ($PrincipalProfile) { $PrincipalProfile.displayName } else { $Principal }
            ObjectId                        = $Principal
            ObjectType                      = $ObjectTypeLower
            TransitiveByObjectId            = $null
            TransitiveByObjectDisplayName   = $null
        }
    }
    
    Write-Progress -Activity "Processing Eligible Assignments" -Completed -Id 100
    Write-Host "✓ Processed $($AadEligibleUserRoleAssignments.Count) eligible assignments" -ForegroundColor Green
    #endregion

    #region Remove activated (eligible) assignments and mark time-bounded assignments in permanent assignments
    # Use PIM assignments fetched earlier in parallel
    $AadActiveRoleAssignments = $AadRoleAssignmentsByPim | Where-Object { $_.assignmentType -eq 'Activated' }
    $AadTimeBoundedRoleAssignments = $AadRoleAssignmentsByPim | Where-Object { $_.assignmentType -eq 'Assigned' -and $null -ne $_.endDateTime }

    # Build hashtable lookups for O(1) performance instead of -in operator O(N)
    $ActiveAssignmentLookup = @{}
    $ActiveAssignmentOriginLookup = @{}
    foreach ($ActiveAssignment in $AadActiveRoleAssignments) {
        if ($ActiveAssignment.id) { $ActiveAssignmentLookup[$ActiveAssignment.id] = $true }
        if ($ActiveAssignment.RoleAssignmentOriginId) { $ActiveAssignmentOriginLookup[$ActiveAssignment.RoleAssignmentOriginId] = $true }
    }
    
    $TimeBoundedAssignmentLookup = @{}
    $TimeBoundedOriginLookup = @{}
    foreach ($TimeBoundedAssignment in $AadTimeBoundedRoleAssignments) {
        if ($TimeBoundedAssignment.id) { $TimeBoundedAssignmentLookup[$TimeBoundedAssignment.id] = $true }
        if ($TimeBoundedAssignment.RoleAssignmentOriginId) { $TimeBoundedOriginLookup[$TimeBoundedAssignment.RoleAssignmentOriginId] = $true }
    }

    $AadPermanentRoleAssignmentsWithEnrichment = foreach ($AadRbacActiveAndPermanentAssignment in $AadRbacActiveAndPermanentAssignments) {
        $AssignmentId = $AadRbacActiveAndPermanentAssignment.RoleAssignmentId
        
        if ($ActiveAssignmentLookup.ContainsKey($AssignmentId) -and $ActiveAssignmentOriginLookup.ContainsKey($AssignmentId)) {
            $AadRbacActiveAndPermanentAssignment.RoleAssignmentPIMRelated = $True
            $AadRbacActiveAndPermanentAssignment.RoleAssignmentPIMAssignmentType = "Activated"
        } elseif ($TimeBoundedAssignmentLookup.ContainsKey($AssignmentId) -and $TimeBoundedOriginLookup.ContainsKey($AssignmentId)) {
            $AadRbacActiveAndPermanentAssignment.RoleAssignmentPIMRelated = $True
            $AadRbacActiveAndPermanentAssignment.RoleAssignmentPIMAssignmentType = "TimeBounded"
        } else {
            Write-Verbose "Permanent assignment $($AadRbacActiveAndPermanentAssignment.RoleAssignmentId): No active or eligible assignment detected"
        }
        $AadRbacActiveAndPermanentAssignment
    }

    $AadPermanentRoleAssignments = $AadPermanentRoleAssignmentsWithEnrichment | Where-Object { $_.RoleAssignmentPIMAssignmentType -ne "Activated" }
    #endregion

    # Summarize results with direct permanent (excl.s activated roles) and eligible role assignments
    $AllAadRbacAssignments = @()
    $AllAadRbacAssignments += $AadPermanentRoleAssignments
    $AllAadRbacAssignments += $AadEligibleUserRoleAssignments

    #region Collect transitive assignments by group members of Role-Assignable Groups
    if ($ExpandGroupMembers -eq $True) {    
        $GroupsWithRbacAssignment = $AllAadRbacAssignments | where-object { $_.ObjectType -eq "group" } | Select-Object -Unique ObjectId, ObjectDisplayName
        $GroupCount = $GroupsWithRbacAssignment.Count
        
        if ($GroupCount -eq 0) {
            Write-Verbose "No groups with role assignments found, skipping transitive member expansion"
            $AllTransitiveMembers = [System.Collections.Generic.List[object]]::new()
        } else {
            # Sequential processing: Get-EntraOpsPrivilegedTransitiveGroupMember not available in parallel runspaces
            Write-Verbose "Expanding $GroupCount group(s) for transitive Entra ID role assignments"
            $AllTransitiveMembers = [System.Collections.Generic.List[object]]::new()
            
            foreach ($GroupWithRbacAssignment in $GroupsWithRbacAssignment) {
                $TransitiveMembers = Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId $($GroupWithRbacAssignment.ObjectId)
                foreach ($TransitiveMember in $TransitiveMembers) {
                    $Member = [pscustomobject]@{
                        displayName            = $TransitiveMember.displayName
                        id                     = $TransitiveMember.id
                        '@odata.type'          = $TransitiveMember.'@odata.type'
                        RoleAssignmentSubType  = $TransitiveMember.RoleAssignmentSubType
                        GroupObjectDisplayName = $GroupWithRbacAssignment.ObjectDisplayName
                        GroupObjectId          = $GroupWithRbacAssignment.ObjectId
                    }
                    $AllTransitiveMembers.Add($Member) | Out-Null
                }
            }
        }

        $AadRbacTransitiveAssignments = [System.Collections.Generic.List[object]]::new()
        foreach ($RbacAssignmentByGroup in ($AllAadRbacAssignments | where-object { $_.ObjectType -eq "group" }) ) {

            $RbacAssignmentByNestedGroupMembers = $AllTransitiveMembers | Where-Object { $_.GroupObjectId -eq $RbacAssignmentByGroup.ObjectId }

            if ($RbacAssignmentByNestedGroupMembers.Count -gt 0) {
                $RbacAssignmentByNestedGroupMembers | foreach-object {
                    # Pre-compute string operations
                    $MemberObjectType = $_.'@odata.type'.Replace("#microsoft.graph.", "").ToLower()
                    
                    [pscustomobject]@{
                        RoleAssignmentId                = $RbacAssignmentByGroup.RoleAssignmentId
                        RoleName                        = $RbacAssignmentByGroup.RoleName
                        RoleId                          = $RbacAssignmentByGroup.RoleId
                        RoleType                        = $RbacAssignmentByGroup.RoleType
                        IsPrivileged                    = $RbacAssignmentByGroup.isPrivileged
                        RoleAssignmentPIMRelated        = $RbacAssignmentByGroup.RoleAssignmentPIMRelated
                        RoleAssignmentPIMAssignmentType = $RbacAssignmentByGroup.RoleAssignmentPIMAssignmentType
                        RoleAssignmentScopeId           = $RbacAssignmentByGroup.RoleAssignmentScopeId
                        RoleAssignmentScopeName         = $RbacAssignmentByGroup.RoleAssignmentScopeName
                        RoleAssignmentType              = "Transitive"
                        RoleAssignmentSubType           = $_.RoleAssignmentSubType
                        ObjectDisplayName               = $_.displayName
                        ObjectId                        = $_.id
                        ObjectType                      = $MemberObjectType
                        TransitiveByObjectId            = $RbacAssignmentByGroup.ObjectId
                        TransitiveByObjectDisplayName   = $_.GroupObjectDisplayName
                    }
                }
            } else {
                if ($WarningMessages) {
                    $WarningMessages.Add([PSCustomObject]@{
                            Type    = "Empty Group"
                            Message = "Empty group $($RbacAssignmentByGroup.ObjectId)"
                            Target  = $RbacAssignmentByGroup.ObjectId
                        })
                }
            }

            $AadRbacTransitiveAssignments.Add($TransitiveMember) | Out-Null
        }
    }
    #endregion

    #region Filtering export if needed
    $AllAadRbacAssignments += $AadRbacTransitiveAssignments
    $AllAadRbacAssignments = $AllAadRbacAssignments | where-object { $_.ObjectType -in $PrincipalTypeFilter }
    
    # Efficient deduplication using hashtable with composite key instead of Select-Object -Unique *
    $DeduplicationHash = @{}
    $UniqueAssignments = foreach ($Assignment in $AllAadRbacAssignments) {
        # Create composite key from unique identifying properties
        $Key = "$($Assignment.RoleAssignmentId)|$($Assignment.ObjectId)|$($Assignment.RoleAssignmentType)"
        if (-not $DeduplicationHash.ContainsKey($Key)) {
            $DeduplicationHash[$Key] = $true
            $Assignment
        }
    }
    
    $UniqueAssignments | Sort-Object RoleAssignmentId, RoleAssignmentType, ObjectId
    #endregion
}