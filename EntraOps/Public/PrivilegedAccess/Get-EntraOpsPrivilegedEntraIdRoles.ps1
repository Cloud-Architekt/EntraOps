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
        [System.String]$TenantId = (Get-EntraOpsAzContextValue -Property TenantId)
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("User", "Group", "ServicePrincipal")]
        [Array]$PrincipalTypeFilter = ("User", "Group", "ServicePrincipal")
        ,
        [Parameter(Mandatory = $False)]
        [System.Boolean]$ExpandGroupMembers = $true
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$ExpandCrossTenantGroupMembers = $true
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
    if ([string]::IsNullOrEmpty($PersistentCachePath)) {
        Write-Warning "PersistentCachePath is not set in EntraOps session. Caching will be disabled for this run."
        $PersistentCachePath = $null
    }
    if ($PersistentCachePath -and -not (Test-Path $PersistentCachePath)) {
        New-Item -ItemType Directory -Path $PersistentCachePath -Force | Out-Null
    }
    
    $CacheKey = "EntraOps_RoleData_$($TenantId)"
    $CacheFileName = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($CacheKey)) + ".json"
    $CacheFile = if ($PersistentCachePath) { Join-Path $PersistentCachePath $CacheFileName } else { $null }
    $CacheValid = $false
    $CacheTTL = $__EntraOpsSession.StaticDataCacheTTL  # Use configurable TTL for static data
    
    if ($CacheFile -and (Test-Path $CacheFile)) {
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
        foreach ($SampleFile in @("$EntraOpsBaseFolder/Samples/AadRoleManagementRoleDefinitions.json", "$EntraOpsBaseFolder/Samples/AadRoleManagementAssignments.json")) {
            if (-not (Test-Path -LiteralPath $SampleFile)) {
                throw "Sample file $SampleFile not found — SampleMode requires sample data files under Samples/"
            }
        }
        $AadRoleDefinitions = get-content -Path "$EntraOpsBaseFolder/Samples/AadRoleManagementRoleDefinitions.json" | ConvertFrom-Json -Depth 10
        $AadRoleAssignments = get-content -Path "$EntraOpsBaseFolder/Samples/AadRoleManagementAssignments.json" | ConvertFrom-Json -Depth 10
        $AadEligibleRoleAssignments = @()
        if (Test-Path "$EntraOpsBaseFolder/Samples/AadRoleManagementEligibleAssignments.json") {
            $AadEligibleRoleAssignments = get-content -Path "$EntraOpsBaseFolder/Samples/AadRoleManagementEligibleAssignments.json" | ConvertFrom-Json -Depth 10
        }
        $AadRoleAssignmentsByPim = @()
        $TgRelationships = @()
    } elseif ($CacheValid) {
        $CachedObject = Get-Content $CacheFile -Raw | ConvertFrom-Json
        $AadRoleDefinitions = $CachedObject.Data.RoleDefinitions
        $AadRoleAssignments = $CachedObject.Data.RoleAssignments
        $AadEligibleRoleAssignments = $CachedObject.Data.EligibleAssignments
        $AadRoleAssignmentsByPim = $CachedObject.Data.PimAssignments
        $TgRelationships = if ($CachedObject.Data.TgRelationships) { $CachedObject.Data.TgRelationships } else { @() }

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
        # Filter will be applied in code where we have more control
        $AadEligibleRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleEligibilitySchedules?`$select=id,principalId,roleDefinitionId,directoryScopeId,memberType,status"
        # Fetch PIM assignment schedules early (used later for enrichment)
        $AadRoleAssignmentsByPim = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/roleManagement/directory/roleAssignmentScheduleInstances?`$select=id,roleDefinitionId,assignmentType,endDateTime,startDateTime,roleAssignmentOriginId" -OutputType PSObject
        # Fetch Tenant Governance relationships for delegated admin role assignments
        try {
            # -ThrowOnFailure so a real API failure (e.g. missing permission) lands in the catch
            # below instead of silently returning $null - @($null).Count is 1, not 0, so without
            # this the failure path would misreport "Fetched 1 relationship(s)" on every error.
            $TgRelationships = Invoke-EntraOpsMsGraphQuery -Uri "/beta/directory/tenantGovernance/governanceRelationships" -ThrowOnFailure
            Write-Host "Fetched $(@($TgRelationships).Count) Tenant Governance relationship(s) from API" -ForegroundColor Gray
        } catch {
            Write-Warning "Tenant Governance relationships not available (API error or insufficient permissions): $_"
            if ($null -ne $WarningMessages) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "TenantGovernance"
                        Message = "Failed to fetch Tenant Governance relationships: $($_.Exception.Message)"
                        Target  = "/beta/directory/tenantGovernance/governanceRelationships"
                    })
            }
            $TgRelationships = @()
        }
        Write-Verbose "Parallel data fetch complete"

        # Validate essential data was retrieved
        if ($null -eq $AadRoleDefinitions -or $null -eq $AadRoleAssignments) {
            Write-Error "Failed to retrieve essential role data from Microsoft Graph. Please ensure you are connected (Connect-EntraOps) and have the required permissions."
            return @()
        }
        
        # Ensure collections are arrays even if API returns null
        if ($null -eq $AadEligibleRoleAssignments) { $AadEligibleRoleAssignments = @() }
        if ($null -eq $AadRoleAssignmentsByPim) { $AadRoleAssignmentsByPim = @() }
        if ($null -eq $TgRelationships) { $TgRelationships = @() }

        if ($AadRoleAssignments.Count -gt 0 -and $CacheFile) {
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
                        TgRelationships     = $TgRelationships
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
    
    # Apply filtering in code for better visibility and control
    # Note: Including all status types to prevent missing assignments
    $EligibleToProcess = $AadEligibleRoleAssignments | Where-Object { 
        $_.memberType -eq 'Direct' -and 
        ($_.status -eq 'Provisioned' -or $_.status -eq 'Accepted')
    }
    Write-Verbose "Processing $($EligibleToProcess.Count) eligible assignments (Direct members with Provisioned/Accepted status) out of $($AadEligibleRoleAssignments.Count) total eligible assignments"
    
    foreach ($AadRoleAssignment in $EligibleToProcess) {
        if ($AadRoleAssignment.principalId) { 
            $PrincipalIds.Add($AadRoleAssignment.principalId) | Out-Null 
        }
        if ($AadRoleAssignment.directoryScopeId -and $AadRoleAssignment.directoryScopeId -ne "/" -and $AadRoleAssignment.directoryScopeId -match $GuidPattern) {
            $ScopeIds.Add($Matches[1]) | Out-Null
        }
    }

    # Collect group IDs from Tenant Governance delegated admin assignments for principal resolution
    $ActiveTgRelationships = $TgRelationships | Where-Object { $_.status -eq "active" }

    # Report Tenant Governance relationships that cannot participate in collection.
    if (@($TgRelationships).Count -gt 0 -and @($ActiveTgRelationships).Count -eq 0) {
        $AllStatuses = @($TgRelationships | ForEach-Object { $_.status }) | Select-Object -Unique
        Write-Warning "Found $(@($TgRelationships).Count) TG relationship(s) but none with status 'active'. Statuses found: $($AllStatuses -join ', ')"
        if ($null -ne $WarningMessages) {
            $WarningMessages.Add([PSCustomObject]@{
                    Type    = "TenantGovernance"
                    Message = "No active TG relationships found. Total: $(@($TgRelationships).Count), Statuses: $($AllStatuses -join ', ')"
                    Target  = "status-filter"
                })
        }

        # Include one relationship schema sample in verbose output.
        $FirstTg = $TgRelationships | Select-Object -First 1
        if ($FirstTg) {
            $PropNames = ($FirstTg | Get-Member -MemberType NoteProperty, Property | Select-Object -ExpandProperty Name) -join ', '
            Write-Verbose "TG relationship properties: $PropNames"
            Write-Verbose "TG relationship sample: $($FirstTg | ConvertTo-Json -Depth 3 -Compress)"
        }
    } elseif (@($TgRelationships).Count -gt 0) {
        Write-Host "Found $(@($ActiveTgRelationships).Count) active TG relationship(s) out of $(@($TgRelationships).Count) total" -ForegroundColor Gray
    } else {
        Write-Verbose "No Tenant Governance relationships returned from API"
    }

    foreach ($TgRelationship in $ActiveTgRelationships) {
        # Validate expected property structure (API may use different property names)
        if ($null -eq $TgRelationship.GoverningTenantId -and $null -eq $TgRelationship.governingTenantId) {
            $PropNames = ($TgRelationship | Get-Member -MemberType NoteProperty, Property | Select-Object -ExpandProperty Name) -join ', '
            Write-Warning "TG relationship '$($TgRelationship.id)' missing GoverningTenantId property. Available properties: $PropNames"
            if ($null -ne $WarningMessages) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "TenantGovernance"
                        Message = "TG relationship '$($TgRelationship.id)' missing GoverningTenantId. Properties: $PropNames"
                        Target  = $TgRelationship.id
                    })
            }
        }

        if ($null -eq $TgRelationship.policySnapshot) {
            Write-Warning "TG relationship '$($TgRelationship.id)' has null policySnapshot"
            if ($null -ne $WarningMessages) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "TenantGovernance"
                        Message = "TG relationship '$($TgRelationship.id)' has null policySnapshot - no role assignments can be extracted"
                        Target  = $TgRelationship.id
                    })
            }
            continue
        }

        if ($null -eq $TgRelationship.policySnapshot.delegatedAdministrationRoleAssignments -or @($TgRelationship.policySnapshot.delegatedAdministrationRoleAssignments).Count -eq 0) {
            Write-Warning "TG relationship '$($TgRelationship.id)' has no delegatedAdministrationRoleAssignments in policySnapshot"
            if ($null -ne $WarningMessages) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "TenantGovernance"
                        Message = "TG relationship '$($TgRelationship.id)' policySnapshot has no delegatedAdministrationRoleAssignments"
                        Target  = $TgRelationship.id
                    })
            }
            continue
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
        
        # Tenant Governance groups are resolved independently through remoteTenantGroups and are
        # not added to PrincipalIds. Every ID here belongs to a home-tenant role assignment and
        # must retain the normal fallback path, even when TG references the same group ID.
        $UnresolvedPrincipals = $PrincipalIdArray | Where-Object { -not $DirObjLookup.ContainsKey($_) }
        
        if ($UnresolvedPrincipals.Count -gt 0) {
            Write-Verbose "$($UnresolvedPrincipals.Count) principal(s) not resolved via type-specific endpoints, attempting batched directoryObjects resolution..."

            # Batch the leftovers through the generic directoryObjects/getByIds endpoint first
            # (covers types outside user/group/servicePrincipal, e.g. devices) - one round-trip
            # per 1000 ids instead of one GET per principal. Ids absent from the response are
            # confirmed deleted/unsupported; the per-principal GET below remains only as a
            # fallback when the batch call itself fails.
            $BatchFallbackWorked = $true
            try {
                $DirObjBatchSize = 1000
                $UnresolvedArray = @($UnresolvedPrincipals)
                for ($i = 0; $i -lt $UnresolvedArray.Count; $i += $DirObjBatchSize) {
                    $Batch = @($UnresolvedArray[$i..([Math]::Min($i + $DirObjBatchSize - 1, $UnresolvedArray.Count - 1))])
                    $Body = @{ ids = $Batch } | ConvertTo-Json
                    $Response = Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/directoryObjects/getByIds?`$select=id,displayName" -Body $Body -OutputType PSObject -ThrowOnFailure
                    foreach ($Obj in @($Response)) {
                        if ($null -ne $Obj.id -and -not $DirObjLookup.ContainsKey($Obj.id)) {
                            $DirObjLookup[$Obj.id] = $Obj
                        }
                    }
                }
            } catch {
                Write-Verbose "Batched directoryObjects resolution failed, falling back to individual lookups: $($_.Exception.Message)"
                $BatchFallbackWorked = $false
            }

            $IndividualResolvedCount = 0
            $ConfirmedDeletedCount = 0

            foreach ($UnresolvedId in $UnresolvedPrincipals) {
                if ($DirObjLookup.ContainsKey($UnresolvedId)) {
                    $IndividualResolvedCount++
                    continue
                }
                if ($BatchFallbackWorked) {
                    # Authoritative batch response did not contain this id - confirmed deleted/orphaned.
                    $ConfirmedDeletedCount++
                    Write-Verbose "Confirmed deleted/not found: $UnresolvedId"
                    if ($null -ne $WarningMessages) {
                        $WarningMessages.Add([PSCustomObject]@{
                                Type    = "RoleAssignmentResolution"
                                Message = "Principal $UnresolvedId could not be resolved (likely deleted or insufficient permissions)."
                                Target  = $UnresolvedId
                            })
                    }
                    continue
                }
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
    if ($CacheFile -and ($UnresolvedPrincipalIds.Count -gt 0 -or ($ScopeResolvedCount -gt 0) -or (-not $CacheValid))) {
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
                    TgRelationships     = $TgRelationships
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
    # Thread-safe warning collection for parallel block (List[psobject] is NOT thread-safe)
    $ParallelWarningsPermanent = [System.Collections.Concurrent.ConcurrentBag[psobject]]::new()
    $AadRbacActiveAndPermanentAssignments = $AadRoleAssignments | ForEach-Object -ThrottleLimit 50 -Parallel {
        $AadPrincipalRoleAssignment = $_
        $Principal = $AadPrincipalRoleAssignment.principalId
        
        # Import hashtables from parent scope
        $DirObjLookup = $using:DirObjLookup
        $RoleDefLookup = $using:RoleDefLookup
        $GuidPattern = $using:GuidPattern
        $LocalWarnings = $using:ParallelWarningsPermanent
        $LocalTenantId = $using:TenantId
        
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
            $LocalWarnings.Add([PSCustomObject]@{
                    Type    = "Principal Resolution"
                    Message = "Principal $Principal could not be resolved (deleted/orphaned assignment)"
                    Target  = $Principal
                })
        }

        if ($PrincipalProfile) {
            if ($PrincipalProfile.'@odata.type') {
                $ObjectType = $PrincipalProfile.'@odata.type'.Replace('#microsoft.graph.', '')
            } else {
                # Fallback if odata.type is missing (should not happen on Graph objects)
                Write-Verbose "Object type missing for $Principal"
            }
        } else {
            # Create placeholder for unresolved principal to keep assignment visible
            $ObjectType = "Unknown"
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
            $LocalWarnings.Add([PSCustomObject]@{
                    Type    = "Role Definition"
                    Message = "Role definition $RoleDefId not found in lookup cache"
                    Target  = $RoleDefId
                })
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
            RoleAssignmentId                      = $AadPrincipalRoleAssignment.Id
            RoleName                              = $RoleDefinitionName
            RoleId                                = $RoleDefId
            RoleType                              = $RoleType
            IsPrivileged                          = $RoleIsPrivileged
            RoleAssignmentPIMRelated              = $False
            RoleAssignmentPIMAssignmentType       = "Permanent"
            RoleAssignmentScopeId                 = $AadPrincipalRoleAssignment.directoryScopeId
            RoleAssignmentScopeName               = $RoleAssignmentScopeName
            RoleAssignmentType                    = "Direct"
            RoleAssignmentSubType                 = ""
            ObjectDisplayName                     = if ($PrincipalProfile) { $PrincipalProfile.displayName } else { "[Unresolved: $Principal]" }
            ObjectId                              = $Principal
            ObjectTenantId                        = $LocalTenantId            
            ObjectType                            = $ObjectTypeLower
            TransitiveByObjectId                  = $null
            TransitiveByObjectDisplayName         = $null
            TransitiveByNestingObjectIds          = $null
            TransitiveByNestingObjectDisplayNames = $null
        }
    }

    # Merge thread-safe warnings back into main WarningMessages list
    foreach ($w in $ParallelWarningsPermanent) {
        if ($null -ne $WarningMessages) { $WarningMessages.Add($w) }
    }
    #endregion

    #region Collect eligible direct role assignments
    Write-Host "Get details of Entra ID Eligible Role Assignments..."
    Write-Host "Processing $($EligibleToProcess.Count) eligible assignments..." -ForegroundColor Gray
    
    # Track progress for user feedback using thread-safe counter
    $ProgressCounter = [System.Collections.Concurrent.ConcurrentBag[int]]::new()
    $TotalCount = $EligibleToProcess.Count
    $ProgressInterval = [Math]::Max(1, [Math]::Floor($TotalCount / 20))  # Update every 5%
    
    # Thread-safe warning collection for parallel block
    $ParallelWarningsEligible = [System.Collections.Concurrent.ConcurrentBag[psobject]]::new()
    
    # Already filtered in EligibleToProcess (from top block)
    # Using parallel processing for improved performance with large assignment counts
    $AadEligibleUserRoleAssignments = $EligibleToProcess | ForEach-Object -ThrottleLimit 50 -Parallel {
        $EligiblePrincipalRoleAssignment = $_
        $Principal = $EligiblePrincipalRoleAssignment.principalId
        
        # Import hashtables from parent scope
        $DirObjLookup = $using:DirObjLookup
        $RoleDefLookup = $using:RoleDefLookup
        $GuidPattern = $using:GuidPattern
        $LocalWarnings = $using:ParallelWarningsEligible
        $LocalTenantId = $using:TenantId
        
        # Thread-safe progress tracking using ConcurrentBag
        $LocalCounter = $using:ProgressCounter
        $Total = $using:TotalCount
        $Interval = $using:ProgressInterval
        
        $LocalCounter.Add(1)
        $LocalCount = $LocalCounter.Count
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
            $LocalWarnings.Add([PSCustomObject]@{
                    Type    = "Principal Resolution"
                    Message = "Principal $Principal could not be resolved for eligible assignment (deleted/orphaned)"
                    Target  = $Principal
                })
        }

        if ($PrincipalProfile) {
            if ($PrincipalProfile.'@odata.type') {
                $ObjectType = $PrincipalProfile.'@odata.type'.Replace('#microsoft.graph.', '')
            }
        } else {
            $ObjectType = "Unknown"
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
            $LocalWarnings.Add([PSCustomObject]@{
                    Type    = "Role Definition"
                    Message = "Role definition $RoleDefId not found in lookup cache for eligible assignment"
                    Target  = $RoleDefId
                })
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
            RoleAssignmentId                      = $EligiblePrincipalRoleAssignment.Id
            RoleName                              = $RoleDefinitionName
            RoleId                                = $RoleDefId
            RoleType                              = $RoleType
            IsPrivileged                          = $RoleIsPrivileged
            RoleAssignmentPIMRelated              = $True
            RoleAssignmentPIMAssignmentType       = "Eligible"
            RoleAssignmentScopeId                 = $EligiblePrincipalRoleAssignment.directoryScopeId
            RoleAssignmentScopeName               = $RoleAssignmentScopeName
            RoleAssignmentType                    = "Direct"
            RoleAssignmentSubType                 = ""
            ObjectDisplayName                     = if ($PrincipalProfile) { $PrincipalProfile.displayName } else { "[Unresolved: $Principal]" }
            ObjectId                              = $Principal
            ObjectTenantId                        = $LocalTenantId            
            ObjectType                            = $ObjectTypeLower
            TransitiveByObjectId                  = $null
            TransitiveByObjectDisplayName         = $null
            TransitiveByNestingObjectIds          = $null
            TransitiveByNestingObjectDisplayNames = $null
        }
    }
    
    # Merge thread-safe warnings back into main WarningMessages list
    foreach ($w in $ParallelWarningsEligible) {
        if ($null -ne $WarningMessages) { $WarningMessages.Add($w) }
    }
    
    Write-Progress -Activity "Processing Eligible Assignments" -Completed -Id 100
    Write-Host "✓ Processed $($AadEligibleUserRoleAssignments.Count) eligible assignments" -ForegroundColor Green
    #endregion

    #region Remove activated (eligible) assignments and mark time-bounded assignments in permanent assignments
    # Use PIM assignments fetched earlier in parallel
    $AadActiveRoleAssignments = $AadRoleAssignmentsByPim | Where-Object { $_.assignmentType -eq 'Activated' }
    $AadTimeBoundedRoleAssignments = $AadRoleAssignmentsByPim | Where-Object { $_.assignmentType -eq 'Assigned' -and $null -ne $_.endDateTime }

    # Fixed: Build hashtable lookups correctly - separate lookups for assignment IDs vs origin IDs
    $ActiveAssignmentLookup = @{}
    $ActiveOriginToAssignmentMap = @{}
    foreach ($ActiveAssignment in $AadActiveRoleAssignments) {
        if ($ActiveAssignment.id) { 
            $ActiveAssignmentLookup[$ActiveAssignment.id] = $true 
        }
        # Map origin ID to assignment ID for proper lookup
        if ($ActiveAssignment.roleAssignmentOriginId -and $ActiveAssignment.id) { 
            $ActiveOriginToAssignmentMap[$ActiveAssignment.roleAssignmentOriginId] = $ActiveAssignment.id
        }
    }
    
    $TimeBoundedAssignmentLookup = @{}
    $TimeBoundedOriginToAssignmentMap = @{}
    foreach ($TimeBoundedAssignment in $AadTimeBoundedRoleAssignments) {
        if ($TimeBoundedAssignment.id) { 
            $TimeBoundedAssignmentLookup[$TimeBoundedAssignment.id] = $true 
        }
        # Map origin ID to assignment ID for proper lookup
        if ($TimeBoundedAssignment.roleAssignmentOriginId -and $TimeBoundedAssignment.id) { 
            $TimeBoundedOriginToAssignmentMap[$TimeBoundedAssignment.roleAssignmentOriginId] = $TimeBoundedAssignment.id
        }
    }

    $AadPermanentRoleAssignmentsWithEnrichment = foreach ($AadRbacActiveAndPermanentAssignment in $AadRbacActiveAndPermanentAssignments) {
        $AssignmentId = $AadRbacActiveAndPermanentAssignment.RoleAssignmentId
        
        # Check if this assignment ID represents an activated eligible assignment
        if ($ActiveAssignmentLookup.ContainsKey($AssignmentId)) {
            $AadRbacActiveAndPermanentAssignment.RoleAssignmentPIMRelated = $True
            $AadRbacActiveAndPermanentAssignment.RoleAssignmentPIMAssignmentType = "Activated"
            Write-Verbose "Marked assignment ${AssignmentId} as Activated"
        } elseif ($TimeBoundedAssignmentLookup.ContainsKey($AssignmentId)) {
            $AadRbacActiveAndPermanentAssignment.RoleAssignmentPIMRelated = $True
            $AadRbacActiveAndPermanentAssignment.RoleAssignmentPIMAssignmentType = "TimeBounded"
            Write-Verbose "Marked assignment ${AssignmentId} as TimeBounded"
        } else {
            Write-Verbose "Permanent assignment ${AssignmentId} - No active or eligible assignment detected"
        }
        $AadRbacActiveAndPermanentAssignment
    }

    # Fixed: Include activated assignments in output (with proper flag) instead of excluding them
    # This ensures all current role assignments are visible
    $AadPermanentRoleAssignments = $AadPermanentRoleAssignmentsWithEnrichment
    #endregion

    #region Collect Tenant Governance Delegated Admin Role Assignments
    Write-Host "Get Tenant Governance Delegated Admin Role Assignments..."
    $TgDelegatedActiveAndPermanentAssignments = @()

    if ($null -ne $ActiveTgRelationships -and $ActiveTgRelationships.Count -gt 0) {
        Write-Host "Fetching remote tenant groups..."
        # Remote tenant root group lookup: the only way to resolve a display name for
        # delegated admin groups living in a (non-managing) governing tenant. Best-effort -
        # a failure here must not abort the whole role collection.
        $RemoteTgGroups = @()
        try {
            $RemoteTgGroups = @(Invoke-EntraOpsMsGraphQuery -Uri "/beta/directory/remoteTenantGroups" -OutputType PSObject)
        } catch {
            Write-Warning "Could not fetch remote tenant groups (remote tenant root group resolution unavailable): $($_.Exception.Message)"
            if ($null -ne $WarningMessages) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "TenantGovernance"
                        Message = "Failed to fetch /beta/directory/remoteTenantGroups - TG group display names fall back to governing tenant name: $($_.Exception.Message)"
                        Target  = "/beta/directory/remoteTenantGroups"
                    })
            }
        }
        Write-Host "Found $(@($RemoteTgGroups | Where-Object { $null -ne $_ }).Count) remote tenant group(s)"

        # O(1) lookup by remote group id for the parallel block below (avoids scanning
        # the whole array in every runspace).
        $RemoteTgGroupLookup = @{}
        foreach ($RemoteTgGroup in $RemoteTgGroups) {
            if (-not [string]::IsNullOrEmpty($RemoteTgGroup.remoteGroupId) -and -not $RemoteTgGroupLookup.ContainsKey($RemoteTgGroup.remoteGroupId)) {
                $RemoteTgGroupLookup[$RemoteTgGroup.remoteGroupId] = $RemoteTgGroup
            }
        }

        Write-Host "Processing $($ActiveTgRelationships.Count) active Tenant Governance relationship(s)..."

        # Flatten nested structure into processable items for parallel execution
        $TgFlattenedAssignments = [System.Collections.Generic.List[psobject]]::new()
        foreach ($TgRelationship in $ActiveTgRelationships) {
            Write-Verbose "Processing Tenant Governance Relationship $($TgRelationship.id)"

            if ($null -eq $TgRelationship.policySnapshot) {
                Write-Warning "Skipping TG relationship '$($TgRelationship.id)': policySnapshot is null"
                continue
            }

            $DelegatedAssignments = $TgRelationship.policySnapshot.delegatedAdministrationRoleAssignments
            if ($null -eq $DelegatedAssignments -or @($DelegatedAssignments).Count -eq 0) {
                Write-Warning "Skipping TG relationship '$($TgRelationship.id)': no delegatedAdministrationRoleAssignments found in policySnapshot"
                $SnapshotProps = ($TgRelationship.policySnapshot | Get-Member -MemberType NoteProperty, Property | Select-Object -ExpandProperty Name) -join ', '
                Write-Verbose "policySnapshot properties: $SnapshotProps"
                continue
            }

            foreach ($DelegatedGroupAssignment in $DelegatedAssignments) {
                if ($null -eq $DelegatedGroupAssignment.roleTemplates -or @($DelegatedGroupAssignment.roleTemplates).Count -eq 0) {
                    Write-Warning "TG relationship '$($TgRelationship.id)': group '$($DelegatedGroupAssignment.groupId)' has no roleTemplates"
                    continue
                }

                foreach ($RoleAssignment in $DelegatedGroupAssignment.roleTemplates) {
                    $TgFlattenedAssignments.Add([pscustomobject]@{
                            GoverningTenantId   = $TgRelationship.GoverningTenantId
                            GoverningTenantName = $TgRelationship.GoverningTenantName
                            GroupId             = $DelegatedGroupAssignment.groupId
                            RoleTemplateId      = $RoleAssignment.id
                            RoleTemplateName    = $RoleAssignment.name
                        }) | Out-Null
                }
            }
        }

        if ($TgFlattenedAssignments.Count -eq 0) {
            Write-Warning "No TG delegated admin role assignments extracted despite $($ActiveTgRelationships.Count) active relationship(s). Check API response structure."
            if ($null -ne $WarningMessages) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "TenantGovernance"
                        Message = "Zero flattened assignments from $($ActiveTgRelationships.Count) active TG relationships. Possible API schema mismatch."
                        Target  = "TgFlattening"
                    })
            }
        }

        Write-Host "Processing $($TgFlattenedAssignments.Count) Tenant Governance delegated admin role assignment(s)..."

        if ($TgFlattenedAssignments.Count -gt 0) {
            # Thread-safe warning collection for parallel block (List[psobject] is NOT thread-safe)
            $ParallelWarningsTg = [System.Collections.Concurrent.ConcurrentBag[psobject]]::new()

            $TgDelegatedActiveAndPermanentAssignments = $TgFlattenedAssignments | ForEach-Object -ThrottleLimit 50 -Parallel {
                $TgAssignment = $_

                # Import hashtables from parent scope
                $DirObjLookup = $using:DirObjLookup
                $RoleDefLookup = $using:RoleDefLookup
                $LocalWarnings = $using:ParallelWarningsTg
                # Remote tenant group lookup must be imported explicitly - outer variables are
                # not visible inside ForEach-Object -Parallel without $using:.
                $RemoteTgGroupLookup = $using:RemoteTgGroupLookup

                $RoleId = "$($TgAssignment.GoverningTenantId)_$($TgAssignment.GroupId)_$($TgAssignment.RoleTemplateId)"

                # Resolve Role using RoleDefLookup hashtable for O(1) lookup
                $RoleDefinitionName = $TgAssignment.RoleTemplateName
                $RoleType = "CustomRole"
                $RoleIsPrivileged = $false

                if ($RoleDefLookup.ContainsKey($TgAssignment.RoleTemplateId)) {
                    $Role = $RoleDefLookup[$TgAssignment.RoleTemplateId]
                    if ($Role.isBuiltIn -eq $True -or $Role.isBuiltIn -eq "true") {
                        $RoleType = "BuiltInRole"
                        $RoleIsPrivileged = $Role.isPrivileged
                        $RoleDefinitionName = $Role.displayName
                    } else {
                        $LocalWarnings.Add([PSCustomObject]@{
                                Type    = "TenantGovernance"
                                Message = "Delegated Admin Role $($TgAssignment.RoleTemplateId) is not a built-in role (unexpected)."
                                Target  = $TgAssignment.RoleTemplateId
                            })
                    }
                } else {
                    $LocalWarnings.Add([PSCustomObject]@{
                            Type    = "TenantGovernance"
                            Message = "Role definition $($TgAssignment.RoleTemplateId) not found in lookup cache for TG delegated admin assignment"
                            Target  = $TgAssignment.RoleTemplateId
                        })
                }

                # Resolve group display name via the remote tenant groups lookup (remote tenant
                # root group). These groups live in the governing tenant and can never be resolved
                # through home-tenant endpoints. Prefer the actual group display name (same property
                # Get-EntraOpsPrivilegedEntraObject uses), fall back to the remote tenant's primary
                # domain, then to the governing tenant name.
                $GroupDisplayName = $null
                $RemoteTgGroup = $RemoteTgGroupLookup[$TgAssignment.GroupId]
                if ($null -ne $RemoteTgGroup) {
                    $GroupDisplayName = if (-not [string]::IsNullOrEmpty($RemoteTgGroup.remoteGroupDisplayName)) {
                        $RemoteTgGroup.remoteGroupDisplayName
                    } else {
                        $RemoteTgGroup.remoteTenantPrimaryDomain
                    }
                }
                if ([string]::IsNullOrEmpty($GroupDisplayName)) {
                    $GroupDisplayName = if (-not [string]::IsNullOrEmpty($TgAssignment.GoverningTenantName)) {
                        "$($TgAssignment.GoverningTenantName) (remote tenant group)"
                    } else {
                        "[Remote tenant group: $($TgAssignment.GroupId)]"
                    }
                }

                [pscustomobject]@{
                    RoleAssignmentId                      = $RoleId
                    RoleName                              = $RoleDefinitionName
                    RoleId                                = $TgAssignment.RoleTemplateId
                    RoleType                              = $RoleType
                    IsPrivileged                          = $RoleIsPrivileged
                    RoleAssignmentPIMRelated              = $False
                    RoleAssignmentPIMAssignmentType       = "Permanent"
                    RoleAssignmentScopeId                 = "/"
                    RoleAssignmentScopeName               = "Directory"
                    RoleAssignmentType                    = "Direct"
                    RoleAssignmentSubType                 = "Tenant Governance Delegated Admin"
                    ObjectDisplayName                     = $GroupDisplayName
                    ObjectId                              = $TgAssignment.GroupId
                    ObjectTenantId                        = $TgAssignment.GoverningTenantId
                    ObjectType                            = "group"
                    TransitiveByObjectId                  = $null
                    TransitiveByObjectDisplayName         = $null
                    TransitiveByNestingObjectIds          = $null
                    TransitiveByNestingObjectDisplayNames = $null
                }
            }

            # Merge thread-safe warnings back into main WarningMessages list
            foreach ($w in $ParallelWarningsTg) {
                if ($null -ne $WarningMessages) { $WarningMessages.Add($w) }
            }

            Write-Host "✓ Processed $($TgDelegatedActiveAndPermanentAssignments.Count) Tenant Governance delegated admin role assignments" -ForegroundColor Green
        }
    } else {
        if (@($TgRelationships).Count -gt 0) {
            Write-Warning "No active Tenant Governance relationships found ($(@($TgRelationships).Count) total, none with status 'active')"
        } else {
            Write-Verbose "No Tenant Governance relationships available"
        }
    }
    #endregion

    # Summarize results with direct permanent (excl.s activated roles) and eligible role assignments
    $AllAadRbacAssignments = @()
    $AllAadRbacAssignments += $AadPermanentRoleAssignments
    $AllAadRbacAssignments += $AadEligibleUserRoleAssignments
    $AllAadRbacAssignments += $TgDelegatedActiveAndPermanentAssignments

    #region Collect transitive assignments by group members of Role-Assignable Groups
    if ($ExpandGroupMembers -eq $True) {    
        $GroupsWithRbacAssignment = $AllAadRbacAssignments | where-object { $_.ObjectType -eq "group" } | Select-Object -Unique ObjectId, ObjectDisplayName, ObjectTenantId
        $GroupCount = $GroupsWithRbacAssignment.Count
        
        if ($GroupCount -eq 0) {
            Write-Verbose "No groups with role assignments found, skipping transitive member expansion"
            $AllTransitiveMembers = [System.Collections.Generic.List[object]]::new()
        } else {
            # Separate local and cross-tenant groups
            $LocalGroups = @($GroupsWithRbacAssignment | Where-Object { [string]::IsNullOrEmpty($_.ObjectTenantId) -or $_.ObjectTenantId -eq $TenantId })
            $CrossTenantGroups = @($GroupsWithRbacAssignment | Where-Object { -not [string]::IsNullOrEmpty($_.ObjectTenantId) -and $_.ObjectTenantId -ne $TenantId })

            # Sequential processing: Get-EntraOpsPrivilegedTransitiveGroupMember not available in parallel runspaces
            Write-Verbose "Expanding $GroupCount group(s) for transitive Entra ID role assignments ($($LocalGroups.Count) local, $($CrossTenantGroups.Count) cross-tenant)"
            $AllTransitiveMembers = [System.Collections.Generic.List[object]]::new()
            
            # Expand local groups (current Graph context)
            foreach ($GroupWithRbacAssignment in $LocalGroups) {
                $TransitiveMembers = Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId $($GroupWithRbacAssignment.ObjectId) -TenantId $TenantId -WarningMessages $WarningMessages
                foreach ($TransitiveMember in $TransitiveMembers) {
                    $Member = [pscustomobject]@{
                        displayName               = $TransitiveMember.displayName
                        id                        = $TransitiveMember.id
                        '@odata.type'             = $TransitiveMember.'@odata.type'
                        RoleAssignmentSubType     = $TransitiveMember.RoleAssignmentSubType
                        GroupObjectDisplayName    = $GroupWithRbacAssignment.ObjectDisplayName
                        GroupObjectId             = $GroupWithRbacAssignment.ObjectId
                        NestingObjectIds          = $TransitiveMember.NestingObjectIds
                        NestingObjectDisplayNames = $TransitiveMember.NestingObjectDisplayNames
                    }
                    $AllTransitiveMembers.Add($Member) | Out-Null
                }
            }

            # Expand cross-tenant groups (requires Graph context switch per foreign tenant)
            # Skip when $ExpandCrossTenantGroupMembers is $false — caller (e.g. Get-EntraOpsPrivilegedEAMEntraId)
            # handles expansion and object resolution together in Stage 5b with a single auth prompt.
            if ($CrossTenantGroups.Count -gt 0 -and $ExpandCrossTenantGroupMembers) {
                $CrossTenantGroupsByTenant = $CrossTenantGroups | Group-Object ObjectTenantId

                $AuthType = $__EntraOpsSession.AuthenticationType
                $IsInteractiveAuth = $AuthType -in @('UserInteractive', 'DeviceAuthentication')
                # In REST-only mode (Connect-EntraOps -UseInvokeRestMethodOnly), the Graph SDK is not
                # installed by design - the "context switch" must not go through Connect-MgGraph.
                # Invoke-EntraOpsMsGraphQuery's REST path instead reads CurrentGraphTenantId from the
                # session to pick the right cached token and cache-scoping key for this call.
                $IsRestOnlyMode = [bool]$__EntraOpsSession['UseInvokeRestMethodOnly']

                # Home token needed only for non-interactive restore (Connect-MgGraph -AccessToken).
                # For interactive, home restore uses Connect-MgGraph -TenantId (MSAL cache).
                # Managing tenant always uses Get-AzAccessToken (silent for all auth types because
                # Connect-EntraOps already pre-authenticated to managing tenant via Get-AzAccessToken).
                # Not needed in REST-only mode, where restore is just clearing CurrentGraphTenantId.
                $HomeToken = $null
                if (-not $IsRestOnlyMode -and -not $IsInteractiveAuth) {
                    try {
                        $HomeToken = (Get-AzAccessToken -ResourceTypeName "MSGraph" -TenantId $Global:TenantIdContext -AsSecureString -ErrorAction Stop).Token
                    } catch {
                        Write-Warning "Could not acquire home tenant token for context restore: $($_.Exception.Message). Cross-tenant group expansion skipped."
                        $CrossTenantGroupsByTenant = @()
                    }
                }

                # Scopes for the interactive home-tenant restore via Connect-MgGraph -TenantId.
                $HomeTenantScopes = @(
                    "AdministrativeUnit.Read.All",
                    "Application.Read.All",
                    "CustomSecAttributeAssignment.Read.All",
                    "Directory.Read.All",
                    "Group.Read.All",
                    "GroupMember.Read.All",
                    "PrivilegedAccess.Read.AzureADGroup",
                    "PrivilegedEligibilitySchedule.Read.AzureADGroup",
                    "RemoteTenantGroups.Read.All",
                    "RoleManagement.Read.All",
                    "User.Read.All"
                )

                foreach ($TenantGroup in $CrossTenantGroupsByTenant) {
                    $ForeignTenantId = $TenantGroup.Name

                    # A Graph context switch is only possible for the configured managing tenant
                    # (pre-authenticated by Connect-EntraOps). Groups from any other foreign tenant
                    # (e.g. Tenant Governance governing tenants) cannot be expanded or resolved -
                    # they were already marked as foreign principals during collection and their
                    # display name comes from the remoteTenantGroups (remote tenant root group)
                    # lookup instead.
                    if ([string]::IsNullOrEmpty($Global:ManagingTenantIdContext) -or $ForeignTenantId -ne $Global:ManagingTenantIdContext) {
                        Write-Verbose "Skipping transitive expansion for $($TenantGroup.Group.Count) group(s) in tenant $ForeignTenantId - not the configured managing tenant, no Graph context available."
                        if ($WarningMessages) {
                            $WarningMessages.Add([PSCustomObject]@{
                                    Type    = "CrossTenant-ExpansionSkipped"
                                    Message = "Skipped transitive expansion of $($TenantGroup.Group.Count) group(s) in tenant $ForeignTenantId - tenant is not the configured managing tenant ('$Global:ManagingTenantIdContext'), display names resolve via remote tenant root group only."
                                    Target  = $ForeignTenantId
                                })
                        }
                        continue
                    }

                    try {
                        Write-Verbose "Switching Graph tenant context to tenant $ForeignTenantId for transitive group expansion ($($TenantGroup.Group.Count) groups)"
                        if ($IsRestOnlyMode) {
                            $__EntraOpsSession['CurrentGraphTenantId'] = $ForeignTenantId
                        } else {
                            # Always use Get-AzAccessToken for managing tenant (silent — Az session has
                            # a cached token from Connect-EntraOps pre-auth, no browser/device prompt).
                            $ForeignToken = (Get-AzAccessToken -ResourceTypeName "MSGraph" -TenantId $ForeignTenantId -AsSecureString -ErrorAction Stop).Token
                            Connect-MgGraph -AccessToken $ForeignToken -NoWelcome -ErrorAction Stop
                        }

                        foreach ($GroupWithRbacAssignment in $TenantGroup.Group) {
                            try {
                                $TransitiveMembers = Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId $($GroupWithRbacAssignment.ObjectId) -TenantId $ForeignTenantId -WarningMessages $WarningMessages
                                foreach ($TransitiveMember in $TransitiveMembers) {
                                    $Member = [pscustomobject]@{
                                        displayName               = $TransitiveMember.displayName
                                        id                        = $TransitiveMember.id
                                        '@odata.type'             = $TransitiveMember.'@odata.type'
                                        RoleAssignmentSubType     = $TransitiveMember.RoleAssignmentSubType
                                        GroupObjectDisplayName    = $GroupWithRbacAssignment.ObjectDisplayName
                                        GroupObjectId             = $GroupWithRbacAssignment.ObjectId
                                        NestingObjectIds          = $TransitiveMember.NestingObjectIds
                                        NestingObjectDisplayNames = $TransitiveMember.NestingObjectDisplayNames
                                    }
                                    $AllTransitiveMembers.Add($Member) | Out-Null
                                }
                            } catch {
                                Write-Warning "Failed to expand cross-tenant group $($GroupWithRbacAssignment.ObjectId) in tenant $ForeignTenantId : $($_.Exception.Message)"
                                if ($WarningMessages) {
                                    $WarningMessages.Add([PSCustomObject]@{
                                            Type    = "CrossTenant-TransitiveExpansion"
                                            Message = "Failed to expand group $($GroupWithRbacAssignment.ObjectId) in tenant $ForeignTenantId : $($_.Exception.Message)"
                                            Target  = $GroupWithRbacAssignment.ObjectId
                                        })
                                }
                            }
                        }
                    } catch {
                        Write-Warning "Failed to switch MgGraph context to tenant $ForeignTenantId : $($_.Exception.Message)"
                        if ($WarningMessages) {
                            $WarningMessages.Add([PSCustomObject]@{
                                    Type    = "CrossTenant-ContextSwitch"
                                    Message = "Failed to switch MgGraph context to tenant $ForeignTenantId : $($_.Exception.Message)"
                                    Target  = $ForeignTenantId
                                })
                        }
                    } finally {
                        # Restore home-tenant MgGraph context.
                        # Interactive: Connect-MgGraph -TenantId hits the MSAL cache (full-scope token
                        #              from Connect-EntraOps) — no prompt, no scope loss.
                        # Non-interactive: Connect-MgGraph -AccessToken uses the Az app token which
                        #              carries full application permissions.
                        try {
                            if ($IsRestOnlyMode) {
                                $__EntraOpsSession.Remove('CurrentGraphTenantId')
                            } elseif ($IsInteractiveAuth) {
                                Connect-MgGraph -TenantId $Global:TenantIdContext -Scopes $HomeTenantScopes -NoWelcome -ErrorAction Stop
                            } elseif ($null -ne $HomeToken) {
                                Connect-MgGraph -AccessToken $HomeToken -NoWelcome -ErrorAction Stop
                            }
                            Write-Verbose "Restored Microsoft Graph context to home tenant '$Global:TenantIdContext'."
                        } catch {
                            Write-Warning "Failed to restore home tenant Microsoft Graph context: $($_.Exception.Message)"
                        }
                    }
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
                    
                    $TransitiveMember = [pscustomobject]@{
                        RoleAssignmentId                      = $RbacAssignmentByGroup.RoleAssignmentId
                        RoleName                              = $RbacAssignmentByGroup.RoleName
                        RoleId                                = $RbacAssignmentByGroup.RoleId
                        RoleType                              = $RbacAssignmentByGroup.RoleType
                        IsPrivileged                          = $RbacAssignmentByGroup.isPrivileged
                        RoleAssignmentPIMRelated              = $RbacAssignmentByGroup.RoleAssignmentPIMRelated
                        RoleAssignmentPIMAssignmentType       = $RbacAssignmentByGroup.RoleAssignmentPIMAssignmentType
                        RoleAssignmentScopeId                 = $RbacAssignmentByGroup.RoleAssignmentScopeId
                        RoleAssignmentScopeName               = $RbacAssignmentByGroup.RoleAssignmentScopeName
                        RoleAssignmentType                    = "Transitive"
                        RoleAssignmentSubType                 = $_.RoleAssignmentSubType
                        ObjectDisplayName                     = $_.displayName
                        ObjectId                              = $_.id
                        ObjectTenantId                        = $RbacAssignmentByGroup.ObjectTenantId
                        ObjectType                            = $MemberObjectType
                        TransitiveByObjectId                  = $RbacAssignmentByGroup.ObjectId
                        TransitiveByObjectDisplayName         = $_.GroupObjectDisplayName
                        TransitiveByNestingObjectIds          = $_.NestingObjectIds
                        TransitiveByNestingObjectDisplayNames = $_.NestingObjectDisplayNames
                    }
                    $AadRbacTransitiveAssignments.Add($TransitiveMember) | Out-Null
                }
            } else {
                # Keep empty group assignments visible (they still have the role, even if no members)
                Write-Verbose "Empty group $($RbacAssignmentByGroup.ObjectId) with role assignment - keeping group assignment in output"
                if ($WarningMessages) {
                    $WarningMessages.Add([PSCustomObject]@{
                            Type    = "Empty Group"
                            Message = "Empty group $($RbacAssignmentByGroup.ObjectId) - no transitive assignments created"
                            Target  = $RbacAssignmentByGroup.ObjectId
                        })
                }
            }
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