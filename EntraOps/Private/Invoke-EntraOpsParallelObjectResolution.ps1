<#
.SYNOPSIS
    Internal helper function for parallel object detail resolution across EntraOps functions.

.DESCRIPTION
    Provides reusable parallel processing logic for resolving object details using Microsoft Graph SDK's
    process-level authentication context. Falls back to sequential processing when parallel is not viable.

.PARAMETER UniqueObjects
    Array of unique objects with ObjectId and ObjectType properties to resolve.

.PARAMETER TenantId
    Tenant ID for object resolution.

.PARAMETER EnableParallelProcessing
    Enable parallel processing. Default is $true.

.PARAMETER ParallelThrottleLimit
    Maximum number of parallel threads. Default is 10.

.OUTPUTS
    Hashtable with ObjectId as key and object details as value.
#>

function Invoke-EntraOpsParallelObjectResolution {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Array]$UniqueObjects,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableParallelProcessing = $true,
        
        [Parameter(Mandatory = $false)]
        [int]$ParallelThrottleLimit = 10
    )
    
    $UniqueObjectIds = @($UniqueObjects.ObjectId)
    
    #region Pre-fetch objects by type for massive performance improvement (Recommendation 2)
    # Standardized cache population using batch requests
    Write-Host "Pre-fetching object details to populate cache..."
    $PreFetchStats = @{ PreFetchedCount = 0; FailedCount = 0 }
    
    # Use beta endpoint to match Get-EntraOpsPrivilegedEntraObject expectations
    # We fetch ALL properties required by the consumer function in the batch call
    $PropsToSelect = "id,displayName,userPrincipalName,userType,isAssignableToRole,isManagementRestricted,onPremisesSyncEnabled,passwordPolicies"
    
    # Reduce batch size from 1000 to 100 to prevent 504 Gateway Timeouts
    $BatchSize = 100
    $TotalBatches = [Math]::Ceiling($UniqueObjectIds.Count / $BatchSize)
    $CurrentBatch = 0
    
    try {
        # Split into smaller batches to avoid Gateway Timeout (504)
        for ($i = 0; $i -lt $UniqueObjectIds.Count; $i += $BatchSize) {
            $CurrentBatch++
            $Batch = $UniqueObjectIds[$i..([Math]::Min($i + $BatchSize - 1, $UniqueObjectIds.Count - 1))]
            
            # Show progress for large datasets
            if ($TotalBatches -gt 1) {
                $PercentComplete = [Math]::Round(($CurrentBatch / $TotalBatches) * 100, 0)
                Write-Progress -Activity "Pre-fetching Object Details" -Status "Batch $CurrentBatch of $TotalBatches ($($Batch.Count) objects)" -PercentComplete $PercentComplete -Id 50
            }
            
            $Body = @{
                ids   = $Batch
                types = @('user', 'group', 'servicePrincipal')
            } | ConvertTo-Json
            
            $Uri = "/beta/directoryObjects/getByIds?`$select=$PropsToSelect"
            
            try {
                $PreFetchedObjects = Invoke-EntraOpsMsGraphQuery -Method POST -Uri $Uri -Body $Body -OutputType PSObject
                
                # POPULATE CACHE: Key objects so Get-EntraOpsPrivilegedEntraObject finds them
                if ($PreFetchedObjects) {
                    $PreFetchedObjects = @($PreFetchedObjects) # Ensure array
                    $PreFetchStats.PreFetchedCount += $PreFetchedObjects.Count
                    
                    # Resolve the tenant discriminator exactly as Invoke-EntraOpsMsGraphQuery does,
                    # so pre-populated keys are found by its cache lookup (which is tenant-scoped
                    # to prevent cross-tenant cache poisoning when processing multiple tenants in
                    # the same session/runspace). Order must match: CurrentGraphTenantId (cross-tenant
                    # switch, REST-only) -> MgContext -> TenantIdContext -> default.
                    $CacheTenantId = $__EntraOpsSession['CurrentGraphTenantId']
                    if ([string]::IsNullOrEmpty($CacheTenantId)) {
                        try {
                            $CacheTenantId = (Get-MgContext -ErrorAction Stop).TenantId
                        } catch {
                            Write-Verbose "Unable to determine current Graph tenant context for cache scoping: $_"
                        }
                    }
                    if ([string]::IsNullOrEmpty($CacheTenantId)) {
                        $CacheTenantId = $Global:TenantIdContext
                    }
                    if ([string]::IsNullOrEmpty($CacheTenantId)) {
                        $CacheTenantId = "default"
                    }

                    foreach ($Obj in $PreFetchedObjects) {
                        # Construct the exact cache key the consumer function will use
                        # Must match the full URL + tenant format used by Invoke-EntraOpsMsGraphQuery
                        $CacheKey = "$CacheTenantId#https://graph.microsoft.com/beta/directoryObjects/$($Obj.id)?`$select=$PropsToSelect"
                        
                        if (-not $__EntraOpsSession.GraphCache.ContainsKey($CacheKey)) {
                            $__EntraOpsSession.GraphCache[$CacheKey] = $Obj
                            
                            # Add valid metadata to prevent expiration checks from failing
                            $__EntraOpsSession.CacheMetadata[$CacheKey] = @{
                                Uri         = $CacheKey
                                CachedTime  = [DateTime]::UtcNow
                                ExpiryTime  = [DateTime]::UtcNow.AddSeconds($__EntraOpsSession.DefaultCacheTTL)
                                ResultCount = 1
                            }
                        }
                    }
                }
            } catch {
                Write-Warning "Batch $CurrentBatch failed: $($_.Exception.Message)"
                $PreFetchStats.FailedCount += $Batch.Count
            }
            
            # Longer anti-throttle delay to prevent 504 errors (increased from 200ms to 500ms)
            if ($i + $BatchSize -lt $UniqueObjectIds.Count) { 
                Start-Sleep -Milliseconds 500 
            }
        }
        
        if ($TotalBatches -gt 1) {
            Write-Progress -Activity "Pre-fetching Object Details" -Completed -Id 50
        }
    } catch {
        Write-Warning "Pre-fetch failed: $($_.Exception.Message)"
        $PreFetchStats.FailedCount += $UniqueObjectIds.Count
    }
    
    Write-Host "Pre-fetch complete: $($PreFetchStats.PreFetchedCount) objects cached, $($PreFetchStats.FailedCount) failed."
    #endregion
    
    Write-Host "Resolving details for $($UniqueObjectIds.Count) unique objects..."
    $ObjectDetailsCache = @{}
    
    # Determine if parallel processing is viable (PowerShell 7+ guaranteed by module prerequisite)
    # Parallel runspaces authenticate either through the Graph SDK's process-wide auth context
    # (SDK mode) or through the shared session's pre-warmed MsGraphTokenCache (REST-only mode:
    # Connect-EntraOps -UseInvokeRestMethodOnly skips Connect-MgGraph entirely for non-interactive
    # auth, so no SDK context exists - the token is pre-warmed here in the main thread because
    # Get-AzAccessToken inside fresh runspaces is not guaranteed to see the Az context).
    # Threshold 5: sequential resolution costs ~4-6s per object (Get-EntraOpsPrivilegedEntraObject
    # makes several Graph calls beyond the pre-fetch), so the runspace pool pays off well below the
    # former threshold of 20.
    $HasSufficientObjects = $UniqueObjectIds.Count -ge 5
    $IsRestOnlyMode = [bool]$__EntraOpsSession['UseInvokeRestMethodOnly']
    $IsUsingMgGraphSDK = $false
    if (-not $IsRestOnlyMode) {
        try {
            $IsUsingMgGraphSDK = $null -ne (Get-MgContext -ErrorAction Stop)
        } catch {
            Write-Verbose "Microsoft Graph SDK context not available - parallel object resolution requires it: $($_.Exception.Message)"
        }
    }
    $RestOnlyParallelReady = $false
    if ($IsRestOnlyMode -and $EnableParallelProcessing) {
        $RestOnlyParallelReady = Initialize-EntraOpsRestOnlyParallelToken
    }
    $HasParallelAuth = $IsUsingMgGraphSDK -or $RestOnlyParallelReady
    $UseParallel = $EnableParallelProcessing -and $HasSufficientObjects -and $HasParallelAuth
    
    if ($UseParallel) {
        $AuthModeLabel = if ($IsUsingMgGraphSDK) { "Microsoft Graph SDK authentication" } else { "REST-only with pre-warmed token" }
        Write-Host "Using parallel processing with $ParallelThrottleLimit threads ($AuthModeLabel)..."
        
        # SDK mode: verify MgGraph connection exists (REST-only mode was validated by the pre-warm)
        $MgGraphModulePath = $null
        if ($IsUsingMgGraphSDK) {
            $MgContext = Get-MgContext
            if ($null -eq $MgContext) {
                Write-Warning "Microsoft Graph is not connected. Falling back to sequential processing."
                $UseParallel = $false
            } else {
                Write-Verbose "MgGraph Context: TenantId=$($MgContext.TenantId), Scopes=$($MgContext.Scopes -join ', ')"
                Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
                $MgGraphModulePath = (Get-Module Microsoft.Graph.Authentication).Path
            }
        }
        
        if ($UseParallel) {
            $EntraOpsModulePath = Split-Path $PSScriptRoot -Parent
            
            # Capture global variables needed by Get-EntraOpsPrivilegedEntraObject
            $LocalEntraOpsConfig = $Global:EntraOpsConfig
            $LocalEntraOpsBaseFolder = $Global:EntraOpsBaseFolder
            $LocalTenantIdContext = $Global:TenantIdContext
            $LocalEntraOpsSession = $Script:__EntraOpsSession

            try {
                $ParallelResults = $UniqueObjects | ForEach-Object -ThrottleLimit $ParallelThrottleLimit -Parallel {
                    $obj = $_
                    $ObjectId = $obj.ObjectId
                    $LocalTenantId = $using:TenantId
                    $LocalEntraOpsPath = $using:EntraOpsModulePath
                    $LocalMgGraphPath = $using:MgGraphModulePath
                    $LocalIsRestOnly = $using:IsRestOnlyMode
                    
                    try {
                        if (-not $LocalIsRestOnly) {
                            if (-not (Get-Module -Name Microsoft.Graph.Authentication)) {
                                Import-Module $LocalMgGraphPath -ErrorAction Stop
                            }
                            
                            $ThreadMgContext = Get-MgContext
                            if ($null -eq $ThreadMgContext) {
                                throw "MgGraph context not available in parallel runspace"
                            }
                        }
                        
                        # Import EntraOps module to get all functions
                        $EntraOpsModuleManifest = Join-Path $LocalEntraOpsPath "EntraOps.psd1"
                        if (Test-Path $EntraOpsModuleManifest) {
                            $env:ENTRAOPS_NOWELCOME = $true
                            if (-not (Get-Module -Name EntraOps)) {
                                Import-Module $EntraOpsModuleManifest -ErrorAction Stop -WarningAction SilentlyContinue
                            }
                        } else {
                            throw "EntraOps module manifest not found at $EntraOpsModuleManifest"
                        }
                        
                        # Inject the shared session INTO THE MODULE SCOPE: module functions resolve
                        # $__EntraOpsSession from their own script scope (created fresh on import), so a
                        # runspace-local $script:/$global: assignment never reaches them. Required for
                        # REST-only auth (pre-warmed MsGraphTokenCache + UseInvokeRestMethodOnly flag)
                        # and makes the pre-fetched GraphCache visible to runspaces in both modes.
                        if ($using:LocalEntraOpsSession) {
                            $script:__EntraOpsSession = $using:LocalEntraOpsSession
                            $EntraOpsModuleInstance = Get-Module -Name EntraOps
                            & $EntraOpsModuleInstance { param($s) Set-Variable -Name __EntraOpsSession -Value $s -Scope Script } $script:__EntraOpsSession
                        } elseif (-not (Get-Variable -Name __EntraOpsSession -Scope Script -ErrorAction SilentlyContinue)) {
                            $script:__EntraOpsSession = @{
                                GraphCache    = @{}
                                CacheMetadata = @{}
                            }
                        }
                        
                        # Restore global variables in parallel runspace. UseInvokeRestMethodOnly mirrors the
                        # session mode: SDK mode authenticates via the process-wide MgGraph context, REST-only
                        # mode via the shared session's pre-warmed token cache
                        New-Variable -Name UseInvokeRestMethodOnly -Value $LocalIsRestOnly -Scope Global -Force -ErrorAction SilentlyContinue
                        New-Variable -Name EntraOpsConfig -Value $using:LocalEntraOpsConfig -Scope Global -Force -ErrorAction SilentlyContinue
                        New-Variable -Name EntraOpsBaseFolder -Value $using:LocalEntraOpsBaseFolder -Scope Global -Force -ErrorAction SilentlyContinue
                        # Cache-key tenant scoping in REST-only mode falls back to this global (no MgContext)
                        New-Variable -Name TenantIdContext -Value $using:LocalTenantIdContext -Scope Global -Force -ErrorAction SilentlyContinue
                        
                        $ObjectDetails = Get-EntraOpsPrivilegedEntraObject -AadObjectId $ObjectId -TenantId $LocalTenantId
                        
                        [PSCustomObject]@{
                            ObjectId = $ObjectId
                            Details  = $ObjectDetails
                            Success  = $true
                            ThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
                        }
                    } catch {
                        [PSCustomObject]@{
                            ObjectId = $ObjectId
                            Details  = $null
                            Success  = $false
                            Error    = $_.Exception.Message
                            ThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
                        }
                    }
                }
                
                # Process results
                $SuccessCount = 0
                $FailureCount = 0
                
                foreach ($Result in $ParallelResults) {
                    if ($Result.Success) {
                        $ObjectDetailsCache[$Result.ObjectId] = $Result.Details
                        $SuccessCount++
                    } else {
                        Write-Warning "Failed to get details for object $($Result.ObjectId): $($Result.Error)"
                        $ObjectDetailsCache[$Result.ObjectId] = $null
                        $FailureCount++
                    }
                }
                
                Write-Host "Parallel processing completed: $SuccessCount successful, $FailureCount failed (throttle limit $ParallelThrottleLimit)"
                
            } catch {
                Write-Warning "Parallel processing failed: $($_.Exception.Message). Falling back to sequential processing."
                $UseParallel = $false
            }
        }
    }
    
    # Sequential processing fallback
    if (-not $UseParallel) {
        if ($EnableParallelProcessing) {
            $Reasons = @()
            if (-not $HasSufficientObjects) { $Reasons += "dataset too small (<5 objects)" }
            if (-not $HasParallelAuth) {
                $Reasons += if ($IsRestOnlyMode) { "Graph token pre-warm for REST-only parallel processing failed" } else { "Microsoft Graph SDK context not available" }
            }
            if ($Reasons.Count -gt 0) {
                Write-Host "Using sequential processing: $($Reasons -join ', ')"
            }
        } else {
            Write-Host "Using sequential processing (parallel disabled)..."
        }
        
        for ($i = 0; $i -lt $UniqueObjectIds.Count; $i++) {
            $ObjectId = $UniqueObjectIds[$i]
            
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
    
    return $ObjectDetailsCache
}
