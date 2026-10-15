<#
.SYNOPSIS
    Disconnect from Azure and Microsoft Graph connections and clear EntraOps cache.

.DESCRIPTION
    Disconnects from Azure Resource Management and Microsoft Graph API by using Disconnect-AzAccount and Disconnect-MgGraph.
    Clears all EntraOps cache (memory and persistent) and optionally clears Microsoft Graph SDK cache.

.PARAMETER ClearGraphCache
    If set to $true, the Microsoft Graph SDK cache folder will be deleted. Default is $false.

.PARAMETER MgGraphCacheFolder
    Folder where the cache of Microsoft Graph SDK is stored and will be deleted. Default is '$env:USERPROFILE\.graph'

.PARAMETER ClearEntraOpsCache
    Type of EntraOps cache to clear. Options: All (default), Memory, Persistent, Expired. Default is 'All'.

.EXAMPLE
    Disconnect from Azure and Microsoft Graph API, clearing all EntraOps cache
    Disconnect-EntraOps

.EXAMPLE
    Disconnect and clear both EntraOps and Microsoft Graph SDK cache
    Disconnect-EntraOps -ClearGraphCache $true

.EXAMPLE
    Disconnect and clear only expired EntraOps cache entries
    Disconnect-EntraOps -ClearEntraOpsCache Expired
#>

function Disconnect-EntraOps {
    param (
        [Parameter(Mandatory = $False)]
        [boolean]$ClearGraphCache = $false
        ,
        [Parameter(Mandatory = $false)]
        [string]$MgGraphCacheFolder = "$env:USERPROFILE\.graph"
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "Memory", "Persistent", "Expired")]
        [string]$ClearEntraOpsCache = "All"
    )

    # Disconnect from Azure PowerShell
    Write-Verbose "Disconnecting from Azure PowerShell..."
    Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
    Clear-AzContext -Scope Process -Force

    # Clear EntraOps cache (memory and/or persistent based on parameter)
    Write-Verbose "Clearing EntraOps cache (Type: $ClearEntraOpsCache)..."
    try {
        Clear-EntraOpsCache -CacheType $ClearEntraOpsCache
    } catch {
        Write-Warning "Failed to clear EntraOps cache: $_"
    }

    # Reset session state set by Connect-EntraOps
    $__EntraOpsSession['AuthenticationType'] = $null
    $__EntraOpsSession.Remove('UseInvokeRestMethodOnly')
    $__EntraOpsSession.Remove('ConfigFilePath')
    if ($__EntraOpsSession.NonPimGroupIds) { $__EntraOpsSession.NonPimGroupIds.Clear() }
    if ($__EntraOpsSession.RetryStatistics) {
        $__EntraOpsSession.RetryStatistics.TotalRetries = 0
        $__EntraOpsSession.RetryStatistics.ThrottledRequests = 0
        $__EntraOpsSession.RetryStatistics.FailedRequests = 0
        $__EntraOpsSession.RetryStatistics.NonRetryableRequests = 0
        $__EntraOpsSession.RetryStatistics.FailedRequestDetails = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
        $__EntraOpsSession.RetryStatistics.NonRetryableRequestDetails = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    }

    # Remove the tenant-derived globals created by Connect-EntraOps so a later cmdlet cannot silently
    # keep operating against the previous tenant's context, configuration or output folders.
    $TenantContextVariables = @(
        'EntraOpsConfig'
        'TenantIdContext'
        'TenantNameContext'
        'ManagingTenantIdContext'
        'ManagingTenantNameContext'
        'EntraOpsIncludeObjectDetails'
        'XdrAvdHuntingAccess'
        'DefaultFolderClassification'
        'DefaultFolderClassifiedEam'
    )
    Write-Verbose "Removing tenant context variables: $($TenantContextVariables -join ', ')"
    foreach ($TenantContextVariable in $TenantContextVariables) {
        Remove-Variable -Name $TenantContextVariable -Scope Global -Force -ErrorAction SilentlyContinue
    }

    # Remove cached access tokens (Microsoft Graph and ARM) from the module-private session store
    # and any legacy global variables set by previous module versions
    Write-Verbose "Removing cached access tokens..."
    $__EntraOpsSession.MsGraphTokenCache.Clear()
    $__EntraOpsSession.ArmTokenCache.Clear()
    Remove-Variable -Name MsGraphAccessToken -Scope Global -Force -ErrorAction SilentlyContinue
    Remove-Variable -Name UseInvokeRestMethodOnly -Scope Global -Force -ErrorAction SilentlyContinue


    # Disconnect from Microsoft Graph SDK if connected. REST-only installations do not have the
    # Microsoft.Graph.Authentication module, so the commands are resolved before they are called.
    $MgContext = if (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue) { Get-MgContext -ErrorAction SilentlyContinue } else { $null }
    if ($null -ne $MgContext) {
        Write-Verbose "Disconnecting from Microsoft Graph..."
        $MgCallbackWarnings = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
        $MgOutputWriter = Get-EntraOpsGraphOutputWriter
        $MgWarningWriter = if ($null -ne $MgOutputWriter) { $MgOutputWriter.WriteWarning } else { $null }
        try {
            # The SDK logs cache failures through the output callback saved by Connect-MgGraph,
            # bypassing Disconnect-MgGraph's WarningAction/WarningVariable. Capture that path too.
            # A .NET delegate is safe on SDK worker threads; a PowerShell scriptblock is not.
            if ($null -ne $MgOutputWriter) {
                $MgOutputWriter.WriteWarning = [Action[string]]$MgCallbackWarnings.Enqueue
            }
            Disconnect-MgGraph -ErrorAction Stop -WarningAction Continue 3>&1 | ForEach-Object {
                if ($_ -is [System.Management.Automation.WarningRecord]) {
                    $MgCallbackWarnings.Enqueue($_.Message)
                }
            }
        } catch {
            # Suppress SessionNotInitialized errors as the session may have already been cleared
            if ($_.Exception.Message -notmatch "SessionNotInitialized") {
                Write-Warning "Failed to disconnect from Microsoft Graph: $_"
            }
        } finally {
            if ($null -ne $MgOutputWriter) {
                $MgOutputWriter.WriteWarning = $MgWarningWriter
            }
            foreach ($MgDisconnectWarning in $MgCallbackWarnings.ToArray()) {
                $WarningMessage = "$MgDisconnectWarning"
                if ($WarningMessage -match '^Failed to clear the persisted MSAL token cache during Disconnect-MgGraph: The authority \(including the tenant ID\) must be in a well-formed URI format\.') {
                    Write-Verbose $WarningMessage
                } else {
                    Write-Warning $WarningMessage
                }
            }
        }
        
        # Optionally delete Microsoft Graph SDK cache folder
        if ($ClearGraphCache -eq $true -and (Test-Path $MgGraphCacheFolder)) {
            Write-Verbose "Clearing Microsoft Graph SDK cache folder: $MgGraphCacheFolder"
            Remove-Item "$MgGraphCacheFolder" -Recurse -Force
        }
    }
    
    #region Validation: Verify all disconnections and cache clearing
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  ✓ Disconnect Validation" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    # Validate Azure disconnection
    $AzContextCheck = Get-AzContext -ErrorAction SilentlyContinue
    if ($null -eq $AzContextCheck) {
        Write-Host "  ✓ Azure Account        : Disconnected" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Azure Account        : Still connected (Account: $($AzContextCheck.Account))" -ForegroundColor Yellow
    }
    
    # Validate Microsoft Graph disconnection
    $MgContextCheck = if (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue) { Get-MgContext -ErrorAction SilentlyContinue } else { $null }
    if ($null -eq $MgContextCheck) {
        Write-Host "  ✓ Microsoft Graph      : Disconnected" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Microsoft Graph      : Still connected (TenantId: $($MgContextCheck.TenantId))" -ForegroundColor Yellow
    }
    
    # Validate EntraOps cache clearing
    $MemoryCacheCount = if ($__EntraOpsSession.GraphCache) { $__EntraOpsSession.GraphCache.Count } else { 0 }
    $MemoryCacheMetadataCount = if ($__EntraOpsSession.CacheMetadata) { $__EntraOpsSession.CacheMetadata.Count } else { 0 }
    
    if ($MemoryCacheCount -eq 0 -and $MemoryCacheMetadataCount -eq 0) {
        Write-Host "  ✓ Memory Cache         : Cleared (0 entries)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Memory Cache         : $MemoryCacheCount entries, $MemoryCacheMetadataCount metadata" -ForegroundColor Yellow
    }
    
    # Validate persistent cache (if cleared)
    if ($ClearEntraOpsCache -in @("All", "Persistent")) {
        if (Test-Path $__EntraOpsSession.PersistentCachePath) {
            $PersistentFiles = Get-ChildItem -Path $__EntraOpsSession.PersistentCachePath -Filter "*.json" -ErrorAction SilentlyContinue
            $PersistentCount = $PersistentFiles.Count
            
            if ($PersistentCount -eq 0) {
                Write-Host "  ✓ Persistent Cache     : Cleared (0 files)" -ForegroundColor Green
            } else {
                Write-Host "  ⚠ Persistent Cache     : $PersistentCount files remaining" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  ✓ Persistent Cache     : Directory removed" -ForegroundColor Green
        }
    } else {
        Write-Host "  ℹ Persistent Cache     : Not cleared (CacheType: $ClearEntraOpsCache)" -ForegroundColor Gray
    }
    
    # Validate session state reset
    $AuthTypeCleaned = $null -eq $__EntraOpsSession['AuthenticationType']
    if ($AuthTypeCleaned) {
        Write-Host "  ✓ Session State        : Cleared (AuthenticationType reset)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Session State        : AuthenticationType still set ($($__EntraOpsSession['AuthenticationType']))" -ForegroundColor Yellow
    }

    # Validate tenant context removal
    $RemainingTenantContext = @($TenantContextVariables | Where-Object { Get-Variable -Name $_ -Scope Global -ErrorAction SilentlyContinue })
    $TenantContextCleaned = $RemainingTenantContext.Count -eq 0
    if ($TenantContextCleaned) {
        Write-Host "  ✓ Tenant Context       : Cleared ($($TenantContextVariables.Count) variables removed)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Tenant Context       : Still set ($($RemainingTenantContext -join ', '))" -ForegroundColor Yellow
    }

    # Validate token cache removal
    $TokenCacheCount = $__EntraOpsSession.MsGraphTokenCache.Count + $__EntraOpsSession.ArmTokenCache.Count
    $TokenCacheCleaned = $TokenCacheCount -eq 0
    if ($TokenCacheCleaned) {
        Write-Host "  ✓ Token Cache          : Cleared (0 entries)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Token Cache          : $TokenCacheCount entries remaining" -ForegroundColor Yellow
    }

    # Overall status
    $AllCleared = ($null -eq $AzContextCheck) -and ($null -eq $MgContextCheck) -and ($MemoryCacheCount -eq 0) -and ($MemoryCacheMetadataCount -eq 0) -and $AuthTypeCleaned -and $TenantContextCleaned -and $TokenCacheCleaned
    
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    if ($AllCleared) {
        Write-Host "  ✓ Successfully disconnected from EntraOps session" -ForegroundColor Green
        Write-Host "    All connections closed and cache cleared" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Disconnection completed with warnings" -ForegroundColor Yellow
        Write-Host "    Review the status above for details" -ForegroundColor Yellow
    }
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    #endregion
}