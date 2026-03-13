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


    # Disconnect from Microsoft Graph SDK if connected
    $MgContext = Get-MgContext -ErrorAction SilentlyContinue
    if ($null -ne $MgContext) {
        Write-Verbose "Disconnecting from Microsoft Graph..."
        try {
            Disconnect-MgGraph -ErrorAction Stop | Out-Null
        } catch {
            # Suppress SessionNotInitialized errors as the session may have already been cleared
            if ($_.Exception.Message -notmatch "SessionNotInitialized") {
                Write-Warning "Failed to disconnect from Microsoft Graph: $_"
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
    $MgContextCheck = Get-MgContext -ErrorAction SilentlyContinue
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
    
    # Overall status
    $AllCleared = ($null -eq $AzContextCheck) -and ($null -eq $MgContextCheck) -and ($MemoryCacheCount -eq 0) -and ($MemoryCacheMetadataCount -eq 0)
    
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