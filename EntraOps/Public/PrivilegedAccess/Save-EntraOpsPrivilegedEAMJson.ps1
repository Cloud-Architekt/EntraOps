<#
.SYNOPSIS
    Export and save EntraOps Privileged EAM data to JSON files.

.DESCRIPTION
    Get information from EntraOps about classification based on Enterprise Access Model and save them as JSON to folder.

.PARAMETER ExportFolder
    Folder where the JSON files should be stored. Default is ./PrivilegedEAM.

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement, ResourceApps.

.PARAMETER UseCache
    Use existing cache instead of clearing it before analysis. Default is $false (cache is cleared for fresh data).
    Set to $true to leverage cached data from previous calls for better performance.

.PARAMETER DefaultCacheTTL
    Cache TTL (in seconds) for regular API responses during this execution. Default is 7200 (2 hours).
    If not specified, uses 2 hours for this execution and restores session value afterwards.

.PARAMETER StaticDataCacheTTL
    Cache TTL (in seconds) for static data like role definitions during this execution. Default is 7200 (2 hours).
    If not specified, uses 2 hours for this execution and restores session value afterwards.

.EXAMPLE
    Export and save JSON files of EntraOps to default folder
    Save-EntraOpsPrivilegedEAMJson

.EXAMPLE
    Export using cached data for better performance
    Save-EntraOpsPrivilegedEAMJson -UseCache $true

.EXAMPLE
    Run with custom cache TTL of 6 hours
    Save-EntraOpsPrivilegedEAMJson -DefaultCacheTTL 21600 -StaticDataCacheTTL 21600
#>

function Save-EntraOpsPrivilegedEAMJson {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$ExportFolder = $DefaultFolderClassifiedEam
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")]
        [Array]$RbacSystems = ("EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$UseCache = $false
        ,
        [Parameter(Mandatory = $False)]
        [System.Int32]$DefaultCacheTTL = 7200 # Default is 2 hours for this cmdlet
        ,
        [Parameter(Mandatory = $False)]
        [System.Int32]$StaticDataCacheTTL = 7200 # Default is 2 hours for this cmdlet
    )

    # Store original TTL values to restore after execution
    $OriginalDefaultTTL = $__EntraOpsSession.DefaultCacheTTL
    $OriginalStaticTTL = $__EntraOpsSession.StaticDataCacheTTL

    # Check if custom TTL values were provided (non-default)
    $CustomTTLProvided = ($PSBoundParameters.ContainsKey('DefaultCacheTTL') -or $PSBoundParameters.ContainsKey('StaticDataCacheTTL'))
    
    # Use provided values (default 2 hours for this cmdlet)
    $EffectiveDefaultTTL = $DefaultCacheTTL
    $EffectiveStaticTTL = $StaticDataCacheTTL

    # Set TTL values for this execution
    $__EntraOpsSession.DefaultCacheTTL = $EffectiveDefaultTTL
    $__EntraOpsSession.StaticDataCacheTTL = $EffectiveStaticTTL

    # Notify user about TTL changes
    if ($EffectiveDefaultTTL -ne $OriginalDefaultTTL -or $EffectiveStaticTTL -ne $OriginalStaticTTL) {
        Write-Host ""
        Write-Host "════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  ⏱️  Cache TTL Modified for This Execution" -ForegroundColor Cyan
        Write-Host "════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  Default Cache TTL    : $([Math]::Round($EffectiveDefaultTTL / 3600, 1)) hours (was $([Math]::Round($OriginalDefaultTTL / 3600, 1)) hours)" -ForegroundColor Yellow
        Write-Host "  Static Data Cache TTL: $([Math]::Round($EffectiveStaticTTL / 3600, 1)) hours (was $([Math]::Round($OriginalStaticTTL / 3600, 1)) hours)" -ForegroundColor Yellow
        Write-Host "  ℹ️  Cache will be restored to original values after completion" -ForegroundColor Gray
        Write-Host "════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
    }

    try {
        if (-not $UseCache) {
            Write-Output "Clearing cache before analyzing RBAC and classification data"
            Clear-EntraOpsCache
        } else {
            Write-Output "Using existing cache for analysis (UseCache = $true)"
            Write-Verbose "Current cache contains $($__EntraOpsSession.GraphCache.Count) entries"
        }

        #region Entra ID
        if ($RbacSystems -contains "EntraID") {
            $EamAzureAD = Get-EntraOpsPrivilegedEAMEntraId
            Save-EntraOpsEAMRbacSystemJson -ExportFolder "$($DefaultFolderClassifiedEam)/EntraID" -RbacSystemName "EntraID" -EamData $EamAzureAD -AggregateFileName "EntraID.json"
        }
        #endregion

        #region Entra Resource Apps
        if ($RbacSystems -contains "ResourceApps") {
            $EamAzureAdResourceApps = Get-EntraOpsPrivilegedEAMResourceApps
            Save-EntraOpsEAMRbacSystemJson -ExportFolder "$($DefaultFolderClassifiedEam)/ResourceApps" -RbacSystemName "ResourceApps" -EamData $EamAzureAdResourceApps -AggregateFileName "ResourceApps.json"
        }
        #endregion

        #region Device Management
        if ($RbacSystems -contains "DeviceManagement") {
            $EamDeviceMgmt = Get-EntraOpsPrivilegedEAMIntune
            Save-EntraOpsEAMRbacSystemJson -ExportFolder "$($DefaultFolderClassifiedEam)/DeviceManagement" -RbacSystemName "DeviceManagement" -EamData $EamDeviceMgmt -AggregateFileName "DeviceManagement.json"
        }
        #endregion

        #region Identity Governance
        if ($RbacSystems -contains "IdentityGovernance") {
            $EamIdGov = Get-EntraOpsPrivilegedEAMIdGov
            Save-EntraOpsEAMRbacSystemJson -ExportFolder "$($DefaultFolderClassifiedEam)/IdentityGovernance" -RbacSystemName "IdentityGovernance" -EamData $EamIdGov -AggregateFileName "IdentityGovernance.json"
        }
        #endregion
        #region Defender
        if ($RbacSystems -contains "Defender") {
            $EamDefender = Get-EntraOpsPrivilegedEAMDefender
            Save-EntraOpsEAMRbacSystemJson -ExportFolder "$($DefaultFolderClassifiedEam)/Defender" -RbacSystemName "Defender" -EamData $EamDefender -AggregateFileName "Defender.json"
        }
        #endregion

        # Display Throttle Statistics Summary
        if ($__EntraOpsSession.ContainsKey('RetryStatistics') -and $__EntraOpsSession.RetryStatistics.TotalRetries -gt 0) {
            Write-Host ""
            Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
            Write-Host "  ⚠ API Throttling Summary" -ForegroundColor Yellow
            Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow

            $Stats = $__EntraOpsSession.RetryStatistics
            Write-Host "  Total Retries       : $($Stats.TotalRetries)" -ForegroundColor Yellow
            Write-Host "  Throttled Requests  : $($Stats.ThrottledRequests)" -ForegroundColor Yellow

            if ($Stats.FailedRequests -gt 0) {
                Write-Host "  ❌ Failed Requests   : $($Stats.FailedRequests)" -ForegroundColor Red
                Write-Error "Some requests failed completely after exhausting retries. Check logs for details."
            } else {
                Write-Host "  ✓ All requests succeeded after retries" -ForegroundColor Green
            }
            Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
            Write-Host ""
        }
    } finally {
        # Restore original TTL values
        $__EntraOpsSession.DefaultCacheTTL = $OriginalDefaultTTL
        $__EntraOpsSession.StaticDataCacheTTL = $OriginalStaticTTL
    
        Write-Verbose "Cache TTL restored to original values: Default=$([Math]::Round($OriginalDefaultTTL / 3600, 1))h, Static=$([Math]::Round($OriginalStaticTTL / 3600, 1))h"
    }
}