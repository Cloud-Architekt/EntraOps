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

.PARAMETER ExportFailedRequests
    Export details of failed requests (Uri, StatusCode, ErrorMessage, Category) to a local
    FailedRequests_*.json file in the export folder. Category is either "ExhaustedRetries" (a request
    retried the maximum number of times for a transient/throttling condition and still failed) or
    "NonRetryable" (an expected data condition, e.g. a deleted access package catalog or a group not
    enabled for PIM for Groups). Default is $false, so no file is written locally by default.

.PARAMETER IncludeJustification
    Include the Justification property (documenting a manual classification overwrite) on all Classification
    entries of the exported objects. Default is $false, so the property is not present in the export at all.

.PARAMETER IncludeObjectDetails
    Include descriptive object details in console output. Defaults to ConsoleOutput.IncludeObjectDetails from
    EntraOpsConfig.json. Object IDs are always shown.

.EXAMPLE
    Export and save JSON files of EntraOps to default folder
    Save-EntraOpsPrivilegedEAMJson

.EXAMPLE
    Export using cached data for better performance
    Save-EntraOpsPrivilegedEAMJson -UseCache $true

.EXAMPLE
    Run with custom cache TTL of 6 hours
    Save-EntraOpsPrivilegedEAMJson -DefaultCacheTTL 21600 -StaticDataCacheTTL 21600

.EXAMPLE
    Export failed request details to a local FailedRequests_*.json file
    Save-EntraOpsPrivilegedEAMJson -ExportFailedRequests $true
#>

function Save-EntraOpsPrivilegedEAMJson {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$ExportFolder = $DefaultFolderClassifiedEam
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("Azure", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")]
        [Array]$RbacSystems = ("Azure", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$UseCache = $false
        ,
        [Parameter(Mandatory = $False)]
        [System.Int32]$DefaultCacheTTL = 7200 # Default is 2 hours for this cmdlet
        ,
        [Parameter(Mandatory = $False)]
        [System.Int32]$StaticDataCacheTTL = 7200 # Default is 2 hours for this cmdlet
        ,
        [Parameter(Mandatory = $False)]
        [System.Boolean]$ExportFailedRequests = $false
        ,
        [Parameter(Mandatory = $False)]
        [System.Boolean]$IncludeObjectDetails = [bool]$Global:EntraOpsIncludeObjectDetails
        ,
        [Parameter(Mandatory = $False)]
        [switch]$IncludeJustification
    )

    # Store original TTL values to restore after execution
    $OriginalDefaultTTL = $__EntraOpsSession.DefaultCacheTTL
    $OriginalStaticTTL = $__EntraOpsSession.StaticDataCacheTTL

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
            $EamAzureAD = Get-EntraOpsPrivilegedEAMEntraId -IncludeJustification:$IncludeJustification -IncludeObjectDetails $IncludeObjectDetails
            Save-EntraOpsEAMRbacSystemJson -ExportFolder "$($ExportFolder)/EntraID" -RbacSystemName "EntraID" -EamData $EamAzureAD -AggregateFileName "EntraID.json"
        }
        #endregion

        #region Entra Resource Apps
        if ($RbacSystems -contains "ResourceApps") {
            $EamAzureAdResourceApps = Get-EntraOpsPrivilegedEAMResourceApps -IncludeJustification:$IncludeJustification -IncludeObjectDetails $IncludeObjectDetails
            Save-EntraOpsEAMRbacSystemJson -ExportFolder "$($ExportFolder)/ResourceApps" -RbacSystemName "ResourceApps" -EamData $EamAzureAdResourceApps -AggregateFileName "ResourceApps.json"
        }
        #endregion

        #region Device Management
        if ($RbacSystems -contains "DeviceManagement") {
            $EamDeviceMgmt = Get-EntraOpsPrivilegedEAMIntune -IncludeJustification:$IncludeJustification -IncludeObjectDetails $IncludeObjectDetails
            Save-EntraOpsEAMRbacSystemJson -ExportFolder "$($ExportFolder)/DeviceManagement" -RbacSystemName "DeviceManagement" -EamData $EamDeviceMgmt -AggregateFileName "DeviceManagement.json"
        }
        #endregion

        #region Identity Governance
        if ($RbacSystems -contains "IdentityGovernance") {
            $EamIdGov = Get-EntraOpsPrivilegedEAMIdGov -IncludeJustification:$IncludeJustification -IncludeObjectDetails $IncludeObjectDetails
            Save-EntraOpsEAMRbacSystemJson -ExportFolder "$($ExportFolder)/IdentityGovernance" -RbacSystemName "IdentityGovernance" -EamData $EamIdGov -AggregateFileName "IdentityGovernance.json"
        }
        #endregion
        #region Defender
        if ($RbacSystems -contains "Defender") {
            $EamDefender = Get-EntraOpsPrivilegedEAMDefender -IncludeJustification:$IncludeJustification -IncludeObjectDetails $IncludeObjectDetails
            Save-EntraOpsEAMRbacSystemJson -ExportFolder "$($ExportFolder)/Defender" -RbacSystemName "Defender" -EamData $EamDefender -AggregateFileName "Defender.json"
        }
        #endregion

        #region Azure
        # Azure RBAC is collected last so classification of managed identities (resolved from the other RBAC
        # systems) is available beforehand. Get-EntraOpsPrivilegedEAMAzure uses the Azure (Get-AzContext) tenant.
        if ($RbacSystems -contains "Azure") {
            $EamAzure = Get-EntraOpsPrivilegedEAMAzure -IncludeJustification:$IncludeJustification -IncludeObjectDetails $IncludeObjectDetails
            Save-EntraOpsEAMRbacSystemJson -ExportFolder "$($ExportFolder)/Azure" -RbacSystemName "Azure" -EamData $EamAzure -AggregateFileName "Azure.json"
        }
        #endregion

        $ResolvedExportFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ExportFolder)
        Write-Host ""
        Write-Host "PrivilegedEAM export written to $ResolvedExportFolder" -ForegroundColor Green
        foreach ($RbacSystem in @($RbacSystems)) {
            $AggregateFile = Join-Path (Join-Path $ResolvedExportFolder $RbacSystem) "$RbacSystem.json"
            if (Test-Path -LiteralPath $AggregateFile -PathType Leaf) { Write-Host "  $($RbacSystem.PadRight(18)): $AggregateFile" -ForegroundColor Gray }
        }

        # Display Throttle Statistics Summary
        if ($__EntraOpsSession.ContainsKey('RetryStatistics') -and ($__EntraOpsSession.RetryStatistics.TotalRetries -gt 0 -or $__EntraOpsSession.RetryStatistics.FailedRequests -gt 0 -or $__EntraOpsSession.RetryStatistics.NonRetryableRequests -gt 0)) {
            Write-Host ""
            Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
            Write-Host "  ⚠ API Throttling Summary" -ForegroundColor Yellow
            Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow

            $Stats = $__EntraOpsSession.RetryStatistics
            Write-Host "  Total Retries       : $($Stats.TotalRetries)" -ForegroundColor Yellow
            Write-Host "  Throttled Requests  : $($Stats.ThrottledRequests)" -ForegroundColor Yellow

            # Requests that failed immediately on a non-retryable status (404 for a deleted access
            # package catalog/directory object, 400 for a group not enabled for PIM for Groups, etc.).
            # These are expected data conditions the caller already accounts for (falls back or logs a
            # dedicated warning), so they are reported for visibility only and never fail the run.
            if ($Stats.NonRetryableRequests -gt 0) {
                Write-Host "  ℹ Non-Retryable Requests (expected, e.g. deleted/unsupported resources): $($Stats.NonRetryableRequests)" -ForegroundColor Yellow
            }

            $FailedRequestDetails = @($Stats.FailedRequestDetails)
            $NonRetryableRequestDetails = @($Stats.NonRetryableRequestDetails)
            $AllRequestDetails = @($FailedRequestDetails | ForEach-Object { $_ | Add-Member -NotePropertyName Category -NotePropertyValue "ExhaustedRetries" -Force -PassThru }) +
                @($NonRetryableRequestDetails | ForEach-Object { $_ | Add-Member -NotePropertyName Category -NotePropertyValue "NonRetryable" -Force -PassThru })

            $ExportedLogPath = $null
            if ($AllRequestDetails.Count -gt 0 -and $ExportFailedRequests) {
                $ExportedLogPath = Join-Path -Path $ExportFolder -ChildPath "FailedRequests_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                $AllRequestDetails | Sort-Object Timestamp | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportedLogPath -Force
                Write-Host "  Details exported to : $ExportedLogPath" -ForegroundColor Yellow
                Write-Host ""
            }

            if ($NonRetryableRequestDetails.Count -gt 0) {
                Write-Host "  Non-retryable request(s):" -ForegroundColor Yellow
                # Grouped by (StatusCode, GUID-normalized Uri) so e.g. 30 deleted Access Package Catalogs
                # collapse into a single summarized line instead of one line per catalog ID.
                foreach ($Group in (Group-EntraOpsRequestDetailsByUriTemplate -RequestDetails $NonRetryableRequestDetails | Sort-Object StatusCode, NormalizedUri)) {
                    Write-EntraOpsGroupedRequestDetail -Group $Group -Color "Yellow" -DetailColor "DarkYellow" -IncludeObjectDetails $IncludeObjectDetails
                }
            }

            if ($Stats.FailedRequests -gt 0) {
                Write-Host "  ❌ Failed Requests   : $($Stats.FailedRequests)" -ForegroundColor Red

                if ($FailedRequestDetails.Count -gt 0) {
                    Write-Host "  Failed request(s):" -ForegroundColor Red
                    foreach ($Group in (Group-EntraOpsRequestDetailsByUriTemplate -RequestDetails $FailedRequestDetails | Sort-Object StatusCode, NormalizedUri)) {
                        Write-EntraOpsGroupedRequestDetail -Group $Group -Color "Red" -DetailColor "DarkRed" -IncludeObjectDetails $IncludeObjectDetails
                    }
                }
                # Intended non-terminating post-export summary (exports above already completed);
                # -ErrorAction Continue keeps these Write-Error calls non-terminating despite the
                # module-wide $ErrorActionPreference = "Stop"
                if ($ExportedLogPath) {
                    Write-Error "Some requests failed completely after exhausting retries. See '$ExportedLogPath' for details." -ErrorAction Continue
                } else {
                    Write-Error "Some requests failed completely after exhausting retries. Re-run with -ExportFailedRequests `$true to export details to a local JSON file." -ErrorAction Continue
                }
            } elseif ($Stats.NonRetryableRequests -eq 0) {
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