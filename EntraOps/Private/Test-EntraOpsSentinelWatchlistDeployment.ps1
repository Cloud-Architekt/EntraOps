<#
.SYNOPSIS
    Verify that a deployed Sentinel watchlist exists, has rows and, for split uploads, as many items as were exported.

.DESCRIPTION
    New-GkSeAzSentinelWatchlist (SentinelEnrichment) deletes the existing watchlist and redeploys it from the CSV. It
    doesn't report a failed redeployment after the delete, so a run can end with the watchlist missing. It also splits
    a CSV larger than ~1 MB into several blocks and deploys each one as an ARM template deployment that reuses a
    single deployment name - the watchlist display name. Observed behaviour is that a block can be reported as
    deployed while its deployment is still in "running" state, after which the next block starts a deployment under
    the same name. That race can drop the rows of an earlier block without surfacing any error.

    This helper closes the gap on the EntraOps side:
    - The watchlist must exist after the upload (one request).
    - It must contain rows. The first page of items is read; while it is empty, the read is repeated a few times
      because the items of a freshly deployed watchlist can take a moment to become readable.
    - For a CSV at or above SplitThresholdBytes all pages are counted and compared with the exported row count,
      because only a split upload can hit the race. Smaller watchlists deploy as a single block and are not paged.

    It never throws - a verification problem must not fail a sync that may well have succeeded. Count mismatches are
    written as warnings; a missing or empty watchlist is returned in Issue so the caller can report all watchlists
    of a run together.

.PARAMETER SubscriptionId
    Subscription of the Log Analytics workspace hosting the watchlist.

.PARAMETER ResourceGroupName
    Resource group of the Log Analytics workspace hosting the watchlist.

.PARAMETER WorkspaceName
    Name of the Log Analytics workspace hosting the watchlist.

.PARAMETER WatchListName
    Alias/display name of the watchlist to verify.

.PARAMETER ExpectedItemCount
    Number of rows exported to the CSV for this watchlist.

.PARAMETER WatchListFilePath
    Path to the exported CSV. Its size decides whether SentinelEnrichment splits the upload, and therefore
    whether counting all items is worth its paging cost. Omit to always count all items.

.PARAMETER SplitThresholdBytes
    CSV size at or above which SentinelEnrichment splits the upload into multiple blocks. Default is 1 MB,
    matching the module's own behaviour ("CSV file size is X MB. Splitting into blocks of ~1 MB...").

.PARAMETER EmptyRetryCount
    Number of additional reads while the watchlist returns no items. Default is 3.

.PARAMETER EmptyRetryDelaySeconds
    Wait between the reads of an empty watchlist. Default is 10 seconds.

.PARAMETER ApiVersion
    Microsoft.SecurityInsights API version. Defaults to the version used by SentinelEnrichment.

.OUTPUTS
    [pscustomobject] with WatchListName, Exists ($null when it could not be determined), ItemCount (all items for a
    counted watchlist, the items of the first page otherwise, -1 when unknown), Counted, and Issue ('Missing',
    'Empty' or $null).
#>

function Test-EntraOpsSentinelWatchlistDeployment {

    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
        ,
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName
        ,
        [Parameter(Mandatory = $true)]
        [string]$WorkspaceName
        ,
        [Parameter(Mandatory = $true)]
        [string]$WatchListName
        ,
        [Parameter(Mandatory = $true)]
        [int]$ExpectedItemCount
        ,
        [Parameter(Mandatory = $false)]
        [string]$WatchListFilePath
        ,
        [Parameter(Mandatory = $false)]
        [long]$SplitThresholdBytes = 1MB
        ,
        [Parameter(Mandatory = $false)]
        [int]$EmptyRetryCount = 3
        ,
        [Parameter(Mandatory = $false)]
        [int]$EmptyRetryDelaySeconds = 10
        ,
        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2025-06-01"
    )

    $Result = [pscustomobject]@{
        WatchListName = $WatchListName
        Exists        = $null
        ItemCount     = -1
        Counted       = $false
        Issue         = $null
    }

    # A single-block upload gets one ARM deployment of its own and cannot hit the shared-name race, so only the
    # first page is read to confirm it has rows.
    $CountAllItems = $true
    if (-not [string]::IsNullOrEmpty($WatchListFilePath) -and (Test-Path -LiteralPath $WatchListFilePath)) {
        $CsvSize = (Get-Item -LiteralPath $WatchListFilePath).Length
        $CountAllItems = $CsvSize -ge $SplitThresholdBytes
        Write-Verbose "Verifying $WatchListName - CSV is $([Math]::Round($CsvSize / 1MB, 2)) MB, $(if ($CountAllItems) { 'split into multiple same-named ARM deployments: counting all items' } else { 'deployed as a single block: checking for rows' })."
    }

    $EncodedWatchListName = [System.Uri]::EscapeDataString($WatchListName)
    $WatchListUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/watchlists/$($EncodedWatchListName)?api-version=$ApiVersion"
    $ItemsUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/watchlists/$EncodedWatchListName/watchlistItems?api-version=$ApiVersion"

    try {
        $WatchListResponse = Invoke-AzRestMethod -Method "GET" -Uri $WatchListUri
    } catch {
        Write-Warning "  [!] Could not verify watchlist $WatchListName - watchlist query failed: $($_.Exception.Message)"
        return $Result
    }
    if ($WatchListResponse.StatusCode -eq 404) {
        $Result.Exists = $false
        $Result.Issue = 'Missing'
        return $Result
    }
    if ($WatchListResponse.StatusCode -ne 200) {
        Write-Warning "  [!] Could not verify watchlist $WatchListName - watchlist query returned HTTP $($WatchListResponse.StatusCode)."
        return $Result
    }
    $Result.Exists = $true

    $ItemCount = 0
    $Uri = $ItemsUri
    $PageCount = 0
    # Bound the paging loop: a watchlist that keeps returning nextLink must not hang the sync.
    $MaxPages = 500
    $EmptyReads = 0

    try {
        while ($null -ne $Uri -and $PageCount -lt $MaxPages) {
            $Response = Invoke-AzRestMethod -Method "GET" -Uri $Uri
            if ($Response.StatusCode -ne 200) {
                Write-Warning "  [!] Could not verify watchlist $WatchListName - item query returned HTTP $($Response.StatusCode)."
                return $Result
            }
            $Payload = $Response.Content | ConvertFrom-Json -Depth 20
            # @($null).Count is 1: a page without an item list must not count as one item
            if ($null -eq $Payload -or $null -eq $Payload.PSObject.Properties['value'] -or $null -eq $Payload.value) {
                Write-Warning "  [!] Could not verify watchlist $WatchListName - item query returned no item list."
                return $Result
            }
            $PageItemCount = @($Payload.value).Count
            if ($PageCount -eq 0 -and $PageItemCount -eq 0 -and $EmptyReads -lt $EmptyRetryCount) {
                $EmptyReads++
                Write-Verbose "Watchlist $WatchListName returned no items yet - reading again in $EmptyRetryDelaySeconds second(s) ($EmptyReads/$EmptyRetryCount)."
                Start-Sleep -Seconds $EmptyRetryDelaySeconds
                continue
            }
            $ItemCount += $PageItemCount
            $Uri = if ($CountAllItems) { $Payload.nextLink } else { $null }
            $PageCount++
        }
    } catch {
        Write-Warning "  [!] Could not verify watchlist $WatchListName - item query failed: $($_.Exception.Message)"
        return $Result
    }

    if ($PageCount -ge $MaxPages -and $null -ne $Uri) {
        Write-Warning "  [!] Stopped counting items of watchlist $WatchListName after $MaxPages pages - verification incomplete."
        return $Result
    }

    $Result.ItemCount = $ItemCount
    $Result.Counted = $CountAllItems
    if ($ItemCount -eq 0 -and $ExpectedItemCount -gt 0) {
        $Result.Issue = 'Empty'
    } elseif ($CountAllItems -and $ItemCount -ne $ExpectedItemCount) {
        Write-Warning "  [!] Watchlist $WatchListName contains $ItemCount item(s) but $ExpectedItemCount row(s) were exported. Large watchlists are deployed in blocks that share one ARM deployment name, so an earlier block may have been overwritten. Re-run the watchlist upload and verify in Sentinel."
    } else {
        Write-Verbose "Watchlist $WatchListName verified: $ItemCount item(s)$(if ($CountAllItems) { ' match the exported row count' } else { ' on the first page' })."
    }

    return $Result
}
