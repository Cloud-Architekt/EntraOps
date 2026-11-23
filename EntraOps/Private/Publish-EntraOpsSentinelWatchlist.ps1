<#
.SYNOPSIS
    Replace a Sentinel watchlist with the content of a CSV file, record the writing deployment and verify the result.

.DESCRIPTION
    Wraps New-GkSeAzSentinelWatchlist (SentinelEnrichment, which deletes and redeploys the watchlist):
    - The watchlist description records the tenant and the deployment that wrote it (see
      Get-EntraOpsDeploymentIdentity). Before the watchlist is replaced, the description of the existing one is read;
      when another deployment or tenant wrote it last, a warning names both. Two deployments writing the same
      watchlists replace each other's data on every run.
    - After the upload, Test-EntraOpsSentinelWatchlistDeployment checks that the watchlist exists and has rows.
    - Block files that SentinelEnrichment writes next to the CSV for a split upload are removed.

    The upload runs without verbose output: it would print the subscription ID, workspace and watchlist URIs.

.PARAMETER SubscriptionId
    Subscription of the Microsoft Sentinel workspace.

.PARAMETER ResourceGroupName
    Resource group of the Microsoft Sentinel workspace.

.PARAMETER WorkspaceName
    Name of the Microsoft Sentinel workspace.

.PARAMETER WatchListName
    Display name and alias of the watchlist.

.PARAMETER WatchListFilePath
    CSV file with the watchlist items.

.PARAMETER SearchKey
    Column used as itemsSearchKey.

.PARAMETER ExpectedItemCount
    Number of rows in the CSV file.

.PARAMETER DefaultDuration
    Default time to live of the watchlist items. Default is P14D.

.PARAMETER ApiVersion
    Microsoft.SecurityInsights API version. Defaults to the version used by SentinelEnrichment.

.OUTPUTS
    [pscustomobject] returned by Test-EntraOpsSentinelWatchlistDeployment.
#>
function Publish-EntraOpsSentinelWatchlist {

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
        [string]$WatchListFilePath
        ,
        [Parameter(Mandatory = $true)]
        [string]$SearchKey
        ,
        [Parameter(Mandatory = $true)]
        [int]$ExpectedItemCount
        ,
        [Parameter(Mandatory = $false)]
        [string]$DefaultDuration = "P14D"
        ,
        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2025-06-01"
    )

    $Deployment = Get-EntraOpsDeploymentIdentity
    $Tenant = @($Global:TenantNameContext, $Global:TenantIdContext) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($Tenant)) { $Tenant = 'unknown' }
    $Description = "EntraOps | Tenant: $Tenant | Deployment: $Deployment"

    #region Warn when another deployment or tenant wrote this watchlist last
    $WatchListUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/watchlists/$([System.Uri]::EscapeDataString($WatchListName))?api-version=$ApiVersion"
    try {
        $ExistingWatchList = Invoke-AzRestMethod -Method "GET" -Uri $WatchListUri
        if ($ExistingWatchList.StatusCode -eq 200) {
            $PreviousDescription = [string](($ExistingWatchList.Content | ConvertFrom-Json -Depth 10).properties.description)
            if ($PreviousDescription -match 'Tenant:\s*(?<Tenant>[^|]+?)\s*\|\s*Deployment:\s*(?<Deployment>.+?)\s*$') {
                $PreviousTenant = $Matches.Tenant
                $PreviousDeployment = $Matches.Deployment
                if ($PreviousDeployment -ne $Deployment -or $PreviousTenant -ne $Tenant) {
                    Write-Warning "Watchlist $WatchListName was last written by '$PreviousDeployment' (tenant $PreviousTenant) and is now replaced by '$Deployment' (tenant $Tenant). Each run replaces the data of the other deployment: let only one deployment per tenant write WatchLists, Log Analytics and the Apply* automation."
                }
            } else {
                Write-Verbose "Watchlist $WatchListName has no EntraOps writer in its description yet."
            }
        }
    } catch {
        Write-Verbose "Could not read the description of watchlist $($WatchListName): $($_.Exception.Message)"
    }
    #endregion

    $Parameters = @{
        WatchListFilePath        = $WatchListFilePath
        DisplayName              = $WatchListName
        WatchListDescription     = $Description
        itemsSearchKey           = $SearchKey
        SubscriptionId           = $SubscriptionId
        ResourceGroupName        = $ResourceGroupName
        WorkspaceName            = $WorkspaceName
        DefaultDuration          = $DefaultDuration
        ReplaceExistingWatchlist = $true
    }
    try {
        New-GkSeAzSentinelWatchlist @Parameters | Out-Null
    } finally {
        # SentinelEnrichment writes <name>_<n>.csv next to the CSV for a split upload and leaves them behind
        $WatchListFolder = Split-Path -Path $WatchListFilePath -Parent
        $WatchListBaseName = [System.IO.Path]::GetFileNameWithoutExtension($WatchListFilePath)
        if (-not [string]::IsNullOrEmpty($WatchListFolder) -and (Test-Path -LiteralPath $WatchListFolder)) {
            Get-ChildItem -LiteralPath $WatchListFolder -Filter "$($WatchListBaseName)_*.csv" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.BaseName -match "^$([regex]::Escape($WatchListBaseName))_\d+$" } |
            Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }

    $Verification = Test-EntraOpsSentinelWatchlistDeployment -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -WatchListName $WatchListName -ExpectedItemCount $ExpectedItemCount -WatchListFilePath $WatchListFilePath -ApiVersion $ApiVersion
    switch ($Verification.Issue) {
        'Missing' { Write-Warning "  [!] Watchlist $WatchListName does not exist after the upload of $ExpectedItemCount row(s)." }
        'Empty' { Write-Warning "  [!] Watchlist $WatchListName exists but has no items after the upload of $ExpectedItemCount row(s)." }
        default {
            $CountText = if ($Verification.ItemCount -lt 0) { 'item count not verified' } elseif ($Verification.Counted) { "$($Verification.ItemCount) item(s)" } else { 'items present' }
            Write-Host "Watchlist $WatchListName uploaded: $ExpectedItemCount row(s) exported, $CountText."
        }
    }
    return $Verification
}
