<#
.SYNOPSIS
    Get information of service principals to create content for the WatchList "ManagedIdentityAssignedResources", "MdcAttackPaths", "WorkloadIdentityInfo" and "WorkloadIdentityRecommendations".

.DESCRIPTION
    Get information of service principals to collect content and create the following watchlists:
    - "ManagedIdentityAssignedResourceId" - List of resources with assigned Managed Identity
    - "WorkloadIdentityAttackPaths" - List of attack paths in Microsoft Defender for Cloud for service principals and managed identities
    - "WorkloadIdentityInfo" - List of service principals with detailed information for Workload Identity
    - "WorkloadIdentityRecommendations" - List of recommendations for Workload Identity in Microsoft Entra ID

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER SentinelResourceGroupName
    Resource group name of the Microsoft Sentinel workspace.

.PARAMETER SentinelSubscriptionId
    Subscription ID of the Microsoft Sentinel workspace.

.PARAMETER SentinelWorkspaceName
    Name of the Microsoft Sentinel workspace.

.EXAMPLE
    Create all watchlists for Workload Identity Enrichment
    Save-EntaOpsWorkloadIdentityEnrichmentWatchLists -SentinelResourceGroupName "SentinelRG" -SentinelSubscriptionId "SentinelSubId" -SentinelWorkspaceName "SentinelWorkspace"
#>

function Save-EntraOpsWorkloadIdentityEnrichmentWatchLists {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$TenantId = $TenantIdContext
        ,
        [Parameter(Mandatory = $True)]
        [System.String]$SentinelResourceGroupName
        ,
        [Parameter(Mandatory = $True)]
        [System.String]$SentinelSubscriptionId
        ,
        [Parameter(Mandatory = $True)]
        [System.String]$SentinelWorkspaceName
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("ManagedIdentityAssignedResourceId", "All", "WorkloadIdentityAttackPaths", "WorkloadIdentityInfo", "WorkloadIdentityRecommendations")]
        [object]$WatchLists = "All"
    )

    try {
        Import-Module "SentinelEnrichment" -ErrorAction Stop
    }
    catch {
        throw "Issue to import SentinelEnrichment modul!"
    }

    #region Workload Identity Assignments
    if ($WatchLists -eq "All" -or $WatchLists -contains "ManagedIdentityAssignedResourceId") {
        Write-Host "Collecting data for ManagedIdentityAssignedResourceId"
        $WatchListName = "ManagedIdentityAssignedResourceId"
        $WatchListAlias = "ManagedIdentityAssignedResourceId"
        $SearchKey = "ObjectId"

        $MiAssignedResourceIds = Get-EntraOpsManagedIdentityAssignments
        $MiAssignedResourceIdWatchlistItems = New-Object System.Collections.ArrayList

        foreach ($MiAssignedResourceId in $MiAssignedResourceIds) {

            $AssociatedWorkloadId = $MiAssignedResourceId.AssociatedWorkloadId | ConvertTo-Json -Depth 10 -Compress -AsArray
            $MiAssignedResourceId | Add-Member -MemberType NoteProperty -Name "AssociatedWorkloadId" -Value $AssociatedWorkloadId -Force
            $TagValue = @("EntraOps", "Automated Enrichment") | ConvertTo-Json -Depth 10 -Compress -AsArray
            $MiAssignedResourceId | Add-Member -MemberType NoteProperty -Name "Tags" -Value $TagValue -Force

            $MiAssignedResourceIdWatchlistItems.Add( $MiAssignedResourceId ) | Out-Null
        }

        if ( $null -ne $MiAssignedResourceIdWatchlistItems ) {

            $WatchListPath = Join-Path $PWD "$($WatchListName).csv"
            $MiAssignedResourceIdWatchlistItems | Export-Csv -Path $WatchListPath -NoTypeInformation -Encoding utf8 -Delimiter ","
            $Parameters = @{
                WatchListFilePath        = $WatchListPath
                DisplayName              = $WatchListName
                itemsSearchKey           = $SearchKey
                SubscriptionId           = $SentinelSubscriptionId
                ResourceGroupName        = $SentinelResourceGroupName
                WorkspaceName            = $SentinelWorkspaceName
                DefaultDuration          = "P14D"
                ReplaceExistingWatchlist = $true
            }
            New-GkSeAzSentinelWatchlist @Parameters
            Remove-Item -Path $WatchListPath -Force
        }
    }
    #endregion

    #region WorkloadIdentityAttackPaths
    if ($WatchLists -eq "All" -or $WatchLists -contains "WorkloadIdentityAttackPaths") {
        $WatchListName = "WorkloadIdentityAttackPaths"
        $WatchListAlias = "WorkloadIdentityAttackPaths"
        $SearchKey = "AttackPathId"

        $WorkloadIdentityAttackPaths = Get-EntraOpsWorkloadIdentityAttackPaths
        $WorkloadIdentityAttackPathsWatchlistItems = New-Object System.Collections.ArrayList

        foreach ($WorkloadIdentityAttackPath in $WorkloadIdentityAttackPaths) {
            $TagValue = @("EntraOps", "Automated Enrichment") | ConvertTo-Json -Depth 10 -Compress -AsArray
            $WorkloadIdentityAttackPath | Add-Member -MemberType NoteProperty -Name "Tags" -Value $TagValue -Force
            $WorkloadIdentityAttackPathsWatchlistItems.Add( $WorkloadIdentityAttackPath ) | Out-Null
        }

        Write-Verbose "Write information to watchlist: $WatchListName"
        if ( ![string]::IsNullOrEmpty($WorkloadIdentityAttackPathsWatchlistItems) ) {

            $WatchListPath = Join-Path $PWD "$($WatchListName).csv"
            $WorkloadIdentityAttackPathsWatchlistItems | Export-Csv -Path $WatchListPath -NoTypeInformation -Encoding utf8 -Delimiter ","
            $Parameters = @{
                WatchListFilePath        = $WatchListPath
                DisplayName              = $WatchListName
                itemsSearchKey           = $SearchKey
                SubscriptionId           = $SentinelSubscriptionId
                ResourceGroupName        = $SentinelResourceGroupName
                WorkspaceName            = $SentinelWorkspaceName
                DefaultDuration          = "P14D"
                ReplaceExistingWatchlist = $true
            }
            New-GkSeAzSentinelWatchlist @Parameters
            Remove-Item -Path $WatchListPath -Force
        }
    }
    #endregion

    #region WorkloadIdentityInfo
    if ($WatchLists -eq "All" -or $WatchLists -contains "WorkloadIdentityInfo") {

        $WatchListName = "WorkloadIdentityInfo"
        $WatchListAlias = "WorkloadIdentityInfo"
        $searchKey = "ServicePrincipalObjectId"

        $WorkloadIdentityInfo = Get-EntraOpsWorkloadIdentityInfo
        $WorkloadIdentityInfoWatchlistItems = New-Object System.Collections.ArrayList

        foreach ($WorkloadIdentity in $WorkloadIdentityInfo) {
            $TagValue = @("EntraOps", "Automated Enrichment") | ConvertTo-Json -Depth 10 -Compress -AsArray
            $WorkloadIdentity | Add-Member -MemberType NoteProperty -Name "Tags" -Value $TagValue -Force
            $WorkloadIdentityInfoWatchlistItems.Add( $WorkloadIdentity ) | Out-Null
        }

        Write-Verbose "Write information to watchlist: $WatchListName"
        if ( ![string]::IsNullOrEmpty($WorkloadIdentityInfoWatchlistItems) ) {
            $WatchListPath = Join-Path $PWD "$($WatchListName).csv"
            $WorkloadIdentityInfoWatchlistItems | Export-Csv -Path $WatchListPath -NoTypeInformation -Encoding utf8 -Delimiter ","
            $Parameters = @{
                WatchListFilePath        = $WatchListPath
                DisplayName              = $WatchListName
                itemsSearchKey           = $SearchKey
                SubscriptionId           = $SentinelSubscriptionId
                ResourceGroupName        = $SentinelResourceGroupName
                WorkspaceName            = $SentinelWorkspaceName
                DefaultDuration          = "P14D"
                ReplaceExistingWatchlist = $true
            }
            New-GkSeAzSentinelWatchlist @Parameters
            Remove-Item -Path $WatchListPath -Force
        }
    }
    #endregion

    #region WorkloadIdentityRecommendations
    if ($WatchLists -eq "All" -or $WatchLists -contains "WorkloadIdentityRecommendations") {

        $WatchListName = "WorkloadIdentityRecommendations"
        $WatchListAlias = "WorkloadIdentityRecommendations"
        $SearchKey = "ImpactedResourceIdentifier"

        $WorkloadIdentityRecommendations = Get-EntraOpsWorkloadIdentityRecommendations
        $WorkloadIdentityRecommendationsWatchlistItems = New-Object System.Collections.ArrayList

        foreach ($WorkloadIdentityRecommendation in $WorkloadIdentityRecommendations) {
            $TagValue = @("EntraOps", "Automated Enrichment") | ConvertTo-Json -Depth 10 -Compress -AsArray
            $WorkloadIdentityRecommendation | Add-Member -MemberType NoteProperty -Name "Tags" -Value $TagValue -Force
            $WorkloadIdentityRecommendationsWatchlistItems.Add( $WorkloadIdentityRecommendation ) | Out-Null
        }

        Write-Verbose "Write information to watchlist: $WatchListName"
        if ( ![string]::IsNullOrEmpty($WorkloadIdentityRecommendationsWatchlistItems) ) {
            $WatchListPath = Join-Path $PWD "$($WatchListName).csv"
            $WorkloadIdentityRecommendationsWatchlistItems | Export-Csv -Path $WatchListPath -NoTypeInformation -Encoding utf8 -Delimiter ","
            $Parameters = @{
                WatchListFilePath        = $WatchListPath
                DisplayName              = $WatchListName
                itemsSearchKey           = $SearchKey
                SubscriptionId           = $SentinelSubscriptionId
                ResourceGroupName        = $SentinelResourceGroupName
                WorkspaceName            = $SentinelWorkspaceName
                DefaultDuration          = "P14D"
                ReplaceExistingWatchlist = $true
            }
            New-GkSeAzSentinelWatchlist @Parameters
            Remove-Item -Path $WatchListPath -Force
        }
    }
    #endregion
}