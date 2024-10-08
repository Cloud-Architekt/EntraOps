<#
.SYNOPSIS
    Get information of Recommendations in Microsoft Entra ID for creating content for the WatchList "WorkloadIdentityRecommendations".

.DESCRIPTION
    Get information of Recommendations in Microsoft Entra ID for creating content for the WatchList "WorkloadIdentityRecommendations".

.PARAMETER StatusFilter
    Filter the recommendations based on the status. Default is "All". Possible values are "All","active","postponed","dismissed","completedByUser","completedBySystem".

.EXAMPLE
    Get a list of all active recommendations in Microsoft Entra
    Get-EntraOpsWorkloadIdentityRecommendations -StatusFilter Active
#>
function Get-EntraOpsWorkloadIdentityRecommendations {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "active", "postponed", "dismissed", "completedByUser", "completedBySystem")]
        [string]$StatusFilter = "All"
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("PSCustomObject", "WatchList")]
        [string]$OutputType = "PSCustomObject"        
    )

    $RecommendationItems = New-Object System.Collections.ArrayList

    Write-Verbose "Collecting data for Entra Recommendations"
    $Recommendations = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/directory/recommendations?`$filter=impactType eq 'apps'" -OutputType PSObject).value | select-object id, displayName, priority, insights, benefits

    $RecommendationItems = foreach ($Recommendation in $Recommendations) {
        $Resources = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/directory/recommendations/$($Recommendation.id)/impactedResources" -OutputType PSObject).value
        $Resources | ForEach-Object {
            $CurrentItem = [pscustomobject]@{
                'RecommendationId'           = $_.recommendationId
                'AddedDateTime'              = $_.AddedDateTime
                'Name'                       = $Recommendation.displayName
                'Priority'                   = $Recommendation.priority
                'Insights'                   = $Recommendation.insights
                'Benefits'                   = $Recommendation.benefits
                'AppId'                      = $_.id
                'Status'                     = $_.status
                'Details'                    = $_.additionaldetails.value
                'ImpactedResourceIdentifier' = $_.recommendationId + "_" + $_.id
            }
            return $CurrentItem
        }
    }

    if ($StatusFilter -ne "All") {
        $FilteredRecommendationItems = $RecommendationItems | where-object { $_.Status -eq $StatusFilter }
        return $FilteredRecommendationItems
    }
    else {
        return $RecommendationItems
    }
}