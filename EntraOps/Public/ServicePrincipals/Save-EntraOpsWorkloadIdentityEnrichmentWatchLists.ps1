<#    
.SYNOPSIS
    Get information of service principals to create content for the WatchList "ManagedIdentityAssignedResources", "MdcAttackPaths", "WorkloadIdentityInfo" and "WorkloadIdentityRecommendations".

.DESCRIPTION
    Get information of service principals to collect content and create the following watchlists:
    - "ManagedIdentityAssignedResources" - List of resources with assigned Managed Identity
    - "MdcAttackPaths" - List of attack paths in Microsoft Defender for Cloud for service principals and managed identities
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
    )

    Set-AzContext -SubscriptionId $SentinelSubscriptionId -TenantId $TenantId | Out-Null

    try {
        Import-Module "SentinelEnrichment" -ErrorAction Stop
    }
    catch {
        throw "Issue to import SentinelEnrichment modul!"
    }

    $WatchListParameters = @{
        SearchKey         = $null
        DisplayName       = $null
        NewWatchlistItems = ""
        SubscriptionId    = $SentinelSubscriptionId
        ResourceGroupName = $SentinelResourceGroupName
        WorkspaceName     = $SentinelWorkspaceName
        Identifiers       = @("Entra ID", "Automated Enrichment")
    }

    #region Workload Identity Assignments
    $WatchlistName = "ManagedIdentityAssignedResources"
    function Get-WorkloadIdentityAssignment {
        Write-Host "Collecting data for Managed Identity Assignments"
        $Query = "resources | where identity has 'SystemAssigned' or identity has 'UserAssigned' | project id, name, type, tags, tenantId, identity"
        $AzGraphResult = Invoke-EntraOpsAzGraphQuery -KqlQuery $Query
        $AssignedManagedIdentity = $AzGraphResult | Where-Object { $_.tenantId -eq "$TenantId" } | foreach-object {
            [PSCustomObject]@{
                'ResourceId'       = $_.id
                'ResourceName'     = $_.name
                'ResourceType'     = $_.type              
                'ResourceTags'     = $_.tags | ConvertTo-Json -Depth 10 -Compress -AsArray
                'ResourceTenantId' = $_.tenantId
                'Identity'         = $_.identity | ConvertTo-Json -Depth 10 -Compress -AsArray               
            }
        }
        return $AssignedManagedIdentity
    }
    $ManagedIdentityAssignedResources = New-Object System.Collections.ArrayList
    $ManagedIdentityAssignedResources = Get-WorkloadIdentityAssignment
    Write-Verbose "Write information to watchlist: $WatchListName"

    if ( $null -ne $ManagedIdentityAssignedResources ) {
        $WatchListParameters.SearchKey = "ResourceId"
        $WatchListParameters.DisplayName = "ManagedIdentityAssignedResources"
        $WatchListParameters.NewWatchlistItems = $ManagedIdentityAssignedResources
        Edit-GkSeAzSentinelWatchlist @WatchListParameters
    }
    #endregion

    #region WorkloadIdentityAttackPaths
    $WatchlistName = "WorkloadIdentityAttackPaths"
    $Query = 'securityresources
    | where type == "microsoft.security/attackpaths"
    | extend AttackPathDisplayName = tostring(properties["displayName"])
    | mvexpand (properties.graphComponent.entities)
    | extend Entity = parse_json(properties_graphComponent_entities)
    | extend EntityType = (Entity.entityType)
    | extend EntityName = (Entity.entityName)
    | extend EntityResourceId = (Entity.entityIdentifiers.azureResourceId)
    | where EntityType == "serviceprincipal" or EntityType == "managedidentity"
    | project id, AttackPathDisplayName, EntityName, EntityType, Description = tostring(properties["description"]), RiskFactors = tostring(properties["riskFactors"]), MitreTtp = tostring(properties["mITRETacticsAndTechniques"]), AttackStory = tostring(properties["attackStory"]), RiskLevel = tostring(properties["riskLevel"]), Target = tostring(properties["target"])'

    $WorkloadIdentityAttackPaths = New-Object System.Collections.ArrayList
    $AttackPathResults = Invoke-EntraOpsAzGraphQuery -KqlQuery $Query
    foreach ($AttackPath in $AttackPathResults) {
        $CurrentItem = @{
            'AttackPathId'          = $AttackPath.Id
            'AttackPathDisplayName' = $AttackPath.AttackPathDisplayName
            'AttackStory'           = $AttackPath.AttackStory
            'EntityName'            = $AttackPath.EntityName
            'EntityType'            = $AttackPath.EntityType
            'Description'           = $AttackPath.Description
            'RiskFactors'           = $AttackPath.RiskFactors
            'RiskLevel'             = $AttackPath.RiskLevel
            'MitreTtp'              = $AttackPath.MitreTtp
            'Target'                = $AttackPath.Target | ConvertTo-Json -Compress -AsArray
            'Tags'                  = @("WorkloadIdentityAttackPaths", "Automated Enrichment")
        }
        $WorkloadIdentityAttackPaths.Add( $CurrentItem ) | Out-Null
    }

    Write-Verbose "Write information to watchlist: $WatchListName"
    if ($WorkloadIdentityAttackPaths) {
        $WatchListParameters.SearchKey = "AttackPathId"
        $WatchListParameters.DisplayName = "WorkloadIdentityAttackPaths"
        $WatchListParameters.NewWatchlistItems = $WorkloadIdentityAttackPaths
        Edit-GkSeAzSentinelWatchlist @WatchListParameters
    }
    #endregion    

    #region WorkloadIdentityInfo
    $WatchlistName = "WorkloadIdentityInfo"
    Write-Host "Collecting data for $WatchlistName and upload as Watchlist"
    $WorkloadIdentityInfoItems = Get-EntraOpsWorkloadIdentityInfo

    Write-Verbose "Write information to watchlist: $WatchListName"
    if ( $null -ne $WorkloadIdentityInfoItems ) {
        $WatchListPath = Join-Path $PWD "$($WatchListName).csv"
        $WorkloadIdentityInfoItems | Export-Csv -Path $WatchListPath -NoTypeInformation -Encoding utf8 -Delimiter ","
        $Param2 = @{
            WatchListFilePath        = $WatchListPath
            DisplayName              = $WatchListName
            itemsSearchKey           = "ServicePrincipalObjectId"
            SubscriptionId           = $SentinelSubscriptionId
            ResourceGroupName        = $SentinelResourceGroupName
            WorkspaceName            = $SentinelWorkspaceName
            DefaultDuration          = "P14D"
            ReplaceExistingWatchlist = $true
        }
        New-GkSeAzSentinelWatchlist @Param2
    }
    #endregion

    #region WorkloadIdentityRecommendation
    Write-Host "Collecting data for Entra Recommendations and upload as Watchlist"
    $WorkloadIdentityRecommendations = Get-EntraOpsWorkloadIdentityRecommendations

    Write-Verbose "Write information to watchlist: $WatchListName"
    if ( $null -ne $WorkloadIdentityRecommendations ) {
        $WatchListParameters.DisplayName = "WorkloadIdentityRecommendations"
        $WatchListParameters.SearchKey = "ImpactedResourceIdentifier"
        $WatchListParameters.NewWatchlistItems = $WorkloadIdentityRecommendations
        Edit-GkSeAzSentinelWatchlist @WatchListParameters
    }
    #endregion
}