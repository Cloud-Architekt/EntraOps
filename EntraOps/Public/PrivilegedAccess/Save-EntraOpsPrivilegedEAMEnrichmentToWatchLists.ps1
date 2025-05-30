<#
.SYNOPSIS
    Get information of EntraOps Privileged EAM to add related entries to watchlist templates of HighValueAssets, IdentityCorrelation and VIP Users.

.DESCRIPTION
    Get information from EntraOps Privileged EAM to collect content and create the following watchlists:
    - "High Value Assets" - The High Value Assets watchlist lists devices, resources, and other assets that have critical value in the organization, it includes the identified privileged devices from EntraOps and resources from Get-EntraOpsControlObjects.
    - "VIP Users" - The VIP Users watchlist lists user accounts of employees that have high impact value in the organization, it includes the identified privileged users from EntraOps.
    - "Identity Correlation" - The Identity Correlation watchlist lists related user accounts that belong to the same person, it includes the users which has been identified by using custom security attribute to connect privileged and regular work accounts.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER SentinelResourceGroupName
    Resource group name of the Microsoft Sentinel workspace.

.PARAMETER SentinelSubscriptionId
    Subscription ID of the Microsoft Sentinel workspace.

.PARAMETER SentinelWorkspaceName
    Name of the Microsoft Sentinel workspace.

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement, ResourceApps.

.PARAMETER WatchListTemplates
    Define scope of WatchList templates which should be updated. Default is "All". Supported templates are "VIPUsers", "HighValueAssets", "IdentityCorrelation".

.EXAMPLE
    Save data of EntraOps Privileged EAM insights to WatchList in Microsoft Sentinel Workspace for correlation between work and privileged accounts.
    Save-EntraOpsPrivilegedEAMEnrichmentToWatchLists WatchListTemplates "IdentityCorrelation" -SentinelSubscriptionId "3f72a077-c32a-423c-8503-41b93d3b0737" -SentinelResourceGroupName "EntraOpsResourceGroup" -SentinelWorkspaceName "EntraOpsWorkspace"
#>
function Save-EntraOpsPrivilegedEAMEnrichmentToWatchLists {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet("Object", "RoleClassification")]
        [System.String]$UserClassificationSource = "RoleClassification"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$ImportPath = $DefaultFolderClassifiedEam
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
        [Parameter(Mandatory = $false)]
        [ValidateSet("Azure", "AzureBilling", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")]
        [object]$RbacSystems = ("Azure", "AzureBilling", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("None", "All", "VIPUsers", "HighValueAssets", "IdentityCorrelation")]
        [object]$WatchListTemplates = "All"
    )

    try {
        Import-Module "SentinelEnrichment" -ErrorAction Stop
    } catch {
        throw "Issue to import SentinelEnrichment modul!"
    }

    #region EntraOps Classification data
    $Privileges = foreach ($Rbac in $RbacSystems) {
        try {
            Get-Content -Path "$($ImportPath)/$($Rbac)/$($Rbac).json" -ErrorAction Stop | ConvertFrom-Json -Depth 10
        } catch {
            Write-Warning "No information found for $Rbac in file $($ImportPath)/$($Rbac)/$($Rbac).json"
            continue
        }
    }
    #endregion

    #region VIP Users
    if ($WatchListTemplates -eq "All" -or $WatchListTemplates -contains "VIPUsers") {
        $WatchListName = "VIP Users"
        $WatchListAlias = "VIPUsers"

        function Get-VIPUsers {
            $NewVipUserWatchlistItems = New-Object System.Collections.ArrayList

            Write-Host "Collecting data for VIPUsers"
            $PrivilegedUsers = $Privileges | Where-Object { $_.ObjectType -eq "user" } | Select-Object -unique ObjectId, ObjectUserPrincipalName, ObjectAdminTierLevelName
            foreach ($PrivilegedUser in $PrivilegedUsers) {
                $OnPremSid = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/v1.0/users/$($PrivilegedUser.ObjectId)?`$select=onPremisesSecurityIdentifier"

                # Set tags
                $Tags = New-Object System.Collections.ArrayList
                $Tags.Add("EntraOps") | Out-Null
                $Tags.Add("Automated Enrichment") | Out-Null

                if ($UserClassificationSource -eq "Object") {
                    # Get classification by custom security attribute of the privileged user
                    $Classification = ($Privileges | Where-Object { $_.ObjectId -eq $PrivilegedUser.ObjectId } | Select-Object -Unique ObjectAdminTierLevelName)[0]
                    $Tags.Add($($Classification.AdminTierLevelName)) | Out-Null
                } else {
                    # Get highest classification by assigned roles
                    $Classification = ($Privileges | Where-Object { $_.ObjectId -eq $PrivilegedUser.ObjectId } | Select-Object -ExpandProperty Classification | Sort-Object AdminTierLevel | Select-Object AdminTierLevelName)[0]
                    $Tags.Add($($Classification.AdminTierLevelName)) | Out-Null
                }

                # Check if privileged user object has been classified and is different to role classification
                if ($null -ne $PrivilegedUser.ObjectAdminTierLevelName -and $PrivilegedUser.ObjectAdminTierLevelName -ne $Classification.AdminTierLevelName) {
                    $Tags.Add("TierBreach") | Out-Null
                }

                $CurrentItem = @{
                    "User Identifier"     = $PrivilegedUser.ObjectId
                    "User AAD Object Id"  = $PrivilegedUser.ObjectId
                    "User On-Prem Sid"    = $OnPremSid.onPremisesSecurityIdentifier
                    "User Principal Name" = $PrivilegedUser.ObjectUserPrincipalName
                    "Tags"                = $Tags
                }
                $NewVipUserWatchlistItems.Add( $CurrentItem ) | Out-Null
            }
            return $NewVipUserWatchlistItems
        }
        $NewWatchlistItems = New-Object System.Collections.ArrayList
        $NewWatchlistItems = Get-VIPUsers
        Write-Verbose "Write information to watchlist: $WatchListName"

        if ( $null -ne $NewWatchlistItems ) {
            $SearchKey = "User Identifier"
            $Parameters = @{
                SearchKey         = $SearchKey
                DisplayName       = $WatchListName
                WatchListAlias    = $WatchListAlias
                NewWatchlistItems = $NewWatchlistItems
                SubscriptionId    = $SentinelSubscriptionId
                ResourceGroupName = $SentinelResourceGroupName
                WorkspaceName     = $SentinelWorkspaceName
                OverrideTags      = $true
                Identifiers       = @("EntraOps", "Automated Enrichment")
            }
            Edit-GkSeAzSentinelWatchlist @Parameters
        }
    }
    #endregion

    #region Identity Correlation
    if ($WatchListTemplates -eq "All" -or $WatchListTemplates -contains "IdentityCorrelation") {
        $WatchListName = "Identity Correlation"
        $WatchListAlias = "IdentityCorrelation"
        function Get-IdentityCorrelation {
            $NewIdentityCorrelationWatchlistItems = New-Object System.Collections.ArrayList

            Write-Host "Collecting data for IdentityCorrelation"
            $PrivilegedUsers = $Privileges | Where-Object { $_.ObjectType -eq "user" } | Select-Object -unique ObjectId, AssociatedWorkAccount, ObjectUserPrincipalName, ObjectAdminTierLevelName
            $AssociatedWorkAccounts = $PrivilegedUsers | Select-Object -ExpandProperty AssociatedWorkAccount | Select-Object -Unique
            foreach ($AssociatedWorkAccount in $AssociatedWorkAccounts) {
                $WorkAccountDetails = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/v1.0/users/$($AssociatedWorkAccount)?`$select=id,userPrincipalName,onPremisesSecurityIdentifier,mail,employeeId"
                $AssociatedPrivilegedUsers = $PrivilegedUsers | Where-Object { $_.AssociatedWorkAccount -eq $AssociatedWorkAccount } | Select-Object -unique ObjectId, ObjectUserPrincipalName, ObjectAdminTierLevelName
                foreach ($AssociatedPrivilegedUser in $AssociatedPrivilegedUsers) {

                    # Set tags
                    $Tags = New-Object System.Collections.ArrayList
                    $Tags.Add("EntraOps") | Out-Null
                    $Tags.Add("Automated Enrichment") | Out-Null

                    if ($UserClassificationSource -eq "Object") {
                        # Get classification by custom security attribute of the privileged user
                        $Classification = ($Privileges | Where-Object { $_.ObjectId -eq $AssociatedPrivilegedUser.ObjectId } | Select-Object -Unique ObjectAdminTierLevelName)[0]
                        $Tags.Add($($Classification.AdminTierLevelName)) | Out-Null
                    } else {
                        # Get highest classification by assigned roles
                        $Classification = ($Privileges | Where-Object { $_.ObjectId -eq $AssociatedPrivilegedUser.ObjectId } | Select-Object -ExpandProperty Classification | Sort-Object AdminTierLevel | Select-Object AdminTierLevelName)[0]
                        $Tags.Add($($Classification.AdminTierLevelName)) | Out-Null
                    }

                    $CurrentItem = @{
                        "User Identifier"                  = $WorkAccountDetails.id
                        "User AAD Object Id"               = $WorkAccountDetails.id
                        "User On-Prem Sid"                 = $WorkAccountDetails.onPremisesSecurityIdentifier
                        "User Principal Name"              = $WorkAccountDetails.userPrincipalName
                        "Employee Id"                      = $WorkAccountDetails.employeeId
                        "Email"                            = $WorkAccountDetails.mail
                        "Associated Privileged Account ID" = $AssociatedPrivilegedUser.ObjectId
                        "Associated Privileged Account"    = $AssociatedPrivilegedUser.ObjectUserPrincipalName
                        "Tags"                             = $Tags
                    }
                    $NewIdentityCorrelationWatchlistItems.Add( $CurrentItem ) | Out-Null
                }
            }
            return $NewIdentityCorrelationWatchlistItems
        }
        $NewWatchlistItems = New-Object System.Collections.ArrayList
        $NewWatchlistItems = Get-IdentityCorrelation
        Write-Verbose "Write information to watchlist: $WatchListName"

        if ( $null -ne $NewWatchlistItems ) {
            $SearchKey = "Associated Privileged Account ID"
            $Parameters = @{
                SearchKey         = $SearchKey
                DisplayName       = $WatchListName
                WatchListAlias    = $WatchListAlias
                NewWatchlistItems = $NewWatchlistItems
                SubscriptionId    = $SentinelSubscriptionId
                ResourceGroupName = $SentinelResourceGroupName
                WorkspaceName     = $SentinelWorkspaceName
                Identifiers       = @("EntraOps", "Automated Enrichment")
                OverrideTags      = $true
            }
            Edit-GkSeAzSentinelWatchlist @Parameters
        }
    }
    #endregion

    #region High Value Assets
    if ($WatchListTemplates -eq "All" -or $WatchListTemplates -contains "HighValueAssets") {
        $WatchListName = "High Value Assets"
        $WatchListAlias = "HighValueAssets"
        function Get-HighValueAssets {
            Write-Host "Collecting data for High Value Assets"
            $HighValueAssets = @()

            $DeviceQuery = 'ExposureGraphNodes
            | where isnotnull(NodeProperties.rawData.criticalityLevel) and (NodeProperties.rawData.criticalityLevel.criticalityLevel <1)
            | where (NodeLabel == "device")
            | extend "Asset Type" == "Device"
            | mv-apply EntityIds = parse_json(EntityIds) on
                (
                where EntityIds.type =~ "DeviceInventoryId"
                | extend
                    DeviceId = tostring(EntityIds.DeviceInventoryId)
                )
            | extend DeviceId = tostring(parse_json(EntityIds).id)
            | project ["AssetType"] = "Device",
                    ["AssetId"] = DeviceId,
                    ["AssetFQDN"] = NodeName,                    
                    ["AssetName"] = NodeName,
                    ["Tags"] = parse_json(NodeProperties).rawData.criticalityLevel.ruleNames;'
            $Body = @{
                "Query" = $DeviceQuery;
            } | ConvertTo-Json
            $Devices = (Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/security/runHuntingQuery" -Body $Body -OutputType PSObject).results
            $HighValueAssets += $Devices

            $AzureResourceQuery = 'ExposureGraphNodes
            | where isnotnull(NodeProperties.rawData.criticalityLevel) and (NodeProperties.rawData.environmentName == "Azure")
            | mv-apply EntityIds = parse_json(EntityIds) on
                (
                where EntityIds.type =~ "AzureResourceId"
                | extend
                    ResourceId = tostring(EntityIds.AzureResourceId)
                )
            | extend AzureResourceId = tostring(parse_json(EntityIds).id)
            | extend IpAddresses = parse_json(NodeProperties).rawData.networkingComponentMetadata.ipAddresses
            | project ["AssetType"] = "Azure resource",
                    ["AssetId"] = AzureResourceId,
                    ["AssetFQDN"] = NodeName,
                    ["AssetName"] = NodeName,
                    ["IPAddress"] = IpAddresses,
                    ["Tags"] = parse_json(NodeProperties).rawData.criticalityLevel.ruleNames'
            $Body = @{
                "Query" = $AzureResourceQuery;
            } | ConvertTo-Json
            $AzureResources = (Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/security/runHuntingQuery" -Body $Body -OutputType PSObject).results
            $HighValueAssets += $AzureResources

            $NewHighValueAssetWatchlistItems = New-Object System.Collections.ArrayList

            foreach ($HighValueAsset in $HighValueAssets) {
                $Tags = New-Object System.Collections.ArrayList
                $Tags.Add("EntraOps") | Out-Null
                $Tags.Add("XSPM") | Out-Null
                $Tags.Add("Automated Enrichment") | Out-Null
                foreach ($Tag in $CriticalResource.Tags) {
                    $Tags.Add( $Tag ) | Out-Null
                }

                $CurrentItem = @{
                    "Asset Type" = $HighValueAsset.AssetType
                    "Asset Id"   = $HighValueAsset.AssetId
                    "Asset Name" = $HighValueAsset.AssetName
                    "Asset FQDN" = $HighValueAsset.AssetFQDN
                    "IP Address" = $HighValueAsset.IPAddress | ConvertTo-Json -Compress -AsArray
                    "Tags"       = $Tags
                }
                $NewHighValueAssetWatchlistItems.Add( $CurrentItem ) | Out-Null
            }
            return $NewHighValueAssetWatchlistItems
        }
        $NewWatchlistItems = New-Object System.Collections.ArrayList
        $NewWatchlistItems = Get-HighValueAssets
        Write-Verbose "Write information to watchlist: $WatchListName"

        if ( $null -ne $NewWatchlistItems ) {
            $SearchKey = "Asset Id"
            $Parameters = @{
                SearchKey         = $SearchKey
                DisplayName       = $WatchListName
                WatchListAlias    = $WatchListAlias
                NewWatchlistItems = $NewWatchlistItems
                SubscriptionId    = $SentinelSubscriptionId
                ResourceGroupName = $SentinelResourceGroupName
                WorkspaceName     = $SentinelWorkspaceName
                Identifiers       = @("EntraOps", "Automated Enrichment")
                OverrideTags      = $true
            }
            Edit-GkSeAzSentinelWatchlist @Parameters
        }
    }
    #endregion
}