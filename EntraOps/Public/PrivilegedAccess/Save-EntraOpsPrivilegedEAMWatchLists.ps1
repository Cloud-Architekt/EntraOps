<#
.SYNOPSIS
    Save Privileged EAM classification from EntraOps as WatchList.

.DESCRIPTION
    Get information from EntraOps about classification based on Enterprise Access Model and save it as WatchList in Microsoft Sentinel.

.PARAMETER ImportPath
    Folder where the classification files should be stored. Default is ./PrivilegedEAM.

.PARAMETER SentinelSubscriptionId
    Subscription ID of the Microsoft Sentinel workspace.

.PARAMETER SentinelResourceGroupName
    Resource group name of the Microsoft Sentinel workspace.

.PARAMETER SentinelWorkspaceName
    Name of the Microsoft Sentinel workspace.

.PARAMETER WatchListPrefix
    Prefix for all WatchLists wihich will be created by this cmldet. Default is EntraOps_.

.PARAMETER WatchListTemplates
    Type of WatchLists to be created. Default is None. Possible values are All, VIPUsers, HighValueAssets, IdentityCorrelation.

.PARAMETER WatchListWorkloadIdentity
    Type of WatchLists to be created. Default is None. Possible values are All, ManagedIdentityAssignedResourceId, WorkloadIdentityAttackPaths, WorkloadIdentityInfo, WorkloadIdentityRecommendations.

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement, ResourceApps.

.EXAMPLE
    Save data of EntraOps Privileged EAM insights to WatchList in Microsoft Sentinel Workspace defined in parameter.
    Save-EntraOpsPrivilegedEAMWatchLists -SentinelSubscriptionId "3f72a077-c32a-423c-8503-41b93d3b0737" -SentinelResourceGroupName "EntraOpsResourceGroup" -SentinelWorkspaceName "EntraOpsWorkspace"

.EXAMPLE
    Save data of EntraOps Privileged EAM insights to WatchList in Microsoft Sentinel Workspace defined in config file and available in global variable.
    $SentinelWatchListsParams = $EntraOpsConfig.SentinelWatchLists
    Save-EntraOpsPrivilegedEAMWatchLists @SentinelWatchListsParams
#>

function Save-EntraOpsPrivilegedEAMWatchLists {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory = $false)]
        [System.String]$ImportPath = $DefaultFolderClassifiedEam
        ,
        [Parameter(Mandatory = $true)]
        [System.String]$SentinelSubscriptionId
        ,
        [Parameter(Mandatory = $true)]
        [System.String]$SentinelResourceGroupName
        ,
        [Parameter(Mandatory = $true)]
        [System.String]$SentinelWorkspaceName
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$WatchListPrefix = "EntraOps_"
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Azure", "AzureBilling", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")]
        [object]$RbacSystems = ("Azure", "AzureBilling", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("None", "All", "VIPUsers", "HighValueAssets", "IdentityCorrelation")]
        [object]$WatchListTemplates = "None"
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("None", "ManagedIdentityAssignedResourceId", "All", "WorkloadIdentityAttackPaths", "WorkloadIdentityInfo", "WorkloadIdentityRecommendations")]
        [object]$WatchListWorkloadIdentity = "None"
    )

    Install-EntraOpsRequiredModule -ModuleName SentinelEnrichment
    $NewPrincipalsWatchlistItems = New-Object System.Collections.ArrayList
    $NewRoleAssignmentsWatchlistItems = New-Object System.Collections.ArrayList
    foreach ($Rbac in $RbacSystems) {

        try {
            $Privileges = Get-Content -Path "$($ImportPath)/$($Rbac)/$($Rbac).json" -ErrorAction Stop | ConvertFrom-Json -Depth 10
        } catch {
            Write-Warning "No information found for $Rbac in file $($ImportPath)/$($Rbac)/$($Rbac).json"
            continue
        }
        if ( ![string]::IsNullOrEmpty($Privileges) ) {
            foreach ( $Privilege in $Privileges) {
                $CurrentPrincipalItem = [PSCustomObject]@{
                    "ObjectId"                      = $Privilege.ObjectId
                    "ObjectType"                    = $Privilege.ObjectType
                    "ObjectSubType"                 = $Privilege.ObjectSubType
                    "ObjectDisplayName"             = $Privilege.ObjectDisplayName
                    "ObjectUserPrincipalName"       = $Privilege.ObjectDisplayName
                    "ObjectAdminTierLevel"          = $Privilege.ObjectAdminTierLevel
                    "ObjectAdminTierLevelName"      = $Privilege.ObjectAdminTierLevelName
                    "OnPremSynchronized"            = $Privilege.OnPremSynchronized
                    "AssignedAdministrativeUnits"   = $Privilege.AssignedAdministrativeUnits | ConvertTo-Json -Depth 10 -Compress -AsArray
                    "RestrictedManagementByRAG"     = $Privilege.RestrictedManagementByRAG -eq $true
                    "RestrictedManagementByAadRole" = $Privilege.RestrictedManagementByAadRole -eq $true
                    "RestrictedManagementByRMAU"    = $Privilege.RestrictedManagementByRMAU -eq $True
                    "RoleSystem"                    = $Rbac
                    "Classification"                = $Privilege.Classification | ConvertTo-Json -Depth 10 -Compress -AsArray
                    "Owners"                        = $Privilege.Owners | ConvertTo-Json -Depth 10 -Compress -AsArray
                    "OwnedObjects"                  = $Privilege.OwnedObjects | ConvertTo-Json -Depth 10 -Compress -AsArray
                    "OwnedDevices"                  = $Privilege.OwnedDevices | ConvertTo-Json -Depth 10 -Compress -AsArray
                    "AssociatedWorkAccount"         = $Privilege.AssociatedWorkAccount | ConvertTo-Json -Depth 10 -Compress -AsArray
                    "AssociatedPawDevice"           = $Privilege.AssociatedPawDevice | ConvertTo-Json -Depth 10 -Compress -AsArray
                    "Tags"                          = @("$($Rbac)", "Privileged Principal", "Automated Enrichment") | ConvertTo-Json -Depth 10 -Compress
                    "UniqueId"                      = "$($Privilege.ObjectId)-$($Rbac)"
                }
                $NewPrincipalsWatchlistItems.Add( $CurrentPrincipalItem ) | Out-Null

                foreach ( $RoleAssignment in $Privilege.RoleAssignments) {
                    $RoleAssignment | Add-Member -MemberType NoteProperty -Name "Classification" -Value "$($RoleAssignment.Classification | ConvertTo-Json -Depth 10 -Compress -AsArray)" -Force
                    if ($null -eq $RoleAssignment.TransitiveByObjectId ) {
                        $RoleAssignment | Add-Member -MemberType NoteProperty -Name "UniqueId" -Value "$($RoleAssignment.RoleAssignmentId)_$($RoleAssignment.PrincipalId)" -Force
                    } else {
                        $RoleAssignment | Add-Member -MemberType NoteProperty -Name "UniqueId" -Value "$($RoleAssignment.RoleAssignmentId)_$($RoleAssignment.PrincipalId)_$($RoleAssignment.TransitiveByObjectId)" -Force
                    }
                    $TagValue = @("$($Rbac)", "Classification", "Automated Enrichment") | ConvertTo-Json -Depth 10 -Compress -AsArray
                    $RoleAssignment | Add-Member -MemberType NoteProperty -Name "RoleSystem" -Value $Rbac -Force
                    $RoleAssignment | Add-Member -MemberType NoteProperty -Name "Tags" -Value $TagValue -Force
                    $NewRoleAssignmentsWatchlistItems.Add( $RoleAssignment ) | Out-Null
                }
            }
            $WatchListName = "$($WatchListPrefix)Principals"
            Write-Output "Write information to watchlist: $WatchListName"
            if ( $null -ne $NewPrincipalsWatchlistItems ) {

                $WatchListPath = Join-Path $PWD "$($WatchListName).csv"
                $NewPrincipalsWatchlistItems | Export-Csv -Path $WatchListPath -NoTypeInformation -Encoding utf8 -Delimiter ","
                $Parameters = @{
                    WatchListFilePath        = $WatchListPath
                    DisplayName              = $WatchListName
                    itemsSearchKey           = "UniqueId"
                    SubscriptionId           = $SentinelSubscriptionId
                    ResourceGroupName        = $SentinelResourceGroupName
                    WorkspaceName            = $SentinelWorkspaceName
                    DefaultDuration          = "P14D"
                    ReplaceExistingWatchlist = $true
                }
                New-GkSeAzSentinelWatchlist @Parameters
                Remove-Item -Path $WatchListPath -Force
            }

            $WatchListName = "$($WatchListPrefix)RoleAssignments"
            Write-Output "Write information to watchlist: $WatchListName"

            if ( ![string]::IsNullOrEmpty($NewRoleAssignmentsWatchlistItems) ) {

                $WatchListPath = Join-Path $PWD "$($WatchListName).csv"
                $NewRoleAssignmentsWatchlistItems | Export-Csv -Path $WatchListPath -NoTypeInformation -Encoding utf8 -Delimiter ","
                $Parameters = @{
                    WatchListFilePath        = $WatchListPath
                    DisplayName              = $WatchListName
                    itemsSearchKey           = "UniqueId"
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
    }

    if ($WatchListTemplates -notcontains "None") {
        $Parameters = @{
            SentinelSubscriptionId    = $SentinelSubscriptionId
            SentinelResourceGroupName = $SentinelResourceGroupName
            SentinelWorkspaceName     = $SentinelWorkspaceName
            WatchListTemplates        = $WatchListTemplates
            RbacSystems               = $RbacSystems

        }
        Save-EntraOpsPrivilegedEAMEnrichmentToWatchLists @Parameters
    }

    if ($WatchListWorkloadIdentity -notcontains "None") {
        $Parameters = @{
            SentinelSubscriptionId    = $SentinelSubscriptionId
            SentinelResourceGroupName = $SentinelResourceGroupName
            SentinelWorkspaceName     = $SentinelWorkspaceName
            WatchLists                = $WatchListWorkloadIdentity

        }
        Save-EntraOpsWorkloadIdentityEnrichmentWatchLists @Parameters
    }
}