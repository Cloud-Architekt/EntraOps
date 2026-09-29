<#
.SYNOPSIS
    Save Privileged EAM classification from EntraOps as WatchList.

.DESCRIPTION
    Get information from EntraOps about classification based on Enterprise Access Model and save it as WatchList in Microsoft Sentinel.

.PARAMETER ImportPath
    Folder where the classification files should be stored. Default is ./PrivilegedEAM.

.PARAMETER ExportFolder
    Folder where the local WatchList CSV files should be written. Default is the current working directory.

.PARAMETER SentinelSubscriptionId
    Subscription ID of the Microsoft Sentinel workspace. Required unless SkipUploadSaveLocal is set.

.PARAMETER SentinelResourceGroupName
    Resource group name of the Microsoft Sentinel workspace. Required unless SkipUploadSaveLocal is set.

.PARAMETER SentinelWorkspaceName
    Name of the Microsoft Sentinel workspace. Required unless SkipUploadSaveLocal is set.

.PARAMETER WatchListPrefix
    Prefix for all WatchLists wihich will be created by this cmldet. Default is EntraOps_.

.PARAMETER WatchListTemplates
    Type of WatchLists to be created. Default is None. Possible values are All, VIPUsers, HighValueAssets, IdentityCorrelation.

.PARAMETER WatchListWorkloadIdentity
    Type of WatchLists to be created. Default is None. Possible values are All, ManagedIdentityAssignedResourceId, WorkloadIdentityAttackPaths, WorkloadIdentityInfo, WorkloadIdentityRecommendations.

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, EntraID, IdentityGovernance, DeviceManagement, ResourceApps.
    AzureBilling and Defender remain available as explicit opt-in values.

.PARAMETER SkipUploadSaveLocal
    Skip upload to Sentinel and save WatchList locally. Default is false.

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
        [Parameter(Mandatory = $false)]
        [System.String]$ExportFolder = $PWD
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$SentinelSubscriptionId
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$SentinelResourceGroupName
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$SentinelWorkspaceName
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$WatchListPrefix = "EntraOps_"
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Azure", "AzureBilling", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")]
        [object]$RbacSystems = ("Azure", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps")
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("None", "All", "VIPUsers", "HighValueAssets", "IdentityCorrelation")]
        [object]$WatchListTemplates = "None"
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("None", "ManagedIdentityAssignedResourceId", "All", "WorkloadIdentityAttackPaths", "WorkloadIdentityInfo", "WorkloadIdentityRecommendations")]
        [object]$WatchListWorkloadIdentity = "None"
        ,
        [Parameter(Mandatory = $False)]
        [boolean]$SkipUploadSaveLocal = $false
        ,
        [Parameter(Mandatory = $False)]
        [boolean]$IngestToWatchLists = $false
    )

    # --- Path safety: ensure ImportPath is under the expected base directory ---
    $ResolvedImportPath = [System.IO.Path]::GetFullPath($ImportPath)
    $ResolvedBaseFolder = [System.IO.Path]::GetFullPath($EntraOpsBaseFolder)
    if (-not (Test-EntraOpsPathWithinRoot -Path $ImportPath -Root $EntraOpsBaseFolder -AllowRoot)) {
        throw "Security check failed: ImportPath '$ResolvedImportPath' is not under the expected base directory '$ResolvedBaseFolder'."
    }

    # --- Ensure ExportFolder exists so local WatchList CSVs have somewhere to land ---
    $ResolvedExportFolder = [System.IO.Path]::GetFullPath($ExportFolder)
    if (-not (Test-Path -LiteralPath $ResolvedExportFolder)) {
        try {
            New-Item -ItemType Directory -Path $ResolvedExportFolder -Force -ErrorAction Stop | Out-Null
        } catch {
            throw "Failed to create ExportFolder '$ResolvedExportFolder': $($_.Exception.Message)"
        }
    }

    if ( -not $SkipUploadSaveLocal ) {
        if ([string]::IsNullOrEmpty($SentinelSubscriptionId) -or [string]::IsNullOrEmpty($SentinelResourceGroupName) -or [string]::IsNullOrEmpty($SentinelWorkspaceName)) {
            throw "SentinelSubscriptionId, SentinelResourceGroupName and SentinelWorkspaceName are required when SkipUploadSaveLocal is not set."
        }
        Install-EntraOpsRequiredModule -ModuleName SentinelEnrichment        
    }
    $NewPrincipalsWatchlistItems = New-Object System.Collections.ArrayList
    $NewRoleAssignmentsWatchlistItems = New-Object System.Collections.ArrayList
    $NewRoleAssignmentClassificationsWatchlistItems = New-Object System.Collections.ArrayList
    $SeenClassificationUniqueIds = [System.Collections.Generic.HashSet[string]]::new()
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
                    "ObjectTenantId"                = $Privilege.ObjectTenantId
                    "ObjectType"                    = $Privilege.ObjectType
                    "ObjectSubType"                 = $Privilege.ObjectSubType
                    "ObjectDisplayName"             = $Privilege.ObjectDisplayName
                    "ObjectUserPrincipalName"       = $Privilege.ObjectUserPrincipalName
                    "ObjectAdminTierLevel"          = $Privilege.ObjectAdminTierLevel
                    "ObjectAdminTierLevelName"      = $Privilege.ObjectAdminTierLevelName
                    "OnPremSynchronized"            = $Privilege.OnPremSynchronized
                    "AssignedAdministrativeUnits"   = $Privilege.AssignedAdministrativeUnits | ConvertTo-Json -Depth 10 -Compress -AsArray
                    "RestrictedManagementByRAG"     = $Privilege.RestrictedManagementByRAG -eq $true
                    "RestrictedManagementByAadRole" = $Privilege.RestrictedManagementByAadRole -eq $true
                    "RestrictedManagementByRMAU"    = $Privilege.RestrictedManagementByRMAU -eq $True
                    "RoleSystem"                    = $Rbac
                    # Principal-level KQL filters consume only this unique tier and service summary.
                    # Classification evidence is represented separately at role-assignment granularity below.
                    "Classification"                = $Privilege.Classification | Select-Object AdminTierLevel, AdminTierLevelName, Service | Sort-Object AdminTierLevel, AdminTierLevelName, Service -Unique | ConvertTo-Json -Depth 10 -Compress -AsArray
                    "Owners"                        = $Privilege.Owners | ConvertTo-Json -Depth 10 -Compress -AsArray
                    "Sponsors"                      = $Privilege.Sponsors | ConvertTo-Json -Depth 10 -Compress -AsArray
                    "OwnedObjects"                  = $Privilege.OwnedObjects | ConvertTo-Json -Depth 10 -Compress -AsArray
                    "OwnedDevices"                  = $Privilege.OwnedDevices | ConvertTo-Json -Depth 10 -Compress -AsArray
                    "IdentityParent"                = $Privilege.IdentityParent
                    "AssociatedWorkAccount"         = $Privilege.AssociatedWorkAccount | ConvertTo-Json -Depth 10 -Compress -AsArray
                    "AssociatedPawDevice"           = $Privilege.AssociatedPawDevice | ConvertTo-Json -Depth 10 -Compress -AsArray
                    "Tags"                          = @("$($Rbac)", "Privileged Principal", "Automated Enrichment") | ConvertTo-Json -Depth 10 -Compress
                    "UniqueId"                      = "$($Privilege.ObjectId)-$($Rbac)"
                }
                $NewPrincipalsWatchlistItems.Add( $CurrentPrincipalItem ) | Out-Null

                foreach ( $RoleAssignment in $Privilege.RoleAssignments) {
                    # Extract classification into separate watchlist to avoid 10 KB item limit
                    $RoleAssignmentClassifications = $RoleAssignment.Classification
                    if ($null -ne $RoleAssignmentClassifications) {
                        foreach ($ClassificationItem in $RoleAssignmentClassifications) {
                            $ClassificationUniqueId = "$($RoleAssignment.RoleAssignmentId)_$($ClassificationItem.AdminTierLevelName)_$($ClassificationItem.Service)"
                            if (-not $SeenClassificationUniqueIds.Add($ClassificationUniqueId)) {
                                continue
                            }
                            $ClassificationWatchlistItem = [PSCustomObject]@{
                                "RoleAssignmentId"           = $RoleAssignment.RoleAssignmentId
                                "RoleAssignmentScopeId"      = $RoleAssignment.RoleAssignmentScopeId
                                "RoleDefinitionName"         = $RoleAssignment.RoleDefinitionName
                                "RoleDefinitionId"           = $RoleAssignment.RoleDefinitionId
                                "RoleSystem"                 = $Rbac
                                "AdminTierLevel"             = $ClassificationItem.AdminTierLevel
                                "AdminTierLevelName"         = $ClassificationItem.AdminTierLevelName
                                "Service"                    = $ClassificationItem.Service
                                "TaggedBy"                   = $ClassificationItem.TaggedBy
                                "TaggedByObjectIds"          = $ClassificationItem.TaggedByObjectIds | ConvertTo-Json -Depth 10 -Compress -AsArray
                                "TaggedByObjectDisplayNames" = $ClassificationItem.TaggedByObjectDisplayNames | ConvertTo-Json -Depth 10 -Compress -AsArray
                                "TaggedByRoleSystem"         = $ClassificationItem.TaggedByRoleSystem
                                "Tags"                       = @("$($Rbac)", "RoleClassification", "Automated Enrichment") | ConvertTo-Json -Depth 10 -Compress -AsArray
                                "UniqueId"                   = $ClassificationUniqueId
                            }
                            $NewRoleAssignmentClassificationsWatchlistItems.Add($ClassificationWatchlistItem) | Out-Null
                        }
                    }

                    # Remove Classification from RoleAssignment to reduce watchlist item size
                    $RoleAssignment.PSObject.Properties.Remove("Classification")

                    if ($null -eq $RoleAssignment.TransitiveByObjectId ) {
                        $RoleAssignment | Add-Member -MemberType NoteProperty -Name "UniqueId" -Value "$($RoleAssignment.RoleAssignmentId)_$($RoleAssignment.PrincipalId)" -Force
                    } else {
                        $RoleAssignment | Add-Member -MemberType NoteProperty -Name "UniqueId" -Value "$($RoleAssignment.RoleAssignmentId)_$($RoleAssignment.PrincipalId)_$($RoleAssignment.TransitiveByObjectId)" -Force
                    }
                    $TagValue = @("$($Rbac)", "Role Assignment", "Automated Enrichment") | ConvertTo-Json -Depth 10 -Compress -AsArray
                    $RoleAssignment | Add-Member -MemberType NoteProperty -Name "RoleSystem" -Value $Rbac -Force
                    $RoleAssignment | Add-Member -MemberType NoteProperty -Name "Tags" -Value $TagValue -Force
                    if ($RoleAssignment.PSObject.Properties.Match('TransitiveByNestingObjectDisplayNames').Count -gt 0) {
                        $RoleAssignment.TransitiveByNestingObjectDisplayNames = $RoleAssignment.TransitiveByNestingObjectDisplayNames | ConvertTo-Json -Depth 10 -Compress -AsArray
                    }
                    if ($RoleAssignment.PSObject.Properties.Match('TransitiveByNestingObjectIds').Count -gt 0) {
                        $RoleAssignment.TransitiveByNestingObjectIds = $RoleAssignment.TransitiveByNestingObjectIds | ConvertTo-Json -Depth 10 -Compress -AsArray
                    }
                    $NewRoleAssignmentsWatchlistItems.Add( $RoleAssignment ) | Out-Null
                }
            }
        }
    }

    if ( $NewPrincipalsWatchlistItems.Count -gt 0 ) {
        $WatchListName = "$($WatchListPrefix)Principals"
        Write-Output "Write information to watchlist: $WatchListName"

        $WatchListPath = Join-Path $ResolvedExportFolder "$($WatchListName).csv"
        $NewPrincipalsWatchlistItems | Sort-Object ObjectDisplayName | Export-Csv -Path $WatchListPath -NoTypeInformation -Encoding utf8 -Delimiter ","
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
        if ( -not $SkipUploadSaveLocal ) {
            New-GkSeAzSentinelWatchlist @Parameters -Verbose
            $null = Test-EntraOpsSentinelWatchlistDeployment -SubscriptionId $SentinelSubscriptionId -ResourceGroupName $SentinelResourceGroupName -WorkspaceName $SentinelWorkspaceName -WatchListName $WatchListName -ExpectedItemCount $NewPrincipalsWatchlistItems.Count -WatchListFilePath $WatchListPath
            Remove-Item -Path $WatchListPath -Force
        }
    }

    if ( $NewRoleAssignmentsWatchlistItems.Count -gt 0 ) {
        $WatchListName = "$($WatchListPrefix)RoleAssignments"
        Write-Output "Write information to watchlist: $WatchListName"
        $WatchListPath = Join-Path $ResolvedExportFolder "$($WatchListName).csv"
        $NewRoleAssignmentsWatchlistItems | Sort-Object AdminTierLevel, RoleSystem, ObjectDisplayName | Export-Csv -Path $WatchListPath -NoTypeInformation -Encoding utf8 -Delimiter ","
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
        if ( -not $SkipUploadSaveLocal ) {
            New-GkSeAzSentinelWatchlist @Parameters -Verbose
            $null = Test-EntraOpsSentinelWatchlistDeployment -SubscriptionId $SentinelSubscriptionId -ResourceGroupName $SentinelResourceGroupName -WorkspaceName $SentinelWorkspaceName -WatchListName $WatchListName -ExpectedItemCount $NewRoleAssignmentsWatchlistItems.Count -WatchListFilePath $WatchListPath
            Remove-Item -Path $WatchListPath -Force
        }
    }

    if ( $NewRoleAssignmentClassificationsWatchlistItems.Count -gt 0 ) {
        $WatchListName = "$($WatchListPrefix)RoleClassifications"
        Write-Output "Write information to watchlist: $WatchListName"
        $WatchListPath = Join-Path $ResolvedExportFolder "$($WatchListName).csv"
        $NewRoleAssignmentClassificationsWatchlistItems | Sort-Object AdminTierLevel, Service | Export-Csv -Path $WatchListPath -NoTypeInformation -Encoding utf8 -Delimiter ","
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
        if ( -not $SkipUploadSaveLocal ) {
            New-GkSeAzSentinelWatchlist @Parameters -Verbose
            $null = Test-EntraOpsSentinelWatchlistDeployment -SubscriptionId $SentinelSubscriptionId -ResourceGroupName $SentinelResourceGroupName -WorkspaceName $SentinelWorkspaceName -WatchListName $WatchListName -ExpectedItemCount $NewRoleAssignmentClassificationsWatchlistItems.Count -WatchListFilePath $WatchListPath
            Remove-Item -Path $WatchListPath -Force
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
        if ( -not $SkipUploadSaveLocal ) {
            Save-EntraOpsPrivilegedEAMEnrichmentToWatchLists @Parameters 
        }        
    }
    if ($WatchListWorkloadIdentity -notcontains "None") {
        $Parameters = @{
            SentinelSubscriptionId    = $SentinelSubscriptionId
            SentinelResourceGroupName = $SentinelResourceGroupName
            SentinelWorkspaceName     = $SentinelWorkspaceName
            WatchLists                = $WatchListWorkloadIdentity

        }

        if ( -not $SkipUploadSaveLocal ) {
            Save-EntraOpsWorkloadIdentityEnrichmentWatchLists @Parameters
        }                
    }
}
