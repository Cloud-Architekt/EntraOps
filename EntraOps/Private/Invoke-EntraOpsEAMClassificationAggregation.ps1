<#
.SYNOPSIS
    Aggregates classifications per unique object and builds standardized EAM output objects.

.DESCRIPTION
    Shared helper that replaces the duplicated classification aggregation logic found in every
    EAM cmdlet's final stage. Handles both parallel and sequential processing paths, builds
    unique classification sets per object, applies "Unclassified" fallback, and constructs
    the standardized output PSCustomObject via New-EntraOpsEAMOutputObject.

    This function eliminates ~150 lines of duplicated code per EAM cmdlet.

.PARAMETER UniqueObjects
    Array of unique objects with ObjectId and ObjectType properties.

.PARAMETER ObjectDetailsCache
    Hashtable mapping ObjectId → resolved object details from Get-EntraOpsPrivilegedEntraObject.

.PARAMETER RbacClassificationsByObject
    Hashtable mapping ObjectId → classified role assignments (from Group-Object ObjectId -AsHashTable).

.PARAMETER RoleSystem
    The RBAC system name (e.g., "EntraID", "Defender", "DeviceManagement", "IdentityGovernance", "ResourceApps").

.PARAMETER EnableParallelProcessing
    Enable parallel processing. Default is $true.

.PARAMETER ParallelThrottleLimit
    Maximum number of parallel threads. Default is 10.

.PARAMETER WarningMessages
    Reference to the List[psobject] for collecting warnings.

.OUTPUTS
    Array of standardized EAM output objects.
#>

function Invoke-EntraOpsEAMClassificationAggregation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Array]$UniqueObjects,

        [Parameter(Mandatory = $true)]
        [hashtable]$ObjectDetailsCache,

        [Parameter(Mandatory = $true)]
        [hashtable]$RbacClassificationsByObject,

        [Parameter(Mandatory = $true)]
        [string]$RoleSystem,

        [Parameter(Mandatory = $false)]
        [bool]$EnableParallelProcessing = $true,

        [Parameter(Mandatory = $false)]
        [int]$ParallelThrottleLimit = 10,

        [Parameter(Mandatory = $false)]
        [System.Collections.Generic.List[psobject]]$WarningMessages
    )

    # Determine if parallel processing is viable (PowerShell 7+ guaranteed by module prerequisite)
    $HasSufficientObjects = $UniqueObjects.Count -ge 50
    $UseParallelForClassification = $EnableParallelProcessing -and $HasSufficientObjects

    if ($UseParallelForClassification) {
        $SyncObjectDetailsCache = [System.Collections.Hashtable]::Synchronized($ObjectDetailsCache)
        $SyncRbacByObject = [System.Collections.Hashtable]::Synchronized($RbacClassificationsByObject)

        $ClassificationThrottleLimit = [Math]::Min($ParallelThrottleLimit * 2, 100)
        Write-Host "Using parallel classification processing with $ClassificationThrottleLimit threads for $($UniqueObjects.Count) objects..." -ForegroundColor Yellow

        $ClassifiedObjects = $UniqueObjects | ForEach-Object -ThrottleLimit $ClassificationThrottleLimit -Parallel {
            $obj = $_
            $ObjectId = $obj.ObjectId

            if ($null -ne $ObjectId) {
                $SharedDetailsCache = $using:SyncObjectDetailsCache
                $SharedRbacByObject = $using:SyncRbacByObject
                $LocalRoleSystem = $using:RoleSystem

                $ObjectDetails = $SharedDetailsCache[$ObjectId]

                if ($null -eq $ObjectDetails) {
                    Write-Verbose "Skipping object $ObjectId - failed to retrieve details"
                    return
                }

                $RbacClassifiedAssignments = $SharedRbacByObject[$ObjectId]

                # Aggregate unique classifications using hashtable
                $UniqueClassificationsHash = @{}
                foreach ($Assignment in $RbacClassifiedAssignments) {
                    if ($null -ne $Assignment.Classification) {
                        foreach ($ClassItem in $Assignment.Classification) {
                            $key = "$($ClassItem.AdminTierLevel)|$($ClassItem.AdminTierLevelName)|$($ClassItem.Service)"
                            if (-not $UniqueClassificationsHash.ContainsKey($key)) {
                                $UniqueClassificationsHash[$key] = $ClassItem
                            }
                        }
                    }
                }

                $Classification = @($UniqueClassificationsHash.Values | Select-Object -Unique -ExcludeProperty TaggedBy, TaggedByObjectIds, TaggedByObjectDisplayNames | Sort-Object AdminTierLevel, AdminTierLevelName, Service)
                if ($Classification.Count -eq 0) {
                    $Classification = @([PSCustomObject]@{
                        'AdminTierLevel'     = "Unclassified"
                        'AdminTierLevelName' = "Unclassified"
                        'Service'            = "Unclassified"
                    })
                }

                # Build output object inline (cannot call module functions from parallel runspace)
                [PSCustomObject]@{
                    'ObjectId'                      = $ObjectId
                    'ObjectType'                    = ($ObjectDetails.ObjectType ?? 'unknown').ToLower()
                    'ObjectSubType'                 = $ObjectDetails.ObjectSubType
                    'ObjectDisplayName'             = $ObjectDetails.ObjectDisplayName
                    'ObjectUserPrincipalName'       = $ObjectDetails.ObjectSignInName
                    'ObjectAdminTierLevel'          = $ObjectDetails.AdminTierLevel
                    'ObjectAdminTierLevelName'      = $ObjectDetails.AdminTierLevelName
                    'OnPremSynchronized'            = $ObjectDetails.OnPremSynchronized
                    'AssignedAdministrativeUnits'   = $ObjectDetails.AssignedAdministrativeUnits
                    'RestrictedManagementByRAG'     = $ObjectDetails.RestrictedManagementByRAG
                    'RestrictedManagementByAadRole' = $ObjectDetails.RestrictedManagementByAadRole
                    'RestrictedManagementByRMAU'    = $ObjectDetails.RestrictedManagementByRMAU
                    'RoleSystem'                    = $LocalRoleSystem
                    'Classification'                = $Classification
                    'RoleAssignments'               = @($RbacClassifiedAssignments | Sort-Object { ($_.Classification | Sort-Object AdminTierLevel | Select-Object -First 1).AdminTierLevel }, RoleDefinitionName, RoleAssignmentScopeId)
                    'Sponsors'                      = $ObjectDetails.Sponsors
                    'Owners'                        = $ObjectDetails.Owners
                    'OwnedObjects'                  = $ObjectDetails.OwnedObjects
                    'OwnedDevices'                  = $ObjectDetails.OwnedDevices
                    'IdentityParent'                = $ObjectDetails.IdentityParent
                    'AssociatedWorkAccount'         = $ObjectDetails.AssociatedWorkAccount
                    'AssociatedPawDevice'           = $ObjectDetails.AssociatedPawDevice
                }
            }
        }

        if ($ClassifiedObjects.Count -ne $UniqueObjects.Count -and $null -ne $WarningMessages) {
            $WarningMessages.Add([PSCustomObject]@{Type = "Stage-Classification-Parallel"; Message = "Parallel classification returned fewer objects than expected. Expected: $($UniqueObjects.Count), Actual: $($ClassifiedObjects.Count)" })
            Write-Warning "Parallel classification returned fewer objects than expected. Expected: $($UniqueObjects.Count), Actual: $($ClassifiedObjects.Count)"
        }
    } else {
        if ($EnableParallelProcessing) {
            Write-Host "Using sequential classification processing (dataset too small: $($UniqueObjects.Count) objects)" -ForegroundColor Yellow
        } else {
            Write-Host "Using sequential classification processing (parallel disabled)..." -ForegroundColor Yellow
        }

        $ClassifiedObjects = $UniqueObjects | ForEach-Object {
            if ($null -ne $_.ObjectId) {
                $ObjectId = $_.ObjectId
                if ($VerbosePreference -ne 'SilentlyContinue') {
                    Write-Verbose -Message "Processing classifications for $($ObjectId)..."
                }

                # Object types
                $ObjectDetails = $ObjectDetailsCache[$ObjectId]

                # Skip if object details couldn't be retrieved
                if ($null -eq $ObjectDetails) {
                    if ($null -ne $WarningMessages) {
                        $WarningMessages.Add([PSCustomObject]@{
                            Type    = "Skipping Object"
                            Message = "Skipping object $ObjectId - failed to retrieve details"
                            Target  = $ObjectId
                        })
                    }
                    return
                }

                # RBAC Assignments
                $RbacClassifiedAssignments = $RbacClassificationsByObject[$ObjectId]

                # Classification - use hashtable for unique aggregation
                $UniqueClassificationsHash = @{}
                foreach ($Assignment in $RbacClassifiedAssignments) {
                    if ($null -ne $Assignment.Classification) {
                        foreach ($ClassItem in $Assignment.Classification) {
                            $key = "$($ClassItem.AdminTierLevel)|$($ClassItem.AdminTierLevelName)|$($ClassItem.Service)"
                            if (-not $UniqueClassificationsHash.ContainsKey($key)) {
                                $UniqueClassificationsHash[$key] = $ClassItem
                            }
                        }
                    }
                }

                $Classification = @($UniqueClassificationsHash.Values | Select-Object -Unique -ExcludeProperty TaggedBy, TaggedByObjectIds, TaggedByObjectDisplayNames | Sort-Object AdminTierLevel, AdminTierLevelName, Service)
                if ($Classification.Count -eq 0) {
                    $Classification = @([PSCustomObject]@{
                        'AdminTierLevel'     = "Unclassified"
                        'AdminTierLevelName' = "Unclassified"
                        'Service'            = "Unclassified"
                    })
                }

                New-EntraOpsEAMOutputObject `
                    -ObjectId $ObjectId `
                    -ObjectDetails $ObjectDetails `
                    -Classification $Classification `
                    -RoleAssignments @($RbacClassifiedAssignments) `
                    -RoleSystem $RoleSystem
            }
        }
    }

    return $ClassifiedObjects
}
