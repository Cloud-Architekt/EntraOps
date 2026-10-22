<#
.SYNOPSIS
    Update membership on security groups based on EntraOps classification which can be used for targeting Conditional Access policies.

.DESCRIPTION
    Security Groups for the different Enterprise Access Levels will be updated based on the classification of EntraOps.
    Objects will be assigned to the corresponding Administrative Units based on the classification.
    This security groups can be used for targeting Conditional Access policies.

.PARAMETER ApplyToAccessTierLevel
    Array of Access Tier Levels to be processed. Default is ControlPlane, ManagementPlane.

.PARAMETER FilterObjectType
    Array of object types to be processed. Default is User, Group.

.PARAMETER GroupPrefix
    String to define the prefix of the Conditional Access Inclusion Groups. Default is "sug_Entra.CA.IncludeUsers.PrivilegedAccounts."

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, EntraID, IdentityGovernance, ResourceApps, DeviceManagement, Defender.

.PARAMETER RemovalSafetyThreshold
    Fraction of current members that may be removed in a single run before the sync aborts the group as a
    suspected upstream data issue. Default is 0.5 (50%).

.PARAMETER ForceRemovalBeyondSafetyThreshold
    Apply removals even when they exceed RemovalSafetyThreshold. Needed to reconcile a group that drifted
    far from its desired state (for example one over-populated by an earlier run), because such a group
    can never converge on its own - every run recomputes the same oversized delta and aborts again.
    Review the delta from a normal (aborting) run first, then re-run with this switch.

.PARAMETER IncludeObjectDetails
    Include object display names and detailed API errors in console output. Defaults to
    ConsoleOutput.IncludeObjectDetails from EntraOpsConfig.json. Object IDs are always shown.

.EXAMPLE
    Update Conditional Access Target Groups for EntraID, IdentityGovernance and ResourceApps RBAC systems with assigned User and Group objects
    Update-EntraOpsPrivilegedConditionalAccessGroup -GroupPrefix "sug_Entra.CA.IncludeUsers.PrivilegedAccounts." -RbacSystems ("EntraID", "IdentityGovernance")

.EXAMPLE
    Apply a cleanup that the safety threshold blocked, after reviewing the reported delta
    Update-EntraOpsPrivilegedConditionalAccessGroup -RbacSystems ("IdentityGovernance") -ForceRemovalBeyondSafetyThreshold
#>

function Update-EntraOpsPrivilegedConditionalAccessGroup {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False)]
        [ValidateSet("ControlPlane", "ManagementPlane")]
        [Array]$ApplyToAccessTierLevel = ("ControlPlane", "ManagementPlane")
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("User", "Group")]
        [Array] $FilterObjectType = ("User", "Group")
        ,
        [Parameter(Mandatory = $False)]
        [string]$GroupPrefix = "sug_Entra.CA.IncludeUsers.PrivilegedAccounts."
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("Azure", "EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement", "Defender")]
        [Array]$RbacSystems = ("Azure", "EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement", "Defender")
        ,
        [Parameter(Mandatory = $false)]
        [String]$AdminUnitName
        ,
        [Parameter(Mandatory = $false)]
        [string]$TenantId = (Get-EntraOpsAzContextValue -Property TenantId)
        ,
        [Parameter(Mandatory = $False)]
        [ValidateRange(0.0, 1.0)]
        [double]$RemovalSafetyThreshold = 0.5
        ,
        [Parameter(Mandatory = $False)]
        [switch]$ForceRemovalBeyondSafetyThreshold
        ,
        [Parameter(Mandatory = $False)]
        [boolean]$IncludeObjectDetails = [bool]$Global:EntraOpsIncludeObjectDetails
        ,
        [Parameter(Mandatory = $False)]
        [boolean]$ApplyConditionalAccessTargetGroups = $false
    )


    # Get all unique AdminTierLevels which needs to be iterated for assigning objects to Conditional Access Target Groups
    $PrivilegedEamTierLevels = Get-ChildItem -Path "$($DefaultFolderClassification)/Templates" -File -Recurse -Exclude *.Param.json | foreach-object { Get-Content $_.FullName -Filter "*.json" | ConvertFrom-Json }
    $SelectedPrivilegedEamTierLevels = $PrivilegedEamTierLevels | where-object { $_.EAMTierLevelName -in $ApplyToAccessTierLevel } | select-object -unique @{Name = 'AdminTierLevel'; Expression = 'EAMTierLevelTagValue' }, @{Name = 'AdminTierLevelName'; Expression = 'EAMTierLevelName' }
    #endregion

    # Summary tracking
    $SyncSummary = [System.Collections.Generic.List[psobject]]::new()
    $TotalAdded = 0
    $TotalRemoved = 0
    $WarningMessages = New-Object -TypeName "System.Collections.Generic.List[psobject]"

    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host " EntraOps - Conditional Access Group Sync" -ForegroundColor Cyan
    Write-Host " RBAC Systems : $($RbacSystems -join ', ')" -ForegroundColor Cyan
    Write-Host " Access Tiers : $($ApplyToAccessTierLevel -join ', ')" -ForegroundColor Cyan
    Write-Host " Group Prefix : $GroupPrefix" -ForegroundColor Cyan
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""

    foreach ($RbacSystem in $RbacSystems) {
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host " RBAC System: $RbacSystem" -ForegroundColor DarkCyan
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan

        $ClassificationEamFile = "$DefaultFolderClassifiedEam/$RbacSystem/$($RbacSystem).json"

        #region Get principals from EAM classification files and filter out objects without classification and objects not related to the RBAC system or object type filter
        $PrivilegedEam = @()
        $PrivilegedEam += Get-ChildItem -Path $ClassificationEamFile | foreach-object { Get-Content $_.FullName -Filter "*.json" | ConvertFrom-Json }
        $PrivilegedEam = $PrivilegedEam | Where-Object { $_.ObjectType -in $FilterObjectType }
        $PrivilegedEamCount = ($PrivilegedEam | Where-Object { $null -eq $_.Classification }).count
        if ($PrivilegedEamCount -gt 0) {
            Write-Warning "Numbers of objects without classification: $PrivilegedEamCount"
            $WarningMessages.Add([PSCustomObject]@{ Type = "UnclassifiedObjects"; Message = "$PrivilegedEamCount object(s) without classification in $RbacSystem" })
        }
        $PrivilegedEamClassifiedObjects = $PrivilegedEam | where-object { $_.Classification.AdminTierLevel -notcontains $null -and $_.RoleSystem -eq $RbacSystem }

        #region Assign all principals in Privileged EAM to Conditional Access Target Groups
        foreach ($TierLevel in $SelectedPrivilegedEamTierLevels) {
            $GroupName = "$GroupPrefix" + $TierLevel.AdminTierLevelName + "." + $($RbacSystem)
            $GrpAdded = 0
            $GrpRemoved = 0
            $GrpFailed = 0
            $GrpStatus = "OK"

            Write-Host ""
            Write-Host "  Group: $GroupName" -ForegroundColor White

            $Groups = @(Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/v1.0/groups?`$filter=DisplayName eq '$(ConvertTo-EntraOpsODataStringLiteral -Value $GroupName)'" -OutputType PSObject -DisableCache)
            # -AllowNotFound: a missing group is handled by the NOT FOUND skip branch below so the
            # remaining tiers/RBAC systems still synchronize; duplicates still throw (F-10 safety).
            $GroupId = (Select-EntraOpsUniqueGraphObject -InputObject $Groups -ObjectDescription "group '$GroupName'" -AllowNotFound).id
            if ($null -eq $GroupId) {
                Write-Warning "  [SKIP] Could not find group: $GroupName"
                $WarningMessages.Add([PSCustomObject]@{ Type = "GroupNotFound"; Message = "Could not find group: $GroupName" })
                $SyncSummary.Add([PSCustomObject]@{
                    RbacSystem    = $RbacSystem
                    Group         = $GroupName
                    MembersBefore = "N/A"
                    Added         = 0
                    Removed       = 0
                    Failed        = 0
                    Status        = "NOT FOUND"
                })
                continue
            }

            $PrivilegedObjects = @()
            $PrivilegedObjects = ($PrivilegedEamClassifiedObjects | Where-Object { $_.Classification.AdminTierLevelName -contains $TierLevel.AdminTierLevelName -and $_.RoleSystem -eq $RbacSystem })

            $ForeignTenantObjects = @($PrivilegedObjects | Where-Object { -not [string]::IsNullOrEmpty($_.ObjectTenantId) -and $_.ObjectTenantId -ne $TenantId })
            if ($ForeignTenantObjects.Count -gt 0) {
                Write-Warning "  [SKIP] Excluded $($ForeignTenantObjects.Count) object(s) not owned by tenant $TenantId"
                $WarningMessages.Add([PSCustomObject]@{ Type = "ForeignTenantObject"; Message = "Skipped $($ForeignTenantObjects.Count) object(s) not owned by tenant $TenantId for $GroupName" })
            }
            $PrivilegedObjects = @($PrivilegedObjects | Where-Object { [string]::IsNullOrEmpty($_.ObjectTenantId) -or $_.ObjectTenantId -eq $TenantId })

            $CurrentGroupMembers = @()
            $CurrentGroupMembers = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/groups/$($GroupId)/members" -OutputType PSObject -DisableCache)

            $CurrentMemberCount = @($CurrentGroupMembers.Id).Count
            $DesiredMemberCount = @($PrivilegedObjects.ObjectId).Count
            Write-Host "  Current members : $CurrentMemberCount | Desired: $DesiredMemberCount" -ForegroundColor Gray

            # Deduplicate both sides before diff - an object with multiple role assignments at the
            # same tier level appears once per assignment in the EAM JSON, producing duplicate ObjectIds.
            # Compare-Object with duplicates in either side produces duplicate add/remove entries.
            $DesiredIds = @($PrivilegedObjects.ObjectId | Select-Object -Unique)
            $CurrentIds = @($CurrentGroupMembers.Id | Select-Object -Unique)

            # Check if group members already exists for sync, or just adding new items
            if ($Null -eq $CurrentGroupMembers.Id) {
                # Deduplicate - same object may appear multiple times with different role assignments
                $UniqueDesiredObjects = $PrivilegedObjects | Sort-Object ObjectId -Unique
                Write-Host "  Group is empty - adding all $(@($UniqueDesiredObjects).Count) objects" -ForegroundColor Yellow
                foreach ($PrivObj in $UniqueDesiredObjects) {
                    try {
                        $GroupMember = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/directoryObjects/$($PrivObj.ObjectId)" -DisableCache -OutputType PSObject -ThrowOnFailure -SuppressNotFoundWarning
                        $MemberType = $GroupMember.'@odata.type'.Replace('#microsoft.graph.', '')
                        if ($IncludeObjectDetails) {
                            Write-Host "  [+] ADD  [$MemberType] $($GroupMember.displayName)" -ForegroundColor Green
                        } else {
                            Write-Host "  [+] ADD  [$MemberType] $($PrivObj.ObjectId)" -ForegroundColor Green
                        }

                        $OdataBody = @{
                            '@odata.id' = "https://graph.microsoft.com/beta/directoryObjects/$($PrivObj.ObjectId)"
                        } | ConvertTo-Json

                        Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/beta/groups/$($GroupId)/members/`$ref" -Body $OdataBody -OutputType PSObject -ThrowOnFailure
                        $GrpAdded++
                    } catch {
                        if (Test-EntraOpsGraphNotFoundError -ErrorRecord $_ -DestinationUri "/v1.0/groups/$($GroupId)") {
                            Write-Warning "  [SKIP] Object $($PrivObj.ObjectId) no longer exists (deleted after the last Pull) - not added to $GroupName"
                            $WarningMessages.Add([PSCustomObject]@{ Type = "ObjectNotFound"; Message = "Skipped deleted object $($PrivObj.ObjectId) for $GroupName" })
                            continue
                        }
                        $AddFailureMessage = if ($IncludeObjectDetails) { "FAIL ADD $($PrivObj.ObjectId) to $GroupName`: $_" } else { "Failed to add object $($PrivObj.ObjectId) to $GroupName" }
                        Write-Warning "  [!] $AddFailureMessage"
                        $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = $AddFailureMessage })
                        $GrpFailed++
                    }
                }
            } elseif ($null -ne $PrivilegedObjects.ObjectId) {
                $MemberDiff    = Compare-Object $DesiredIds $CurrentIds
                $MembersToRemove = @($MemberDiff | Where-Object { $_.SideIndicator -eq "=>" })
                $MembersToAdd    = @($MemberDiff | Where-Object { $_.SideIndicator -eq "<=" })

                if ($MemberDiff.Count -eq 0) {
                    Write-Host "  No changes required - group is already in sync" -ForegroundColor DarkGreen
                } else {
                    Write-Host "  Delta: +$($MembersToAdd.Count) to add  -$($MembersToRemove.Count) to remove" -ForegroundColor Yellow
                }

                # Enforce the configured membership-removal threshold.
                $SafetyCheck = Test-EntraOpsRemovalSafetyThreshold -CurrentCount $CurrentIds.Count -RemovalCount $MembersToRemove.Count -RemovalSafetyThreshold $RemovalSafetyThreshold
                $ThresholdPercent = $SafetyCheck.ThresholdPercent
                $RemovalThreshold = $SafetyCheck.RemovalThreshold
                $ExceedsThreshold = $SafetyCheck.Exceeds
                $SkipRemovals = $ExceedsThreshold -and -not $ForceRemovalBeyondSafetyThreshold
                if ($SkipRemovals) {
                    Write-Warning "  [ABORT] $($MembersToRemove.Count) removals exceeds $ThresholdPercent% safety threshold ($RemovalThreshold of $($CurrentIds.Count) members). This may indicate an upstream data issue. Review the delta above, then re-run with -ForceRemovalBeyondSafetyThreshold to apply."
                    $WarningMessages.Add([PSCustomObject]@{ Type = "SafetyAbort"; Message = "Aborted $GroupName`: $($MembersToRemove.Count) removals exceeds $ThresholdPercent% safety threshold ($RemovalThreshold of $($CurrentIds.Count) members) - re-run with -ForceRemovalBeyondSafetyThreshold to apply" })
                    $GrpStatus = "ABORTED"
                } else {
                    if ($ExceedsThreshold) {
                        Write-Warning "  [FORCED] Applying $($MembersToRemove.Count) removals despite exceeding the $ThresholdPercent% safety threshold ($RemovalThreshold of $($CurrentIds.Count) members) - requested via -ForceRemovalBeyondSafetyThreshold."
                        $WarningMessages.Add([PSCustomObject]@{ Type = "SafetyOverride"; Message = "Forced $($MembersToRemove.Count) removals in $GroupName beyond the $ThresholdPercent% safety threshold ($RemovalThreshold of $($CurrentIds.Count) members)" })
                        $GrpStatus = "FORCED"
                    }
                    foreach ($MemberChange in $MembersToRemove) {
                        try {
                            $GroupMember = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/directoryObjects/$($MemberChange.InputObject)" -OutputType PSObject -ThrowOnFailure -SuppressNotFoundWarning
                            $MemberType  = $GroupMember.'@odata.type'.Replace('#microsoft.graph.', '')
                            if ($IncludeObjectDetails) {
                                Write-Host "  [-] REM  [$MemberType] $($GroupMember.displayName)" -ForegroundColor Yellow
                            } else {
                                Write-Host "  [-] REM  [$MemberType] $($MemberChange.InputObject)" -ForegroundColor Yellow
                            }
                            Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "/beta/groups/$($GroupId)/members/$($MemberChange.InputObject)/`$ref" -OutputType PSObject -ThrowOnFailure
                            $GrpRemoved++
                        } catch {
                            if (Test-EntraOpsGraphNotFoundError -ErrorRecord $_ -DestinationUri "/v1.0/groups/$($GroupId)") {
                                Write-Warning "  [SKIP] Object $($MemberChange.InputObject) no longer exists - nothing to remove from $GroupName"
                                $WarningMessages.Add([PSCustomObject]@{ Type = "ObjectNotFound"; Message = "Skipped removal of deleted object $($MemberChange.InputObject) from $GroupName" })
                                continue
                            }
                            $RemoveFailureMessage = if ($IncludeObjectDetails) { "FAIL REMOVE $($MemberChange.InputObject) from $GroupName`: $_" } else { "Failed to remove object $($MemberChange.InputObject) from $GroupName" }
                            Write-Warning "  [!] $RemoveFailureMessage"
                            $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = $RemoveFailureMessage })
                            $GrpFailed++
                        }
                    }
                }
                foreach ($MemberChange in $MembersToAdd) {
                    try {
                        $GroupMember = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/directoryObjects/$($MemberChange.InputObject)" -DisableCache -OutputType PSObject -ThrowOnFailure -SuppressNotFoundWarning
                        $MemberType  = $GroupMember.'@odata.type'.Replace('#microsoft.graph.', '')
                        if ($IncludeObjectDetails) {
                            Write-Host "  [+] ADD  [$MemberType] $($GroupMember.displayName)" -ForegroundColor Green
                        } else {
                            Write-Host "  [+] ADD  [$MemberType] $($MemberChange.InputObject)" -ForegroundColor Green
                        }

                        $OdataBody = @{
                            '@odata.id' = "https://graph.microsoft.com/beta/directoryObjects/$($MemberChange.InputObject)"
                        } | ConvertTo-Json

                        Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/beta/groups/$($GroupId)/members/`$ref" -Body $OdataBody -OutputType PSObject -ThrowOnFailure
                        $GrpAdded++
                    } catch {
                        if (Test-EntraOpsGraphNotFoundError -ErrorRecord $_ -DestinationUri "/v1.0/groups/$($GroupId)") {
                            Write-Warning "  [SKIP] Object $($MemberChange.InputObject) no longer exists (deleted after the last Pull) - not added to $GroupName"
                            $WarningMessages.Add([PSCustomObject]@{ Type = "ObjectNotFound"; Message = "Skipped deleted object $($MemberChange.InputObject) for $GroupName" })
                            continue
                        }
                        $AddFailureMessage = if ($IncludeObjectDetails) { "FAIL ADD $($MemberChange.InputObject) to $GroupName`: $_" } else { "Failed to add object $($MemberChange.InputObject) to $GroupName" }
                        Write-Warning "  [!] $AddFailureMessage"
                        $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = $AddFailureMessage })
                        $GrpFailed++
                    }
                }
            }
            # No privileged objects found for the group
            else {
                Write-Warning "  [SKIP] No classified objects found for $GroupName. Existing members untouched for safety - remove manually if needed."
                $WarningMessages.Add([PSCustomObject]@{ Type = "EmptyScope"; Message = "No classified objects found for $GroupName - existing members untouched" })
                $GrpStatus = "SKIPPED"
            }

            if ($GrpFailed -gt 0) { $GrpStatus = "ERRORS" }
            $TotalAdded   += $GrpAdded
            $TotalRemoved += $GrpRemoved

            $SyncSummary.Add([PSCustomObject]@{
                RbacSystem    = $RbacSystem
                Group         = $GroupName
                MembersBefore = $CurrentMemberCount
                Added         = $GrpAdded
                Removed       = $GrpRemoved
                Failed        = $GrpFailed
                Status        = $GrpStatus
            })
        }
        #endregion
    }

    # Final summary
    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host " Conditional Access Group Sync - Complete" -ForegroundColor Cyan
    Write-Host "  Total added  : $TotalAdded" -ForegroundColor Green
    Write-Host "  Total removed: $TotalRemoved" -ForegroundColor Yellow
    if (($SyncSummary | Where-Object { $_.Failed -gt 0 }).Count -gt 0) {
        Write-Host "  Failures     : $(($SyncSummary | Measure-Object -Property Failed -Sum).Sum)" -ForegroundColor Red
    }
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""
    Show-EntraOpsWarningSummary -WarningMessages $WarningMessages -IncludeObjectDetails $IncludeObjectDetails
    $SyncSummary | Format-Table -AutoSize -Property RbacSystem, Group, MembersBefore,
        @{Name = 'Added';   Expression = { $_.Added };   Align = 'Right'},
        @{Name = 'Removed'; Expression = { $_.Removed }; Align = 'Right'},
        @{Name = 'Failed';  Expression = { $_.Failed };  Align = 'Right'},
        Status

    Assert-EntraOpsConditionalAccessGroupSyncSucceeded -SyncSummary @($SyncSummary)
}