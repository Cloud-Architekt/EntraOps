<#
.SYNOPSIS
    Updates (Restricted Management) Administrative Units based on EntraOps classification.

.DESCRIPTION
    (Restricted Management) Administrative Units for the different Enterprise Access Levels will be updated based on the classification of EntraOps.
    Objects will be assigned to the corresponding Administrative Units based on the classification.

.PARAMETER ApplyToAccessTierLevel
    Array of Access Tier Levels to be processed. Default is ControlPlane, ManagementPlane.

.PARAMETER FilterObjectType
    Array of object types to be processed. Default is User, Group. Service Principal and application objects are not supported to be assigned to AUs.

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement, ResourceApps.

.PARAMETER RemovalSafetyThreshold
    Fraction of current members that may be removed in a single run before removals for that Administrative Unit abort. Default is 0.5 (50%).

.PARAMETER ForceRemovalBeyondSafetyThreshold
    Apply a reviewed removal plan even when it exceeds RemovalSafetyThreshold.

.PARAMETER IncludeObjectDetails
    Include object display names and detailed API errors in console output. Defaults to
    ConsoleOutput.IncludeObjectDetails from EntraOpsConfig.json. Object IDs are always shown.

.EXAMPLE
    Update administrative units for EntraID, IdentityGovernance and ResourceApps RBAC systems with User and Group objectss
    Update-EntraOpsPrivilegedAdministrativeUnit -RbacSystems ("EntraID", "IdentityGovernance") -FilterObjectType ("User", "Group") -RestrictedAUMode "Selected"
#>

function Update-EntraOpsPrivilegedAdministrativeUnit {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False)]
        [ValidateSet("ControlPlane", "ManagementPlane")]
        [Array]$ApplyToAccessTierLevel = ("ControlPlane", "ManagementPlane")
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("User", "Group")]
        [Array]$FilterObjectType = ("User", "Group")
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("Azure", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")]
        [Array]$RbacSystems = ("EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement", "Defender")
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("None", "Selected", "All")]
        [string]$RestrictedAuMode = "Selected" #Default value will not create RMAU for Tier0 and EntraID and Identity Governance RBACs
        ,
        [Parameter(Mandatory = $False)]
        [string]$TenantId = (Get-EntraOpsAzContextValue -Property TenantId)
        ,
        # Maximum fraction of current AU members removable per synchronization.
        [Parameter(Mandatory = $False)]
        [ValidateRange(0, 1)]
        [double]$RemovalSafetyThreshold = 0.5
        ,
        # Permits removals that exceed RemovalSafetyThreshold.
        [Parameter(Mandatory = $False)]
        [switch]$ForceRemovalBeyondSafetyThreshold
        ,
        [Parameter(Mandatory = $False)]
        [boolean]$IncludeObjectDetails = [bool]$Global:EntraOpsIncludeObjectDetails
        ,
        [Parameter(Mandatory = $False)]
        [boolean]$ApplyAdministrativeUnitAssignments = $false
    )

    # Summary tracking across all AUs
    $SyncSummary = [System.Collections.Generic.List[psobject]]::new()
    $TotalAdded = 0
    $TotalRemoved = 0
    $TotalSkipped = 0
    $WarningMessages = New-Object -TypeName "System.Collections.Generic.List[psobject]"

    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host " EntraOps - Administrative Unit Sync" -ForegroundColor Cyan
    Write-Host " RBAC Systems : $($RbacSystems -join ', ')" -ForegroundColor Cyan
    Write-Host " Access Tiers : $($ApplyToAccessTierLevel -join ', ')" -ForegroundColor Cyan
    Write-Host " Object Types : $($FilterObjectType -join ', ')" -ForegroundColor Cyan
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""

    $RbacSystemCounter = 0
    foreach ($RbacSystem in $RbacSystems) {
        $RbacSystemCounter++
        Write-Progress -Activity "Updating Administrative Units" -Status "Processing RBAC system $RbacSystemCounter of $($RbacSystems.Count): $RbacSystem" -PercentComplete (($RbacSystemCounter / $RbacSystems.Count) * 100)
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host " RBAC System: $RbacSystem ($RbacSystemCounter/$($RbacSystems.Count))" -ForegroundColor DarkCyan
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan

        # Get EAM classification files
        if ($RbacSystem -eq "EntraID") {
            $ClassificationTemplateSubFolder = "AadResources"
        } elseif ($RbacSystem -eq "ResourceApps") {
            $ClassificationTemplateSubFolder = "ApiPermissions"
        } else {
            $ClassificationTemplateSubFolder = $RbacSystem
        }
        $Classification = "$DefaultFolderClassifiedEam/$RbacSystem/$($RbacSystem).json"
        $ClassificationTemplates = "$DefaultFolderClassification/Templates/Classification_$($ClassificationTemplateSubFolder).json"

        $PrivilegedEamClassificationFiles = @()
        $PrivilegedEamClassificationFiles = Get-ChildItem -Path $ClassificationTemplates -Filter "*.json"
        $PrivilegedEamClassifications = $PrivilegedEamClassificationFiles | foreach-object { Get-Content -Path $_.FullName | ConvertFrom-Json } | where-object { $_.EAMTierLevelName -in $ApplyToAccessTierLevel } | select-object -unique EAMTierLevelName, EAMTierLevelTagValue

        #region Assign all principals in Privileged EAM to restricted AUs
        $PrivilegedEam = @()
        $PrivilegedEam += Get-ChildItem -Path $Classification | foreach-object { Get-Content $_.FullName -Filter "*.json" | ConvertFrom-Json }
        $PrivilegedEam = $PrivilegedEam | Where-Object { $_.ObjectType -in $FilterObjectType }

        $PrivilegedEamCount = ($PrivilegedEam | Where-Object { $null -eq $_.Classification }).count
        if ($PrivilegedEamCount -gt 0) {
            Write-Warning "Numbers of objects without classification: $PrivilegedEamCount"
            $WarningMessages.Add([PSCustomObject]@{ Type = "UnclassifiedObjects"; Message = "$PrivilegedEamCount object(s) without classification in $RbacSystem" })
        }
        $PrivilegedEamClassifiedObjects = $PrivilegedEam | where-object { $_.Classification.AdminTierLevel -notcontains $null -and $_.RoleSystem -eq $RbacSystem }

        $TierLevelIndex = 0
        foreach ($TierLevel in $PrivilegedEamClassifications) {
            $TierLevelIndex++
            Write-Progress -Activity "Updating Administrative Units" -Status "$RbacSystem - Processing tier $TierLevelIndex of $($PrivilegedEamClassifications.Count): Tier$($TierLevel.EAMTierLevelTagValue)-$($TierLevel.EAMTierLevelName)" -PercentComplete (($TierLevelIndex / $PrivilegedEamClassifications.Count) * 100)

            $AdminUnitId = $null
            $IsRestrictedManagementAu = $false
            $AdminUnitName = "Tier" + $TierLevel.EAMTierLevelTagValue + "-" + $TierLevel.EAMTierLevelName + "." + $RbacSystem
            $AuAdded = 0
            $AuRemoved = 0
            $AuFailed = 0
            $AuSkipped = 0
            $AuStatus = "OK"

            Write-Host ""
            Write-Host "  AU: $AdminUnitName" -ForegroundColor White

            $AdministrativeUnits = @(Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/administrativeUnits?`$filter=DisplayName eq '$(ConvertTo-EntraOpsODataStringLiteral -Value $AdminUnitName)'" -DisableCache)
            # -AllowNotFound: a missing AU is handled by the SKIP branch below so the remaining
            # tiers/RBAC systems still reconcile; duplicates still throw (F-10 safety).
            $AdminUnit = Select-EntraOpsUniqueGraphObject -InputObject $AdministrativeUnits -ObjectDescription "administrative unit '$AdminUnitName'" -AllowNotFound
            $AdminUnitId = $AdminUnit.id
            if ($null -ne $AdminUnit) {
                $IsRestrictedManagementAu = $AdminUnit.isMemberManagementRestricted -eq $true
            }
            if ($null -eq $AdminUnitId) {
                Write-Warning "  [SKIP] Could not find AU: $AdminUnitName"
                $WarningMessages.Add([PSCustomObject]@{ Type = "AuNotFound"; Message = "Could not find AU: $AdminUnitName" })
                $SyncSummary.Add([PSCustomObject]@{
                        RbacSystem    = $RbacSystem
                        AdminUnit     = $AdminUnitName
                        MembersBefore = "N/A"
                        Added         = 0
                        Removed       = 0
                        Failed        = 0
                        Status        = "NOT FOUND"
                    })
                continue
            }

            $EntraOpsPrivilegedObjects = @()
            $EntraOpsPrivilegedObjects = ($PrivilegedEamClassifiedObjects | Where-Object { $_.Classification.AdminTierLevel -contains $TierLevel.EAMTierLevelTagValue -and $_.Classification.AdminTierLevelName -contains $TierLevel.EAMTierLevelName -and $_.RoleSystem -eq $RbacSystem })

            $ForeignTenantObjects = @($EntraOpsPrivilegedObjects | Where-Object { -not [string]::IsNullOrEmpty($_.ObjectTenantId) -and $_.ObjectTenantId -ne $TenantId })
            if ($ForeignTenantObjects.Count -gt 0) {
                Write-Warning "  [SKIP] Excluded $($ForeignTenantObjects.Count) object(s) not owned by tenant $TenantId"
                $WarningMessages.Add([PSCustomObject]@{ Type = "ForeignTenantObject"; Message = "Skipped $($ForeignTenantObjects.Count) object(s) not owned by tenant $TenantId for $AdminUnitName" })
                $AuSkipped += $ForeignTenantObjects.Count
                $TotalSkipped += $ForeignTenantObjects.Count
            }
            $EntraOpsPrivilegedObjects = @($EntraOpsPrivilegedObjects | Where-Object { [string]::IsNullOrEmpty($_.ObjectTenantId) -or $_.ObjectTenantId -eq $TenantId })

            # Exclude role-assignable and PIM-enabled groups from desired set when target AU is restricted management
            if ($IsRestrictedManagementAu) {
                # Identify PIM-enabled groups from EAM role assignment data (eligible/active members indicate PIM for Groups is enabled)
                $PimEnabledGroupIds = @($PrivilegedEam.RoleAssignments | Where-Object { $_.RoleAssignmentSubType -in @("Eligible member", "Active member", "Nested Eligible member") } | Select-Object -ExpandProperty TransitiveByObjectId -Unique)

                $ExcludedGroups = @($EntraOpsPrivilegedObjects | Where-Object {
                        $_.ObjectType -eq 'Group' -and ($_.ObjectSubType -eq 'Role-assignable' -or $_.ObjectId -in $PimEnabledGroupIds)
                    })
                if ($ExcludedGroups.Count -gt 0) {
                    foreach ($ExclGroup in $ExcludedGroups) {
                        $ExclReason = if ($ExclGroup.ObjectSubType -eq 'Role-assignable') { "role-assignable" } else { "PIM-enabled" }
                        $ExcludedGroupMessage = if ($IncludeObjectDetails) { "$ExclReason group excluded from restricted management AU ${AdminUnitName}: $($ExclGroup.ObjectDisplayName) ($($ExclGroup.ObjectId))" } else { "$ExclReason group $($ExclGroup.ObjectId) excluded from restricted management AU $AdminUnitName" }
                        Write-Warning "  [SKIP] $ExcludedGroupMessage"
                        $WarningMessages.Add([PSCustomObject]@{ Type = "GroupExcludedFromRMAU"; Message = $ExcludedGroupMessage })
                        $AuSkipped++
                        $TotalSkipped++
                    }
                    $ExcludedGroupIds = $ExcludedGroups.ObjectId
                    $EntraOpsPrivilegedObjects = @($EntraOpsPrivilegedObjects | Where-Object { $_.ObjectId -notin $ExcludedGroupIds })
                }
            }

            $CurrentAdminUnitMembers = @()
            $CurrentAdminUnitMembers = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/administrativeUnits/$($AdminUnitId)/members" -OutputType PSObject -DisableCache)

            $CurrentMemberCount = @($CurrentAdminUnitMembers.Id).Count
            $DesiredMemberCount = @($EntraOpsPrivilegedObjects.ObjectId).Count
            Write-Host "  Current members : $CurrentMemberCount | Desired: $DesiredMemberCount" -ForegroundColor Gray

            # Check if AU members already exists for sync, or just adding new items
            if ($Null -eq $CurrentAdminUnitMembers.Id) {
                Write-Host "  AU is empty - adding all $DesiredMemberCount objects" -ForegroundColor Yellow
                # Add all members to the AU
                foreach ($PrivObj in $EntraOpsPrivilegedObjects) {
                    try {
                        $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/directoryObjects/$($PrivObj.ObjectId)" -OutputType PSObject -ThrowOnFailure -SuppressNotFoundWarning
                        $AdminUnitMemberObjectType = $AdminUnitMember.'@odata.type'.Replace('#microsoft.graph.', '')
                        if ($IncludeObjectDetails) {
                            Write-Host "  [+] ADD  [$AdminUnitMemberObjectType] $($AdminUnitMember.displayName)" -ForegroundColor Green
                        } else {
                            Write-Host "  [+] ADD  [$AdminUnitMemberObjectType] $($PrivObj.ObjectId)" -ForegroundColor Green
                        }

                        $OdataBody = @{
                            '@odata.id' = "https://graph.microsoft.com/beta/directoryObjects/$($PrivObj.ObjectId)"
                        } | ConvertTo-Json
                        Invoke-EntraOpsMsGraphQuery -Method "POST" -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/`$ref" -DisableCache -Body $OdataBody -OutputType PSObject -ThrowOnFailure
                        $AuAdded++
                    } catch {
                        if (Test-EntraOpsGraphNotFoundError -ErrorRecord $_ -DestinationUri "/beta/administrativeUnits/$($AdminUnitId)") {
                            Write-Warning "  [SKIP] Object $($PrivObj.ObjectId) no longer exists (deleted after the last Pull) - not added to $AdminUnitName"
                            $WarningMessages.Add([PSCustomObject]@{ Type = "ObjectNotFound"; Message = "Skipped deleted object $($PrivObj.ObjectId) for $AdminUnitName" })
                            $AuSkipped++
                            $TotalSkipped++
                            continue
                        }
                        $AddFailureMessage = if ($IncludeObjectDetails) { "FAIL ADD $($PrivObj.ObjectId) to $AdminUnitName`: $_" } else { "Failed to add object $($PrivObj.ObjectId) to $AdminUnitName" }
                        Write-Warning "  [!] $AddFailureMessage"
                        $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = $AddFailureMessage })
                        $AuFailed++
                    }
                }
            }
            # Check if privileged objects exists which should be synced to existing AU
            elseif ($null -ne $EntraOpsPrivilegedObjects.ObjectId) {
                # Add or remove members from the AU which are not in scope of classification
                $Diff = Compare-Object $($EntraOpsPrivilegedObjects.ObjectId) $($CurrentAdminUnitMembers.Id)
                $ToRemove = @($Diff | Where-Object { $_.SideIndicator -eq "=>" })
                $ToAdd = @($Diff | Where-Object { $_.SideIndicator -eq "<=" })

                if ($Diff.Count -eq 0) {
                    Write-Host "  No changes required - AU is already in sync" -ForegroundColor DarkGreen
                } else {
                    Write-Host "  Delta: +$($ToAdd.Count) to add  -$($ToRemove.Count) to remove" -ForegroundColor Yellow
                }

                # Enforce the configured membership-removal threshold.
                $SafetyCheck = Test-EntraOpsRemovalSafetyThreshold -CurrentCount @($CurrentAdminUnitMembers.Id).Count -RemovalCount $ToRemove.Count -RemovalSafetyThreshold $RemovalSafetyThreshold
                $SkipRemovals = $SafetyCheck.Exceeds -and -not $ForceRemovalBeyondSafetyThreshold
                if ($SkipRemovals) {
                    Write-Warning "  [ABORT] $($ToRemove.Count) removals exceeds $($SafetyCheck.ThresholdPercent)% safety threshold ($($SafetyCheck.RemovalThreshold) of $(@($CurrentAdminUnitMembers.Id).Count) members). This may indicate an upstream data issue. Review the delta above, then re-run with -ForceRemovalBeyondSafetyThreshold to apply."
                    $WarningMessages.Add([PSCustomObject]@{ Type = "SafetyAbort"; Message = "Aborted $AdminUnitName`: $($ToRemove.Count) removals exceeds $($SafetyCheck.ThresholdPercent)% safety threshold ($($SafetyCheck.RemovalThreshold) of $(@($CurrentAdminUnitMembers.Id).Count) members) - re-run with -ForceRemovalBeyondSafetyThreshold to apply" })
                    $AuStatus = "ABORTED"
                } elseif ($SafetyCheck.Exceeds) {
                    Write-Warning "  [FORCED] Applying $($ToRemove.Count) removals despite exceeding the $($SafetyCheck.ThresholdPercent)% safety threshold - requested via -ForceRemovalBeyondSafetyThreshold."
                    $WarningMessages.Add([PSCustomObject]@{ Type = "SafetyOverride"; Message = "Forced $($ToRemove.Count) removals in $AdminUnitName beyond the $($SafetyCheck.ThresholdPercent)% safety threshold" })
                    $AuStatus = "FORCED"
                }

                if (-not $SkipRemovals) {
                    foreach ($Entry in $ToRemove) {
                        try {
                            $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/directoryObjects/$($Entry.InputObject)" -OutputType PSObject -ThrowOnFailure -SuppressNotFoundWarning
                            $MemberType = $AdminUnitMember.'@odata.type'.Replace('#microsoft.graph.', '')
                            if ($IncludeObjectDetails) {
                                Write-Host "  [-] REM  [$MemberType] $($AdminUnitMember.displayName)" -ForegroundColor Yellow
                            } else {
                                Write-Host "  [-] REM  [$MemberType] $($Entry.InputObject)" -ForegroundColor Yellow
                            }
                            Invoke-EntraOpsMsGraphQuery -Method "DELETE" -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/$($Entry.InputObject)/`$ref" -OutputType PSObject -ThrowOnFailure
                            $AuRemoved++
                        } catch {
                            if (Test-EntraOpsGraphNotFoundError -ErrorRecord $_ -DestinationUri "/beta/administrativeUnits/$($AdminUnitId)") {
                                Write-Warning "  [SKIP] Object $($Entry.InputObject) no longer exists - nothing to remove from $AdminUnitName"
                                $WarningMessages.Add([PSCustomObject]@{ Type = "ObjectNotFound"; Message = "Skipped removal of deleted object $($Entry.InputObject) from $AdminUnitName" })
                                $AuSkipped++
                                $TotalSkipped++
                                continue
                            }
                            $RemoveFailureMessage = if ($IncludeObjectDetails) { "FAIL REMOVE $($Entry.InputObject) from $AdminUnitName`: $_" } else { "Failed to remove object $($Entry.InputObject) from $AdminUnitName" }
                            Write-Warning "  [!] $RemoveFailureMessage"
                            $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = $RemoveFailureMessage })
                            $AuFailed++
                        }
                    }
                }

                foreach ($Entry in $ToAdd) {
                    try {
                        $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/directoryObjects/$($Entry.InputObject)" -DisableCache -OutputType PSObject -ThrowOnFailure -SuppressNotFoundWarning
                        $MemberType = $AdminUnitMember.'@odata.type'.Replace('#microsoft.graph.', '')
                        if ($IncludeObjectDetails) {
                            Write-Host "  [+] ADD  [$MemberType] $($AdminUnitMember.displayName)" -ForegroundColor Green
                        } else {
                            Write-Host "  [+] ADD  [$MemberType] $($Entry.InputObject)" -ForegroundColor Green
                        }

                        $OdataBody = @{
                            '@odata.id' = "https://graph.microsoft.com/beta/directoryObjects/$($Entry.InputObject)"
                        } | ConvertTo-Json

                        Invoke-EntraOpsMsGraphQuery -Method "POST" -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/`$ref" -DisableCache -Body $OdataBody -OutputType PSObject -ThrowOnFailure
                        $AuAdded++
                    } catch {
                        if (Test-EntraOpsGraphNotFoundError -ErrorRecord $_ -DestinationUri "/beta/administrativeUnits/$($AdminUnitId)") {
                            Write-Warning "  [SKIP] Object $($Entry.InputObject) no longer exists (deleted after the last Pull) - not added to $AdminUnitName"
                            $WarningMessages.Add([PSCustomObject]@{ Type = "ObjectNotFound"; Message = "Skipped deleted object $($Entry.InputObject) for $AdminUnitName" })
                            $AuSkipped++
                            $TotalSkipped++
                            continue
                        }
                        $AddFailureMessage = if ($IncludeObjectDetails) { "FAIL ADD $($Entry.InputObject) to $AdminUnitName`: $_" } else { "Failed to add object $($Entry.InputObject) to $AdminUnitName" }
                        Write-Warning "  [!] $AddFailureMessage"
                        $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = $AddFailureMessage })
                        $AuFailed++
                    }
                }
            }
            # No privileged objects found for the AU, cleanup existing assignments
            else {
                Write-Warning "  [SKIP] No classified objects found for $AdminUnitName. Existing members untouched for safety - remove manually if needed."
                $WarningMessages.Add([PSCustomObject]@{ Type = "EmptyScope"; Message = "No classified objects found for $AdminUnitName - existing members untouched" })
                $AuStatus = "SKIPPED"
            }

            if ($AuFailed -gt 0) { $AuStatus = "ERRORS" }
            $TotalAdded += $AuAdded
            $TotalRemoved += $AuRemoved

            $SyncSummary.Add([PSCustomObject]@{
                    RbacSystem    = $RbacSystem
                    AdminUnit     = $AdminUnitName
                    MembersBefore = $CurrentMemberCount
                    Added         = $AuAdded
                    Removed       = $AuRemoved
                    Failed        = $AuFailed
                    Skipped       = $AuSkipped
                    Status        = $AuStatus
                })
        }
        #endregion
    }

    # Final summary
    Write-Host ""
    Write-Host "========================================================="  -ForegroundColor Cyan
    Write-Host " Administrative Unit Sync - Complete" -ForegroundColor Cyan
    Write-Host "  Total added  : $TotalAdded" -ForegroundColor Green
    Write-Host "  Total removed: $TotalRemoved" -ForegroundColor Yellow
    if ($TotalSkipped -gt 0) {
        Write-Host "  Total skipped: $TotalSkipped" -ForegroundColor DarkYellow
    }
    if (($SyncSummary | Where-Object { $_.Failed -gt 0 }).Count -gt 0) {
        Write-Host "  Failures     : $(($SyncSummary | Measure-Object -Property Failed -Sum).Sum)" -ForegroundColor Red
    }
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""
    Show-EntraOpsWarningSummary -WarningMessages $WarningMessages -IncludeObjectDetails $IncludeObjectDetails
    $SyncSummary | Format-Table -AutoSize -Property RbacSystem, AdminUnit, MembersBefore,
    @{Name = 'Added'; Expression = { $_.Added }; Align = 'Right' },
    @{Name = 'Removed'; Expression = { $_.Removed }; Align = 'Right' },
    @{Name = 'Failed'; Expression = { $_.Failed }; Align = 'Right' },
    @{Name = 'Skipped'; Expression = { $_.Skipped }; Align = 'Right' },
    Status

    $FailureCount = ($SyncSummary | Measure-Object -Property Failed -Sum).Sum
    $AbortedCount = @($SyncSummary | Where-Object { $_.Status -eq 'ABORTED' }).Count
    if ($FailureCount -gt 0 -or $AbortedCount -gt 0) {
        $Reasons = [System.Collections.Generic.List[string]]::new()
        if ($FailureCount -gt 0) { $Reasons.Add("$FailureCount membership operation(s) failed") | Out-Null }
        if ($AbortedCount -gt 0) { $Reasons.Add("$AbortedCount AU synchronization(s) aborted by the removal safety threshold") | Out-Null }
        throw "Administrative Unit sync did not complete: $($Reasons -join '; '). Review the warning summary above."
    }
}