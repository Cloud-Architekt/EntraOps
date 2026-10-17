<#
.SYNOPSIS
    Add privileged users without any protection (by role-assignable groups, assigned directory role or existing RMAU membership) to an Restricted Management Administrative Units to avoid delegated management by lower privileged user.

.DESCRIPTION
    Add privileged users without any protection (by role-assignable groups, assigned directory role or existing RMAU membership) to an Restricted Management Administrative Units to avoid delegated management by lower privileged user.

.PARAMETER ApplyToAccessTierLevel
    Array of Access Tier Levels to be processed. Default is ControlPlane, ManagementPlane.

.PARAMETER FilterObjectType
    Array of object types to be processed. Default is User, Group. Service Principal and application objects are not supported to be protected by RMAU.

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement, ResourceApps.

.PARAMETER IncludeUnprotectedDevices
    Also sync devices owned by/associated to privileged users (OwnedDevices, AssociatedPawDevice) into the same tier's RMAU, unless already protected by another RMAU.

.PARAMETER RemovalSafetyThreshold
    Fraction of current members that may be removed in a single run. Principal and device removals are planned together; an oversized plan applies no removals to that RMAU. Default is 0.5 (50%).

.PARAMETER ForceRemovalBeyondSafetyThreshold
    Apply a reviewed removal plan even when it exceeds RemovalSafetyThreshold.

.PARAMETER IncludeObjectDetails
    Include object display names and detailed API errors in console output. Defaults to
    ConsoleOutput.IncludeObjectDetails from EntraOpsConfig.json. Object IDs are always shown.

.EXAMPLE
    Assign privileged users without any protection but privileges in RBAC Systems "IdentityGovernance" to Restricted Management Administrative Units
    Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit -RbacSystems ("IdentityGovernance")
#>

function Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit {

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
        [ValidateSet("Azure", "EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement", "Defender")]
        [Array]$RbacSystems = ("Azure", "EntraID", "IdentityGovernance", "DeviceManagement", "Defender")
        ,
        # Maximum fraction of current RMAU members removable per synchronization.
        [Parameter(Mandatory = $False)]
        [ValidateRange(0, 1)]
        [double]$RemovalSafetyThreshold = 0.5
        ,
        # Permits removals that exceed RemovalSafetyThreshold.
        [Parameter(Mandatory = $False)]
        [switch]$ForceRemovalBeyondSafetyThreshold
        ,
        [Parameter(Mandatory = $False)]
        [switch]$IncludeUnprotectedDevices
        ,
        [Parameter(Mandatory = $False)]
        [boolean]$IncludeObjectDetails = [bool]$Global:EntraOpsIncludeObjectDetails
        ,
        [Parameter(Mandatory = $False)]
        [boolean]$ApplyRmauAssignmentsForUnprotectedObjects = $false
    )

    # Get all privileged EAM objects
    $PrivilegedEamObjects = foreach ($RbacSystem in $RbacSystems) {
        Get-Content "$DefaultFolderClassifiedEam/$RbacSystem/$($RbacSystem).json" | ConvertFrom-Json
    }

    # Get all privileged EAM objects without any restricted management and their tier levels
    $UnprotectedPrivilegedUser = $PrivilegedEamObjects | Where-Object {
        $_.RestrictedManagementByRAG -ne $True -and `
            $_.RestrictedManagementByAadRole -ne $True -and `
            $_.RestrictedManagementByRMAU -ne $True -and `
            $_.ObjectType -in $FilterObjectType }

    # Get all unique AdminTierLevels which needs to be iterated for assigning objects to Conditional Access Target Groups
    $PrivilegedEamTierLevels = Get-ChildItem -Path "$($DefaultFolderClassification)/Templates" -File -Recurse -Exclude *.Param.json | foreach-object { Get-Content $_.FullName -Filter "*.json" | ConvertFrom-Json }
    $SelectedPrivilegedEamTierLevels = $PrivilegedEamTierLevels | where-object { $_.EAMTierLevelName -in $ApplyToAccessTierLevel } | select-object -unique @{Name = 'AdminTierLevel'; Expression = 'EAMTierLevelTagValue' }, @{Name = 'AdminTierLevelName'; Expression = 'EAMTierLevelName' }
    # Always process the most privileged tier first, independent of how $ApplyToAccessTierLevel is ordered
    # in the config, so a device claimed by Tier 0 reaches its AU before a lower tier evaluates it.
    $SelectedPrivilegedEamTierLevels = @($SelectedPrivilegedEamTierLevels | Sort-Object { [int]$_.AdminTierLevel })
    #endregion

    # Summary tracking
    $SyncSummary = [System.Collections.Generic.List[psobject]]::new()
    $TotalAdded = 0
    $TotalRemoved = 0
    $TotalKept = 0
    $WarningMessages = New-Object -TypeName "System.Collections.Generic.List[psobject]"
    $TenantId = (Get-AzContext).Tenant.Id

    # Devices carry no EAM classification of their own - they inherit their tier from the privileged users
    # that own or use them. A user classified at more than one tier would otherwise make the same device
    # "desired" in every tier's AU, leaving the winner dependent on tier iteration order. Resolve each
    # device to its most privileged (lowest) tier once, up front, so the outcome is deterministic.
    $DeviceTierAssignment = @{}
    # AU names this run manages, so a sibling tier's AU is not mistaken for unrelated RMAU protection.
    $ManagedAdminUnitNames = @($SelectedPrivilegedEamTierLevels | ForEach-Object { "Tier" + $_.AdminTierLevel + "-" + $_.AdminTierLevelName + ".UnprotectedObjects" })
    if ($IncludeUnprotectedDevices) {
        foreach ($Tier in $SelectedPrivilegedEamTierLevels) {
            $TierDeviceOwners = $PrivilegedEamObjects | Where-Object {
                $_.ObjectType -eq "user" -and `
                    $_.Classification.AdminTierLevel -contains $Tier.AdminTierLevel -and `
                    $_.Classification.AdminTierLevelName -contains $Tier.AdminTierLevelName -and `
                    ([string]::IsNullOrEmpty($_.ObjectTenantId) -or $_.ObjectTenantId -eq $TenantId)
            }
            foreach ($OwnedDeviceId in @($TierDeviceOwners | ForEach-Object { @($_.OwnedDevices) + @($_.AssociatedPawDevice) } | Where-Object { $_ })) {
                if (-not $DeviceTierAssignment.ContainsKey($OwnedDeviceId) -or [int]$Tier.AdminTierLevel -lt [int]$DeviceTierAssignment[$OwnedDeviceId]) {
                    $DeviceTierAssignment[$OwnedDeviceId] = $Tier.AdminTierLevel
                }
            }
        }
    }

    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host " EntraOps - Unprotected Objects RMAU Sync" -ForegroundColor Cyan
    Write-Host " RBAC Systems : $($RbacSystems -join ', ')" -ForegroundColor Cyan
    Write-Host " Access Tiers : $($ApplyToAccessTierLevel -join ', ')" -ForegroundColor Cyan
    Write-Host " Object Types : $($FilterObjectType -join ', ')" -ForegroundColor Cyan
    Write-Host " Unprotected  : $(@($UnprotectedPrivilegedUser).Count) objects identified across all tiers" -ForegroundColor Cyan
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""

    #region Assign all unprotected principals in Privileged EAM to restricted AUs or remove from RMAU if no longer privileged
    foreach ($TierLevel in $SelectedPrivilegedEamTierLevels) {

        $AdminUnitId = $null
        $AdminUnitName = "Tier" + $TierLevel.AdminTierLevel + "-" + $TierLevel.AdminTierLevelName + ".UnprotectedObjects"
        $AuAdded = 0
        $AuRemoved = 0
        $AuKept = 0
        $AuFailed = 0
        $AuStatus = "OK"

        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host " AU: $AdminUnitName" -ForegroundColor DarkCyan
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan

        $AdministrativeUnits = @(Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/administrativeUnits?`$filter=DisplayName eq '$(ConvertTo-EntraOpsODataStringLiteral -Value $AdminUnitName)'" -DisableCache -OutputType PSObject)
        # -AllowNotFound: a missing AU is handled by the SKIP branch below so the remaining
        # tiers still reconcile; duplicates still throw (F-10 safety).
        $AdminUnitId = (Select-EntraOpsUniqueGraphObject -InputObject $AdministrativeUnits -ObjectDescription "administrative unit '$AdminUnitName'" -AllowNotFound).id
        if ($null -eq $AdminUnitId) {
            Write-Warning "  [SKIP] Could not find AU: $AdminUnitName"
            $WarningMessages.Add([PSCustomObject]@{ Type = "AuNotFound"; Message = "Could not find AU: $AdminUnitName" })
            $SyncSummary.Add([PSCustomObject]@{
                    AdminUnit     = $AdminUnitName
                    MembersBefore = "N/A"
                    Added         = 0
                    Removed       = 0
                    Kept          = 0
                    Failed        = 0
                    Status        = "NOT FOUND"
                })
            continue
        }

        # Get privileged objects for this tier level
        $UnprotectedPrivilegedUserOnTierLevel = @($UnprotectedPrivilegedUser | Where-Object { $_.Classification.AdminTierLevel -contains $TierLevel.AdminTierLevel -and $_.Classification.AdminTierLevelName -contains $TierLevel.AdminTierLevelName })
        $CurrentAdminUnitMembers = @()
        $CurrentAdminUnitMembers = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/administrativeUnits/$($AdminUnitId)/members" -OutputType PSObject -DisableCache)

        $CurrentMemberCount = @($CurrentAdminUnitMembers.Id).Count
        $DesiredMemberCount = $UnprotectedPrivilegedUserOnTierLevel.Count
        Write-Host "  Current members : $CurrentMemberCount | Unprotected objects for tier: $DesiredMemberCount" -ForegroundColor Gray

        $DesiredPrincipalIds = @($UnprotectedPrivilegedUserOnTierLevel.ObjectId | Where-Object { $_ } | Select-Object -Unique)
        $CurrentPrincipalMembers = @($CurrentAdminUnitMembers | Where-Object { $_.'@odata.type' -in @('#microsoft.graph.user', '#microsoft.graph.group') })
        $CurrentPrincipalIds = @($CurrentPrincipalMembers.Id | Select-Object -Unique)
        $PrincipalIdsToAdd = @($DesiredPrincipalIds | Where-Object { $_ -notin $CurrentPrincipalIds })
        $PrincipalRemovalPlan = [System.Collections.Generic.List[psobject]]::new()

        foreach ($CurrentMember in @($CurrentPrincipalMembers | Where-Object { $_.id -notin $DesiredPrincipalIds })) {
            $EamEntry = $PrivilegedEamObjects | Where-Object { $_.ObjectId -eq $CurrentMember.id } | Select-Object -First 1
            $RemoveReason = $null

            if ($null -eq $EamEntry) {
                $RemoveReason = "no longer privileged"
            } elseif ($EamEntry.RestrictedManagementByAadRole -eq $True -or $EamEntry.RestrictedManagementByRAG -eq $True) {
                $RemoveReason = "protected by AadRole or RAG"
            } else {
                $MemberType = $CurrentMember.'@odata.type'.Replace('#microsoft.graph.', '')
                $MemberAUs = Invoke-EntraOpsMsGraphQuery -Uri "/beta/$($MemberType)s/$($CurrentMember.id)/memberOf/Microsoft.Graph.AdministrativeUnit" -OutputType PSObject -DisableCache
                $OtherRMAUs = $MemberAUs | Where-Object { $_.isMemberManagementRestricted -eq $True -and $_.id -ne $AdminUnitId }
                if ($null -ne $OtherRMAUs) {
                    $RemoveReason = "protected by another RMAU"
                }
            }

            if ($null -ne $RemoveReason) {
                $PrincipalRemovalPlan.Add([PSCustomObject]@{
                        Id     = $CurrentMember.id
                        Type   = $CurrentMember.'@odata.type'.Replace('#microsoft.graph.', '')
                        Name   = $CurrentMember.displayName
                        Reason = $RemoveReason
                    })
            } else {
                if ($IncludeObjectDetails) {
                    Write-Host "  [~] KEEP [$($CurrentMember.'@odata.type'.Replace('#microsoft.graph.', ''))] $($CurrentMember.displayName) (this AU is the only RMAU)" -ForegroundColor DarkYellow
                } else {
                    Write-Host "  [~] KEEP [$($CurrentMember.'@odata.type'.Replace('#microsoft.graph.', ''))] $($CurrentMember.id) (this AU is the only RMAU)" -ForegroundColor DarkYellow
                }
                $AuKept++
            }
        }

        foreach ($UnsupportedMember in @($CurrentAdminUnitMembers | Where-Object { $_.'@odata.type' -notin @('#microsoft.graph.user', '#microsoft.graph.group', '#microsoft.graph.device') })) {
            Write-Warning "  [!] Unsupported object type $($UnsupportedMember.'@odata.type') - skipping"
            $WarningMessages.Add([PSCustomObject]@{ Type = "UnsupportedObjectType"; Message = "Unsupported object type $($UnsupportedMember.'@odata.type') in $AdminUnitName - skipped" })
            $AuKept++
        }

        $DesiredDeviceIds = @()
        $CurrentDeviceMemberIds = @()
        $DeviceIdsToAdd = [System.Collections.Generic.List[string]]::new()
        $DeviceRemovalPlan = [System.Collections.Generic.List[psobject]]::new()
        if ($IncludeUnprotectedDevices) {
            $PrivilegedUsersAtTier = $PrivilegedEamObjects | Where-Object {
                $_.ObjectType -eq "user" -and `
                    $_.Classification.AdminTierLevel -contains $TierLevel.AdminTierLevel -and `
                    $_.Classification.AdminTierLevelName -contains $TierLevel.AdminTierLevelName
            }
            $ForeignTenantDeviceOwners = @($PrivilegedUsersAtTier | Where-Object {
                    -not [string]::IsNullOrEmpty($_.ObjectTenantId) -and $_.ObjectTenantId -ne $TenantId
                })
            if ($ForeignTenantDeviceOwners.Count -gt 0) {
                Write-Warning "  [SKIP] Excluded devices for $($ForeignTenantDeviceOwners.Count) user(s) not owned by tenant $TenantId"
                $WarningMessages.Add([PSCustomObject]@{ Type = "ForeignTenantDeviceOwner"; Message = "Skipped devices for $($ForeignTenantDeviceOwners.Count) user(s) not owned by tenant $TenantId for $AdminUnitName" })
            }
            $PrivilegedUsersAtTier = @($PrivilegedUsersAtTier | Where-Object {
                    [string]::IsNullOrEmpty($_.ObjectTenantId) -or $_.ObjectTenantId -eq $TenantId
                })
            # Restricted to devices pinned to this tier by $DeviceTierAssignment - a device owned by a user
            # classified at several tiers belongs to the most privileged one only.
            $DesiredDeviceIds = @($PrivilegedUsersAtTier | ForEach-Object { @($_.OwnedDevices) + @($_.AssociatedPawDevice) } | Where-Object { $_ } | Select-Object -Unique | Where-Object { $DeviceTierAssignment[$_] -eq $TierLevel.AdminTierLevel })
            $DeviceMembersUri = "/v1.0/directory/administrativeUnits/$AdminUnitId/members"
            $CurrentDeviceMemberIds = @((Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "$DeviceMembersUri/microsoft.graph.device" -OutputType PSObject -DisableCache) | Where-Object { $null -ne $_.id } | Select-Object -ExpandProperty id)

            if ($DesiredDeviceIds.Count -gt 0) {
                Write-Host "  Checking $($DesiredDeviceIds.Count) device(s) owned by/associated to Tier $($TierLevel.AdminTierLevelName) users..." -ForegroundColor Gray
            }

            foreach ($DeviceId in $DesiredDeviceIds) {
                $Device = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/v1.0/devices/$DeviceId" -OutputType PSObject -DisableCache -SuppressNotFoundWarning
                if ($null -eq $Device -or [string]::IsNullOrEmpty($Device.id)) {
                    $DeviceNotFoundMessage = if ($IncludeObjectDetails) { "Device $DeviceId was not found in tenant $TenantId" } else { "Device $DeviceId was not found in the target tenant" }
                    Write-Warning "  [SKIP] $DeviceNotFoundMessage"
                    $WarningMessages.Add([PSCustomObject]@{ Type = "DeviceNotFound"; Message = "$DeviceNotFoundMessage for $AdminUnitName" })
                    continue
                }
                $DeviceAUs = @(Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/devices/$DeviceId/memberOf/microsoft.graph.administrativeUnit" -OutputType PSObject -DisableCache -SuppressNotFoundWarning | Where-Object { $null -ne $_.id })
                # Treat memberships in sibling EntraOps tier AUs as managed rather than external protection.
                $HasOtherRMAU = ($DeviceAUs | Where-Object { $_.isMemberManagementRestricted -eq $True -and $_.id -ne $AdminUnitId -and $_.displayName -notin $ManagedAdminUnitNames }).Count -gt 0

                if ($HasOtherRMAU) {
                    if ($DeviceId -in $CurrentDeviceMemberIds) {
                        $DeviceRemovalPlan.Add([PSCustomObject]@{ Id = $DeviceId; Reason = "protected by another RMAU" })
                    }
                    continue
                }

                if ($DeviceId -notin $CurrentDeviceMemberIds) {
                    $DeviceIdsToAdd.Add($DeviceId)
                } else {
                    $AuKept++
                }
            }

            foreach ($StaleDeviceId in @($CurrentDeviceMemberIds | Where-Object { $_ -notin $DesiredDeviceIds })) {
                $DeviceRemovalPlan.Add([PSCustomObject]@{ Id = $StaleDeviceId; Reason = "no longer associated to a privileged Tier $($TierLevel.AdminTierLevelName) user" })
            }
        }

        $PlannedRemovalCount = $PrincipalRemovalPlan.Count + $DeviceRemovalPlan.Count
        $SafetyCheck = Test-EntraOpsRemovalSafetyThreshold -CurrentCount $CurrentMemberCount -RemovalCount $PlannedRemovalCount -RemovalSafetyThreshold $RemovalSafetyThreshold
        $SkipRemovals = $SafetyCheck.Exceeds -and -not $ForceRemovalBeyondSafetyThreshold

        Write-Host "  Delta: +$($PrincipalIdsToAdd.Count + $DeviceIdsToAdd.Count) to add  -$PlannedRemovalCount to remove" -ForegroundColor Yellow
        if ($SkipRemovals) {
            Write-Warning "  [ABORT] $PlannedRemovalCount removals exceeds $($SafetyCheck.ThresholdPercent)% safety threshold ($($SafetyCheck.RemovalThreshold) of $CurrentMemberCount members). No removals were applied; additions still proceed. Review the plan, then re-run with -ForceRemovalBeyondSafetyThreshold to apply."
            $WarningMessages.Add([PSCustomObject]@{ Type = "SafetyAbort"; Message = "Aborted removals in $AdminUnitName`: $PlannedRemovalCount exceeds the $($SafetyCheck.ThresholdPercent)% safety threshold ($($SafetyCheck.RemovalThreshold) of $CurrentMemberCount members) - re-run with -ForceRemovalBeyondSafetyThreshold to apply" })
            $AuStatus = "ABORTED"
            $AuKept += $PlannedRemovalCount
        } elseif ($SafetyCheck.Exceeds) {
            Write-Warning "  [FORCED] Applying $PlannedRemovalCount removals despite exceeding the $($SafetyCheck.ThresholdPercent)% safety threshold - requested via -ForceRemovalBeyondSafetyThreshold."
            $WarningMessages.Add([PSCustomObject]@{ Type = "SafetyOverride"; Message = "Forced $PlannedRemovalCount removals in $AdminUnitName beyond the $($SafetyCheck.ThresholdPercent)% safety threshold" })
            $AuStatus = "FORCED"
        }

        if (-not $SkipRemovals) {
            foreach ($Removal in $PrincipalRemovalPlan) {
                try {
                    $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/directoryObjects/$($Removal.Id)" -OutputType PSObject -DisableCache -ThrowOnFailure -SuppressNotFoundWarning
                    if ($IncludeObjectDetails) {
                        Write-Host "  [-] REM  [$($Removal.Type)] $($AdminUnitMember.displayName) ($($Removal.Reason))" -ForegroundColor Yellow
                    } else {
                        Write-Host "  [-] REM  [$($Removal.Type)] $($Removal.Id)" -ForegroundColor Yellow
                    }
                    Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/$($Removal.Id)/`$ref" -OutputType PSObject -DisableCache -ThrowOnFailure
                    $AuRemoved++
                } catch {
                    if (Test-EntraOpsGraphNotFoundError -ErrorRecord $_ -DestinationUri "/beta/administrativeUnits/$($AdminUnitId)") {
                        Write-Warning "  [SKIP] Object $($Removal.Id) no longer exists - nothing to remove from $AdminUnitName"
                        $WarningMessages.Add([PSCustomObject]@{ Type = "ObjectNotFound"; Message = "Skipped removal of deleted object $($Removal.Id) from $AdminUnitName" })
                        continue
                    }
                    $RemoveFailureMessage = if ($IncludeObjectDetails) { "FAIL REMOVE $($Removal.Id) from $AdminUnitName`: $_" } else { "Failed to remove $($Removal.Type) object $($Removal.Id) from $AdminUnitName" }
                    Write-Warning "  [!] $RemoveFailureMessage"
                    $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = $RemoveFailureMessage })
                    $AuFailed++
                }
            }

            foreach ($Removal in $DeviceRemovalPlan) {
                try {
                    Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "$DeviceMembersUri/$($Removal.Id)/`$ref" -OutputType PSObject -ThrowOnFailure
                    if ($IncludeObjectDetails) {
                        Write-Host "  [-] REM  [device] $($Removal.Id) ($($Removal.Reason))" -ForegroundColor Yellow
                    } else {
                        Write-Host "  [-] REM  [device] $($Removal.Id)" -ForegroundColor Yellow
                    }
                    $AuRemoved++
                } catch {
                    if (Test-EntraOpsGraphNotFoundError -ErrorRecord $_ -DestinationUri "/beta/administrativeUnits/$($AdminUnitId)") {
                        Write-Warning "  [SKIP] Device $($Removal.Id) no longer exists - nothing to remove from $AdminUnitName"
                        $WarningMessages.Add([PSCustomObject]@{ Type = "ObjectNotFound"; Message = "Skipped removal of deleted device $($Removal.Id) from $AdminUnitName" })
                        continue
                    }
                    $RemoveFailureMessage = if ($IncludeObjectDetails) { "FAIL REMOVE device $($Removal.Id) from $AdminUnitName`: $_" } else { "Failed to remove device $($Removal.Id) from $AdminUnitName" }
                    Write-Warning "  [!] $RemoveFailureMessage"
                    $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = $RemoveFailureMessage })
                    $AuFailed++
                }
            }
        }

        foreach ($PrincipalId in $PrincipalIdsToAdd) {
            try {
                $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/directoryObjects/$PrincipalId" -OutputType PSObject -DisableCache -ThrowOnFailure -SuppressNotFoundWarning
                $MemberType = $AdminUnitMember.'@odata.type'.Replace('#microsoft.graph.', '')
                if ($IncludeObjectDetails) {
                    Write-Host "  [+] ADD  [$MemberType] $($AdminUnitMember.displayName)" -ForegroundColor Green
                } else {
                    Write-Host "  [+] ADD  [$MemberType] $PrincipalId" -ForegroundColor Green
                }
                $OdataBody = @{ '@odata.id' = "https://graph.microsoft.com/beta/directoryObjects/$PrincipalId" } | ConvertTo-Json
                Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/`$ref" -Body $OdataBody -OutputType PSObject -ThrowOnFailure
                $AuAdded++
            } catch {
                if (Test-EntraOpsGraphNotFoundError -ErrorRecord $_ -DestinationUri "/beta/administrativeUnits/$($AdminUnitId)") {
                    Write-Warning "  [SKIP] Object $PrincipalId no longer exists (deleted after the last Pull) - not added to $AdminUnitName"
                    $WarningMessages.Add([PSCustomObject]@{ Type = "ObjectNotFound"; Message = "Skipped deleted object $PrincipalId for $AdminUnitName" })
                    continue
                }
                $AddFailureMessage = if ($IncludeObjectDetails) { "FAIL ADD $PrincipalId to $AdminUnitName`: $_" } else { "Failed to add principal object $PrincipalId to $AdminUnitName" }
                Write-Warning "  [!] $AddFailureMessage"
                $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = $AddFailureMessage })
                $AuFailed++
            }
        }

        foreach ($DeviceId in $DeviceIdsToAdd) {
            try {
                $OdataBody = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$DeviceId" } | ConvertTo-Json
                Invoke-EntraOpsMsGraphQuery -Method POST -Uri "$DeviceMembersUri/`$ref" -Body $OdataBody -OutputType PSObject -ThrowOnFailure
                if ($IncludeObjectDetails) {
                    Write-Host "  [+] ADD  [device] $DeviceId" -ForegroundColor Green
                } else {
                    Write-Host "  [+] ADD  [device] $DeviceId" -ForegroundColor Green
                }
                $AuAdded++
            } catch {
                if (Test-EntraOpsGraphNotFoundError -ErrorRecord $_ -DestinationUri "/beta/administrativeUnits/$($AdminUnitId)") {
                    Write-Warning "  [SKIP] Device $DeviceId no longer exists (deleted after the last Pull) - not added to $AdminUnitName"
                    $WarningMessages.Add([PSCustomObject]@{ Type = "ObjectNotFound"; Message = "Skipped deleted device $DeviceId for $AdminUnitName" })
                    continue
                }
                $AddFailureMessage = if ($IncludeObjectDetails) { "FAIL ADD device $DeviceId to $AdminUnitName`: $_" } else { "Failed to add device $DeviceId to $AdminUnitName" }
                Write-Warning "  [!] $AddFailureMessage"
                $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = $AddFailureMessage })
                $AuFailed++
            }
        }

        if ($AuFailed -gt 0) { $AuStatus = "ERRORS" }
        $TotalAdded += $AuAdded
        $TotalRemoved += $AuRemoved
        $TotalKept += $AuKept

        $SyncSummary.Add([PSCustomObject]@{
                AdminUnit     = $AdminUnitName
                MembersBefore = $CurrentMemberCount
                Added         = $AuAdded
                Removed       = $AuRemoved
                Kept          = $AuKept
                Failed        = $AuFailed
                Status        = $AuStatus
            })
    }

    # Final summary
    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host " Unprotected Objects RMAU Sync - Complete" -ForegroundColor Cyan
    Write-Host "  Total added  : $TotalAdded" -ForegroundColor Green
    Write-Host "  Total removed: $TotalRemoved" -ForegroundColor Yellow
    if ($TotalKept -gt 0) {
        Write-Host "  Kept (no other RMAU): $TotalKept" -ForegroundColor DarkYellow
    }
    if (($SyncSummary | Where-Object { $_.Failed -gt 0 }).Count -gt 0) {
        Write-Host "  Failures     : $(($SyncSummary | Measure-Object -Property Failed -Sum).Sum)" -ForegroundColor Red
    }
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""
    Show-EntraOpsWarningSummary -WarningMessages $WarningMessages -IncludeObjectDetails $IncludeObjectDetails
    $SyncSummary | Format-Table -AutoSize -Property AdminUnit, MembersBefore,
    @{Name = 'Added'; Expression = { $_.Added }; Align = 'Right' },
    @{Name = 'Removed'; Expression = { $_.Removed }; Align = 'Right' },
    @{Name = 'Kept'; Expression = { $_.Kept }; Align = 'Right' },
    @{Name = 'Failed'; Expression = { $_.Failed }; Align = 'Right' },
    Status

    $FailureCount = ($SyncSummary | Measure-Object -Property Failed -Sum).Sum
    $AbortedCount = @($SyncSummary | Where-Object { $_.Status -eq 'ABORTED' }).Count
    if ($FailureCount -gt 0 -or $AbortedCount -gt 0) {
        $Reasons = [System.Collections.Generic.List[string]]::new()
        if ($FailureCount -gt 0) { $Reasons.Add("$FailureCount membership operation(s) failed") | Out-Null }
        if ($AbortedCount -gt 0) { $Reasons.Add("$AbortedCount RMAU synchronization(s) aborted by the removal safety threshold") | Out-Null }
        throw "RMAU sync did not complete: $($Reasons -join '; '). Review the warning summary above."
    }
}
