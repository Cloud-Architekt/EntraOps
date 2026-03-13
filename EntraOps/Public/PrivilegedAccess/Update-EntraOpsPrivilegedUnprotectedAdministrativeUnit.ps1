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
        [ValidateSet("EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement", "Defender")]
        [Array]$RbacSystems = ("EntraID", "IdentityGovernance", "DeviceManagement", "Defender")
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
    #endregion

    # Summary tracking
    $SyncSummary = [System.Collections.Generic.List[psobject]]::new()
    $TotalAdded = 0
    $TotalRemoved = 0
    $TotalKept = 0
    $WarningMessages = New-Object -TypeName "System.Collections.Generic.List[psobject]"

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

        $AdminUnitId = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/administrativeUnits?`$filter=DisplayName eq '$AdminUnitName'" -DisableCache -OutputType PSObject).id
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
        $UnprotectedPrivilegedUserOnTierLevel = ($UnprotectedPrivilegedUser | Where-Object { $_.Classification.AdminTierLevel -contains $TierLevel.AdminTierLevel -and $_.Classification.AdminTierLevelName -contains $TierLevel.AdminTierLevelName })
        $CurrentAdminUnitMembers = @()
        $CurrentAdminUnitMembers = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/administrativeUnits/$($AdminUnitId)/members" -OutputType PSObject -DisableCache)

        $CurrentMemberCount = @($CurrentAdminUnitMembers.Id).Count
        $DesiredMemberCount = @($UnprotectedPrivilegedUserOnTierLevel.ObjectId).Count
        Write-Host "  Current members : $CurrentMemberCount | Unprotected objects for tier: $DesiredMemberCount" -ForegroundColor Gray

        # Case 1: AU is empty - add all unprotected objects
        if ($null -eq $CurrentAdminUnitMembers.Id) {
            # Deduplicate - same object may appear multiple times with different role assignments
            $UniqueUnprotected = $UnprotectedPrivilegedUserOnTierLevel | Sort-Object ObjectId -Unique
            Write-Host "  AU is empty - adding all $(@($UniqueUnprotected).Count) unprotected objects" -ForegroundColor Yellow
            foreach ($PrivObj in $UniqueUnprotected) {
                try {
                    $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/directoryObjects/$($PrivObj.ObjectId)" -OutputType PSObject -DisableCache
                    $MemberType = $AdminUnitMember.'@odata.type'.Replace('#microsoft.graph.', '')
                    Write-Host "  [+] ADD  [$MemberType] $($AdminUnitMember.displayName)" -ForegroundColor Green

                    $OdataBody = @{
                        '@odata.id' = "https://graph.microsoft.com/beta/directoryObjects/$($PrivObj.ObjectId)"
                    } | ConvertTo-Json
                    Invoke-EntraOpsMsGraphQuery -Method "POST" -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/`$ref" -Body $OdataBody -OutputType PSObject
                    $AuAdded++
                } catch {
                    Write-Warning "  [!] FAIL ADD $($PrivObj.ObjectId): $_"
                    $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = "FAIL ADD $($PrivObj.ObjectId) to $AdminUnitName`: $_" })
                    $AuFailed++
                }
            }

            # Case 2: No unprotected objects at this tier - evaluate existing members for cleanup
            # Note: Where-Object returns @() not $null when empty, so must check Count
        } elseif (@($UnprotectedPrivilegedUserOnTierLevel).Count -eq 0) {
            Write-Host "  No unprotected objects at this tier - evaluating $CurrentMemberCount existing members for removal" -ForegroundColor Yellow

            foreach ($CurrentMember in $CurrentAdminUnitMembers) {
                if ($CurrentMember.'@odata.type' -eq "#microsoft.graph.user") {
                    # Invoke-EntraOpsMsGraphQuery already unwraps pagination - do NOT add .value
                    $AssignmentsToAUs = Invoke-EntraOpsMsGraphQuery -Uri "/beta/users/$($CurrentMember.id)/memberOf/Microsoft.Graph.AdministrativeUnit" -OutputType PSObject -DisableCache
                } elseif ($CurrentMember.'@odata.type' -eq "#microsoft.graph.group") {
                    $AssignmentsToAUs = Invoke-EntraOpsMsGraphQuery -Uri "/beta/groups/$($CurrentMember.id)/memberOf/Microsoft.Graph.AdministrativeUnit" -OutputType PSObject -DisableCache
                } else {
                    Write-Warning "  [!] Unsupported object type $($CurrentMember.'@odata.type') - skipping"
                    $WarningMessages.Add([PSCustomObject]@{ Type = "UnsupportedObjectType"; Message = "Unsupported object type $($CurrentMember.'@odata.type') in $AdminUnitName - skipped" })
                    continue
                }

                $AssignmentsToOtherRMAUs = $AssignmentsToAUs | Where-Object { $_.isMemberManagementRestricted -eq $True -and $_.id -ne $AdminUnitId }
                $MemberType = $CurrentMember.'@odata.type'.Replace('#microsoft.graph.', '')

                # Check all protection types: other RMAU, AadRole, RAG, or no longer privileged
                $EamEntry = $PrivilegedEamObjects | Where-Object { $_.ObjectId -eq $CurrentMember.id } | Select-Object -First 1
                $HasOtherProtection = ($null -ne $AssignmentsToOtherRMAUs) -or `
                ($null -eq $EamEntry) -or `
                ($EamEntry.RestrictedManagementByAadRole -eq $True) -or `
                ($EamEntry.RestrictedManagementByRAG -eq $True)

                if ($HasOtherProtection) {
                    try {
                        $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/directoryObjects/$($CurrentMember.Id)" -OutputType PSObject -DisableCache
                        Write-Host "  [-] REM  [$MemberType] $($AdminUnitMember.displayName) (protected by another RMAU, AadRole/RAG, or no longer privileged)" -ForegroundColor Yellow
                        Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/$($CurrentMember.Id)/`$ref" -OutputType PSObject -DisableCache
                        $AuRemoved++
                    } catch {
                        Write-Warning "  [!] FAIL REMOVE $($CurrentMember.Id): $_"
                        $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = "FAIL REMOVE $($CurrentMember.Id) from $AdminUnitName`: $_" })
                        $AuFailed++
                    }
                } else {
                    Write-Host "  [~] KEEP [$MemberType] $($CurrentMember.displayName) (no other RMAU protecting this object)" -ForegroundColor DarkYellow
                    $AuKept++
                }
            }

            # Case 3: Delta sync - compare desired vs current
        } else {
            # Deduplicate before Compare-Object - same object may appear multiple times
            # in the EAM data with different role assignments at the same tier level.
            $DesiredIds = @($UnprotectedPrivilegedUserOnTierLevel.ObjectId | Select-Object -Unique)
            $CurrentIds = @($CurrentAdminUnitMembers.Id | Select-Object -Unique)
            $Diff = Compare-Object $DesiredIds $CurrentIds
            $ToRemove = @($Diff | Where-Object { $_.SideIndicator -eq "=>" })
            $ToAdd = @($Diff | Where-Object { $_.SideIndicator -eq "<=" })

            if ($Diff.Count -eq 0) {
                Write-Host "  No changes required - AU is already in sync" -ForegroundColor DarkGreen
            } else {
                Write-Host "  Delta: +$($ToAdd.Count) to add  -$($ToRemove.Count) to remove" -ForegroundColor Yellow
            }

            # Process removals - object is in AU but no longer in desired unprotected list.
            # Determine WHY before removing to prevent flip-flop:
            # - Protected by AadRole or RAG → safe to remove (no RMAU needed)
            # - No longer privileged → safe to remove
            # - Has another RMAU → safe to remove (protected elsewhere)
            # - This AU is the only RMAU, no AadRole/RAG → KEEP (removing would set
            #   RestrictedManagementByRMAU=False, causing re-add on next sync cycle)
            foreach ($Entry in $ToRemove) {
                $EamEntry = $PrivilegedEamObjects | Where-Object { $_.ObjectId -eq $Entry.InputObject } | Select-Object -First 1
                $RemoveReason = $null

                if ($null -eq $EamEntry) {
                    $RemoveReason = "no longer privileged"
                } elseif ($EamEntry.RestrictedManagementByAadRole -eq $True -or $EamEntry.RestrictedManagementByRAG -eq $True) {
                    $RemoveReason = "protected by AadRole or RAG"
                } else {
                    # RMAU-only — check if another RMAU exists besides this AU
                    if ($EamEntry.ObjectType -eq 'User') {
                        $EntryAUs = Invoke-EntraOpsMsGraphQuery -Uri "/beta/users/$($Entry.InputObject)/memberOf/Microsoft.Graph.AdministrativeUnit" -OutputType PSObject -DisableCache
                    } elseif ($EamEntry.ObjectType -eq 'Group') {
                        $EntryAUs = Invoke-EntraOpsMsGraphQuery -Uri "/beta/groups/$($Entry.InputObject)/memberOf/Microsoft.Graph.AdministrativeUnit" -OutputType PSObject -DisableCache
                    } else {
                        $EntryAUs = @()
                    }
                    $OtherRMAUs = $EntryAUs | Where-Object { $_.isMemberManagementRestricted -eq $True -and $_.id -ne $AdminUnitId }
                    if ($null -ne $OtherRMAUs) {
                        $RemoveReason = "protected by another RMAU"
                    }
                }

                if ($null -ne $RemoveReason) {
                    try {
                        $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/directoryObjects/$($Entry.InputObject)" -OutputType PSObject
                        $MemberType = $AdminUnitMember.'@odata.type'.Replace('#microsoft.graph.', '')
                        Write-Host "  [-] REM  [$MemberType] $($AdminUnitMember.displayName) ($RemoveReason)" -ForegroundColor Yellow
                        Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/$($Entry.InputObject)/`$ref" -OutputType PSObject
                        $AuRemoved++
                    } catch {
                        Write-Warning "  [!] FAIL remove $($Entry.InputObject): $_"
                        $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = "FAIL remove $($Entry.InputObject) from $AdminUnitName`: $_" })
                        $AuFailed++
                    }
                } else {
                    Write-Host "  [~] KEEP [$($EamEntry.ObjectType)] $($EamEntry.ObjectDisplayName) (this AU is the only RMAU)" -ForegroundColor DarkYellow
                    $AuKept++
                }
            }

            # Process additions
            foreach ($Entry in $ToAdd) {
                try {
                    $AdminUnitMember = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/directoryObjects/$($Entry.InputObject)" -OutputType PSObject -DisableCache
                    $MemberType = $AdminUnitMember.'@odata.type'.Replace('#microsoft.graph.', '')
                    Write-Host "  [+] ADD  [$MemberType] $($AdminUnitMember.displayName)" -ForegroundColor Green

                    $OdataBody = @{
                        '@odata.id' = "https://graph.microsoft.com/beta/directoryObjects/$($Entry.InputObject)"
                    } | ConvertTo-Json
                    Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/beta/administrativeUnits/$($AdminUnitId)/members/`$ref" -Body $OdataBody -OutputType PSObject
                    $AuAdded++
                } catch {
                    Write-Warning "  [!] FAIL ADD $($Entry.InputObject): $_"
                    $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = "FAIL ADD $($Entry.InputObject) to $AdminUnitName`: $_" })
                    $AuFailed++
                }
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
    Show-EntraOpsWarningSummary -WarningMessages $WarningMessages
    $SyncSummary | Format-Table -AutoSize -Property AdminUnit, MembersBefore,
    @{Name = 'Added'; Expression = { $_.Added }; Align = 'Right' },
    @{Name = 'Removed'; Expression = { $_.Removed }; Align = 'Right' },
    @{Name = 'Kept'; Expression = { $_.Kept }; Align = 'Right' },
    @{Name = 'Failed'; Expression = { $_.Failed }; Align = 'Right' },
    Status
}