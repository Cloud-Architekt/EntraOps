<#
.SYNOPSIS
    Creates PIM for Groups eligible owner assignments for the WorkloadPlane groups.

.DESCRIPTION
    With -EnableOwnerAssignment, the workload plane admin becomes eligible owner (no expiration) of each
    WorkloadPlane group (WorkloadPlane-Admins and WorkloadPlane-Users); never of ControlPlane,
    ManagementPlane, CatalogPlane or Microsoft 365 groups. Eligible memberships are granted through
    the access packages.

    Idempotent: an existing eligible owner assignment of the workload plane admin (active
    eligibility schedule) is detected and skipped.

    Without -EnableOwnerAssignment the function returns an empty array without error. Failed lookups or
    assignments are reported together in a terminating error after all groups have been processed.

.PARAMETER ServiceGroups
    All service group objects (owned groups only — delegated groups must be
    excluded).

.PARAMETER WorkloadPlaneAdminPrincipalId
    Object ID of the workload plane admin. Required when -EnableOwnerAssignment is set.
    When provided, an eligible-owner assignment is created so the workload plane admin
    can activate ownership of each WorkloadPlane group via PIM.

.PARAMETER EnableOwnerAssignment
    When set, creates PIM for Groups eligible-owner assignments for the workload plane admin
    on each WorkloadPlane group. Disabled by default (-GroupOwnership Eligible).

.PARAMETER logPrefix
    Text prepended to verbose messages. Defaults to the function name.

.EXAMPLE
    New-EntraOpsServicePIMAssignment -ServiceGroups $ownedGroups -EnableOwnerAssignment `
        -WorkloadPlaneAdminPrincipalId "00000000-0000-0000-0000-000000000001"

    Makes the workload plane admin eligible owner of SG-MyService-WorkloadPlane-Admins and
    SG-MyService-WorkloadPlane-Users.

#>
function New-EntraOpsServicePIMAssignment {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [psobject[]]$ServiceGroups,

        [string]$WorkloadPlaneAdminPrincipalId = "",

        [switch]$EnableOwnerAssignment,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $pimEligibilities = @()
        $isOwnerTarget = { param($group) $EnableOwnerAssignment -and $group.DisplayName -like "*-WorkloadPlane-*" }
        $targetGroups = @($ServiceGroups | Where-Object {
                $_.GroupTypes -notcontains "Unified" -and (& $isOwnerTarget $_)
            })
    }

    process {
        Write-Verbose "$logPrefix Beginning PIM Assignment"

        $createdGroupIds = [System.Collections.Generic.List[string]]::new()
        $ownerFailures = [System.Collections.Generic.List[string]]::new()
        if ($targetGroups.Count -gt 0 -and [string]::IsNullOrWhiteSpace($WorkloadPlaneAdminPrincipalId)) {
            throw "$logPrefix -WorkloadPlaneAdminPrincipalId is required with -EnableOwnerAssignment."
        }
        foreach($group in $targetGroups){
            Write-Verbose "$logPrefix Looking up eligibility for group ID: $($group.Id)"

            # eligibilitySchedules holds the current eligibilities only; schedule requests also contain revoked, denied or failed requests
            try {
                $currentEligibilities = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$($group.Id)'" -OutputType PSObject -DisableCache -ThrowOnFailure
                $pimEligibilities += @($currentEligibilities | Where-Object { $_ })
            } catch {
                Write-Warning "$logPrefix Failed to query eligibility schedules for group $($group.Id). Ensure the group is role-assignable and the caller has PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup permission. Error: $_"
                $ownerFailures.Add("lookup of '$($group.DisplayName)' ($($group.Id)): $($_.Exception.Message)")
                continue
            }

            $ownerParams = @{
                accessId    = "owner"
                principalId = $WorkloadPlaneAdminPrincipalId
                groupId     = $group.Id
                action      = "AdminAssign"
                scheduleInfo = @{
                    startDateTime = (Get-Date).AddHours(-1).ToString("o")
                    expiration    = @{ type = "noExpiration" }
                }
            }
            $existingOwner = @($pimEligibilities | Where-Object { $_.groupId -eq $group.Id -and $_.accessId -eq "owner" -and $_.principalId -eq $WorkloadPlaneAdminPrincipalId })
            if ($existingOwner.Count -gt 0) {
                Write-Verbose "$logPrefix $WorkloadPlaneAdminPrincipalId is already eligible owner of group $($group.Id)"
            } else {
                Write-Verbose "$logPrefix Creating owner eligible assignment for $WorkloadPlaneAdminPrincipalId on group $($group.Id)"
                try {
                    Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" -Body ($ownerParams | ConvertTo-Json -Depth 10) -OutputType PSObject -ThrowOnFailure | Out-Null
                    $createdGroupIds.Add($group.Id)
                } catch {
                    Write-Warning "$logPrefix Failed to create PIM eligible owner assignment for group $($group.Id). Error: $_"
                    $ownerFailures.Add("assignment on '$($group.DisplayName)' ($($group.Id)): $($_.Exception.Message)")
                }
            }
        }
        if ($ownerFailures.Count -gt 0) {
            throw "$logPrefix Failed to ensure $($ownerFailures.Count) PIM for Groups eligible owner assignment(s) for $($WorkloadPlaneAdminPrincipalId): $($ownerFailures -join '; ')"
        }
    }

    end {
        if ($targetGroups.Count -eq 0) {
            Write-Verbose "$logPrefix -EnableOwnerAssignment not set, no PIM for Groups eligibilities to create"
            return [psobject[]]@()
        }
        if ($createdGroupIds.Count -eq 0) {
            return [psobject[]]$pimEligibilities
        }

        $check = @{ Eligibilities = @() }
        $confirmed = Wait-EntraOpsServiceEMCondition -Activity "PIM for Groups eligibilities" -logPrefix $logPrefix -Condition {
            $check.Eligibilities = @()
            foreach($group in $targetGroups){
                try {
                    $check.Eligibilities += @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$($group.Id)'" -OutputType PSObject -DisableCache | Where-Object { $_ })
                } catch {
                    Write-Verbose "$logPrefix Failed to query eligibility during consistency check for group $($group.Id): $_"
                }
            }
            @($createdGroupIds | Where-Object {
                    $groupId = $_
                    -not ($check.Eligibilities | Where-Object { $_.groupId -eq $groupId -and $_.accessId -eq "owner" -and $_.principalId -eq $WorkloadPlaneAdminPrincipalId })
                }).Count -eq 0
        }
        if(-not $confirmed){
            Write-Warning "$logPrefix PIM eligibility consistency with Entra not achieved for $($createdGroupIds.Count) new eligible owner assignment(s). Returning best-effort results."
            return [psobject[]]$pimEligibilities
        }
        return [psobject[]]$check.Eligibilities
    }
}
