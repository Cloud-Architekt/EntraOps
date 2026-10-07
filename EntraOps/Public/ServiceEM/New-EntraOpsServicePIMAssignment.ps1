<#
.SYNOPSIS
    Creates PIM for Groups eligible owner assignments for the WorkloadPlane groups.

.DESCRIPTION
    With -EnableOwnerAssignment, the workload plane admin becomes eligible owner (no expiration) of each
    WorkloadPlane group (WorkloadPlane-Admins and WorkloadPlane-Users); never of ControlPlane,
    ManagementPlane, CatalogPlane or Microsoft 365 groups. Eligible memberships are granted through
    the access packages.

    Idempotent: existing noExpiration eligible assignments are detected and
    skipped.

    Without -EnableOwnerAssignment the function returns an empty array without error.

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

        foreach($group in $targetGroups){
            Write-Verbose "$logPrefix Looking up eligibility for group ID: $($group.Id)"

            try {
                $currentEligibilities = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests?`$filter=groupId eq '$($group.Id)'&`$expand=group,principal,targetSchedule" -OutputType PSObject -DisableCache
                $pimEligibilities += $currentEligibilities
            } catch {
                Write-Warning "$logPrefix Failed to query eligibility schedule requests for group $($group.Id). Ensure the group is role-assignable and the caller has PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup permission. Error: $_"
                continue
            }

            if(-not [string]::IsNullOrWhiteSpace($WorkloadPlaneAdminPrincipalId)){
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
                $neOwner = $WorkloadPlaneAdminPrincipalId + "_noExpiration"
                $eeOwner = $pimEligibilities | Where-Object { $_.groupId -eq $group.Id -and $_.accessId -eq "owner" } | ForEach-Object { $_.principalId+"_"+$_.targetSchedule.scheduleInfo.expiration.type }
                if($neOwner -notin $eeOwner){
                    Write-Verbose "$logPrefix Creating owner eligible assignment for $WorkloadPlaneAdminPrincipalId on group $($group.Id)"
                    try {
                        Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" -Body ($ownerParams | ConvertTo-Json -Depth 10) -OutputType PSObject | Out-Null
                        $pimEligibilities += Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests?`$filter=groupId eq '$($group.Id)'&`$expand=group,principal,targetSchedule" -OutputType PSObject -DisableCache
                    } catch {
                        Write-Warning "$logPrefix Failed to create PIM eligible owner assignment for group $($group.Id). Error: $_"
                    }
                }
            }
        }
    }

    end {
        if ($targetGroups.Count -eq 0) {
            Write-Verbose "$logPrefix -EnableOwnerAssignment not set, no PIM for Groups eligibilities to create"
            return [psobject[]]@()
        }

        $expectedIds = @($pimEligibilities | Where-Object { $_.id } | Select-Object -ExpandProperty id)
        if ($expectedIds.Count -eq 0) {
            Write-Warning "$logPrefix No PIM eligibilities were successfully created or retrieved. Check previous warnings for permission errors (e.g., group not role-assignable, missing PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup)."
            return [psobject[]]@()
        }

        $check = @{}
        $confirmed = Wait-EntraOpsServiceEMCondition -Activity "PIM for Groups eligibilities" -logPrefix $logPrefix -Condition {
            $check.Eligibilities = @()
            foreach($group in $targetGroups){
                try {
                    $check.Eligibilities += Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests?`$filter=groupId eq '$($group.Id)'&`$expand=group,principal,targetSchedule" -OutputType PSObject -DisableCache
                } catch {
                    Write-Verbose "$logPrefix Failed to query eligibility during consistency check for group $($group.Id): $_"
                }
            }
            $actualIds = @($check.Eligibilities | Where-Object { $_.id } | Select-Object -ExpandProperty id)
            (Compare-Object $expectedIds $actualIds | Measure-Object).Count -eq 0
        }
        if(-not $confirmed){
            Write-Warning "$logPrefix PIM eligibility consistency with Entra not achieved. Expected $($expectedIds.Count) entries. Returning best-effort results."
            return [psobject[]]$pimEligibilities
        }
        return [psobject[]]$check.Eligibilities
    }
}