<#
.SYNOPSIS
    Creates PIM for Groups eligible assignments for service admin groups.

.DESCRIPTION
    Creates PIM for Groups eligible assignments with no expiration:
    - PIM staging groups (mailNickname PIM.<ServiceName>.<AccessLevel>.<Role>): the base group with the
      same AccessLevel and Role (e.g. ManagementPlane-Admins) becomes eligible member.
    - With -EnableOwnerAssignment: the workload plane admin becomes eligible owner of each admin and user group.

    The Microsoft 365 group (<ServiceName> Members) never gets eligibilities; access to the admin and
    user groups is granted through access packages.

    Idempotent: existing noExpiration eligible assignments are detected and
    skipped.

    When no PIM staging group exists and -EnableOwnerAssignment isn't set, the function returns an
    empty array without error.

.PARAMETER ServiceGroups
    All service group objects (owned groups only — delegated groups must be
    excluded). PIM staging groups are automatically matched to their base group.

.PARAMETER WorkloadPlaneAdminPrincipalId
    Object ID of the workload plane admin. Required when -EnableOwnerAssignment is set.
    When provided, an eligible-owner assignment is created so the workload plane admin
    can activate ownership of each admin group via PIM.

.PARAMETER EnableOwnerAssignment
    When set, creates PIM for Groups eligible-owner assignments for the workload plane admin
    on each admin and user group. Disabled by default — use this switch to opt in.

.PARAMETER GroupPrefix
    Prefix used in group DisplayNames (e.g. "SG"). Must match the prefix
    passed to New-EntraOpsServiceBootstrap. Defaults to "SG".

.PARAMETER GroupNamingDelimiter
    Delimiter between group name segments (e.g. "-"). Defaults to "-".

.PARAMETER logPrefix
    Text prepended to verbose messages. Defaults to the function name.

.EXAMPLE
    New-EntraOpsServicePIMAssignment -ServiceGroups $ownedGroups

    Makes SG-MyService-ManagementPlane-Admins eligible member of its PIM staging group
    SG-PIM-MyService-ManagementPlane-Admins.

#>
function New-EntraOpsServicePIMAssignment {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [psobject[]]$ServiceGroups,

        [string]$GroupPrefix = "SG",
        [string]$GroupNamingDelimiter = "-",

        [string]$WorkloadPlaneAdminPrincipalId = "",

        [switch]$EnableOwnerAssignment,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $pimEligibilities = @()
        $isStagingGroup = { param($group) $group.MailNickname -like "PIM.*" -or $group.DisplayName -like "*-PIM-*" }
        $targetGroups = @($ServiceGroups | Where-Object {
                $_.DisplayName -notlike "*Members*" -and $_.GroupTypes -notcontains "Unified" -and
                ((& $isStagingGroup $_) -or $EnableOwnerAssignment)
            })

        $pimEligibilityParams = @{
            accessId = "member"
            principalId = ""
            groupId = ""
            action = "AdminAssign"
            scheduleInfo = @{
                startDateTime = (Get-Date).AddHours(-1).ToString("o")
                expiration = @{
                    type = "noExpiration"
                }
            }
        }
    }

    process {
        Write-Verbose "$logPrefix Beginning PIM Assignment"

        foreach($group in $targetGroups){
            $pimEligibilityParams.groupId = $group.Id
            Write-Verbose "$logPrefix Looking up eligibility for group ID: $($group.Id)"

            try {
                $currentEligibilities = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests?`$filter=groupId eq '$($group.Id)'&`$expand=group,principal,targetSchedule" -OutputType PSObject -DisableCache
                $pimEligibilities += $currentEligibilities
            } catch {
                Write-Warning "$logPrefix Failed to query eligibility schedule requests for group $($group.Id). Ensure the group is role-assignable and the caller has PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup permission. Error: $_"
                continue
            }

            if(& $isStagingGroup $group){
                # mailNickname doesn't contain the GroupPrefix, so it also matches groups created with another prefix
                $sourceGroup = if($group.MailNickname -like "PIM.*"){
                    $ServiceGroups | Where-Object { $_.MailNickname -eq ($group.MailNickname -replace '^PIM\.', '') }
                }
                if(-not $sourceGroup){
                    $pimGroupPrefixLen = "$GroupPrefix$($GroupNamingDelimiter)PIM$GroupNamingDelimiter".Length
                    $sourceGroup = $ServiceGroups|Where-Object{$_.DisplayName -like "$GroupPrefix$GroupNamingDelimiter"+$group.DisplayName.Substring($pimGroupPrefixLen)}
                }
                $pimEligibilityParams.principalId = $sourceGroup.Id
                $ne = $pimEligibilityParams.principalId+"_noExpiration"
                # Scope check to current group only — accumulated $pimEligibilities spans all groups
                $ee = $pimEligibilities | Where-Object { $_.groupId -eq $group.Id } | ForEach-Object { $_.principalId+"_"+$_.targetSchedule.scheduleInfo.expiration.type }
                if([string]::IsNullOrWhiteSpace($pimEligibilityParams.principalId)){
                    Write-Warning "$logPrefix No base group found for PIM staging group $($group.DisplayName), skipping eligible member assignment"
                }elseif($ne -notin $ee){
                    Write-Verbose "$logPrefix $($pimEligibilityParams|ConvertTo-Json -Compress)"
                    try {
                        Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" -Body ($pimEligibilityParams | ConvertTo-Json -Depth 10) -OutputType PSObject | Out-Null
                        $pimEligibilities += Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests?`$filter=groupId eq '$($group.Id)'&`$expand=group,principal,targetSchedule" -OutputType PSObject -DisableCache
                    } catch {
                        Write-Warning "$logPrefix Failed to create PIM eligible assignment for group $($group.Id). Error: $_"
                    }
                }
            }

            # Eligible-owner assignment for the workload plane admin (opt-in only).
            if($EnableOwnerAssignment -and -not [string]::IsNullOrWhiteSpace($WorkloadPlaneAdminPrincipalId)){
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
            Write-Verbose "$logPrefix No PIM staging group in this scope and -EnableOwnerAssignment not set, no PIM for Groups eligibilities to create"
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