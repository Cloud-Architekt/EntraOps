<#
.SYNOPSIS
    Classifies the WorkloadPlane groups of a ServiceEM landing zone by administrative unit and Object Classification File.

.DESCRIPTION
    Only WorkloadPlane-Admins (tier ManagementPlane) and WorkloadPlane-Users (tier UserAccess) created by the landing
    zone are handled; ControlPlane, ManagementPlane and administrator groups are classified in another way.
    WorkloadPlane-Admins are classified ManagementPlane because the role assignments of the landing zone (e.g. the
    constrained Role Based Access Control Administrator and the resource roles assigned by ManagementPlane-Admins)
    are classified ManagementPlane: the object tier matches the tier of its access.
    Groups are identified by their mailNickname (<ServiceName>.WorkloadPlane.Admins/Users), not by display name.

    - ServiceEM.AdministrativeUnits.WorkloadPlane / .UserAccess: object ID of an administrative unit the group is
      added to, e.g. to classify it with an Alternate Tier Level Attributes filter on AssignedAdministrativeUnits.
      Role-assignable and PIM-managed groups can't be added to a restricted management administrative unit; they
      are skipped with a warning.
    - ServiceEM.UpdateObjectClassificationFile: adds the groups to the Object Classification File.

    Failures are reported as warnings and don't stop the deployment.

.PARAMETER ServiceGroups
    Groups of the landing zone. Delegated groups are ignored.

.PARAMETER ServiceName
    Name of the service, the first segment of the group mailNickname.

.PARAMETER PimManagedWorkloadPlaneAdmins
    WorkloadPlane-Admins are managed by PIM for Groups (-EnableWorkloadPlanePimForGroups).

.PARAMETER logPrefix
    Text prepended to verbose and warning messages.
#>
function Set-EntraOpsServiceEMWorkloadClassification {
    [CmdletBinding()]
    [OutputType([psobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [psobject[]]$ServiceGroups,

        [Parameter(Mandatory)]
        [string]$ServiceName,

        [switch]$PimManagedWorkloadPlaneAdmins,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    # AuKey names the group in ServiceEM.AdministrativeUnits (WorkloadPlane = WorkloadPlane-Admins), Tier is its classification
    $classificationByNickname = @{
        "$ServiceName.WorkloadPlane.Admins" = @{ AuKey = 'WorkloadPlane'; Tier = 'ManagementPlane' }
        "$ServiceName.WorkloadPlane.Users"  = @{ AuKey = 'UserAccess'; Tier = 'UserAccess' }
    }
    $targets = @(foreach ($group in $ServiceGroups) {
            if ($group.IsDelegated -eq $true -or -not $classificationByNickname.ContainsKey("$($group.MailNickname)")) { continue }
            $classification = $classificationByNickname["$($group.MailNickname)"]
            [pscustomobject]@{ Group = $group; AuKey = $classification.AuKey; Tier = $classification.Tier; AdministrativeUnitId = $null }
        })
    if ($targets.Count -eq 0) { return @() }

    foreach ($auKey in 'WorkloadPlane', 'UserAccess') {
        $auId = [string](Get-EntraOpsServiceEMConfigValue -Path "AdministrativeUnits.$auKey")
        $auTargets = @($targets | Where-Object AuKey -EQ $auKey)
        if ([string]::IsNullOrWhiteSpace($auId) -or $auTargets.Count -eq 0) { continue }
        if ($auId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            Write-Warning "$logPrefix ServiceEM.AdministrativeUnits.$auKey '$auId' is not an object ID; no group is added to it."
            continue
        }
        try {
            $au = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/administrativeUnits/$($auId)?`$select=id,displayName,isMemberManagementRestricted" -OutputType PSObject -DisableCache -ThrowOnFailure
        } catch {
            Write-Warning "$logPrefix Administrative unit $auId (ServiceEM.AdministrativeUnits.$auKey) can't be read; no group is added to it: $($_.Exception.Message)"
            continue
        }

        foreach ($target in $auTargets) {
            $group = $target.Group
            $isPimManaged = $auKey -eq 'WorkloadPlane' -and $PimManagedWorkloadPlaneAdmins
            if ($au.isMemberManagementRestricted -eq $true -and ($group.IsAssignableToRole -eq $true -or $isPimManaged)) {
                Write-Warning "$logPrefix $($group.DisplayName) ($($group.Id)) isn't added to the restricted management administrative unit '$($au.displayName)': $(if ($group.IsAssignableToRole -eq $true) { 'role-assignable' } else { 'PIM-managed' }) groups can't be members of a restricted management administrative unit. Use an administrative unit without restricted management for ServiceEM.AdministrativeUnits.$auKey."
                continue
            }
            $body = @{ '@odata.id' = "https://graph.microsoft.com/beta/directoryObjects/$($group.Id)" } | ConvertTo-Json
            try {
                # A new group can return 404 for a short time
                $added = Wait-EntraOpsServiceEMCondition -Activity "Group $($group.DisplayName) in administrative unit" -MaxWaitSeconds 60 -logPrefix $logPrefix -Condition {
                    try {
                        Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/beta/administrativeUnits/$auId/members/`$ref" -Body $body -OutputType PSObject -DisableCache -ThrowOnFailure -SuppressNotFoundWarning -SuppressBadRequestWarning | Out-Null
                        $true
                    } catch {
                        if ($_.Exception.Data['StatusCode'] -eq 404) { return $false }
                        if ($_.Exception.Data['StatusCode'] -eq 400 -and $_.Exception.Message -like '*already exist*') { return $true }
                        throw
                    }
                }
                if ($added) {
                    $target.AdministrativeUnitId = $auId
                    Write-Verbose "$logPrefix $($group.DisplayName) is a member of administrative unit '$($au.displayName)'"
                } else {
                    Write-Warning "$logPrefix $($group.DisplayName) ($($group.Id)) couldn't be added to administrative unit '$($au.displayName)': the group wasn't found before the wait timed out."
                }
            } catch {
                Write-Warning "$logPrefix $($group.DisplayName) ($($group.Id)) couldn't be added to administrative unit '$($au.displayName)': $($_.Exception.Message)"
            }
        }
    }

    if ((Get-EntraOpsServiceEMConfigValue -Path 'UpdateObjectClassificationFile') -eq $true) {
        $entries = @($targets | ForEach-Object {
                [pscustomobject]@{
                    ObjectId           = $_.Group.Id
                    ObjectDisplayName  = $_.Group.DisplayName
                    AdminTierLevelName = $_.Tier
                    Justification      = "ServiceEM landing zone $ServiceName"
                }
            })
        Update-EntraOpsServiceEMObjectClassificationFile -Entries $entries -logPrefix $logPrefix | Out-Null
    }

    return [psobject[]]@($targets | ForEach-Object {
            [pscustomobject]@{ Id = $_.Group.Id; DisplayName = $_.Group.DisplayName; AdminTierLevelName = $_.Tier; AdministrativeUnitId = $_.AdministrativeUnitId }
        })
}
