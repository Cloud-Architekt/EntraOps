<#
.SYNOPSIS
    Creates Entra PIM assignments

.DESCRIPTION
    Creates the Entra Privileged Identity Management (PIM) assignments

.PARAMETER ServiceGroups
    The Graph Group objects

.PARAMETER logPrefix
    Defines the text to prepend for any verbose messages

.EXAMPLE
    New-EntraOpsServicePIMAssignment -ServiceGroups $groups

#>
function New-EntraOpsServicePIMAssignment {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [psobject[]]$ServiceGroups,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $pimEligibilities = @()

        $pimEligibilityParams = @{
            accessId = "member"
            principalId = ($ServiceGroups|Where-Object{$_.DisplayName -like "* Members"}).Id
            groupId = ""
            action = "AdminAssign"
            scheduleInfo = @{
                startDateTime = $((Get-Date).AddHours(-1))
                expiration = @{
                    type = "noExpiration"
                }
            }
        }
    }

    process {
        foreach($group in $ServiceGroups|Where-Object{$_.DisplayName -notlike "*Members*"}){
            $pimEligibilityParams.groupId = $group.Id
            $pimEligibilitySplat = @{
                Filter = "groupId eq '$($group.Id)'"
                ExpandProperty = "Group,Principal,TargetSchedule"
            }
            Write-Verbose "$logPrefix Looking up eligibility for group ID: $($group.Id)"
            $pimEligibilities += Get-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest @pimEligibilitySplat
        
            if($group.DisplayName -like "*-PIM-*"){
                $pimEligibilityParams.principalId = ($ServiceGroups|Where-Object{$_.DisplayName -like "SG-"+$group.DisplayName.Substring(7)}).Id
            }
            $ne = $pimEligibilityParams.principalId+"_noExpiration"
            $ee = $pimEligibilities|ForEach-Object{$_.PrincipalId+"_"+$_.TargetSchedule.ScheduleInfo.Expiration.Type}
            if($ne -notin $ee){
                Write-Verbose "$logPrefix $($pimEligibilityParams|ConvertTo-Json -Compress)"
                New-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $pimEligibilityParams|Out-Null
                $pimEligibilities += Get-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest @pimEligibilitySplat
            }
        }
    }

    end {
        $confirmed = $false
        $i = 0
        while(-not $confirmed){
            Start-Sleep -Seconds ([Math]::Pow(2,$i)-1)
            $checkPimEligibility = @()
            foreach($group in $ServiceGroups|Where-Object{$_.DisplayName -notlike "*Members*"}){
                $pimEligibilitySplat = @{
                    Filter = "groupId eq '$($group.Id)'"
                    ExpandProperty = "Group,Principal,TargetSchedule"
                }
                $checkPimEligibility += Get-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest @pimEligibilitySplat
            }
            if((Compare-Object $pimEligibilities.Id $checkPimEligibility.Id|Measure-Object).Count -eq 0){
                Write-Verbose "$logPrefix Graph consistency found confirming"
                $confirmed = $true
                continue
            }
            $i++
            if($i -gt 5){
                throw "Access Package object consistency with Entra not achieved"
            }
            Write-Verbose "$logPrefix Graph objects not available, sleeping $([Math]::Pow(2,$i)-1) seconds"
        }
        return [psobject[]]$checkPimEligibility
    }
}