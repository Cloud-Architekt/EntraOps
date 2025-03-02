<#
.SYNOPSIS
    Creates an Entra PIM policy

.DESCRIPTION
    Creates the Entra Priviliged Identity Management (PIM) policies for
    the provided groups

.PARAMETER ServiceGroups
    The Graph Group objects

.PARAMETER logPrefix
    Defines the text to prepend for any verbose messages

.EXAMPLE
    New-EntraOpsServicePIMPolicy -ServiceGroups $groups

#>
function New-EntraOpsServicePIMPolicy {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [psobject[]]$ServiceGroups,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $groupPolicies = @()
        $groupPolicyAssignments = @()
        $groupPolicyParams = @{
            rules = @(
                @{
                    "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
                    id = "Expiration_Admin_Eligibility"
                    isExpirationRequired = $false
                },
                @{
                    "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
                    id = "Expiration_Admin_Assignment"
                    isExpirationRequired = $true
                    maximumDuration = "P15D"
                },
                @{
                    "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
                    id = "Expiration_EndUser_Assignment"
                    maximumDuration = "PT10H"
                },
                @{
                    "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule"
                    id = "Enablement_EndUser_Assignment"
                    enabledRules = @(
                        "MultiFactorAuthentication",
                        "Justification"
                    )
                }
            )
        }
    }

    process {
        foreach($group in $ServiceGroups|Where-Object{$_.DisplayName -notlike "*Members*"}){
            $groupPolicySplat = @{
                Filter = "scopeId eq '$($group.Id)' and scopeType eq 'Group'"
            }
            try{
                Write-Verbose "$logPrefix Looking up PIM Policies with Assignments"
                #$groupPolicy = Get-MgPolicyRoleManagementPolicy @groupPolicySplat -ExpandProperty "Rules,EffectiveRules"
                $groupPolicyAssignment = Get-MgPolicyRoleManagementPolicyAssignment @groupPolicySplat
                $groupPolicyAssignments += $groupPolicyAssignment
            }catch{
                Write-Verbose "$logPrefix Failed to find PIM Policies with Assignments"
                Write-Error $_
            }
            $memberPolicy = $groupPolicyAssignment|Where-Object{$_.Id -like "*member"}
            try{
                Write-Verbose "$logPrefix Updaing PIM Policy ID: $($memberPolicy.PolicyId)"
                $groupPolicies += Update-MgPolicyRoleManagementPolicy -UnifiedRoleManagementPolicyId $memberPolicy.PolicyId -BodyParameter $groupPolicyParams
            }catch{
                Write-Verbose "$logPrefix Failed to update PIM Policy"
                Write-Error $_
            }
        }
    }

    end {
        $confirmed = $false
        $i = 0
        while(-not $confirmed){
            Start-Sleep -Seconds ([Math]::Pow(2,$i)-1)
            $checkGroupPolicies = @()
            foreach($group in $ServiceGroups|Where-Object{$_.DisplayName -notlike "*Members*"}){
                $checkGroupPolicySplat = @{
                    Filter = "scopeId eq '$($group.Id)' and scopeType eq 'Group'"
                }
                $checkGroupPolicyAssignment = Get-MgPolicyRoleManagementPolicyAssignment @checkGroupPolicySplat
                $checkGroupPolicies += $checkGroupPolicyAssignment|Where-Object{$_.Id -like "*member"}
            }    
            if((Compare-Object $groupPolicies.Id $checkGroupPolicies.PolicyId|Measure-Object).Count -eq 0){
                Write-Verbose "$logPrefix Graph consistency found confirming"
                $confirmed = $true
                continue
            }
            $i++
            if($i -gt 5){
                throw "PIM Policy consistency with Entra not achieved"
            }
            Write-Verbose "$logPrefix Graph objects not available, sleeping $([Math]::Pow(2,$i)-1) seconds"
        }
        return [psobject[]]$checkGroupPolicies
    }
}