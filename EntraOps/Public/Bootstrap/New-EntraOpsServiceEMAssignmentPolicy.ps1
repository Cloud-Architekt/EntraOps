<#
.SYNOPSIS
    Creates an Entra Group based on the provided role

.DESCRIPTION
    Creates an Entra Group relative to the specific role supplied. Unless for
    custom implementations, should be used by New-EntraOpsServiceBootstrap.

.PARAMETER ServiceName
    The Name of the Service

.PARAMETER ServiceCatalogId
    The Service Catalog GUID

.PARAMETER ServiceGroups
    The Graph Group objects
    
.PARAMETER ServicePackages
    The Graph Access Package objects

.PARAMETER ServiceCatalogResources
    The Graph Catalog Resource objects

.PARAMETER logPrefix
    Defines the text to prepend for any verbose messages

.EXAMPLE
    New-EntraOpsServiceEMAssignmentPolicy -ServiceName "EntraOps" -ServiceCatalogId "<GUID>" -ServiceGroups $groups -ServicePackages $packages

#>
function New-EntraOpsServiceEMAssignmentPolicy {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,

        [Parameter(Mandatory)]
        [string]$ServiceCatalogId,

        [Parameter(Mandatory)]
        [psobject[]]$ServiceGroups,

        [Parameter(Mandatory)]
        [psobject[]]$ServicePackages,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $policies = @()
        $policiesSplat = @{
            ExpandProperty = "AccessPackage,Catalog"
            Filter = "Catalog/Id eq '$ServiceCatalogId'"
        }
        try{
            Write-Verbose "$logPrefix Looking up Assignment Policy"
            $policies += Get-MgEntitlementManagementAssignmentPolicy @policiesSplat
        }catch{
            Write-Error $_
        }
        $policyParams = @{
            requestorSettings = @{
                enableTargetsToSelfAddAccess = $true
                enableTargetsToSelfUpdateAccess = $false
                enableTargetsToSelfRemoveAccess = $true
                allowCustomAssignmentSchedule = $false
                enableOnBehalfRequestorsToAddAccess = $false
                enableOnBehalfRequestorsToUpdateAccess = $false
                enableOnBehalfRequestorsToRemoveAccess = $false
            }
            accessPackage = @{
                id = ""
            }
            reviewSettings = @{
                isEnabled = $true
                expirationBehavior = "keepAccess"
                isRecommendationEnabled = $true
                isReviewerJustificationRequired = $true
                isSelfReview = $false
                schedule = @{
                    startDateTime = (Get-Date).AddDays(4)
                    expiration = @{
                        duration = "P25D"
                        type = "afterDuration"
                    }
                    recurrence = @{
                        pattern = @{
                            type = "absoluteMonthly"
                            interval = 3
                            month = 0
                            dayOfMonth = 0
                        }
                        range = @{
                            type = "noEnd"
                        }
                    }
                }
                primaryReviewers = @(
                    @{
                        "@odata.type" = "#microsoft.graph.groupMembers"
                        groupId = $(($ServiceGroups|Where-Object{$_.DisplayName -like "* Members"}).Id)
                    }
                )
            }
        }
        $baselinePolicyParams = @{
            displayName = "Baseline Policy"
            description = "The baseline policy for $ServiceName access packages."
            allowedTargetScope = "specificDirectoryUsers"
            specificAllowedTargets = @(
                @{
                    "@odata.type" = "#microsoft.graph.groupMembers"
                    groupId = $(($ServiceGroups|Where-Object{$_.DisplayName -like "* Members"}).Id)
                }
            )
            expiration = @{
                duration = "P5D"
                type = "afterDuration"
            }
            requestApprovalSettings = @{
                isApprovalRequiredForAdd = $true
                isApprovalRequiredForUpdate = $false
                stages = @(
                    @{
                        durationBeforeAutomaticDenial = "P2D"
                        isApproverJustificationRequired = $true
                        isEscalationEnabled = $false
                        durationBeforeEscalation = "PT0S"
                        primaryApprovers = @(
                            @{
                                "@odata.type" = "#microsoft.graph.groupMembers"
                                groupId = $(($ServiceGroups|Where-Object{$_.DisplayName -like "* Members"}).Id)
                            }
                        )
                    }
                )
            }
        }
        $initialPolicyParams = @{
            displayName = "Initial Membership Policy"
            description = "The initial membership policy for $ServiceName."
            allowedTargetScope = "allMemberUsers"
            expiration = @{
                type = "noExpiration"
            }
            requestApprovalSettings = @{
                isApprovalRequiredForAdd = $true
                isApprovalRequiredForUpdate = $false
                stages = @(
                    @{
                        durationBeforeAutomaticDenial = "P7D"
                        isApproverJustificationRequired = $true
                        isEscalationEnabled = $false
                        durationBeforeEscalation = "PT0S"
                        primaryApprovers = @(
                            @{
                                "@odata.type" = "#microsoft.graph.requestorManager"
                                managerLevel = 1
                            }
                        )
                        fallbackPrimaryApprovers = @(
                            @{
                                "@odata.type" = "#microsoft.graph.groupMembers"
                                groupId = $(($ServiceGroups|Where-Object{$_.DisplayName -like "* Members"}).Id)
                            }
                        )
                    },
                    @{
                        durationBeforeAutomaticDenial = "P14D"
                        isApproverJustificationRequired = $true
                        isEscalationEnabled = $false
                        durationBeforeEscalation = "PT0S"
                        primaryApprovers = @(
                            @{
                                "@odata.type" = "#microsoft.graph.groupMembers"
                                groupId = $(($ServiceGroups|Where-Object{$_.DisplayName -like "* Members"}).Id)
                            }
                        )
                    }
                )
            }
        }    
    }

    process {
        foreach($package in $ServicePackages){
            $policyParams.accessPackage.id = $package.Id
            if($package.Id -notin $policies.AccessPackage.Id){
                try{
                    Write-Verbose "$logPrefix Assigning Policy for Access Package ID: $($package.Id)"
                    if($package.DisplayName -like "*Members*"){
                        $params = $policyParams + $initialPolicyParams
                        $policies += New-MgEntitlementManagementAssignmentPolicy -BodyParameter $params
                    }else{
                        $params = $policyParams + $baselinePolicyParams
                        $policies += New-MgEntitlementManagementAssignmentPolicy -BodyParameter $params
                    }
                }catch{
                    Write-Verbose "$logPrefix Failed to Assign Policy"
                    Write-Error $_
                }
            }
        }
    }

    end {
        $confirmed = $false
        $i = 0
        while(-not $confirmed){
            Start-Sleep -Seconds ([Math]::Pow(2,$i)-1)
            $checkPolicies = @()
            $checkPolicies = Get-MgEntitlementManagementAssignmentPolicy @policiesSplat
            if((Compare-Object $policies $checkPolicies|Measure-Object).Count -eq 0){
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
        return [psobject[]]$checkPolicies
    }
}