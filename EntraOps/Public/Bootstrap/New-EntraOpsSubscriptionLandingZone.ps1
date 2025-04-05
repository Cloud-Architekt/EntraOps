<#
.SYNOPSIS
    Creates the necessary authorization structure for a new service

.DESCRIPTION
    Creates the foundation for handling authorization of a new service
    in alignment with the Microsoft Enterprise Access Model.

.PARAMETER ServiceName
    The Name of the Service

.PARAMETER logPrefix
    Defines the text to prepend for any verbose messages

.EXAMPLE
    New-EntraOpsServiceBootstrap

#>
function New-EntraOpsSubscriptionLandingZone {
    [OutputType([System.String])]
    [cmdletbinding()]
    param(
        [string[]]$ServiceMembers,

        [string]$ServiceOwner,

        [switch]$OwnerIsNotMember,  

        [switch]$ProhibitDirectElevation,

        [switch]$SkipAzureResourceGroup,

        [string]$AzureRegion = "eastus",

        [string]$DeploymentPrefix = "Default",

        [pscustomobject[]]$LandingZoneComponents = @(
            [pscustomobject]@{
                Role = "Sub"
                ServiceRole = @(
                    [pscustomobject]@{name = "Members"; type = ""; groupType = "Unified"},
                    [pscustomobject]@{name = "Members"; type = "Management"; groupType = ""},
                    [pscustomobject]@{name = "Admins"; type = "Control"; groupType = ""}
                )
            },
            [pscustomobject]@{
                Role = "Rg"
                ServiceRole = @(
                    [pscustomobject]@{name = "Members"; type = ""; groupType = "Unified"},
                    [pscustomobject]@{name = "Members"; type = "Management"; groupType = ""},
                    [pscustomobject]@{name = "Users"; type = "Workload"; groupType = ""},
                    [pscustomobject]@{name = "Admins"; type = "Workload"; groupType = ""},
                    [pscustomobject]@{name = "Admins"; type = "Control"; groupType = ""},
                    [pscustomobject]@{name = "Admins"; type = "Management"; groupType = ""}
                )
            }
        ),

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $report = @()
    }

    process {
        Write-Verbose "$logPrefix Processing LZ"

        foreach($component in $LandingZoneComponents){
            Write-Verbose "$logPrefix Processing LZ Role: $($component.Role)"

            $splatServiceBootstrap = @{
                ServiceName             = $component.Role + "-" + $DeploymentPrefix
                OwnerIsNotMember        = $OwnerIsNotMember
                ProhibitDirectElevation = $ProhibitDirectElevation
                AzureRegion             = $AzureRegion
                ServiceRoles            = $component.ServiceRole
            }
            if($component.Role -eq "Sub"){
                $splatServiceBootstrap += @{
                    ServiceMembers         = $ServiceMembers
                    ServiceOwner           = $ServiceOwner
                    SkipAzureResourceGroup = $true
                }
            }else{
                $splatServiceBootstrap += @{
                    SkipAzureResourceGroup = $SkipAzureResourceGroup
                }
            }
            $report += New-EntraOpsServiceBootstrap @splatServiceBootstrap
        }

        return $report
    }
}