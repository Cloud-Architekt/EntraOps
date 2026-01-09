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
function New-EntraOpsSubscriptionLandingZoneAlt {
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

        [switch]$Smb,

        [pscustomobject[]]$LandingZoneComponents = @(
            [pscustomobject]@{name = "Admins"; type = "Management"; groupType = ""},
            [pscustomobject]@{name = "Members"; type = "Management"; groupType = ""},
            [pscustomobject]@{name = "Admins"; type = "Workload"; groupType = ""},
            [pscustomobject]@{name = "Members"; type = "Workload"; groupType = ""},
            [pscustomobject]@{name = "Admins"; type = "Control"; groupType = ""},
            [pscustomobject]@{name = "Members"; type = ""; groupType = "Unified"},
            [pscustomobject]@{name = "Members"; type = "Catalog"; groupType = ""},
            [pscustomobject]@{name = "Users"; type = "Workload"; groupType = ""}
        ),

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $report = @()
    }

    process {
        Write-Verbose "$logPrefix Processing LZ"

        $splatServiceBootstrap = @{
            ServiceName             = $DeploymentPrefix
            OwnerIsNotMember        = $OwnerIsNotMember
            ProhibitDirectElevation = $ProhibitDirectElevation
            AzureRegion             = $AzureRegion
            ServiceRoles            = $LandingZoneComponents
            ServiceMembers          = $ServiceMembers
            ServiceOwner            = $ServiceOwner
            SkipAzureResourceGroup  = $SkipAzureResourceGroup
        }
        $report += New-EntraOpsServiceBootstrap @splatServiceBootstrap

        return $report
    }
}