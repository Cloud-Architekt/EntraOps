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
function New-EntraOpsLandingZone {
    [OutputType([System.String])]
    [cmdletbinding()]
    param(
        [string[]]$ServiceMembers,

        [string]$ServiceOwner,

        [switch]$OwnerIsNotMember,  

        [switch]$ProhibitDirectElevation,

        [string]$AzureRegion = "eastus",

        [pscustomobject[]]$LandingZoneComponents = @(
            [pscustomobject]@{
                Role = "Billing"
                Components = @(
                    "Bill-Organization"
                )
                ServiceRole = @(
                    [pscustomobject]@{name = "Members"; type = ""; groupType = "Unified"},
                    [pscustomobject]@{name = "Members"; type = "Management"; groupType = ""},
                    [pscustomobject]@{name = "Admins"; type = "Management"; groupType = ""}
                )
            },
            [pscustomobject]@{
                Role = "Mgs"
                Components = @(
                    "Tenant Root Group",
                    "MG-Platform",
                    "MG-Production",
                    "MG-Build"
                )
                ServiceRole = @(
                    [pscustomobject]@{name = "Members"; type = ""; groupType = "Unified"},
                    [pscustomobject]@{name = "Members"; type = "Management"; groupType = ""},
                    [pscustomobject]@{name = "Admins"; type = "Entitlement"; groupType = ""},
                    [pscustomobject]@{name = "Admins"; type = "Control"; groupType = ""}
                )
            },
            [pscustomobject]@{
                Role = "Subs"
                Components = @(
                    "Sub-Management",
                    "Sub-Identity",
                    "Sub-Connectivity",
                    "Sub-Prod-Decommissioned",
                    "Sub-Prod-Platfrom",
                    "Sub-Prod-App",
                    "Sub-Build-Decommissioned",
                    "Sub-Build-Platfrom",
                    "Sub-Build-App"
                )
                ServiceRole = @(
                    [pscustomobject]@{name = "Members"; type = ""; groupType = "Unified"},
                    [pscustomobject]@{name = "Members"; type = "Management"; groupType = ""},
                    [pscustomobject]@{name = "Admins"; type = "Control"; groupType = ""}
                )
            },
            [pscustomobject]@{
                Role = "Rg"
                Components = @(
                    "Rg-Default"
                )
                ServiceRole = @(
                    [pscustomobject]@{name = "Members"; type = ""; groupType = "Unified"},
                    [pscustomobject]@{name = "Members"; type = "Management"; groupType = ""},
                    [pscustomobject]@{name = "Users"; type = "Workload"; groupType = ""},
                    [pscustomobject]@{name = "Admins"; type = "Workload"; groupType = ""},
                    [pscustomobject]@{name = "Admins"; type = "Entitlement"; groupType = ""},
                    [pscustomobject]@{name = "Admins"; type = "Management"; groupType = ""}
                )
            }
        ),

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $report = @{}
    }

    process {
        Write-Verbose "$logPrefix Processing LZ"

        foreach($role in $LandingZoneComponents){
            Write-Verbose "$logPrefix Processing LZ Role: $($role.Role)"
            $report|Add-Member -MemberType NoteProperty -Name $role.Role -Value @{}
            foreach($component in $role.Components){
                Write-Verbose "$logPrefix Processing LZ Components: $($component)"
                $report.$($role.Role)|Add-Member -MemberType NoteProperty -Name $component -Value @{}
                $splatServiceBootstrap = @{
                    ServiceName = $component
                    ServiceMembers = $ServiceMembers
                    ServiceOwner = $ServiceOwner
                    OwnerIsNotMember = $OwnerIsNotMember
                    ProhibitDirectElevation = $ProhibitDirectElevation
                    AzureRegion = $AzureRegion
                    ServiceRoles = $role.ServiceRole
                }
                $report.$($role.Role).$component = New-EntraOpsServiceBootstrap @splatServiceBootstrap
            }
        }
        

        #$report.BillingAccount = New-EntraOpsServiceBootstrap -
        #$report.

        return $report
    }
}