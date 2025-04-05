<#
.SYNOPSIS
    Creates an Entra Group based on the provided role

.DESCRIPTION
    Creates an Entra Group relative to the specific role supplied. Unless for
    custom implementations, should be used by New-EntraOpsServiceBootstrap.

.PARAMETER ServiceName
    The Name of the Service

.PARAMETER ServiceOwner
    The Graph URL of a User.
    "https://graph.microsoft.com/v1.0/users/<ID>"

.PARAMETER ServiceRoles
    An EntraOps Service Roles object

.PARAMETER logPrefix
    Prefix used for log messages. Default is current function name.

.EXAMPLE
    New-EntraOpsServiceEntraGroup -ServiceName "EntraOps" -ServiceOwner $ownerUri -ServiceRoles $roles

    Returns all groups for a specific service

#>
function New-EntraOpsServiceEntraGroup {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,

        [Parameter(Mandatory)]
        [string]$ServiceOwner,

        [Parameter(Mandatory)]
        [psobject[]]$ServiceRoles,

        [Parameter()]
        [switch]$IsAssignableToRole,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        try{
            #Groups
            $groups = @()
            Write-Verbose "$logPrefix Looking up Groups"
            $groups += Get-MgGroup -Search "MailNickname:$ServiceName." -ConsistencyLevel eventual
            $groups += Get-MgGroup -Search "MailNickname:PIM.$ServiceName." -ConsistencyLevel eventual
        }catch{
            Write-Verbose "$logPrefix Failed processing Groups"
            Write-Error $_
        }
        $groupParams = @{
            Description = ""
            SecurityEnabled = $true
            IsAssignableToRole = $IsAssignableToRole
            "owners@odata.bind" = @($ServiceOwner)
        }
        $unifiedParams = $groupParams + @{
            DisplayName = ""
            MailNickname = ""
            GroupTypes = @("Unified")
            MailEnabled = $true
            #"members@odata.bind" = $members
        }
        $secParams = $groupParams + @{
            DisplayName = ""
            MailNickname = ""
            MailEnabled = $false
        }
    }

    process {
        Write-Verbose "$logPrefix Processing $(($ServiceRoles|Measure-Object).Count) Groups"
        foreach($ServiceRole in $ServiceRoles){
            $unifiedParams.Description = "Team $(($ServiceRole.type +" "+ $ServiceRole.name).trim()) supporting $ServiceName"
            $unifiedParams.DisplayName = "$ServiceName $($ServiceRole.Name)"
            $unifiedParams.MailNickname = "$ServiceName.$($ServiceRole.Name)"
            $secParams.Description = "Team $(($ServiceRole.type +" "+ $ServiceRole.name).trim()) supporting $ServiceName"
            $secParams.DisplayName = "SG-$ServiceName-$($ServiceRole.Name)-$($ServiceRole.type)"
            $secParams.MailNickname = "$ServiceName.$($ServiceRole.Name +"."+ $ServiceRole.type)"
            try{
                if($ServiceRole.groupType -eq "Unified" -and $groups.MailNickname -notcontains $unifiedParams.MailNickname){
                    Write-Verbose "$logPrefix $($unifiedParams|ConvertTo-Json -Compress)"
                    $groups += New-MgGroup -BodyParameter $unifiedParams
                }elseif($ServiceRole.groupType -like "" -and $groups.MailNickname -notcontains $secParams.MailNickname){
                    Write-Verbose "$logPrefix $($secParams|ConvertTo-Json -Compress)"
                    $groups += New-MgGroup -BodyParameter $secParams
                    if($ServiceRole.type -eq "Management" -and $ServiceRole.name -eq "Admins"){
                        $secParams.DisplayName = "SG-PIM-$ServiceName-$($ServiceRole.Name)-$($ServiceRole.type)"
                        $secParams.MailNickname = "PIM.$ServiceName.$($ServiceRole.Name +"."+ $ServiceRole.type)"
                        $groups += New-MgGroup -BodyParameter $secParams
                    }
                }
            }catch{
                Write-Verbose "$logPrefix Failed processing Groups"
                Write-Error $_
            }
        }
    }

    end {
        $confirmed = $false
        $i = 0
        Write-Verbose "$logPrefix Verifying Groups are available"
        while(-not $confirmed){
            Start-Sleep -Seconds ([Math]::Pow(2,$i)-1)
            $checkGroups = @()
            $checkGroups += Get-MgGroup -Search "MailNickname:$ServiceName." -ConsistencyLevel eventual
            $checkGroups += Get-MgGroup -Search "MailNickname:PIM.$ServiceName." -ConsistencyLevel eventual
            if((Compare-Object $groups $checkGroups|Measure-Object).Count -eq 0){
                Write-Verbose "$logPrefix Graph consistency found confirming"
                $confirmed = $true
                continue
            }
            $i++
            if($i -gt 5){
                throw "Group object consistency with Entra not achieved"
            }
            Write-Verbose "$logPrefix Graph objects are not available, sleeping $([Math]::Pow(2,$i)-1) seconds"
        }
        return [psobject[]]$checkGroups
    }
}
