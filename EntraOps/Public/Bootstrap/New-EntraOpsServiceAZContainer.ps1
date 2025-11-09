<#
.SYNOPSIS
    Creates an Azure Resource Group and assigns authorizations

.DESCRIPTION
    Creates an Azure Resource Group for the specific service, and provides
    mapping of authorizations for the groups

.PARAMETER ServiceName
    The Name of the Service

.PARAMETER ServiceGroups
    The Graph Group objects

.PARAMETER Location
    Set this to the preferred Azure Region for the Resource Group

.PARAMETER logPrefix
    Defines the text to prepend for any verbose messages

.EXAMPLE
    New-EntraOpsServiceAZContainer -ServiceName "EntraOps" -ServiceGroups $groups

#>
function New-EntraOpsServiceAZContainer {
    [OutputType([psobject])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,

        [Parameter(Mandatory)]
        [psobject[]]$ServiceGroups,

        [ValidateSet("Azure","PIM","Both")]
        [string]$rbacModel = "PIM",

        [switch]$pimForGroups,

        [string]$Location = "eastus",

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        try{
            Write-Verbose "$logPrefix Looking up Azure Resource Group"
            $resourceGroup = Get-AzResourceGroup -Name "RG-$serviceName" -ErrorAction Stop
        }catch{
            if($_.Exception.Message -like "*not exist."){
                Write-Verbose "$logPrefix Azure Resource Group not found, creating"
                $resourceGroup = New-AzResourceGroup -Name "RG-$serviceName" -Location $Location
                $confirmed = $false
                $i = 0
                while(-not $confirmed){
                    Start-Sleep -Seconds ([Math]::Pow(2,$i)-1)
                    $checkResourceGroup = Get-AzResourceGroup -Name "RG-$serviceName"
                    if(($checkResourceGroup|Measure-Object).Count -eq 1){
                        Write-Verbose "$logPrefix Azure consistency found confirming"
                        $confirmed = $true
                        continue
                    }
                    $i++
                    if($i -gt 5){
                        throw "Resource Group consistency with Azure not achieved"
                    }
                    Write-Verbose "$logPrefix Azure resources not available, sleeping $([Math]::Pow(2,$i)-1) seconds"
                }
            }else{
                Write-Verbose "$logPrefix Failed to lookup Azure Resource Group"
                Write-Error $_
            }
        }
        try{
            $owner           = Get-AzRoleDefinition -Name Owner
            $reader          = Get-AzRoleDefinition -Name Reader
            $userAccessAdmin = Get-AzRoleDefinition -Name "User Access Administrator"
            $contributor     = Get-AzRoleDefinition -Name Contributor
        }catch{
            Write-Verbose "$logPrefix Failed to find role definitions"
            Write-Error $_
        }
        $pimAdmins  = $ServiceGroups|Where-Object{$_.DisplayName -like "*-PIM-*"}
        $members    = $ServiceGroups|Where-Object{$_.DisplayName -like "*-Members-Management"}
        $control    = $ServiceGroups|Where-Object{$_.DisplayName -like "*-Admins-Control"}
        $management = $ServiceGroups|Where-Object{$_.DisplayName -like "*-Admins-Management"}
        $scheduleRequestParams = @{
            Name = ""
            RoleDefinitionId = ""
            PrincipalId = ""
            Scope = $resourceGroup.ResourceId
            RequestType = "AdminAssign"
            Justification = "Initial Bootstrap"
            #ExpirationDuration = "P1Y"
            ExpirationType = "NoExpiration" #AfterDuration
            ScheduleInfoStartDateTime = (Get-Date -Format o)
        }
        $roleDefinitionPrefix = "/Subscriptions/$((Get-AzContext).Subscription.Id)/providers/Microsoft.Authorization/roleDefinitions/"
        $rbacSet = @()
        $eligibleRbacSet = @()
        $toAdd = @()
    }

    process {
        if($rbacModel -in ("Azure","Both")){
            $rbacSet = @()
            try{
                Write-Verbose "$logPrefix Looking up Role Assignments for ID: $($resourceGroup.ResourceId)"
                $rbacSet += Get-AzRoleAssignment -Scope $resourceGroup.ResourceId
            }catch{
                Write-Verbose "$logPrefix Failed to get Role Assignments"
                Write-Error $_
            }
            $rbacSplat = @{
                ResourceGroupName = $resourceGroup.ResourceGroupName
            }
            if($pimForGroups -and "$($pimAdmins.Id)_$($owner.Id)" -notin ($rbacSet|ForEach-Object{"$($_.ObjectId)_$($_.RoleDefinitionId)"})){
                $rbacSplat.RoleDefinitionName = $owner.Name
                $rbacSplat.ObjectId = $pimAdmins.Id
                try{
                    Write-Verbose "$logPrefix Creating Role Assignment for ID: $($pimAdmins.Id)"
                    Write-Verbose "$logPrefix $($rbacSplat|ConvertTo-Json -Compress)"
                    $rbacSet += New-AzRoleAssignment @rbacSplat
                }catch{
                    Write-Verbose "$logPrefix Failed to create role assignment"
                    Write-Error $_
                }
            }
            if("$($members.Id)_$($reader.Id)" -notin ($rbacSet|ForEach-Object{"$($_.ObjectId)_$($_.RoleDefinitionId)"})){
                $rbacSplat.RoleDefinitionName = $reader.Name
                $rbacSplat.ObjectId = $members.Id
                try{
                    Write-Verbose "$logPrefix Creating Role Assignment for ID: $($members.Id)"
                    Write-Verbose "$logPrefix $($rbacSplat|ConvertTo-Json -Compress)"
                    $rbacSet += New-AzRoleAssignment @rbacSplat
                }catch{
                    Write-Verbose "$logPrefix Failed to create role assignment"
                    Write-Error $_
                }
            }
        }

        if($rbacModel -in ("PIM","Both")){
            try{
                Write-Verbose "$logPrefix Getting PIM Eligible Assignments"
                $existing = Get-AzRoleEligibilitySchedule -Scope $resourceGroup.ResourceId
                $eligibleRbacSet += $existing|Select-Object @{n="c";e={$_.RoleDefinitionDisplayName + "_" + $_.PrincipalId}}|ForEach-Object c
            }catch{
                Write-Verbose "$logPrefix Failed to get PIM Eligible Assignments"
                Write-Error $_
            }

            if("$($reader.Name)_$($members.Id)" -notin $eligibleRbacSet){
                $toAdd += @{
                    RoleDefinitionId = "$roleDefinitionPrefix/$($reader.Id)"
                    RoleId = $reader.Id
                    PrincipalId = $members.Id
                }
            }
            if("$($contributor.Name)_$($management.Id)" -notin $eligibleRbacSet){
                $toAdd += @{
                    RoleDefinitionId = "$roleDefinitionPrefix/$($contributor.Id)"
                    RoleId = $contributor.Id
                    PrincipalId = $management.Id
                }
            }
            if("$($userAccessAdmin.Name)_$($control.Id)" -notin $eligibleRbacSet){
                $toAdd += @{
                    RoleDefinitionId = "$roleDefinitionPrefix/$($userAccessAdmin.Id)"
                    RoleId = $userAccessAdmin.Id
                    PrincipalId = $control.Id
                }
            }
            
            foreach($add in $toAdd){
                $scheduleRequestParams.Name = [guid]::NewGuid()
                $scheduleRequestParams.RoleDefinitionId = $add.RoleDefinitionId
                $scheduleRequestParams.PrincipalId = $add.PrincipalId

                try{
                    Write-Verbose "$logPrefix Getting role management policy for: $($add.RoleId)"
                    $policy = Get-AzRoleManagementPolicy -Scope $scheduleRequestParams.Scope -Name $add.RoleId
                }catch{
                    Write-Verbose "$logPrefix Failed to get role management policy"
                    Write-Error $_
                }
                if(($policy.Rule|Where-Object{$_.Id -eq "Expiration_Admin_Eligibility"}).IsExpirationRequired){
                    Write-Verbose "$logPrefix Policy requires eligible expiration, updating"
                    $roleManagementPolicySplat = @{
                        Scope = $resourceGroup.ResourceId
                        Name = $add.RoleId
                        Rules = @{
                            id = "Expiration_Admin_Eligibility"
                            IsExpirationRequired = $false
                            ruleType = "RoleManagementPolicyExpirationRule"
                        }
                    }
                    try{
                        Update-AzRoleManagementPolicy @roleManagementPolicySplat
                    }catch{
                        Write-Verbose "$logPrefix Failed to update role management policy rules"
                        Write-Error $_
                    }
                }

                try{
                    Write-Verbose "$logPrefix Creating PIM Eligible Assignment for PrincipalId: $($add.PrincipalId)"
                    $rbacSet += New-AzRoleEligibilityScheduleRequest @scheduleRequestParams
                }catch{
                    Write-Verbose "$logPrefix Failed to create PIM Eligible Assignment"
                    Write-Error $_
                }
            }
        }
    }

    end {
        return [psobject]$resourceGroup
    }
}