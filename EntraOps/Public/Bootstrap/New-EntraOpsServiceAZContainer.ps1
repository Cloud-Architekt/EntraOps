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
            $owner = Get-AzRoleDefinition -Name Owner
            $reader = Get-AzRoleDefinition -Name Reader
        }catch{
            Write-Verbose "$logPrefix Failed to fine role definitions"
            Write-Error $_
        }
        $pimAdmins = $ServiceGroups|Where-Object{$_.DisplayName -like "*-PIM-*"}
        $members = $ServiceGroups|Where-Object{$_.DisplayName -like "*-Members-*"}
        $rbacSet = @()
    }

    process {
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
        if("$($pimAdmins.Id)_$($owner.Id)" -notin ($rbacSet|ForEach-Object{"$($_.ObjectId)_$($_.RoleDefinitionId)"})){
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

    end {
        return [psobject]$resourceGroup
    }
}