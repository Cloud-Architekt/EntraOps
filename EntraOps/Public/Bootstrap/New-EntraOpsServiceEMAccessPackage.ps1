<#
.SYNOPSIS
    Creates access packages

.DESCRIPTION
    Creates an access package in the catalog for the roles

.PARAMETER ServiceName
    The Name of the Service

.PARAMETER ServiceCatalogId
    The Service Catalog GUID

.PARAMETER ServiceRoles
    The EntraOps Service Roles object

.PARAMETER logPrefix
    Defines the text to prepend for any verbose messages

.EXAMPLE
    New-EntraOpsServiceEMAccessPackage -ServiceName "EntraOps" -ServiceCatalogId "<GUID>" -ServiceRoles $roles

#>
function New-EntraOpsServiceEMAccessPackage {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,

        [Parameter(Mandatory)]
        [string]$ServiceCatalogId,

        [Parameter(Mandatory)]
        [psobject[]]$ServiceRoles,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $accessPackageOptions = @{
            ExpandProperty = @("resourceRoleScopes(`$expand=role,scope)","Catalog")
            Filter         = "Catalog/Id eq '$($ServiceCatalogId)'"
        }
        Write-Verbose "$logPrefix Looking up Access Packages"
        try{
            $ServiceAccessPackages = @()
            $ServiceAccessPackages += Get-MgEntitlementManagementAccessPackage @accessPackageOptions
        }catch{
            Write-Verbose "$logPrefix Failed to find Access Packages"
            Write-Error $_
        }
    }

    process {
        Write-Verbose "$logPrefix Processing $(($ServiceRoles|Where-Object{$_.groupType -ne "Unified"}|Measure-Object).Count) Access Package Roles"
        foreach($role in $ServiceRoles|Where-Object{$_.groupType -ne "Unified"}){
            $packageParams = @{
                catalog = @{
                    id = $ServiceCatalogId
                }
                DisplayName = "AP-$ServiceName-$($role.name +"-"+ $role.type)"
                Description = "Access Package for $ServiceName $($role.type +" "+ $role.name)"
            }
            if($packageParams.DisplayName -notin $ServiceAccessPackages.DisplayName){
                try{
                    Write-Verbose "$logPrefix Creating Access Package"
                    $ServiceAccessPackages += New-MgEntitlementManagementAccessPackage -BodyParameter $packageParams
                }catch{
                    Write-Verbose "$logPrefix Failed to create Access Package"
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
            $checkServiceAccessPackages = @()
            $checkServiceAccessPackages = Get-MgEntitlementManagementAccessPackage @accessPackageOptions
            if((Compare-Object $ServiceAccessPackages $checkServiceAccessPackages|Measure-Object).Count -eq 0){
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
        return [psobject[]]$checkServiceAccessPackages
    }
}