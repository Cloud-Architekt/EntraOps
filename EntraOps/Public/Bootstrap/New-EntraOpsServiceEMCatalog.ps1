<#
.SYNOPSIS
    Creates a catalog

.DESCRIPTION
    Creates an Entitlement Management Catalog

.PARAMETER ServiceName
    The Name of the Service

.PARAMETER logPrefix
    Defines the text to prepend for any verbose messages

.EXAMPLE
    New-EntraOpsServiceEMCatalog -ServiceName "EntraOps"

#>
function New-EntraOpsServiceEMCatalog {
    [OutputType([psobject])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        try{
            Write-Verbose "$logPrefix Looking up Catalog"
            $catalog = Get-MgEntitlementManagementCatalog -DisplayNameEq "Catalog-$ServiceName" -ExpandProperty AccessPackages,Resources
        }catch{
            Write-Verbose "$logPrefix Failed to find Catalog"
            Write-Error $_
        }
    }

    process {
        try{
            if(-not $catalog){
                Write-Verbose "$logPrefix Creating Catalog"
                $catalog = New-MgEntitlementManagementCatalog -DisplayName "Catalog-$ServiceName"
            }
        }catch{
            Write-Verbose "$logPrefix Failed to create Catalog"
            Write-Error $_
        }
    }

    end {
        $confirmed = $false
        $i = 0
        while(-not $confirmed){
            Start-Sleep -Seconds ([Math]::Pow(2,$i)-1)
            $checkCatalog = @()
            $checkCatalog = Get-MgEntitlementManagementCatalog -DisplayNameEq "Catalog-$ServiceName" -ExpandProperty AccessPackages,Resources
            if((Compare-Object $catalog $checkCatalog|Measure-Object).Count -eq 0){
                Write-Verbose "$logPrefix Graph consistency found confirming"
                $confirmed = $true
                continue
            }
            $i++
            if($i -gt 5){
                throw "Catlog object consistency with Entra not achieved"
            }
            Write-Verbose "$logPrefix Graph objects not available, sleeping $([Math]::Pow(2,$i)-1) seconds"
        }
        return [psobject]$catalog
    }
}