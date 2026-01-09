<#
.SYNOPSIS
    Removes all catalog resources and the catalog itself

.DESCRIPTION
    Admin removes any assignments, deletes access packages, and deletes the catalog.
    Must use Force switch.

.PARAMETER ServiceCatalogName
    The Service Catalog Display Name

.PARAMETER logPrefix
    Defines the text to prepend for any verbose messages

.EXAMPLE
    Remove-EntraOpsServiceCatalog -ServiceCatalogName "Catalog" -Force

#>
function Remove-EntraOpsServiceCatalog {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceCatalogName,

        [switch]$Force,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    process {
        if(-not $force){
            Write-Warning "$logPrefix Catalog and all associated assignments will be deleted, please use -Force switch to proceed"
            return @{}
        }
        $catalog = Get-MgEntitlementManagementCatalog -DisplayNameEq $ServiceCatalogName -ExpandProperty AccessPackages,Resources
        if(($catalog|Measure-Object).Count -eq 0){
            Write-Warning "$logPrefix Unable to obtain catalog by name"
            return @{}
        }
        Write-Verbose "$logPrefix Obtained Service Catalog $($catalog.Id)"
        foreach($accessPackage in $catalog.accessPackages){
            $assignments=Get-MgEntitlementManagementAssignment -AccessPackageId $accessPackage.Id -ExpandProperty Target
            foreach($assignment in $assignments|Where-Object{$_.State -ne "expired"}){
                Write-Verbose "$logPrefix Removing active assignment for $($assignment.Target.DisplayName)[$($assignment.Target.Email)]"
                $params = @{
                    requestType = "adminRemove"
                    assignment  = @{id=$assignment.Id}
                }
                $requests=New-MgEntitlementManagementAssignmentRequest -BodyParameter $params
                $confirmed = $false
                $i = 0
                while(-not $confirmed){
                    Start-Sleep -Seconds ([Math]::Pow(2,$i)-1)
                    $checkCatalogAssignments = @()
                    $checkCatalogAssignments += $requests|foreach{Get-MgEntitlementManagementAssignmentRequest -AccessPackageAssignmentRequestId $_.Id}
                    $fulfilled = $checkCatalogAssignments|Where-Object{$_.Status -ne "Fulfilled"}|Measure-Object
                    if($fulfilled.Count -ne ($checkCatalogAssignments|Measure-Object).Count){
                        Write-Verbose "$logPrefix Graph consistency found confirming"
                        $confirmed = $true
                        continue
                    }
                    $i++
                    if($i -gt 9){
                        throw "Role assignment requests not processed"
                    }
                    Write-Verbose "$logPrefix Graph objects are not available, sleeping $([Math]::Pow(2,$i)-1) seconds"
                }
            }
            Write-Verbose "$logPrefix Deleting $($accessPackage.DisplayName)[$($accessPackage.Id)]"
            Remove-MgEntitlementManagementAccessPackage -AccessPackageId $accessPackage.Id
        }
        Write-Verbose "$logPrefix Deleting Catalog"
        Remove-MgEntitlementManagementCatalog -AccessPackageCatalogId $catalog.Id
    }

    end {
        return @{}
    }
}
