<#
.SYNOPSIS
    Creates the resources in a catalog

.DESCRIPTION
    Registers the groups as resources for the catalog

.PARAMETER ServiceGroups
    The Graph Group objects

.PARAMETER ServiceCatalogId
    The Service Catalog GUID

.PARAMETER logPrefix
    Defines the text to prepend for any verbose messages

.EXAMPLE
    New-EntraOpsServiceEMCatalogResource -ServiceGroups $groups -ServiceCatalogId "<GUID>"

#>
function New-EntraOpsServiceEMCatalogResource {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [psobject[]]$ServiceGroups,

        [Parameter(Mandatory)]
        [string]$ServiceCatalogId,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $resourceRequests = @()
        $resources = @()
        Write-Verbose "$logPrefix Looking up Catalog Resources"
        try{
            #Catalog Resource Registration
            $resourceOptions = @{
                AccessPackageCatalogId = $ServiceCatalogId
                ExpandProperty         = @("Roles","Scopes")
            }
            $resources += Get-MgEntitlementManagementCatalogResource @resourceOptions
        }catch{
            Write-Verbose "$logPrefix Failed to find Catalog Resources"
            Write-Error $_
        }
    }

    process {
        Write-Verbose "$logPrefix Processing $(($ServiceGroups|Measure-Object).Count) Catalog Resources"
        foreach($group in $ServiceGroups){
            $resourceRequestParam = @{
                requestType = "adminAdd"
                resource    = @{
                    originId     = $group.Id
                    originSystem = "AadGroup"
                }
                catalog     = @{
                    id           = $ServiceCatalogId
                }
            }

            if($group.DisplayName -notin $resources.DisplayName){
                $confirmed = $false
                $i = 0
                while(-not $confirmed){
                    Start-Sleep -Seconds ([Math]::Pow(2,$i)-1)
                    try{
                        Write-Verbose "$logPrefix $($group.DisplayName) not found as catalog resource, adding"
                        $resourceRequests += New-MgEntitlementManagementResourceRequest -BodyParameter $resourceRequestParam -ErrorAction Stop
                        $confirmed = $true
                        continue
                    }catch{
                        Write-Verbose "$logPrefix Failed to add catalog resource"
                        if($_.FullyQualifiedErrorId -like "ResourceAlreadyOnboarded*"){
                            Write-Verbose "$logPrefix Resource already onboarded"
                            $confirmed = $true
                            continue
                        }elseif($_.FullyQualifiedErrorId -like "ResourceNotFoundInOriginSystem*"){
                            Write-Verbose "$logPrefix group not available in Entitlement Management"
                            Write-Error $_
                        }else{
                            Write-Verbose "$logPrefix unknown failure reason, retrying"
                            Write-Error $_
                        }
                    }
                    $i++
                    if($i -gt 5){
                        throw "Group object consistency with Entitlement Management not achieved"
                    }
                    Write-Verbose "$logPrefix Group objects not available, sleeping $([Math]::Pow(2,$i)-1) seconds"
                }
            }
        }
    }

    end {
        $confirmed = $false
        $i = 0
        while(-not $confirmed){
            Start-Sleep -Seconds ([Math]::Pow(2,$i)-1)
            $checkResources = @()
            $checkResources = Get-MgEntitlementManagementCatalogResource @resourceOptions
            if((Compare-Object $ServiceGroups.DisplayName $checkResources.DisplayName|Measure-Object).Count -eq 0){
                Write-Verbose "$logPrefix Graph consistency found confirming"
                $confirmed = $true
                continue
            }
            $i++
            if($i -gt 5){
                throw "Catalog Resource object consistency with Entra not achieved"
            }
            Write-Verbose "$logPrefix Graph objects not available, sleeping $([Math]::Pow(2,$i)-1) seconds"
        }
        return [psobject[]]$checkResources
    }
}