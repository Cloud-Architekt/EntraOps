<#
.SYNOPSIS
    Registers Entra security groups as resources inside an EM catalog.

.DESCRIPTION
    Submits adminAdd resource requests to onboard each provided Entra group
    as an AadGroup resource inside the specified Entitlement Management
    catalog. Only groups not already registered are onboarded.

    Idempotent: groups already present in the catalog (ResourceAlreadyOnboarded)
    are silently skipped.

    Note: Only owned (non-delegated) groups should be passed. Delegated groups
    are not catalog resources and must not be registered here.

.PARAMETER ServiceGroups
    Entra group objects to register as catalog resources. Pass only the
    $ownedGroups subset from New-EntraOpsServiceBootstrap (IsDelegated -ne true).

.PARAMETER ServiceCatalogId
    Object ID of the Entitlement Management catalog to register resources in.

.PARAMETER logPrefix
    Text prepended to verbose messages. Defaults to the function name.

.EXAMPLE
    New-EntraOpsServiceEMCatalogResource `
        -ServiceGroups ($groups | Where-Object { -not $_.IsDelegated }) `
        -ServiceCatalogId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

    Registers all owned service groups as AadGroup resources in the catalog.

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
        $resources = @()
        Write-Verbose "$logPrefix Looking up Catalog Resources"
        try{
            #Catalog Resource Registration
            $catalogResourceUri = "/v1.0/identityGovernance/entitlementManagement/catalogs/$ServiceCatalogId/resources?`$expand=roles,scopes"
            $resources += Invoke-EntraOpsMsGraphQuery -Method GET -Uri $catalogResourceUri -OutputType PSObject -DisableCache
        }catch{
            Write-Verbose "$logPrefix Failed to find Catalog Resources"
            Write-Error $_
        }
    }

    process {
        Write-Verbose "$logPrefix Beginning EM Catalog Resource"

        Write-Verbose "$logPrefix Processing $(($ServiceGroups|Measure-Object).Count) Catalog Resources"
        foreach($group in $ServiceGroups){
            $resourceRequestParam = @{
                requestType = "adminAdd"
                resource = @{
                    originId     = $group.Id
                    originSystem = "AadGroup"
                }
                catalog = @{
                    id = $ServiceCatalogId
                }
            }

            if($group.DisplayName -notin $resources.DisplayName){
                $added = Wait-EntraOpsServiceEMCondition -Activity "Group $($group.DisplayName) in Entitlement Management" -logPrefix $logPrefix -Condition {
                    try{
                        Write-Verbose "$logPrefix $($group.DisplayName) not found as catalog resource, adding"
                        $result = Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/resourceRequests" -Body ($resourceRequestParam | ConvertTo-Json -Depth 10) -OutputType PSObject -ErrorAction Stop
                        if($null -ne $result){
                            return $true
                        }
                        # null return means wrapper absorbed the error as a warning — treat as retriable
                        Write-Verbose "$logPrefix Resource request returned null — will retry"
                    }catch{
                        Write-Verbose "$logPrefix Failed to add catalog resource"
                        if($_.FullyQualifiedErrorId -like "ResourceAlreadyOnboarded*"){
                            Write-Verbose "$logPrefix Resource already onboarded"
                            return $true
                        }elseif($_.FullyQualifiedErrorId -like "ResourceNotFoundInOriginSystem*"){
                            # Expected right after group creation; Write-Error would stop callers with ErrorActionPreference Stop
                            Write-Verbose "$logPrefix Group not yet indexed by Entitlement Management, will retry"
                        }else{
                            Write-Warning "$logPrefix Unexpected error adding catalog resource: $($_.Exception.Message)"
                        }
                    }
                    return $false
                }
                if(-not $added){
                    throw "Group object consistency with Entitlement Management not achieved for $($group.DisplayName)"
                }
            }
        }
    }

    end {
        $check = @{}
        $confirmed = Wait-EntraOpsServiceEMCondition -Activity "Catalog resources" -logPrefix $logPrefix -Condition {
            $check.Resources = Invoke-EntraOpsMsGraphQuery -Method GET -Uri $catalogResourceUri -OutputType PSObject -DisableCache
            $refNames = @($ServiceGroups.DisplayName | Where-Object { $_ })
            $chkNames = @($check.Resources.DisplayName | Where-Object { $_ })
            $refNames.Count -gt 0 -and $chkNames.Count -ge $refNames.Count -and (Compare-Object $refNames $chkNames | Measure-Object).Count -eq 0
        }
        if(-not $confirmed){
            throw "Catalog Resource object consistency with Entra not achieved"
        }
        return [psobject[]]$check.Resources
    }
}