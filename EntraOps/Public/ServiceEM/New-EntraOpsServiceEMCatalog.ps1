<#
.SYNOPSIS
    Creates an Entitlement Management catalog for the service.

.DESCRIPTION
    Creates (or looks up) an Entitlement Management catalog named
    "Catalog-<ServiceName>". The catalog is the container for all
    access packages, resources, and role assignments that make up
    the service's authorization structure.

    Idempotent: if a catalog with the same display name already exists,
    it is returned without modification.

.PARAMETER ServiceName
    Name of the service. The catalog will be named "Catalog-<ServiceName>".

.PARAMETER logPrefix
    Text prepended to verbose messages. Defaults to the function name.

.EXAMPLE
    New-EntraOpsServiceEMCatalog -ServiceName "MyService"

    Creates (or returns the existing) catalog named "Catalog-MyService".

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
        $catalogDisplayName = "Catalog-$ServiceName"
        $encodedCatalogDisplayName = ConvertTo-EntraOpsODataStringLiteral -Value $catalogDisplayName
        try {
            Write-Verbose "$logPrefix Looking up Catalog"
            $catalog = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/catalogs?`$filter=displayName eq '$encodedCatalogDisplayName'&`$expand=accessPackages,resources" -OutputType PSObject -DisableCache
        } catch {
            Write-Verbose "$logPrefix Failed to find Catalog — will attempt create and handle DuplicateCatalog"
            Write-Error $_
        }
    }

    process {
        Write-Verbose "$logPrefix Beginning EM Catalog"

        try {
            if (-not $catalog) {
                Write-Verbose "$logPrefix Creating Catalog"
                $catalog = Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/catalogs" -Body (@{displayName = $catalogDisplayName } | ConvertTo-Json) -OutputType PSObject
            }
        } catch {
            # DuplicateCatalog (400) means the catalog exists but the initial lookup failed
            # (e.g. due to a transient GatewayTimeout). Retry the lookup before giving up.
            if ($_.FullyQualifiedErrorId -like "DuplicateCatalog*" -or $_.Exception.Message -like "*DuplicateCatalog*") {
                Write-Verbose "$logPrefix DuplicateCatalog — retrying lookup"
                try {
                    $catalog = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/catalogs?`$filter=displayName eq '$encodedCatalogDisplayName'&`$expand=accessPackages,resources" -OutputType PSObject -DisableCache
                    Write-Verbose "$logPrefix Recovered catalog via retry lookup: $($catalog.Id)"
                } catch {
                    Write-Verbose "$logPrefix Retry lookup also failed"
                    Write-Error $_
                }
            } else {
                Write-Verbose "$logPrefix Failed to create Catalog"
                Write-Error $_
            }
        }
    }

    end {
        if (-not $catalog -or -not $catalog.Id) {
            throw "Catalog '$catalogDisplayName' could not be created or found. Check the previous errors and the EntitlementManagement.ReadWrite.All permission."
        }
        $check = @{}
        $confirmed = Wait-EntraOpsServiceEMCondition -Activity "Catalog $catalogDisplayName" -logPrefix $logPrefix -Condition {
            $check.Catalog = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/catalogs?`$filter=displayName eq '$encodedCatalogDisplayName'&`$expand=accessPackages,resources" -OutputType PSObject -DisableCache
            $check.Catalog -and $check.Catalog.Id -eq $catalog.Id
        }
        if (-not $confirmed) {
            throw "Catalog object consistency with Entra not achieved"
        }
        return [psobject]$catalog
    }
}