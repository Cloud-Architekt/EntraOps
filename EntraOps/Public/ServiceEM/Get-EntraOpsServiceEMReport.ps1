<#
.SYNOPSIS
    Returns a structured report of all Entitlement Management resources in the tenant.

.DESCRIPTION
    Reads all Entra ID Entitlement Management catalogs and, for each catalog, collects
    the catalog role assignments, registered resources, access packages (including
    their resource role scopes, assignment policies, and all active delivered
    assignments). Returns one object per catalog — suitable for auditing, change
    detection, or validating the state of ServiceEM-provisioned authorization
    structures. No parameters are required; the function reads from the tenant the
    signed-in context has access to.

.EXAMPLE
    Get-EntraOpsServiceEMReport

    Returns a report for every catalog in the tenant, including nested access
    packages, assignment policies, and active member assignments.

.EXAMPLE
    $report = Get-EntraOpsServiceEMReport
    $report | Where-Object { $_.Catalog.DisplayName -like "Catalog-MyService" }

    Filters the full report to the catalog that belongs to "MyService".

#>
function Get-EntraOpsServiceEMReport {
    [OutputType([psobject])]
    [cmdletbinding()]
    param()

    begin {
        $logPrefix = "[$($MyInvocation.MyCommand)]"

        $entraOps = @()        
    }

    process {
        Write-Verbose "$logPrefix Obtaining Catalogs"
        $catalogs = @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/catalogs?`$expand=accessPackages,resources" -OutputType PSObject)
        $entraOpsCatalogs = @()
        foreach($catalog in $catalogs){
            Write-Verbose "$logPrefix Processing Catalog $($catalog.DisplayName)"
            Write-Verbose "$logPrefix Obtaining Catalog Role Assignments"
            $catalogRoles = @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/roleManagement/entitlementManagement/roleAssignments?`$filter=appScopeId eq '/AccessPackageCatalog/$($catalog.Id)'&`$expand=principal,roleDefinition" -OutputType PSObject)

            $catalogResources = @()
            foreach($catalogResource in $catalog.Resources){
                Write-Verbose "$logPrefix Processing Catalog Resource $($catalogResource.DisplayName)"
                Write-Verbose "$logPrefix Obtaining Catalog Resource"
                $catalogResources += @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/catalogs/$($catalog.Id)/resourceRoles?`$filter=originSystem eq '$($catalogResource.OriginSystem)' and resource/id eq '$($catalogResource.id)'&`$expand=resource" -OutputType PSObject)
            }

            Write-Verbose "$logPrefix Obtaining Access Packages"
            $accessPackages = @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/accessPackages?`$filter=catalog/id eq '$($catalog.Id)'&`$expand=resourceRoleScopes(`$expand=role,scope),catalog,assignmentPolicies" -OutputType PSObject)
            $entraOpsAccessPackages = @()
            foreach($accessPackage in $accessPackages){
                Write-Verbose "$logPrefix Processing Access Package $($accessPackage.DisplayName)"
                $policies = $accessPackage.AssignmentPolicies

                Write-Verbose "$logPrefix Obtaining Access Package Assignments"
                $assignments = @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/assignments?`$filter=accessPackage/catalog/id eq '$($catalog.Id)' and state eq 'delivered'&`$expand=accessPackage(`$expand=catalog),accessPackage,target,assignmentPolicy" -OutputType PSObject)

                $entraOpsAccessPackageResources = @()
                foreach($resource in $accessPackage.ResourceRoleScopes.Role){
                    Write-Verbose "$logPrefix Processing Access Package Resource $($resource.OriginId)"
                    $entraOpsAccessPackageResources += $catalogResources | `
                        Where-Object {$_.OriginId -eq $resource.OriginId}
                }

                $entraOpsAccessPackages += [pscustomobject]@{
                    AccessPackage = $accessPackage
                    Policies      = $policies
                    Assignments   = $assignments
                    Resources     = $entraOpsAccessPackageResources
                }
            }

            $entraOpsCatalogs += [pscustomobject]@{
                Catalog          = $catalog
                CatalogRoles     = $catalogRoles
                CatalogResources = $catalogResources
                AccessPackages   = $entraOpsAccessPackages
            }
        }

        $entraOps += [pscustomobject]@{
            TenantId     = (Get-MgContext).TenantId
            InvokingUser = (Get-MgContext).Account
            Catalogs     = $entraOpsCatalogs
        }

        return $entraOps
    }
}