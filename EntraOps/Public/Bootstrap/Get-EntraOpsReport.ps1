<#
.SYNOPSIS
    Obtain the Entitlement Management resources in a tenant

.DESCRIPTION
    Creates a reporting object that defines the objects and relationships.

#>
function Get-EntraOpsReport {
    [OutputType([psobject])]
    [cmdletbinding()]
    param()

    begin {
        $logPrefix = "[$($MyInvocation.MyCommand)]"

        $entraOps = @()        
    }

    process {
        $catalogsOptions = @{
            ExpandProperty = @("AccessPackages","Resources")
        }
        Write-Verbose "$logPrefix Obtaining Catalogs"
        $catalogs = @(Get-MgEntitlementManagementCatalog @catalogsOptions)
        $entraOpsCatalogs = @()
        foreach($catalog in $catalogs){
            Write-Verbose "$logPrefix Processing Catalog $($catalog.DisplayName)"
            $catalogRolesSplat = @{
                ExpandProperty = @("Principal","RoleDefinition")
                Filter         = "AppScopeId eq '/AccessPackageCatalog/$($catalog.Id)'"
            }
            Write-Verbose "$logPrefix Obtaining Catalog Role Assignments"
            $catalogRoles = @(Get-MgRoleManagementEntitlementManagementRoleAssignment @catalogRolesSplat)

            $catalogResources = @()
            foreach($catalogResource in $catalog.Resources){
                Write-Verbose "$logPrefix Processing Catalog Resource $($catalogResource.DisplayName)"
                $roleSplat = @{
                    AccessPackageCatalogId  = $($catalog.Id)
                    Filter                  = "originSystem eq '$($catalogResource.OriginSystem)' and resource/id eq '$($catalogResource.id)'"
                }
                Write-Verbose "$logPrefix Obtaining Catalog Resource"
                $catalogResources += @(Get-MgEntitlementManagementCatalogResourceRole @roleSplat -ExpandProperty Resource)
            }

            $accessPackagesOptions = @{
                ExpandProperty = @("resourceRoleScopes(`$expand=role,scope)","Catalog","AssignmentPolicies")
                Filter         = "Catalog/Id eq '$($catalog.Id)'"
            }
            Write-Verbose "$logPrefix Obtaining Access Packages"
            $accessPackages = @(Get-MgEntitlementManagementAccessPackage @accessPackagesOptions)
            $entraOpsAccessPackages = @()
            foreach($accessPackage in $accessPackages){
                Write-Verbose "$logPrefix Processing Access Package $($accessPackage.DisplayName)"
                $policies = $accessPackage.AssignmentPolicies

                $assignmentsSplat = @{
                    ExpandProperty = "AccessPackage(`$expand=Catalog),AccessPackage,Target,AssignmentPolicy"
                    Filter         = "AccessPackage/Catalog/Id eq '$($catalog.Id)' and State eq 'delivered'"
                }
                Write-Verbose "$logPrefix Obtaining Access Package Assignments"
                $assignments = @(Get-MgEntitlementManagementAssignment @assignmentsSplat)

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