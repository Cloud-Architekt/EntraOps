<#
.SYNOPSIS
    Converts the PowerShell Object to a Mermaid diagram

.DESCRIPTION
    Produces a Mermaid digagram of the resources and relationships within the report object.

.PARAMETER ReportObject
    An object produced by Get-EntraOpsReport
#>
function ConvertTo-Mermaid {
    [OutputType([string])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$ReportObject
    )

    begin {
        $string = @"
graph

"@
        $logPrefix = "[$($MyInvocation.MyCommand)]"
    }

    process {
        foreach($catalog in $ReportObject.Catalogs){
            $string += "  subgraph $($catalog.Catalog.Id) [$($catalog.Catalog.DisplayName)]`n"
            $string += "`n"
            
            $string += "    subgraph $($catalog.Catalog.Id)Roles [Roles]`n"
            foreach($catalogRole in $catalog.CatalogRoles){
                $string += "      $($catalogRole.Id)($($catalogRole.RoleDefinition.DisplayName) - $($catalogRole.Principal.AdditionalProperties["displayName"]))`n"
            }
            $string += "    end`n"

            $string += "`n"
            $string += "    subgraph $($catalog.Catalog.Id)Resources [Resources]`n"
            foreach($catalogResource in $catalog.CatalogResources.Resource|Sort-Object Id -Unique){
                $string += "      $($catalogResource.Id)($($catalogResource.DisplayName))`n"
            }
            $string += "    end`n"

            $string += "`n"
            $string += "    subgraph $($catalog.Catalog.Id)AccessPackages [Access Packages]`n"
            foreach($accessPackage in $catalog.AccessPackages){
                $string += "      subgraph $($accessPackage.AccessPackage.Id) [$($accessPackage.AccessPackage.DisplayName)]`n"
                    foreach($policy in $accessPackage.Policies){
                        $string += "        $($policy.Id)($($policy.DisplayName))`n"
                    }
                $string += "      end`n"
            }
            $string += "    end`n"

            $string += "  end`n`n"
        }

        foreach($target in $ReportObject.Catalogs.AccessPackages.Assignments.Target|Sort-Object Id -Unique){
            $string += "$($target.Id)($($target.DisplayName))`n"
        }
        $string += "`n"

        foreach($assignment in $ReportObject.Catalogs.AccessPackages.Assignments|Sort-Object Id -Unique){
            $string += "$($assignment.Target.Id) --> $($assignment.AssignmentPolicy.Id)`n"
        }
        $string += "`n"

        $ReportObject.Catalogs.AccessPackages | `
            Where-Object { $_.Policies.AllowedTargetScope -eq "specificDirectoryUsers" } | `
            ForEach-Object {
                $scopePolicy = $_.Policies
                $scopeResource = $ReportObject.Catalogs.CatalogResources.Resource | `
                    Where-Object { $_.OriginId -eq $scopePolicy.SpecificAllowedTargets.AdditionalProperties["groupId"] } | `
                    Sort-Object Id -Unique
                
                $string += "$($scopeResource.Id) --> $($scopePolicy.Id)`n"

                <#
                $_.Policies.SpecificAllowedTargets.AdditionalProperties["groupId"] lookup in
                  $ReportObject.Catalogs.CatalogResources.Resource.OriginId for 
                  $entraOps.Catalogs.CatalogResources.Resource.Id --> 
                  $entraOps.Catalogs.AccessPackages.Policies.Id
                #>
            }
        $string += "`n"

        foreach($accessPackageResources in $ReportObject.Catalogs.AccessPackages){
            foreach($resource in $accessPackageResources.Resources){
                $string += "$($accessPackageResources.AccessPackage.Id) --> $($resource.resource.Id)`n"
            }
        }
        $string += "`n"

        foreach($catalogRoleResource in $ReportObject.Catalogs.CatalogRoles){
            $roleResource = $ReportObject.Catalogs.CatalogResources.Resource | `
                Where-Object { $_.OriginId -eq $catalogRoleResource.Principal.Id} | `
                Sort-Object Id -Unique
            $string += "$($roleResource.Id) --> $($catalogRoleResource.Id)`n"
        }
        $string += "`n"

        return $string
    }
}