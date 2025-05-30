<#
.SYNOPSIS
    Creates resource assignments in the access packages

.DESCRIPTION
    Registers the catalog resources with the access packages

.PARAMETER ServiceCatalogId
    The Service Catalog GUID

.PARAMETER ServiceGroups
    The Graph Group objects
    
.PARAMETER ServicePackages
    The Graph Access Package objects

.PARAMETER ServiceCatalogResources
    The Graph Catalog Resource objects

.PARAMETER logPrefix
    Defines the text to prepend for any verbose messages

.EXAMPLE
    New-EntraOpsServiceEMAccessPackageResourceAssignment -ServiceCatalogId "<GUID>" -ServiceGroups $groups -ServicePackages $packages -ServiceCatalogResources $resources

#>
function New-EntraOpsServiceEMAccessPackageResourceAssignment {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceCatalogId,

        [Parameter(Mandatory)]
        [psobject[]]$ServiceGroups,

        [Parameter(Mandatory)]
        [psobject[]]$ServicePackages,

        [Parameter(Mandatory)]
        [psobject[]]$ServiceCatalogResources,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $assignedRoles = @()
        $assignedRoles += $ServicePackages.ResourceRoleScopes
        $packageRoles = @()
    }

    process {
        Write-Verbose "$logPrefix Processing Access Package Assignments for $(($ServiceGroups|Measure-Object).Count) Groups"
        foreach($group in $ServiceGroups){
            if($group.DisplayName -like "*-PIM-*"){continue}
            $resource = $ServiceCatalogResources|Where-Object{`
                $_.DisplayName -eq $group.DisplayName -and `
                $_.OriginSystem -eq "AadGroup"
            }
            Write-Verbose "$logPrefix Processing Access Package Resource ID: $($resource.Id)"
            
            $gn = $group.DisplayName.Substring(2,$group.DisplayName.Length-2)
            $package = $ServicePackages|Where-Object{`
                $_.DisplayName.Substring(2,$_.DisplayName.Length-2) -eq $gn
            }
            if(-not $package){
                $package = $ServicePackages|Where-Object{`
                    $_.DisplayName -like "*Members*"
                }
            }
            Write-Verbose "$logPrefix Processing Access Package ID: $($package.Id)"

            #Get available roles for resource in Catalog
            #Used to validate if Access Package exists for resource role
            $roleSplat = @{
                AccessPackageCatalogId = $ServiceCatalogId
                Filter = "originSystem eq 'AadGroup' and resource/id eq '$($resource.id)'"
            }
            try{
                Write-Verbose "$logPrefix Getting Catalog Resource Roles for Resource ID: $($resource.id)"
                $resourceRoles = Get-MgEntitlementManagementCatalogResourceRole @roleSplat -ExpandProperty Resource
            }catch{
                Write-Verbose "$logPrefix Failed to get Catalog Resource Roles"
                Write-Error $_
            }
            Write-Verbose "$logPrefix Found Catalog Resource Roles: $($resourceRoles.OriginId|ConvertTo-Json -Compress)"

            $resourceParams = @{
                role = @{
                    id = $resource.OriginId
                    originId = ($resourceRoles|Where-Object{$_.DisplayName -eq "Member"}).OriginId
                    originSystem =  $resource.OriginSystem
                    resource = @{
                        id = $resource.Id
                        originId = $resource.OriginId
                        originSystem = $resource.OriginSystem
                    }
                }
                scope = @{
                    originId = $resource.OriginId
                    originSystem = $resource.OriginSystem
                }
            }
            $ex = $package.ResourceRoleScopes|ForEach-Object{"$($_.Role.OriginId)_$($_.Scope.OriginId)"}
            $packageRoles += $ex
            $tb = "$($resourceParams.role.originId)_$($resourceParams.scope.originId)"
            if($tb -notin $ex){
                try{
                    Write-Verbose "$logPrefix Creating new role assignment"
                    Write-Verbose "$logPrefix Resource Param: $($resourceParams|ConvertTo-Json -Compress)"
                    $assignedRoles += New-MgEntitlementManagementAccessPackageResourceRoleScope -AccessPackageId $package.Id -BodyParameter $resourceParams
                    $packageRoles += $tb
                }catch{
                    Write-Verbose "$logPrefix Failed to create new role assignment"
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
            $accessPackageOptions = @{
                ExpandProperty = @("resourceRoleScopes(`$expand=role,scope)","Catalog")
                Filter         = "Catalog/Id eq '$($ServiceCatalogId)'"
            }
            $checkServiceAccessPackages = @()
            $checkServiceAccessPackages = Get-MgEntitlementManagementAccessPackage @accessPackageOptions
            $checkAssignments = $checkServiceAccessPackages.ResourceRoleScopes|ForEach-Object{"$($_.Role.OriginId)_$($_.Scope.OriginId)"}

            if((Compare-Object $($packageRoles|Sort-Object -Unique) $checkAssignments|Measure-Object).Count -eq 0){
                Write-Verbose "$logPrefix Graph consistency found confirming"
                $confirmed = $true
                continue
            }
            $i++
            if($i -gt 5){
                throw "Access Package role assignment consistency with Entra not achieved"
            }
            Write-Verbose "$logPrefix Graph objects not available, sleeping $([Math]::Pow(2,$i)-1) seconds"
        }
        return [psobject[]]$checkServiceAccessPackages
    }
}