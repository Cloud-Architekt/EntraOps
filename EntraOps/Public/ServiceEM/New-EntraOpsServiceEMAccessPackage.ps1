<#
.SYNOPSIS
    Creates Entitlement Management access packages for each service role.

.DESCRIPTION
    Creates one access package per service role inside the specified catalog,
    excluding Unified (Teams channel) groups, ControlPlane-Admins, and
    ManagementPlane-Admins (which are managed through delegation rather than
    self-service). Package names follow the convention:
    AP-<ServiceName>-<AccessLevel>-<RoleName>.

    Idempotent: existing packages with matching display names are reused.

.PARAMETER ServiceName
    Name of the service. Used as part of the access package display name.

.PARAMETER ServiceCatalogId
    Object ID of the Entitlement Management catalog to create packages inside.

.PARAMETER ServiceRoles
    The EntraOps service roles object (as produced by the ServiceBootstrap role
    definitions). Each non-Unified role becomes one access package.

.PARAMETER logPrefix
    Text prepended to verbose messages. Defaults to the function name.

.EXAMPLE
    New-EntraOpsServiceEMAccessPackage -ServiceName "MyService" `
        -ServiceCatalogId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ServiceRoles $roles

    Creates access packages such as AP-MyService-WorkloadPlane-Members,
    AP-MyService-WorkloadPlane-Admins etc. inside the given catalog.

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
        $accessPackageUri = "/v1.0/identityGovernance/entitlementManagement/accessPackages?`$filter=catalog/id eq '$($ServiceCatalogId)'&`$expand=resourceRoleScopes(`$expand=role,scope),catalog"
        Write-Verbose "$logPrefix Looking up Access Packages"
        try{
            # Use [object[]] so PSCustomObject or mixed typed entries can be appended with +=
            [object[]]$ServiceAccessPackages = @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri $accessPackageUri -OutputType PSObject -DisableCache)
        }catch{
            Write-Verbose "$logPrefix Failed to find Access Packages"
            Write-Error $_
        }
    }

    process {
        Write-Verbose "$logPrefix Beginning EM Access Package"

        Write-Verbose "$logPrefix Processing $(($ServiceRoles|Where-Object{$_.groupType -ne "Unified"}|Measure-Object).Count) Access Package Roles"
        foreach($role in $ServiceRoles|Where-Object{$_.groupType -ne "Unified" -and -not ($_.accessLevel -eq "ControlPlane" -and $_.name -eq "Admins")}){
            $packageParams = @{
                catalog = @{
                    id = $ServiceCatalogId
                }
                DisplayName = "AP-$ServiceName-$($role.accessLevel +"-"+ $role.name)"
                Description = "Access Package for $ServiceName $($role.accessLevel +" "+ $role.name)"
            }
            if($packageParams.DisplayName -notin $ServiceAccessPackages.DisplayName){
                try{
                    Write-Verbose "$logPrefix Creating Access Package"
                    $ServiceAccessPackages += Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/accessPackages" -Body (@{catalog=@{id=$ServiceCatalogId};displayName=$packageParams.DisplayName;description=$packageParams.Description} | ConvertTo-Json -Depth 10) -OutputType PSObject
                }catch{
                    Write-Verbose "$logPrefix Failed to create Access Package"
                    Write-Error $_
                }
            }
        }
    }

    end {
        # When no packages exist and none were created (e.g. all roles delegated in Centralized sub scope)
        # skip the consistency wait — Compare-Object throws on empty arrays.
        if (($ServiceAccessPackages | Measure-Object).Count -eq 0) {
            Write-Verbose "$logPrefix No access packages to verify — skipping consistency check"
            return [psobject[]]@()
        }
        $refIds = @($ServiceAccessPackages.id | Where-Object { $_ })
        $check = @{}
        $confirmed = Wait-EntraOpsServiceEMCondition -Activity "Access packages" -logPrefix $logPrefix -Condition {
            $check.Packages = [object[]]@(Invoke-EntraOpsMsGraphQuery -Method GET -Uri $accessPackageUri -OutputType PSObject -DisableCache)
            $chkIds = @($check.Packages.id | Where-Object { $_ })
            $refIds.Count -eq 0 -or (Compare-Object $refIds $chkIds | Measure-Object).Count -eq 0
        }
        if(-not $confirmed){
            throw "Access Package object consistency with Entra not achieved"
        }
        return [psobject[]]$check.Packages
    }
}