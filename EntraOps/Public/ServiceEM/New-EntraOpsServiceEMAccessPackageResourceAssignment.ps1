<#
.SYNOPSIS
    Assigns Entra security groups as resources inside their matching access packages.

.DESCRIPTION
    For each owned (non-delegated, non-PIM) security group, looks up the
    corresponding access package by name and registers the group's Member
    catalog resource role into that package. Package names are matched
    using the pattern AP-<ServiceName>-<AccessLevel>-<RoleName>, derived
    from the group's DisplayName.

    Idempotent: existing resource role scope assignments are detected and
    skipped to avoid duplicates.

.PARAMETER ServiceCatalogId
    Object ID of the Entitlement Management catalog.

.PARAMETER ServiceName
    Name of the service. Used to derive expected access package names from
    group display names.

.PARAMETER ServiceGroups
    Entra group objects to register. Delegated groups (IsDelegated=true) and
    PIM staging groups (*-PIM-*) are automatically skipped.

.PARAMETER ServicePackages
    Access package objects returned by New-EntraOpsServiceEMAccessPackage.

.PARAMETER ServiceCatalogResources
    Catalog resource objects returned by New-EntraOpsServiceEMCatalogResource.

.PARAMETER GroupPrefix
    Prefix used in group DisplayNames (e.g. "SG"). Defaults to "SG".

.PARAMETER GroupNamingDelimiter
    Delimiter between name segments (e.g. "-"). Defaults to "-".

.PARAMETER logPrefix
    Text prepended to verbose messages. Defaults to the function name.

.EXAMPLE
    New-EntraOpsServiceEMAccessPackageResourceAssignment `
        -ServiceCatalogId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ServiceName "MyService" `
        -ServiceGroups $groups `
        -ServicePackages $packages `
        -ServiceCatalogResources $resources

    Maps each security group (e.g. SG-MyService-WorkloadPlane-Members) to its
    corresponding access package (AP-MyService-WorkloadPlane-Members) as a
    Member resource role.

#>
function New-EntraOpsServiceEMAccessPackageResourceAssignment {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceCatalogId,

        [Parameter(Mandatory)]
        [string]$ServiceName,

        [Parameter(Mandatory)]
        [psobject[]]$ServiceGroups,

        [Parameter(Mandatory)]
        [psobject[]]$ServicePackages,

        [Parameter(Mandatory)]
        [psobject[]]$ServiceCatalogResources,

        [string]$GroupPrefix = "SG",

        [string]$GroupNamingDelimiter = "-",

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $assignedRoles = @()
        $assignedRoles += $ServicePackages.ResourceRoleScopes
        $packageRoles = @()
    }

    process {
        Write-Verbose "$logPrefix Beginning EM Access Package Resource Assignment"

        Write-Verbose "$logPrefix Processing Access Package Assignments for $(($ServiceGroups|Measure-Object).Count) Groups"
        foreach($group in $ServiceGroups){
            # Skip PIM groups and delegated groups — delegated groups are not catalog resources
            if($group.DisplayName -like "*-PIM-*"){ continue }
            if($group.IsDelegated -eq $true){ continue }

            $resource = $ServiceCatalogResources|Where-Object{`
                $_.DisplayName -eq $group.DisplayName -and `
                $_.OriginSystem -eq "AadGroup"
            }
            if(-not $resource){
                Write-Verbose "$logPrefix No catalog resource found for group '$($group.DisplayName)' — skipping"
                continue
            }
            Write-Verbose "$logPrefix Processing Access Package Resource ID: $($resource.Id)"

            # Derive the expected access package name from the group display name.
            # Groups are named: {Prefix}{Delim}{ServiceName}{Delim}{Plane}{Delim}{Role}
            #   e.g. SG-Contoso-WorkloadPlane-Admins
            # Packages are named: AP-{ServiceName}-{Plane}-{Role}
            #   e.g. AP-Contoso-WorkloadPlane-Admins
            $groupServicePrefix = "$GroupPrefix$GroupNamingDelimiter$ServiceName$GroupNamingDelimiter"
            if($group.DisplayName.StartsWith($groupServicePrefix)){
                $planePlusRole = $group.DisplayName.Substring($groupServicePrefix.Length)
                $expectedPackageName = "AP$GroupNamingDelimiter$ServiceName$GroupNamingDelimiter$planePlusRole"
                $package = $ServicePackages|Where-Object{ $_.DisplayName -eq $expectedPackageName }
            } else {
                $package = $null
            }

            if(-not $package){
                Write-Verbose "$logPrefix No matching Access Package found for group '$($group.DisplayName)', skipping"
                continue
            }
            Write-Verbose "$logPrefix Processing Access Package ID: $($package.Id)"

            #Get available roles for resource in Catalog
            #Used to validate if Access Package exists for resource role
            try{
                Write-Verbose "$logPrefix Getting Catalog Resource Roles for Resource ID: $($resource.id)"
                $resourceRoles = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/catalogs/$ServiceCatalogId/resourceRoles?`$filter=originSystem eq 'AadGroup' and resource/id eq '$($resource.id)'&`$expand=resource" -OutputType PSObject
            }catch{
                Write-Verbose "$logPrefix Failed to get Catalog Resource Roles — skipping group '$($group.DisplayName)'"
                Write-Error $_
                continue
            }
            if(-not $resourceRoles){
                Write-Verbose "$logPrefix No catalog resource roles returned for '$($group.DisplayName)' (transient?) — skipping"
                continue
            }
            Write-Verbose "$logPrefix Found Catalog Resource Roles: $($resourceRoles.OriginId|ConvertTo-Json -Compress)"

            $memberRole = $resourceRoles|Where-Object{$_.DisplayName -eq "Member"}
            if(-not $memberRole){
                Write-Verbose "$logPrefix Member role not found for '$($group.DisplayName)' (resource not fully indexed?) — skipping"
                continue
            }
            $resourceParams = @{
                role = @{
                    id = $memberRole.Id
                    originId = $memberRole.OriginId
                    originSystem = $resource.OriginSystem
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
                    $postResult = Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/accessPackages/$($package.Id)/resourceRoleScopes" -Body ($resourceParams | ConvertTo-Json -Depth 10) -OutputType PSObject
                    if($null -ne $postResult){
                        $assignedRoles += $postResult
                        $packageRoles += $tb
                    } else {
                        Write-Verbose "$logPrefix Role assignment POST returned null — assignment may not have been created"
                    }
                }catch{
                    Write-Verbose "$logPrefix Failed to create new role assignment"
                    Write-Error $_
                }
            }
        }
    }

    end {
        # When no role assignments were attempted (e.g. all groups skipped due to timeouts),
        # skip the consistency wait entirely.
        if (($packageRoles | Measure-Object).Count -eq 0) {
            Write-Verbose "$logPrefix No role assignments to verify — skipping consistency check"
            return [psobject[]]@()
        }
        $expectedAssignments = @($packageRoles | Sort-Object -Unique)
        $check = @{}
        $confirmed = Wait-EntraOpsServiceEMCondition -Activity "Access package resource roles" -logPrefix $logPrefix -Condition {
            try {
                $check.Packages = [object[]]@(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/accessPackages?`$filter=catalog/id eq '$($ServiceCatalogId)'&`$expand=resourceRoleScopes(`$expand=role,scope),catalog" -OutputType PSObject -DisableCache)
            } catch {
                Write-Verbose "$logPrefix Consistency check lookup failed (transient?) — retrying: $($_.Exception.Message)"
                return $false
            }
            $checkAssignments = @($check.Packages.ResourceRoleScopes | ForEach-Object {"$($_.Role.OriginId)_$($_.Scope.OriginId)"})
            (Compare-Object $expectedAssignments $checkAssignments | Measure-Object).Count -eq 0
        }
        if(-not $confirmed){
            throw "Access Package role assignment consistency with Entra not achieved"
        }
        return [psobject[]]$check.Packages
    }
}
