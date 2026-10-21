<#
.SYNOPSIS
    Assigns Entra security groups as resources inside their matching access packages.

.DESCRIPTION
    For each owned (non-delegated) security group, looks up the
    corresponding access package by name and registers the group's Member
    catalog resource role into that package (Eligible Member for the groups in
    -EligibleMemberGroupIds). Package names are matched
    using the pattern AP-<ServiceName>-<AccessLevel>-<RoleName>, derived
    from the group's DisplayName. The Microsoft 365 group (if created) is added
    to every access package, so all assigned users become members of it.

    Idempotent: existing resource role scope assignments are detected and
    skipped to avoid duplicates.

.PARAMETER ServiceCatalogId
    Object ID of the Entitlement Management catalog.

.PARAMETER ServiceName
    Name of the service. Used to derive expected access package names from
    group display names.

.PARAMETER ServiceGroups
    Entra group objects to register. Delegated groups (IsDelegated=true) are
    automatically skipped.

.PARAMETER ServicePackages
    Access package objects returned by New-EntraOpsServiceEMAccessPackage.

.PARAMETER ServiceCatalogResources
    Catalog resource objects returned by New-EntraOpsServiceEMCatalogResource.

.PARAMETER EligibleMemberGroupIds
    Object IDs of groups managed by PIM for Groups. Their access package delivers the Eligible Member
    role (PIM for Groups eligible membership) instead of the active Member role. Requires Microsoft
    Entra ID Governance or Microsoft Entra Suite licenses.

.PARAMETER GroupPrefix
    Prefix used in group DisplayNames (e.g. "SG"). Defaults to "SG".

.PARAMETER GroupNamingDelimiter
    Delimiter between name segments. Only "-" is supported, see New-EntraOpsServiceEntraGroup.

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

        [string[]]$EligibleMemberGroupIds = @(),

        [string]$GroupPrefix = "SG",

        [ValidateSet('-')]
        [string]$GroupNamingDelimiter = "-",

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $assignedRoles = @()
        $assignedRoles += $ServicePackages.ResourceRoleScopes
        $packageRoles = @()
        $removedRoles = @()
    }

    process {
        Write-Verbose "$logPrefix Beginning EM Access Package Resource Assignment"

        Write-Verbose "$logPrefix Processing Access Package Assignments for $(($ServiceGroups|Measure-Object).Count) Groups"
        $groupPackagePairs = foreach ($group in $ServiceGroups) {
            # Delegated groups are not catalog resources
            if ($group.IsDelegated -eq $true) { continue }

            if ($group.PSObject.Properties.Name -contains 'GroupTypes' -and $group.GroupTypes -contains "Unified") {
                foreach ($unifiedPackage in $ServicePackages) { [pscustomobject]@{ Group = $group; Package = $unifiedPackage } }
                continue
            }

            # Derive the expected access package name from the group display name.
            # Groups are named: {Prefix}{Delim}{ServiceName}{Delim}{Plane}{Delim}{Role}
            #   e.g. SG-Contoso-WorkloadPlane-Admins
            # Packages are named: AP-{ServiceName}-{Plane}-{Role}
            #   e.g. AP-Contoso-WorkloadPlane-Admins
            $groupServicePrefix = "$(if ($GroupPrefix -match '[-_.]$') { $GroupPrefix } else { "$GroupPrefix$GroupNamingDelimiter" })$ServiceName$GroupNamingDelimiter"
            if ($group.DisplayName.StartsWith($groupServicePrefix)) {
                $planePlusRole = $group.DisplayName.Substring($groupServicePrefix.Length)
                $expectedPackageName = "AP$GroupNamingDelimiter$ServiceName$GroupNamingDelimiter$planePlusRole"
                $package = $ServicePackages | Where-Object { $_.DisplayName -eq $expectedPackageName }
            } else {
                $package = $null
            }

            if (-not $package) {
                Write-Verbose "$logPrefix No matching Access Package found for group '$($group.DisplayName)', skipping"
                continue
            }
            [pscustomobject]@{ Group = $group; Package = $package }
        }

        $resourceRolesByResource = @{}
        $roleScopeFailures = [System.Collections.Generic.List[string]]::new()
        foreach ($pair in @($groupPackagePairs)) {
            $group = $pair.Group
            $package = $pair.Package

            # Matched by object ID: a display name can be shared or changed (e.g. another GroupPrefix)
            $resource = $ServiceCatalogResources | Where-Object {
                $_.OriginSystem -eq "AadGroup" -and (
                    ($group.Id -and $_.OriginId -eq $group.Id) -or
                    (-not $group.Id -and $_.DisplayName -eq $group.DisplayName))
            } | Select-Object -First 1
            # A skipped group leaves its access package without access: report it instead of completing successfully
            if (-not $resource) {
                $roleScopeFailures.Add("'$($group.DisplayName)' is not a resource of the catalog, so '$($package.DisplayName)' grants no access to it")
                continue
            }
            Write-Verbose "$logPrefix Processing Access Package Resource ID: $($resource.Id)"
            Write-Verbose "$logPrefix Processing Access Package ID: $($package.Id)"

            #Get available roles for resource in Catalog
            #Used to validate if Access Package exists for resource role
            if (-not $resourceRolesByResource.ContainsKey($resource.Id)) {
                try {
                    Write-Verbose "$logPrefix Getting Catalog Resource Roles for Resource ID: $($resource.id)"
                    # -ThrowOnFailure: a failed lookup must not look like a resource without roles
                    $resourceRolesByResource[$resource.Id] = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/catalogs/$ServiceCatalogId/resourceRoles?`$filter=originSystem eq 'AadGroup' and resource/id eq '$($resource.id)'&`$expand=resource" -OutputType PSObject -ThrowOnFailure
                } catch {
                    $roleScopeFailures.Add("catalog resource roles of '$($group.DisplayName)' could not be read: $($_.Exception.Message)")
                    continue
                }
            }
            $resourceRoles = $resourceRolesByResource[$resource.Id]
            if (-not $resourceRoles) {
                $roleScopeFailures.Add("the catalog returned no resource roles for '$($group.DisplayName)' (resource not yet indexed?); run the deployment again")
                continue
            }
            Write-Verbose "$logPrefix Found Catalog Resource Roles: $($resourceRoles.OriginId|ConvertTo-Json -Compress)"

            $eligible = $group.Id -in $EligibleMemberGroupIds
            # Group roles: Member_<groupId>; EligibleMember_<groupId> only when the group is managed by PIM for Groups
            $findRole = { param($prefix, $name) $resourceRoles | Where-Object { $_.OriginId -eq "$($prefix)_$($resource.OriginId)" -or $_.DisplayName -eq $name } | Select-Object -First 1 }
            $memberRole = if ($eligible) { & $findRole 'EligibleMember' 'Eligible Member' } else { & $findRole 'Member' 'Member' }
            if (-not $memberRole) {
                if ($eligible) {
                    Write-Warning "$logPrefix Eligible Member role not found for '$($group.DisplayName)' in the catalog (group not yet managed by PIM for Groups, or no Microsoft Entra ID Governance license). No resource role is added to the access package, run the deployment again later."
                } else {
                    $roleScopeFailures.Add("the Member role of '$($group.DisplayName)' was not found in the catalog (resource not yet indexed?); run the deployment again")
                }
                continue
            }
            $resourceParams = @{
                role  = @{
                    id           = $memberRole.Id
                    originId     = $memberRole.OriginId
                    originSystem = $resource.OriginSystem
                    resource     = @{
                        id           = $resource.Id
                        originId     = $resource.OriginId
                        originSystem = $resource.OriginSystem
                    }
                }
                scope = @{
                    originId     = $resource.OriginId
                    originSystem = $resource.OriginSystem
                }
            }
            # A package is paired with several groups; roles removed for an earlier group must not return from its stale snapshot
            $ex = @($package.ResourceRoleScopes | ForEach-Object { "$($_.Role.OriginId)_$($_.Scope.OriginId)" } | Where-Object { $_ -notin $removedRoles })
            $packageRoles += $ex
            if (-not $eligible) {
                # No active Member next to Eligible Member: it would bypass the PIM activation
                $eligibleScope = @($package.ResourceRoleScopes | Where-Object {
                        "$($_.Role.OriginId)" -like 'EligibleMember_*' -and $_.Scope.OriginId -eq $resource.OriginId -and
                        "$($_.Role.OriginId)_$($_.Scope.OriginId)" -notin $removedRoles
                    })
                if ($eligibleScope.Count -gt 0) {
                    Write-Warning "$logPrefix '$($package.DisplayName)' delivers '$($group.DisplayName)' as Eligible Member (PIM for Groups). The active Member role is not added, so membership still requires PIM activation. Run the deployment with PIM for Groups enabled for this group, or remove the Eligible Member role from the access package to switch to active membership."
                    continue
                }
            }
            $activeRemovalFailed = $false
            if ($eligible) {
                # An active Member role (e.g. deployed without PIM for Groups) would bypass the PIM activation
                $activeRole = & $findRole 'Member' 'Member'
                foreach ($activeScope in @($package.ResourceRoleScopes | Where-Object { $activeRole -and $_.Role.OriginId -eq $activeRole.OriginId -and $_.Scope.OriginId -eq $resource.OriginId })) {
                    Write-Warning "$logPrefix Replacing the active Member role of '$($group.DisplayName)' in '$($package.DisplayName)' with Eligible Member; assigned users lose their active membership and must activate it with PIM for Groups."
                    try {
                        Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "/v1.0/identityGovernance/entitlementManagement/accessPackages/$($package.Id)/resourceRoleScopes/$($activeScope.Id)" -OutputType PSObject -ThrowOnFailure | Out-Null
                        $removed = "$($activeScope.Role.OriginId)_$($activeScope.Scope.OriginId)"
                        $removedRoles += $removed
                        $packageRoles = @($packageRoles | Where-Object { $_ -ne $removed })
                    } catch {
                        $activeRemovalFailed = $true
                        Write-Warning "$logPrefix Failed to remove the active Member role of '$($group.DisplayName)' from '$($package.DisplayName)', Eligible Member is not added; run the deployment again. Error: $($_.Exception.Message)"
                    }
                }
            }
            if ($activeRemovalFailed) { continue }
            $tb = "$($resourceParams.role.originId)_$($resourceParams.scope.originId)"
            if ($tb -notin $ex) {
                try {
                    Write-Verbose "$logPrefix Creating new role assignment"
                    Write-Verbose "$logPrefix Resource Param: $($resourceParams|ConvertTo-Json -Compress)"
                    $postResult = Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/accessPackages/$($package.Id)/resourceRoleScopes" -Body ($resourceParams | ConvertTo-Json -Depth 10) -OutputType PSObject -ThrowOnFailure
                    if ($null -ne $postResult) {
                        $assignedRoles += $postResult
                        $packageRoles += $tb
                    } else {
                        Write-Verbose "$logPrefix Role assignment POST returned null — assignment may not have been created"
                    }
                } catch {
                    Write-Verbose "$logPrefix Failed to create new role assignment"
                    $roleScopeFailures.Add("$($memberRole.DisplayName) of '$($group.DisplayName)' in '$($package.DisplayName)': $($_.Exception.Message)")
                }
            }
        }
        if ($roleScopeFailures.Count -gt 0) {
            throw "$logPrefix Failed to add $($roleScopeFailures.Count) resource role(s) to access packages: $($roleScopeFailures -join '; ')"
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
            $checkAssignments = @($check.Packages.ResourceRoleScopes | ForEach-Object { "$($_.Role.OriginId)_$($_.Scope.OriginId)" } | Sort-Object -Unique)
            # Packages of the catalog may hold further resource roles (e.g. added manually or by another deployment)
            @($expectedAssignments | Where-Object { $_ -notin $checkAssignments }).Count -eq 0
        }
        if (-not $confirmed) {
            throw "Access Package role assignment consistency with Entra not achieved"
        }
        return [psobject[]]$check.Packages
    }
}
