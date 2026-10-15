<#
.SYNOPSIS
    Creates Entra security and Microsoft 365 groups for each service role.

.DESCRIPTION
    Creates one Entra group per entry in the ServiceRoles object. Security groups
    are created for roles with an empty groupType or groupType = "Security". Microsoft 365
    (Unified) groups are created for roles with groupType = "Unified".

    ControlPlane, ManagementPlane and CatalogPlane security groups are created as role-assignable
    (isAssignableToRole = $true) to protect their members and owners from less privileged administrators.
    WorkloadPlane-Admins are role-assignable only with -RoleAssignableWorkloadPlaneAdmins; all other security
    groups (e.g. WorkloadPlane-Users) and Unified groups are not role-assignable. Creating role-assignable groups
    requires the caller to have Privileged Role Administrator or Global Administrator.
    The setting only applies when a group is created; Entra ID can't change it afterwards.

    Group names follow the convention:
    <GroupPrefix><Delimiter><ServiceName><Delimiter><AccessLevel><Delimiter><RoleName>
    A GroupPrefix that ends with '-', '_' or '.' (e.g. "SG_") is followed directly by the ServiceName.

    Idempotent: an existing group with exactly the expected MailNickname is reused, but only when it can't
    have been created by a less privileged user: ControlPlane, ManagementPlane and CatalogPlane groups must
    be role-assignable security groups; all other groups must be role-assignable or already be a resource of
    the catalog Catalog-<ServiceName>. Otherwise, or when the MailNickname is ambiguous, the function stops
    before creating any group. Other groups with the <ServiceName>. MailNickname prefix aren't returned.
    Only called directly for custom implementations; New-EntraOpsServiceBootstrap
    is the standard entry point.

.PARAMETER ServiceName
    Name of the service. Forms the central segment of the group MailNickname
    and DisplayName.

.PARAMETER WorkloadPlaneAdmin
    Optional Graph API owner URL for the group owner, in the form:
    "https://graph.microsoft.com/v1.0/users/<ObjectId>"
    
    This can also be provided as just the ObjectId (GUID), and the function
    will automatically construct the proper OData bind URL. Only set as owner of
    WorkloadPlane groups; omit to create groups without owners.

.PARAMETER GroupPrefix
    Prefix prepended to all group DisplayNames and MailNicknames. Defaults to "SG".

.PARAMETER GroupNamingDelimiter
    Delimiter between name segments. Only "-" is supported: the other ServiceEM cmdlets find the groups
    by their "-" delimited display name suffix (e.g. *-ControlPlane-Admins).

.PARAMETER RoleAssignableWorkloadPlaneAdmins
    Creates WorkloadPlane-Admins as role-assignable group.

.PARAMETER ServiceRoles
    EntraOps service roles object. Each row produces one group. The accessLevel,
    name, and groupType columns control the group variant.

.PARAMETER logPrefix
    Text prepended to verbose messages. Defaults to the function name.

.EXAMPLE
    New-EntraOpsServiceEntraGroup `
        -ServiceName "MyService" `
        -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/00000000-0000-0000-0000-000000000001" `
        -ServiceRoles $roles

    Creates all security and Microsoft 365 groups for "MyService". Returns all group objects.

#>
function New-EntraOpsServiceEntraGroup {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,

        [string]$WorkloadPlaneAdmin,

        [string]$GroupPrefix = "SG",
        [ValidateSet('-')]
        [string]$GroupNamingDelimiter = "-",

        [switch]$RoleAssignableWorkloadPlaneAdmins,

        [Parameter(Mandatory)]
        [psobject[]]$ServiceRoles,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        # ServiceName is part of mailNickname and of the $search query below
        if ($ServiceName -notmatch '^[A-Za-z0-9_.-]+$') {
            throw "ServiceName '$ServiceName' is invalid. Use letters, digits, '_', '.' or '-'."
        }
        $groupNamePrefix = if ($GroupPrefix -match '[-_.]$') { $GroupPrefix } else { "$GroupPrefix$GroupNamingDelimiter" }
        # Normalize WorkloadPlaneAdmin to the OData bind format
        if (-not [string]::IsNullOrWhiteSpace($WorkloadPlaneAdmin)) {
            # Check if WorkloadPlaneAdmin is already in OData URL format (users or servicePrincipals)
            if ($WorkloadPlaneAdmin -match '^https://graph\.microsoft\.com/v1\.0/(users|servicePrincipals)/') {
                $ownerUri = $WorkloadPlaneAdmin
                Write-Verbose "$logPrefix WorkloadPlaneAdmin provided as OData URL: $ownerUri"
            } else {
                # Assume it's just an ObjectId and construct the OData URL
                # Validate it looks like a GUID
                if ($WorkloadPlaneAdmin -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                    $ownerUri = "https://graph.microsoft.com/v1.0/users/$WorkloadPlaneAdmin"
                    Write-Verbose "$logPrefix WorkloadPlaneAdmin converted to OData URL: $ownerUri"
                } else {
                    throw "WorkloadPlaneAdmin must be either a valid GUID (ObjectId) or a full OData URL (https://graph.microsoft.com/v1.0/users/<ObjectId> or https://graph.microsoft.com/v1.0/servicePrincipals/<ObjectId>). Received: $WorkloadPlaneAdmin"
                }
            }
        } else {
            Write-Verbose "$logPrefix No group owner requested; creating groups without owners"
        }

        try {
            #Groups
            $groups = @()
            Write-Verbose "$logPrefix Looking up Groups"
            $groups += Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/groups?`$search=`"mailNickname:$ServiceName.`"" -ConsistencyLevel "eventual" -OutputType PSObject -DisableCache -ThrowOnFailure
            # $search also matches tokens inside the nickname (e.g. PIM.<ServiceName>.*)
            $groups = @($groups | Where-Object { $_.MailNickname -like "$ServiceName.*" })
        } catch {
            # Without the lookup result every group would be created again (mailNickname isn't unique for security groups)
            throw "Failed to look up the existing groups of '$ServiceName'; no group was created: $($_.Exception.Message)"
        }

        $catalogDisplayName = "Catalog-$ServiceName"
        $provenance = @{ CatalogResourceIds = $null }
        $getCatalogResourceIds = {
            if ($null -eq $provenance.CatalogResourceIds) {
                $encodedCatalogDisplayName = ConvertTo-EntraOpsODataStringLiteral -Value $catalogDisplayName
                $catalogs = @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/catalogs?`$filter=displayName eq '$encodedCatalogDisplayName'&`$expand=resources" -OutputType PSObject -DisableCache -ThrowOnFailure |
                    Where-Object { $_.DisplayName -eq $catalogDisplayName })
                $provenance.CatalogResourceIds = if ($catalogs.Count -eq 1) { @($catalogs[0].Resources.OriginId | Where-Object { $_ }) } else { @() }
            }
            $provenance.CatalogResourceIds
        }
        $assertReusableGroup = {
            param($existingGroup, [bool]$RequireRoleAssignable)
            $details = $existingGroup
            if ($null -eq $existingGroup.IsAssignableToRole -or $null -eq $existingGroup.SecurityEnabled) {
                $details = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/groups/$($existingGroup.Id)?`$select=id,isAssignableToRole,securityEnabled" -OutputType PSObject -DisableCache -ThrowOnFailure
            }
            if ($details.IsAssignableToRole -eq $true -and $details.SecurityEnabled -eq $true) { return }
            $groupLabel = "'$($existingGroup.DisplayName)' ($($existingGroup.Id), mailNickname $($existingGroup.MailNickname))"
            if ($RequireRoleAssignable) {
                throw "Existing group $groupLabel isn't a role-assignable security group and isn't reused, because any user who can create groups could have created it. Verify and delete the group, or rename its mailNickname, then run the landing zone again."
            }
            if ($existingGroup.Id -notin @(& $getCatalogResourceIds)) {
                throw "Existing group $groupLabel isn't a resource of the catalog '$catalogDisplayName' and isn't reused, because any user who can create groups could have created it. Verify the group and delete it, or add it as resource to '$catalogDisplayName', then run the landing zone again."
            }
        }
        $expectedNicknames = [System.Collections.Generic.List[string]]::new()
        # Base parameters shared by all group types
        $groupParams = @{
            description     = ""
            securityEnabled = $true
        }

        # Unified (Microsoft 365) groups cannot be role-assignable
        $unifiedParams = $groupParams + @{
            displayName        = ""
            mailNickname       = ""
            groupTypes         = @("Unified")
            mailEnabled        = $true
            isAssignableToRole = $false
            #"members@odata.bind" = $members
        }

        $secParams = $groupParams + @{
            displayName        = ""
            mailNickname       = ""
            mailEnabled        = $false
            isAssignableToRole = $true
        }
    }

    process {
        Write-Verbose "$logPrefix Beginning EntraGroup"

        Write-Verbose "$logPrefix Processing $(($ServiceRoles|Measure-Object).Count) Groups"
        foreach ($ServiceRole in $ServiceRoles) {
            $validationErrors = @()
            
            # Validate ServiceRole properties
            if ([string]::IsNullOrWhiteSpace($ServiceRole.Name)) {
                $validationErrors += "ServiceRole.Name is required"
            }
            
            # Construct names
            $unifiedParams.Description = "Team $(($ServiceRole.accessLevel +" "+ $ServiceRole.name).trim()) supporting $ServiceName"
            $unifiedParams.DisplayName = "$ServiceName $($ServiceRole.Name)"
            $unifiedParams.MailNickname = "$ServiceName.$($ServiceRole.Name)"
            $secParams.Description = "Team $(($ServiceRole.accessLevel +" "+ $ServiceRole.name).trim()) supporting $ServiceName"
            if ([string]::IsNullOrEmpty($ServiceRole.accessLevel)) {
                $secParams.DisplayName = "$groupNamePrefix$ServiceName$($GroupNamingDelimiter)$($ServiceRole.Name)"
                $secParams.MailNickname = "$ServiceName.$($ServiceRole.Name)"
            } else {
                $secParams.DisplayName = "$groupNamePrefix$ServiceName$($GroupNamingDelimiter)$($ServiceRole.accessLevel)$($GroupNamingDelimiter)$($ServiceRole.Name)"
                $secParams.MailNickname = "$ServiceName.$($ServiceRole.accessLevel).$($ServiceRole.Name)"
            }
            $secParams.isAssignableToRole = $ServiceRole.accessLevel -in @('ControlPlane', 'ManagementPlane', 'CatalogPlane') -or
            ($RoleAssignableWorkloadPlaneAdmins -and $ServiceRole.accessLevel -eq 'WorkloadPlane' -and $ServiceRole.Name -eq 'Admins')
            
            # Validate displayName length (max 256 chars)
            if ($secParams.DisplayName.Length -gt 256) {
                $validationErrors += "DisplayName '$($secParams.DisplayName)' exceeds maximum length of 256 characters (current: $($secParams.DisplayName.Length))"
            }
            if ($unifiedParams.DisplayName.Length -gt 256) {
                $validationErrors += "DisplayName '$($unifiedParams.DisplayName)' exceeds maximum length of 256 characters (current: $($unifiedParams.DisplayName.Length))"
            }
            
            # Validate mailNickname length (max 64 chars) and format
            $mailNicknamePattern = '^[a-zA-Z0-9_.-]+$'
            if ($secParams.MailNickname.Length -gt 64) {
                $validationErrors += "MailNickname '$($secParams.MailNickname)' exceeds maximum length of 64 characters (current: $($secParams.MailNickname.Length))"
            }
            if ($secParams.MailNickname -notmatch $mailNicknamePattern) {
                $validationErrors += "MailNickname '$($secParams.MailNickname)' contains invalid characters. Only alphanumeric, underscore, dot, and hyphen allowed."
            }
            if ($unifiedParams.MailNickname.Length -gt 64) {
                $validationErrors += "MailNickname '$($unifiedParams.MailNickname)' exceeds maximum length of 64 characters (current: $($unifiedParams.MailNickname.Length))"
            }
            if ($unifiedParams.MailNickname -notmatch $mailNicknamePattern) {
                $validationErrors += "MailNickname '$($unifiedParams.MailNickname)' contains invalid characters. Only alphanumeric, underscore, dot, and hyphen allowed."
            }
            
            # Throw if validation errors found
            if ($validationErrors.Count -gt 0) {
                throw "VALIDATION FAILED for ServiceRole '$($ServiceRole.Name)':`n  - $($validationErrors -join "`n  - ")"
            }
            
            Write-Verbose "$logPrefix Validated group parameters for '$($ServiceRole.Name)'"
            # Owners can manage membership, so only WorkloadPlane groups get one
            $secParams.Remove("owners@odata.bind")
            if ($ServiceRole.accessLevel -eq "WorkloadPlane" -and -not [string]::IsNullOrWhiteSpace($ownerUri)) {
                $secParams["owners@odata.bind"] = @($ownerUri)
            }
            $isSecurityGroup = [string]::IsNullOrEmpty($ServiceRole.groupType) -or $ServiceRole.groupType -eq "Security"
            $expectedNickname = if ($ServiceRole.groupType -eq "Unified") { $unifiedParams.MailNickname } elseif ($isSecurityGroup) { $secParams.MailNickname } else { $null }
            if ($expectedNickname) {
                $expectedNicknames.Add($expectedNickname)
                $existingGroups = @($groups | Where-Object { $_.MailNickname -eq $expectedNickname })
                if ($existingGroups.Count -gt 1) {
                    throw "Found $($existingGroups.Count) groups with mailNickname '$expectedNickname' ($($existingGroups.Id -join ', ')). Delete the groups that weren't created by ServiceEM, then run the landing zone again."
                }
                if ($existingGroups.Count -eq 1) {
                    $requireRoleAssignable = $ServiceRole.groupType -ne "Unified" -and $ServiceRole.accessLevel -in @('ControlPlane', 'ManagementPlane', 'CatalogPlane')
                    & $assertReusableGroup $existingGroups[0] $requireRoleAssignable
                    Write-Verbose "$logPrefix Reusing existing group $($existingGroups[0].DisplayName) ($($existingGroups[0].Id))"
                }
            }
            try {
                if ($ServiceRole.groupType -eq "Unified" -and $groups.MailNickname -notcontains $unifiedParams.MailNickname) {
                    Write-Verbose "$logPrefix $($unifiedParams|ConvertTo-Json -Compress)"
                    $groups += Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/groups" -Body ($unifiedParams | ConvertTo-Json -Depth 10) -OutputType PSObject -ThrowOnFailure
                } elseif ($isSecurityGroup -and $groups.MailNickname -notcontains $secParams.MailNickname) {
                    Write-Verbose "$logPrefix $($secParams|ConvertTo-Json -Compress)"
                    $groups += Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/groups" -Body ($secParams | ConvertTo-Json -Depth 10) -OutputType PSObject -ThrowOnFailure
                }
            } catch {
                throw "Failed to create group for service role '$($ServiceRole.accessLevel) $($ServiceRole.Name)': $($_.Exception.Message)"
            }
        }
    }

    end {
        Write-Verbose "$logPrefix Verifying Groups are available"
        $refIds = @($groups | Where-Object { $_.MailNickname -in $expectedNicknames } | ForEach-Object { $_.id } | Where-Object { $_ })
        $check = @{}
        $confirmed = Wait-EntraOpsServiceEMCondition -Activity "Groups" -logPrefix $logPrefix -Condition {
            $check.Groups = @()
            $check.Groups += Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/groups?`$search=`"mailNickname:$ServiceName.`"" -ConsistencyLevel "eventual" -OutputType PSObject -DisableCache
            $check.Groups = @($check.Groups | Where-Object { $_.MailNickname -in $expectedNicknames })
            $chkIds = @($check.Groups.id | Where-Object { $_ })
            $refIds.Count -gt 0 -and $chkIds.Count -ge $refIds.Count -and (Compare-Object $refIds $chkIds | Measure-Object).Count -eq 0
        }
        if (-not $confirmed) {
            throw "Group object consistency with Entra not achieved"
        }
        return [psobject[]]$check.Groups
    }
}
