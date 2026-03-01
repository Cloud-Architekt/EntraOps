<#
.SYNOPSIS
    Get a list in schema of EntraOps with all service principals with exposed app roles and delegated permissions in Entra ID.

.DESCRIPTION
    Get a list in schema of EntraOps with all service principals with exposed app roles and delegated permissions in Entra ID.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.EXAMPLE
    List of all app roles and delegated permissions from service principals in Entra ID.
    Get-EntraOpsPrivilegedAppRoles
#>

function Get-EntraOpsPrivilegedAppRoles {
    param (
        [Parameter(Mandatory = $False)]
        [System.String]$TenantId = (Get-AzContext).Tenant.id
        ,
        [Parameter(Mandatory = $False)]
        [System.Collections.Generic.List[psobject]]$WarningMessages
    )

    # Set Error Action
    $ErrorActionPreference = "Stop"

    # Optimization: Fetch all required data in bulk to avoid N+1 queries in loops
    
    # 1. Fetch Global Delegated Permissions (OAuth2PermissionGrants)
    Write-Verbose "Fetching all OAuth2PermissionGrants..."
    $GlobalDelegatedPermissions = Invoke-EntraOpsMsGraphQuery -Uri "/beta/oauth2PermissionGrants" -OutputType PSObject

    # 2. Fetch Service Principals with App Role Assignments (Permissions granted TO them)
    # Using $expand=appRoleAssignments allows us to get the permissions granted TO the SPs in the same call (pagination handled by Invoke-EntraOpsMsGraphQuery)
    # This replaces the need to query /servicePrincipals/{id}/appRoleAssignments for every SP.
    Write-Verbose "Fetching Service Principals with AppRoleAssignments..."
    $ServicePrincipals = Invoke-EntraOpsMsGraphQuery -Uri "/beta/servicePrincipals?`$select=id,appDisplayName,appRoles,publishedPermissionScopes,principalType&`$expand=appRoleAssignments" -OutputType PSObject

    # 3. Create Optimized Lookup Hashtable for Resources (Id -> Metadata)
    # Includes nested hashtables for AppRoles (Id -> Name) and Scopes (Value -> Id) for O(1) lookup
    Write-Verbose "Building Resource Lookup Table..."
    $ResourceLookup = @{}
    foreach ($Sp in $ServicePrincipals) {
        $AppRoleLookup = @{}
        if ($Sp.appRoles) {
            foreach ($Role in $Sp.appRoles) {
                # Graph objects might be PSCustomObject or Hashtable depending on deserialization
                $RId = if ($Role.id) { $Role.id } else { $Role["id"] }
                $RVal = if ($Role.value) { $Role.value } else { $Role["value"] }
                if ($RId) { $AppRoleLookup[$RId] = $RVal }
            }
        }

        $ScopeLookup = @{}
        if ($Sp.publishedPermissionScopes) {
            foreach ($Scope in $Sp.publishedPermissionScopes) {
                $SId = if ($Scope.id) { $Scope.id } else { $Scope["id"] }
                $SVal = if ($Scope.value) { $Scope.value } else { $Scope["value"] }
                if ($SVal) { $ScopeLookup[$SVal] = $SId }
            }
        }

        $ResourceLookup[$Sp.Id] = @{
            DisplayName = $Sp.appDisplayName
            AppRoles    = $AppRoleLookup
            Scopes      = $ScopeLookup
        }
    }

    $AllAssignments = @()

    # 4. Process Application Permissions (AppRoleAssignments)
    Write-Verbose "Processing App Role Assignments..."
    foreach ($Sp in $ServicePrincipals) {
        if ($Sp.appRoleAssignments) {
            $SpAppRoleAssignments = @($Sp.appRoleAssignments)
            
            # Check for expansion usage limit (20) and fetch full list if necessary
            if ($SpAppRoleAssignments.Count -ge 20) {
                Write-Verbose "Service Principal $($Sp.Id) hit expansion limit (20+ assignments). Fetching full list..."
                $SpAppRoleAssignments = Invoke-EntraOpsMsGraphQuery -Uri "/beta/servicePrincipals/$($Sp.Id)/appRoleAssignments" -OutputType PSObject
            }

            foreach ($AppRole in $SpAppRoleAssignments) {
                # Resolve details using Lookup
                $RoleName = $null
                $ResourceName = $AppRole.resourceDisplayName

                # If resourceId is missing, search through ResourceLookup to find which resource owns this appRoleId
                if ($null -eq $AppRole.resourceId -and $null -ne $AppRole.appRoleId) {
                    Write-Verbose "ResourceId missing for appRoleId $($AppRole.appRoleId). Searching ResourceLookup..."
                    foreach ($ResourceId in $ResourceLookup.Keys) {
                        if ($ResourceLookup[$ResourceId].AppRoles.ContainsKey($AppRole.appRoleId)) {
                            $AppRole.resourceId = $ResourceId
                            $ResourceName = $ResourceLookup[$ResourceId].DisplayName
                            $RoleName = $ResourceLookup[$ResourceId].AppRoles[$AppRole.appRoleId]
                            Write-Verbose "Found appRoleId in resource: $ResourceName ($ResourceId)"
                            break
                        }
                    }
                }
                
                # Standard lookup when resourceId is present
                if ($null -ne $AppRole.resourceId -and $ResourceLookup.ContainsKey($AppRole.resourceId)) {
                    $ResourceMeta = $ResourceLookup[$AppRole.resourceId]
                    $ResourceName = $ResourceMeta.DisplayName
                    if ($null -ne $AppRole.appRoleId -and $ResourceMeta.AppRoles.ContainsKey($AppRole.appRoleId)) {
                        $RoleName = $ResourceMeta.AppRoles[$AppRole.appRoleId]
                    }
                }

                $AllAssignments += [pscustomobject]@{
                    RoleAssignmentId                      = $AppRole.Id
                    RoleAssignmentScopeId                 = $AppRole.resourceId
                    RoleAssignmentScopeName               = $ResourceName
                    RoleAssignmentType                    = "Direct"
                    PIMManagedRole                        = $False
                    PIMAssignmentType                     = "Permanent"
                    RoleDefinitionName                    = $RoleName
                    RoleDefinitionId                      = $AppRole.appRoleId
                    RoleType                              = "Application"
                    RoleIsPrivileged                      = ""
                    Classification                        = $null
                    ObjectId                              = $Sp.Id
                    ObjectType                            = if ($Sp.principalType) { $Sp.principalType.ToLower() } else { "serviceprincipal" }
                    TransitiveByObjectId                  = $null
                    TransitiveByObjectDisplayName         = $null
                    TransitiveByNestingObjectIds          = $null
                    TransitiveByNestingObjectDisplayNames = $null
                }
            }
        }
    }

    # 5. Process Delegated Permissions (OAuth2PermissionGrants)
    Write-Verbose "Processing Delegated Permissions..."
    foreach ($Grant in $GlobalDelegatedPermissions) {
        # Original code iterated ServicePrincipals, so effectively filtering for assignments to them.
        # We match clientId against our loaded Service Principals to replicate this filtering.
        # Also, we must process ALL consentTypes ('Principal' and 'AllPrincipals'), as the original endpoint did.
        
        if ($Grant.clientId -and $ResourceLookup.ContainsKey($Grant.clientId)) { 
            $ResourceMeta = $null
            $ScopeLookup = $null
             
            if ($null -ne $Grant.resourceId -and $ResourceLookup.ContainsKey($Grant.resourceId)) {
                $ResourceMeta = $ResourceLookup[$Grant.resourceId]
                $ScopeLookup = $ResourceMeta.Scopes
            }
            # If resourceId is missing, search through ResourceLookup to find matching scope
            elseif ($null -eq $Grant.resourceId -and -not [string]::IsNullOrWhiteSpace($Grant.scope)) {
                Write-Verbose "ResourceId missing for OAuth2PermissionGrant $($Grant.Id). Searching ResourceLookup by scopes..."
                $Scopes = $Grant.scope -split " "
                foreach ($ResourceId in $ResourceLookup.Keys) {
                    $FoundMatch = $false
                    foreach ($Scope in $Scopes) {
                        if (-not [string]::IsNullOrWhiteSpace($Scope) -and $ResourceLookup[$ResourceId].Scopes.ContainsKey($Scope)) {
                            $Grant.resourceId = $ResourceId
                            $ResourceMeta = $ResourceLookup[$ResourceId]
                            $ScopeLookup = $ResourceMeta.Scopes
                            Write-Verbose "Found scope '$Scope' in resource: $($ResourceMeta.DisplayName) ($ResourceId)"
                            $FoundMatch = $true
                            break
                        }
                    }
                    if ($FoundMatch) { break }
                }
            }

            $Scopes = $Grant.scope -split " "
            foreach ($Scope in $Scopes) {
                if (-not [string]::IsNullOrWhiteSpace($Scope)) {
                    $ScopeId = $null
                    if ($null -ne $Scope -and $ScopeLookup -and $ScopeLookup.ContainsKey($Scope)) {
                        $ScopeId = $ScopeLookup[$Scope]
                    }

                    $AllAssignments += [pscustomobject]@{
                        RoleAssignmentId                      = $Grant.Id
                        RoleAssignmentScopeId                 = $Grant.resourceId
                        RoleAssignmentScopeName               = if ($ResourceMeta) { $ResourceMeta.DisplayName } else { $null }
                        RoleAssignmentType                    = "Direct"
                        PIMManagedRole                        = $False
                        PIMAssignmentType                     = "Permanent"
                        RoleDefinitionName                    = $Scope
                        RoleDefinitionId                      = $ScopeId
                        RoleType                              = "Delegated"
                        RoleIsPrivileged                      = ""
                        Classification                        = $null
                        ObjectId                              = $Grant.clientId
                        ObjectType                            = "serviceprincipal"
                        TransitiveByObjectId                  = $null
                        TransitiveByObjectDisplayName         = $null
                        TransitiveByNestingObjectIds          = $null
                        TransitiveByNestingObjectDisplayNames = $null
                    }
                }
            }
        }
    }

    $AllAssignments | sort-object -property RoleAssignmentScopeName, RoleDefinitionName, RoleType, RoleAssignmentId, RoleAssignmentScopeId
}
