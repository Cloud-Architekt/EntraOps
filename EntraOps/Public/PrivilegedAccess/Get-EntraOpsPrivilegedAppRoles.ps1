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
    )

    # Set Error Action
    $ErrorActionPreference = "Stop"
    $ServicePrincipals = Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/servicePrincipals"

    # Get all role assignments
    $AllAssignments = foreach ($ServicePrincipal in $ServicePrincipals) {
        # Application Permissions
        $AppRoleAssignments = (Invoke-EntraOpsMsGraphQuery -Uri "/beta/servicePrincipals/$($ServicePrincipal.Id)/appRoleAssignments" -OutputType PSObject)
        if ($AppRoleAssignments.Id) {
            foreach ($AppRole in $AppRoleAssignments) {
                [pscustomobject]@{
                    RoleAssignmentId              = $AppRole.Id
                    RoleAssignmentScopeId         = $AppRole.resourceId
                    RoleAssignmentScopeName       = $AppRole.resourceDisplayName
                    RoleAssignmentType            = "Direct"
                    PIMManagedRole                = $False
                    PIMAssignmentType             = "Permanent"
                    RoleDefinitionName            = $null
                    RoleDefinitionId              = $AppRole.appRoleId
                    RoleType                      = "Application"
                    RoleIsPrivileged              = ""
                    Classification                = $null
                    ObjectId                      = $AppRole.principalId
                    ObjectType                    = $AppRole.principalType.ToLower()
                    TransitiveByObjectId          = $null
                    TransitiveByObjectDisplayName = $null
                }
            }
        }

        # Delegated Permissions
        $DelegatedPermissions = (Invoke-EntraOpsMsGraphQuery -Uri "/beta/servicePrincipals/$($ServicePrincipal.Id)/oauth2PermissionGrants" -OutputType PSObject)
        if ($DelegatedPermissions.Id) {
            foreach ($Grant in $DelegatedPermissions) {
                $Scopes = $Grant.scope -split " "
                foreach ($Scope in $Scopes) {
                    if (-not [string]::IsNullOrWhiteSpace($Scope)) {
                        [pscustomobject]@{
                            RoleAssignmentId              = $Grant.Id
                            RoleAssignmentScopeId         = $Grant.resourceId
                            RoleAssignmentScopeName       = $null
                            RoleAssignmentType            = "Direct"
                            PIMManagedRole                = $False
                            PIMAssignmentType             = "Permanent"
                            RoleDefinitionName            = $Scope
                            RoleDefinitionId              = $null
                            RoleType                      = "Delegated"
                            RoleIsPrivileged              = ""
                            Classification                = $null
                            ObjectId                      = $Grant.clientId
                            ObjectType                    = "serviceprincipal"
                            TransitiveByObjectId          = $null
                            TransitiveByObjectDisplayName = $null
                        }
                    }
                }
            }
        }
    }

    # Get names for app roles and delegated permissions
    $ResourceIds = ($AllAssignments | Select-Object -unique RoleAssignmentScopeId).RoleAssignmentScopeId
    $Resources = foreach ($ResourceId in $ResourceIds) {
        Invoke-EntraOpsMsGraphQuery -Uri "/beta/servicePrincipals/$($ResourceId)?$select=appRoles,publishedPermissionScopes,appDisplayName"
    }

    # Lookup for app role names and delegated permission ids
    $AppRoleAssignments = foreach ($Assignment in $AllAssignments) {
        $Resource = $Resources | where-object { $_.id -eq $Assignment.RoleAssignmentScopeId }
        
        if ($Assignment.RoleType -eq "Application") {
            $MatchedRole = $Resource | select-object -ExpandProperty AppRoles | Where-Object { $_.id -eq $($Assignment.RoleDefinitionId) }
            $Assignment.RoleDefinitionName = $MatchedRole.value
        } elseif ($Assignment.RoleType -eq "Delegated") {
            $Assignment.RoleAssignmentScopeName = $Resource.appDisplayName
            $MatchedScope = $Resource | select-object -ExpandProperty publishedPermissionScopes | Where-Object { $_.value -eq $($Assignment.RoleDefinitionName) }
            $Assignment.RoleDefinitionId = $MatchedScope.id
        }
        $Assignment
    }
    $AppRoleAssignments
    $AppRoleAssignments = $AppRoleAssignments | sort-object -property RoleAssignmentScopeName, RoleDefinitionName
}
