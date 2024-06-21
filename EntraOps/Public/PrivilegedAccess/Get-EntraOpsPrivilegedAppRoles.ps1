<#
.SYNOPSIS
    Get a list in schema of EntraOps with all service principals with exposed app roles in Entra ID.

.DESCRIPTION
    Get a list in schema of EntraOps with all service principals with exposed app roles in Entra ID.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.EXAMPLE
    List of all app roles from service principals in Entra ID.
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
    $AppRoleAssignments = foreach ($ServicePrincipal in $ServicePrincipals) {
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
    }

    # Get names for app roles
    $AppRoleResourceIds = ($AppRoleAssignments | Select-Object -unique RoleAssignmentScopeId).RoleAssignmentScopeId
    $AppRolesByResource = foreach ($AppRoleResourceId in $AppRoleResourceIds) {
        Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/servicePrincipals/$($AppRoleResourceId)?$select=appRoles,appDisplayName"
    }

    # Lookup for app role names for app role assignments
    $AppRoleAssignments = foreach ($AppRoleAssignment in $AppRoleAssignments) {
        $MatchedAppRole = $AppRolesByResource | where-object { $_.id -eq $AppRoleAssignment.RoleAssignmentScopeId } | select-object -ExpandProperty AppRoles | Where-Object { $_.id -eq $($AppRoleAssignment.RoleDefinitionId) }
        $AppRoleAssignment.RoleDefinitionName = $MatchedAppRole.value
        $AppRoleAssignment
    }
    $AppRoleAssignments
}