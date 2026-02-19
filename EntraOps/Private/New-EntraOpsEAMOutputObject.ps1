function New-EntraOpsEAMOutputObject {
    <#
    .SYNOPSIS
        Builds a standardized EAM output PSCustomObject from object details, classifications, and role assignments.
    .DESCRIPTION
        Shared helper that constructs the 20+ property output object used identically across
        all EAM cmdlets (EntraID, Defender, Intune, IdGov, ResourceApps).
    .PARAMETER ObjectId
        The object ID of the principal.
    .PARAMETER ObjectDetails
        The resolved object details from Get-EntraOpsPrivilegedEntraObject.
    .PARAMETER Classification
        The aggregated classification array for this object.
    .PARAMETER RoleAssignments
        The role assignments for this object.
    .PARAMETER RoleSystem
        The RBAC system name (e.g., "EntraID", "Defender", "DeviceManagement", "IdentityGovernance", "ResourceApps").
    .OUTPUTS
        [PSCustomObject] Standardized EAM output object.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ObjectId,

        [Parameter(Mandatory = $true)]
        [object]$ObjectDetails,

        [Parameter(Mandatory = $true)]
        [array]$Classification,

        [Parameter(Mandatory = $true)]
        [array]$RoleAssignments,

        [Parameter(Mandatory = $true)]
        [string]$RoleSystem
    )

    [PSCustomObject]@{
        'ObjectId'                      = $ObjectId
        'ObjectType'                    = ($ObjectDetails.ObjectType ?? 'unknown').ToLower()
        'ObjectSubType'                 = $ObjectDetails.ObjectSubType
        'ObjectDisplayName'             = $ObjectDetails.ObjectDisplayName
        'ObjectUserPrincipalName'       = $ObjectDetails.ObjectSignInName
        'ObjectAdminTierLevel'          = $ObjectDetails.AdminTierLevel
        'ObjectAdminTierLevelName'      = $ObjectDetails.AdminTierLevelName
        'OnPremSynchronized'            = $ObjectDetails.OnPremSynchronized
        'AssignedAdministrativeUnits'   = $ObjectDetails.AssignedAdministrativeUnits
        'RestrictedManagementByRAG'     = $ObjectDetails.RestrictedManagementByRAG
        'RestrictedManagementByAadRole' = $ObjectDetails.RestrictedManagementByAadRole
        'RestrictedManagementByRMAU'    = $ObjectDetails.RestrictedManagementByRMAU
        'RoleSystem'                    = $RoleSystem
        'Classification'                = $Classification
        'RoleAssignments'               = @($RoleAssignments | Sort-Object { ($_.Classification | Sort-Object AdminTierLevel | Select-Object -First 1).AdminTierLevel }, RoleDefinitionName, RoleAssignmentScopeId)
        'Sponsors'                      = $ObjectDetails.Sponsors
        'Owners'                        = $ObjectDetails.Owners
        'OwnedObjects'                  = $ObjectDetails.OwnedObjects
        'OwnedDevices'                  = $ObjectDetails.OwnedDevices
        'IdentityParent'                = $ObjectDetails.IdentityParent
        'AssociatedWorkAccount'         = $ObjectDetails.AssociatedWorkAccount
        'AssociatedPawDevice'           = $ObjectDetails.AssociatedPawDevice
    }
}
