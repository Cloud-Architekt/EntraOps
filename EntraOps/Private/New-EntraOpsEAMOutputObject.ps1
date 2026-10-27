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

    # Warn when upstream tier names and values do not match the canonical map; preserve source values.
    $CanonicalTierLevelByName = @{ ControlPlane = '0'; ManagementPlane = '1'; WorkloadPlane = '1'; UserAccess = '2'; Unclassified = 'Unclassified' }
    $PairTierLevelName = "$($ObjectDetails.AdminTierLevelName)"
    $PairTierLevel = "$($ObjectDetails.AdminTierLevel)"
    if ($CanonicalTierLevelByName.ContainsKey($PairTierLevelName) -and -not [string]::IsNullOrEmpty($PairTierLevel) -and $PairTierLevel -ne $CanonicalTierLevelByName[$PairTierLevelName]) {
        # This pair is sourced from Custom Security Attributes (two independently-tagged fields -
        # see EntraOpsConfig.json CustomSecurityAttributes.PrivilegedUserAttribute /
        # PrivilegedServicePrincipalAttribute and their paired *AdminTierLevelAttribute /
        # *AdminTierLevelNameAttribute field names) or, if enabled, AlternateObjectTierLevelAttributes.
        # Values are preserved as-is rather than normalized: silently picking one side of a
        # contradictory tier tag risks masking a genuine, security-relevant tagging mistake in either
        # direction. Fix the inconsistent value at its source in Microsoft Entra (or the alternate
        # filter expression) - do not edit generated JSON - then re-run collection. This is a hard
        # warning from CI's Test-EntraOpsGeneratedArtifacts diagnostic. See docs/core.html
        # "Classify by Custom Security Attributes" for the two paired field names to check.
        Write-Warning "Contradictory admin tier pair on object '$ObjectId' ($RoleSystem): ObjectAdminTierLevel '$PairTierLevel' does not match ObjectAdminTierLevelName '$PairTierLevelName' (canonical value: $($CanonicalTierLevelByName[$PairTierLevelName])). Fix the underlying Custom Security Attribute (or AlternateObjectTierLevelAttributes filter) for this object - see docs/core.html 'Classify by Custom Security Attributes'."
    }

    [PSCustomObject]@{
        'ObjectId'                      = $ObjectId
        'ObjectTenantId'                = $ObjectDetails.ObjectTenantId
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
        'RoleAssignments'               = @($RoleAssignments | Sort-Object { ($_.Classification | Sort-Object AdminTierLevel -Top 1).AdminTierLevel }, RoleDefinitionName, RoleAssignmentScopeId, RoleAssignmentId)
        'Sponsors'                      = $ObjectDetails.Sponsors
        'Owners'                        = $ObjectDetails.Owners
        'OwnedObjects'                  = $ObjectDetails.OwnedObjects
        'OwnedDevices'                  = $ObjectDetails.OwnedDevices
        'IdentityParent'                = $ObjectDetails.IdentityParent
        'AssociatedWorkAccount'         = $ObjectDetails.AssociatedWorkAccount
        'AssociatedPawDevice'           = $ObjectDetails.AssociatedPawDevice
    }
}
