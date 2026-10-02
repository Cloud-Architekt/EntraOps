function Test-EntraOpsAlternateObjectTierLevelEnabled {
    <#
    .SYNOPSIS
        Returns $true when AlternateObjectTierLevelAttributes filters classify the given object type.
    .DESCRIPTION
        The 'Enabled' property of the object type section (User, ServicePrincipal, Group) decides.
        Without it, older config files keep their behavior: User and ServicePrincipal follow the
        top-level 'Enabled' property, Group is enabled when at least one Group filter is set.
    .PARAMETER ObjectType
        The EntraOps object type. One of 'User', 'ServicePrincipal' or 'Group'.
    .PARAMETER AlternateObjectTierLevelAttributes
        The "AlternateObjectTierLevelAttributes" section of EntraOpsConfig.json (or $null/absent).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('User', 'ServicePrincipal', 'Group')]
        [string]$ObjectType,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSObject]$AlternateObjectTierLevelAttributes
    )

    if ($null -eq $AlternateObjectTierLevelAttributes) {
        return $false
    }

    $TypeConfig = $AlternateObjectTierLevelAttributes.$ObjectType
    if ($null -ne $TypeConfig -and $null -ne $TypeConfig.Enabled) {
        return $TypeConfig.Enabled -eq $true
    }

    if ($ObjectType -eq 'Group') {
        return $null -ne $TypeConfig -and @('ControlPlane', 'ManagementPlane', 'WorkloadPlane', 'UserAccess' | Where-Object { -not [string]::IsNullOrWhiteSpace($TypeConfig.$_) }).Count -gt 0
    }

    return $AlternateObjectTierLevelAttributes.Enabled -eq $true
}
