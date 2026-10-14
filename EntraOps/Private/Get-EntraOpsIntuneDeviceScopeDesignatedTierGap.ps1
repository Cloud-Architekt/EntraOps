function Get-EntraOpsIntuneDeviceScopeDesignatedTierGap {
    <#
    .SYNOPSIS
        Reports Control Plane users whose designated tier does not contribute devices to the Tier 0 Intune scope.
    .DESCRIPTION
        Tier1Users must be the users selected for the active Intune scope mode (empty for
        ControlPlaneDevicesOnly). Returns one gap entry per tenant-local user with owned or PAW
        devices, distinguishing ManagementPlane designation from exclusion from the privileged scope.
    #>
    [CmdletBinding()]
    param (
        [AllowNull()][AllowEmptyCollection()][object[]]$PrivilegedObjects,
        [AllowNull()][AllowEmptyCollection()][object[]]$Tier0Users,
        [AllowNull()][AllowEmptyCollection()][object[]]$Tier1Users,
        [AllowNull()][AllowEmptyString()][string]$HomeTenantId
    )

    $Tier0UserIds = @($Tier0Users | Where-Object { $null -ne $_ } | ForEach-Object { "$($_.ObjectId)".ToLowerInvariant() })
    $Tier1UserIds = @($Tier1Users | Where-Object { $null -ne $_ } | ForEach-Object { "$($_.ObjectId)".ToLowerInvariant() })
    $GapUsers = @($PrivilegedObjects | Where-Object {
            $null -ne $_ -and
            $_.ObjectType -eq 'user' -and
            ([string]::IsNullOrWhiteSpace($HomeTenantId) -or [string]::IsNullOrEmpty($_.ObjectTenantId) -or $_.ObjectTenantId -eq $HomeTenantId) -and
            (@($_.OwnedDevices | Where-Object { $_ }).Count -gt 0 -or @($_.AssociatedPawDevice | Where-Object { $_ }).Count -gt 0) -and
            "$($_.ObjectId)".ToLowerInvariant() -notin $Tier0UserIds
        } | Sort-Object ObjectId -Unique)

    foreach ($User in $GapUsers) {
        $DeviceScopeTier = if ("$($User.ObjectId)".ToLowerInvariant() -in $Tier1UserIds) { 'ManagementPlane' } else { 'None' }
        $ScopeMessage = if ($DeviceScopeTier -eq 'ManagementPlane') {
            'devices are classified as Tier 1 (ManagementPlane) instead of Tier 0 (ControlPlane)'
        } else {
            'devices are not in the privileged Intune device scope'
        }
        $GapType = if ($DeviceScopeTier -eq 'ManagementPlane') {
            'IntuneDeviceScopeDesignatedTierGap.ManagementPlane'
        } else {
            'IntuneDeviceScopeDesignatedTierGap.Excluded'
        }
        [pscustomobject]@{
            Type            = $GapType
            ObjectId        = $User.ObjectId
            DeviceScopeTier = $DeviceScopeTier
            Message         = "Control Plane user $($User.ObjectId) with owned or PAW devices is not designated ControlPlane by ObjectAdminTierLevelName - $ScopeMessage"
        }
    }
}
