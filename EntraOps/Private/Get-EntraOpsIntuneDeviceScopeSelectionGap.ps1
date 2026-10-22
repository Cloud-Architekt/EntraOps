function Get-EntraOpsIntuneDeviceScopeSelectionGap {
    <#
    .SYNOPSIS
        Reports owned or PAW devices of Control Plane users that are not selected for privileged Intune scope generation.
    .DESCRIPTION
        Compares the owned and PAW devices of tenant-local Control Plane users with the device IDs selected
        for the active Intune scope mode (Tier0DeviceIds plus Tier1DeviceIds). Returns one entry per user with
        at least one unselected device. SourceSelection states whether the user itself was selected as a
        ControlPlane or ManagementPlane source; it is context, not the confirmed cause of the gap
        (e.g. device data from live resolution can differ from the export used for selection).
        Selection does not establish effective coverage: selected devices still require groups with Intune
        scope tag assignments.
    .PARAMETER PrivilegedObjects
        Control Plane objects from Get-EntraOpsClassificationControlPlaneObjects.
    .PARAMETER Tier0Users
        Users selected as ControlPlane sources.
    .PARAMETER Tier1Users
        Users selected as ManagementPlane sources in the active mode (empty for ControlPlaneDevicesOnly).
    .PARAMETER SelectedDeviceIds
        Device IDs selected for privileged Intune scope generation in the active mode.
    .PARAMETER HomeTenantId
        Home tenant ID; users of other tenants are skipped. When empty, users are not filtered by tenant.
    #>
    [CmdletBinding()]
    param (
        [AllowNull()][AllowEmptyCollection()][object[]]$PrivilegedObjects,
        [AllowNull()][AllowEmptyCollection()][object[]]$Tier0Users,
        [AllowNull()][AllowEmptyCollection()][object[]]$Tier1Users,
        [AllowNull()][AllowEmptyCollection()][object[]]$SelectedDeviceIds,
        [AllowNull()][AllowEmptyString()][string]$HomeTenantId
    )

    $NewIdSet = {
        param([object[]]$Values)
        $Set = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($Value in $Values) {
            if (-not [string]::IsNullOrWhiteSpace("$Value")) { [void]$Set.Add("$Value".Trim().ToLowerInvariant()) }
        }
        , $Set
    }
    $GetOptionalValue = {
        param($Object, [string]$PropertyName)
        $Property = $Object.PSObject.Properties[$PropertyName]
        if ($null -ne $Property) { $Property.Value } else { $null }
    }

    $SelectedDevices = & $NewIdSet $SelectedDeviceIds
    $Tier0UserIds = & $NewIdSet @($Tier0Users | Where-Object { $null -ne $_ } | ForEach-Object { & $GetOptionalValue $_ 'ObjectId' })
    $Tier1UserIds = & $NewIdSet @($Tier1Users | Where-Object { $null -ne $_ } | ForEach-Object { & $GetOptionalValue $_ 'ObjectId' })

    $UserGroups = @($PrivilegedObjects | Where-Object {
            $null -ne $_ -and
            "$(& $GetOptionalValue $_ 'ObjectType')" -eq 'user' -and
            -not [string]::IsNullOrWhiteSpace("$(& $GetOptionalValue $_ 'ObjectId')") -and
            ([string]::IsNullOrWhiteSpace($HomeTenantId) -or [string]::IsNullOrEmpty("$(& $GetOptionalValue $_ 'ObjectTenantId')") -or "$(& $GetOptionalValue $_ 'ObjectTenantId')" -eq $HomeTenantId)
        } | Group-Object -Property { "$($_.ObjectId)".Trim().ToLowerInvariant() } | Sort-Object Name)

    foreach ($UserGroup in $UserGroups) {
        # Original casing for display; first non-null device value per normalized ID.
        $DeviceIdsByKey = [ordered]@{}
        foreach ($Entry in $UserGroup.Group) {
            foreach ($DeviceId in @(& $GetOptionalValue $Entry 'OwnedDevices') + @(& $GetOptionalValue $Entry 'AssociatedPawDevice')) {
                if ([string]::IsNullOrWhiteSpace("$DeviceId")) { continue }
                $Key = "$DeviceId".Trim().ToLowerInvariant()
                if (-not $DeviceIdsByKey.Contains($Key)) { $DeviceIdsByKey[$Key] = "$DeviceId".Trim() }
            }
        }
        $UnselectedDeviceIds = @($DeviceIdsByKey.Keys | Where-Object { -not $SelectedDevices.Contains($_) } | Sort-Object | ForEach-Object { $DeviceIdsByKey[$_] })
        if ($UnselectedDeviceIds.Count -eq 0) { continue }

        $UserId = "$($UserGroup.Group[0].ObjectId)"
        $SourceSelection = if ($Tier0UserIds.Contains($UserGroup.Name)) {
            'ControlPlane'
        } elseif ($Tier1UserIds.Contains($UserGroup.Name)) {
            'ManagementPlane'
        } else {
            'None'
        }
        $SourceText = if ($SourceSelection -eq 'None') { 'user not selected as source' } else { "user selected as $SourceSelection source" }

        [pscustomobject]@{
            Type                = 'IntuneDeviceScopeSelectionGap'
            ObjectId            = $UserId
            SourceSelection     = $SourceSelection
            UnselectedDeviceIds = $UnselectedDeviceIds
            Message             = "Control Plane user $UserId has $($UnselectedDeviceIds.Count) owned or PAW device(s) not selected for privileged Intune scope generation in the active mode ($SourceText)"
        }
    }
}
