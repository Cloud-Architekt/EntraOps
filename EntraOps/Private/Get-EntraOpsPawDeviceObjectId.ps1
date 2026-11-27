<#
.SYNOPSIS
    Returns the object IDs of the PAW devices of a privileged object of the Privileged EAM export.

.DESCRIPTION
    AssociatedPawDeviceObjectId holds the object IDs of the devices that the PAW attribute names
    (Resolve-EntraOpsPawDeviceObjectId); AssociatedPawDevice keeps the references as the attribute has them (device
    ID or object ID), for example for Microsoft Sentinel and BloodHound. Device lookups in Microsoft Graph, the
    finding rules and the reports need the object ID. Exports of EntraOps before 1.2.0 have no
    AssociatedPawDeviceObjectId: their AssociatedPawDevice is returned instead.

.PARAMETER Object
    A privileged object of the Privileged EAM export (PSCustomObject or dictionary).
#>
function Get-EntraOpsPawDeviceObjectId {
    param($Object)

    if ($null -eq $Object) { return @() }
    $Resolved = $null
    $HasResolved = $false
    if ($Object -is [System.Collections.IDictionary]) {
        $HasResolved = $Object.Contains('AssociatedPawDeviceObjectId')
        $Resolved = if ($HasResolved) { $Object['AssociatedPawDeviceObjectId'] } else { $Object['AssociatedPawDevice'] }
    } else {
        $HasResolved = $null -ne $Object.PSObject.Properties['AssociatedPawDeviceObjectId']
        $Resolved = if ($HasResolved) { $Object.AssociatedPawDeviceObjectId } elseif ($null -ne $Object.PSObject.Properties['AssociatedPawDevice']) { $Object.AssociatedPawDevice }
    }
    @(@($Resolved) | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") } | ForEach-Object { "$_" })
}
