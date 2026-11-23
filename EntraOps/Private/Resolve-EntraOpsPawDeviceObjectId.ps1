<#
.SYNOPSIS
    Resolves a PAW reference of the custom security attribute of a privileged user to the object ID of its device.

.DESCRIPTION
    The PAW attribute (CustomSecurityAttributes.PrivilegedUserPawAttribute, associatedSecureAdminWorkstation) names
    the device by its device ID (deviceId, as the Microsoft Entra admin center and Intune show it) or by its object
    ID. The Privileged EAM export keeps the reference (AssociatedPawDevice) and adds the object ID
    (AssociatedPawDeviceObjectId): the reports, the finding rules (EO.4007, EO.4008) and the device lookups
    (administrative units, owned devices) use the object ID (Get-EntraOpsPawDeviceObjectId), so the reference is
    resolved to it:
      * a device with this device ID: its object ID
      * else a device with this object ID: the reference itself
      * else (no such device): $null with a warning, so the user counts as without PAW
    A reference that cannot be checked (Microsoft Graph fails with another error than 404) is kept as it is.
    Both lookups are GET requests of the Graph cache, so a PAW of several users is looked up once.

.PARAMETER Value
    The reference of the attribute.

.PARAMETER UserId
    Object ID of the privileged user, for the warnings.

.OUTPUTS
    The object ID of the device (lower case), or $null.
#>
function Resolve-EntraOpsPawDeviceObjectId {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory = $false)]
        [string]$UserId
    )

    $Reference = $Value.Trim()
    if (-not $Reference) { return $null }
    if ($Reference -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        Write-Warning "The PAW reference '$Reference' of user $UserId is no device ID or object ID; it is ignored."
        return $null
    }

    # The device ID, as admins usually enter it.
    try {
        $ByDeviceId = @(Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/v1.0/devices?`$filter=deviceId eq '$Reference'&`$select=id" -OutputType PSObject -ThrowOnFailure | Where-Object { $_.id })
    } catch {
        Write-Warning "The PAW reference '$Reference' of user $UserId could not be checked ($($_.Exception.Message)); it is kept as it is."
        return $Reference.ToLowerInvariant()
    }
    if ($ByDeviceId.Count -gt 0) { return "$($ByDeviceId[0].id)".ToLowerInvariant() }

    # The object ID of the device.
    try {
        $ByObjectId = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/v1.0/devices/$($Reference)?`$select=id" -OutputType PSObject -ThrowOnFailure -SuppressNotFoundWarning
        if ($ByObjectId.id) { return "$($ByObjectId.id)".ToLowerInvariant() }
    } catch {
        if ($_.Exception.Data['StatusCode'] -ne 404) {
            Write-Warning "The PAW reference '$Reference' of user $UserId could not be checked ($($_.Exception.Message)); it is kept as it is."
            return $Reference.ToLowerInvariant()
        }
    }
    Write-EntraOpsWarningOnce -Key "PawReferenceWithoutDevice|$Reference|$UserId" -Message "The PAW reference '$Reference' of user $UserId matches no device (neither its device ID nor its object ID); the user counts as without PAW."
    return $null
}
