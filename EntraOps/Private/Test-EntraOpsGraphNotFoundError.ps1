<#
.SYNOPSIS
    Tests whether an error record from Invoke-EntraOpsMsGraphQuery -ThrowOnFailure means that the
    requested directory object no longer exists.

.DESCRIPTION
    Membership synchronization reads the Privileged EAM export from the last Pull run. An object can
    be deleted in Microsoft Entra between that Pull and the Push run, so Microsoft Graph answers
    HTTP 404 (Request_ResourceNotFound) for it. Callers use this test to skip such objects instead of
    counting them as failed membership operations. Any other status code stays a failure.

    A membership POST/DELETE also answers 404 when the destination administrative unit or group itself
    was deleted during the run. With -DestinationUri the destination is read once more; when it is
    confirmed missing the function returns $false so the caller reports a failed operation instead of
    a harmless skip. An inconclusive check (any other error while reading the destination) keeps the
    404 classified as a deleted source object.

.PARAMETER ErrorRecord
    The error record caught from Invoke-EntraOpsMsGraphQuery -ThrowOnFailure.

.PARAMETER DestinationUri
    Graph URI of the destination administrative unit or group of the membership operation, for example
    /beta/administrativeUnits/{id} or /v1.0/groups/{id}.
#>
function Test-EntraOpsGraphNotFoundError {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter(Mandatory = $false)]
        [string]$DestinationUri
    )

    $IsNotFound = {
        param($Exception)
        if ($null -eq $Exception) { return $false }
        if ($Exception.Data['StatusCode'] -eq 404) { return $true }
        if ("$($Exception.Data['ErrorCode'])" -eq 'Request_ResourceNotFound') { return $true }
        return $false
    }

    if (-not (& $IsNotFound $ErrorRecord.Exception)) { return $false }
    if ([string]::IsNullOrWhiteSpace($DestinationUri)) { return $true }

    try {
        Invoke-EntraOpsMsGraphQuery -Method GET -Uri $DestinationUri -OutputType PSObject -DisableCache -ThrowOnFailure -SuppressNotFoundWarning | Out-Null
        return $true
    } catch {
        if (& $IsNotFound $_.Exception) {
            Write-Warning "Destination $DestinationUri no longer exists - membership operations against it are reported as failed."
            return $false
        }
        Write-Verbose "Could not verify destination $DestinationUri ($($_.Exception.Message)); treating the 404 as a deleted source object."
        return $true
    }
}
