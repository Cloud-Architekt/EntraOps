<#
.SYNOPSIS
    Returns since when a Tenant Governance resource type has been preserved as stale.

.DESCRIPTION
    A resource type that stays PreservedStale keeps the StaleSince of its previous state, so the age covers every
    consecutive snapshot in which the type could not be captured. A type that becomes stale now, or whose previous
    state has no StaleSince (manifests written before StaleSince existed), starts at the attempt time of this
    snapshot. Returns the time as a UTC ISO 8601 string, or $null when no time can be read.

.PARAMETER PreviousState
    ResourceTypeStates entry of the type in the previous snapshot manifest, or $null.

.PARAMETER AttemptDateTime
    Creation time of the current snapshot job.
#>
function Get-EntraOpsTenantGovernanceStaleSince {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [object]$PreviousState,

        [Parameter(Mandatory = $false)]
        [object]$AttemptDateTime
    )

    $ConvertToUtcString = {
        param([object]$Value)
        if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime.ToString('o') }
        if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
        $Parsed = [datetimeoffset]::MinValue
        if (-not [string]::IsNullOrWhiteSpace("$Value") -and [datetimeoffset]::TryParse("$Value", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$Parsed)) {
            return $Parsed.UtcDateTime.ToString('o')
        }
        return $null
    }

    if ($null -ne $PreviousState -and "$($PreviousState.Status)" -eq 'PreservedStale') {
        $PreviousStaleSince = & $ConvertToUtcString $PreviousState.StaleSince
        if ($PreviousStaleSince) { return $PreviousStaleSince }
    }
    return (& $ConvertToUtcString $AttemptDateTime)
}

<#
.SYNOPSIS
    Formats the stale resource types of a snapshot manifest with the time they have been stale for a warning.
#>
function Format-EntraOpsTenantGovernanceStaleAge {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [object[]]$ResourceTypeStates
    )

    $Now = (Get-Date).ToUniversalTime()
    $Entries = foreach ($State in @($ResourceTypeStates | Where-Object { $null -ne $_ -and "$($_.Status)" -eq 'PreservedStale' })) {
        $Since = [datetimeoffset]::MinValue
        if ($State.StaleSince -and [datetimeoffset]::TryParse("$($State.StaleSince)", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$Since)) {
            $Days = [Math]::Floor(($Now - $Since.UtcDateTime).TotalDays)
            "$($State.ResourceType) (stale since $($Since.UtcDateTime.ToString('yyyy-MM-dd')), $Days day(s))"
        } else {
            "$($State.ResourceType) (stale since unknown)"
        }
    }
    return (@($Entries) -join ', ')
}
