function Get-EntraOpsRetryAfterSeconds {
    <#
    .SYNOPSIS
        Returns the Retry-After delay in seconds of a throttled HTTP response, or $null when none is given.
    .DESCRIPTION
        HttpResponseMessage headers (Invoke-RestMethod, Invoke-MgGraphRequest) have no string indexer, so
        Headers['Retry-After'] is always empty there; the typed RetryAfter property carries the value as a
        delta or an HTTP date. Dictionary-shaped headers are read by name. Both the delta-seconds and the
        HTTP-date form of the header are supported.
    .PARAMETER Response
        The response object of the failed request (e.g. $_.Exception.Response).
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Response
    )

    # Direct assignment: returning the headers through a statement would enumerate them into key/value pairs.
    if ($null -eq $Response) { return $null }
    $Headers = $Response.Headers
    if ($null -eq $Headers) { return $null }

    $ConvertDate = {
        param([DateTimeOffset]$Date)
        [int][Math]::Max(0, [Math]::Ceiling(($Date - [DateTimeOffset]::UtcNow).TotalSeconds))
    }

    if ($Headers -is [System.Net.Http.Headers.HttpResponseHeaders]) {
        $RetryAfter = $Headers.RetryAfter
        if ($null -eq $RetryAfter) { return $null }
        # PowerShell unwraps the Nullable<TimeSpan>/Nullable<DateTimeOffset> properties itself.
        if ($null -ne $RetryAfter.Delta) { return [int][Math]::Ceiling($RetryAfter.Delta.TotalSeconds) }
        if ($null -ne $RetryAfter.Date) { return (& $ConvertDate $RetryAfter.Date) }
        return $null
    }

    $Value = $null
    if ($Headers -is [System.Collections.IDictionary]) {
        foreach ($Key in $Headers.Keys) {
            if ("$Key" -eq 'Retry-After') { $Value = @($Headers[$Key])[0] }
        }
    }
    if ([string]::IsNullOrWhiteSpace("$Value")) { return $null }

    $Seconds = 0
    if ([int]::TryParse("$Value".Trim(), [ref]$Seconds)) { return [Math]::Max(0, $Seconds) }
    $Date = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse("$Value".Trim(), [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$Date)) {
        return (& $ConvertDate $Date)
    }
    return $null
}
