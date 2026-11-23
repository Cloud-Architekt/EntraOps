function New-EntraOpsPrivilegeHistoryFindingContext {
    <#
    .SYNOPSIS
        Builds the Privileged EAM snapshots that the Privilege History finding rules compare.
    .DESCRIPTION
        Reads the generated Privilege History report data (PrivilegeHistory/data/privilege-history-data.js in
        -ReportPath) and returns its snapshots with content, oldest first. The rules compare the newest
        snapshot (Latest) with the snapshot before it (Previous). SkipReason is set when the data is missing
        or has fewer than two snapshots.

        Used by Invoke-EntraOpsFindingEvaluation.
    .PARAMETER ReportPath
        The Reports folder with the generated report data.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ReportPath
    )

    $Path = Join-Path $ReportPath 'PrivilegeHistory/data/privilege-history-data.js'
    $Context = [pscustomobject]@{ Area = 'PrivilegeHistory'; Previous = $null; Latest = $null }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $Context | Add-Member -NotePropertyName SkipReason -NotePropertyValue "No Privilege History data found in $ReportPath. Generate the report data with New-EntraOpsReportingData, or pass -ReportPath."
        return $Context
    }

    $Data = (Read-EntraOpsReportDataFile -Path $Path).Data

    # Snapshots with content, sorted by commit date (stable); a snapshot without a readable commit date sorts
    # first. New-EntraOpsPrivilegedEamPrivilegeHistoryData keeps the objects of a limited number of snapshots
    # (-MaxDetailedSnapshots) and thins the others out (hasDetail false, no objects): they only have trend
    # numbers and cannot be compared, so the previous snapshot is the newest one before the latest that has objects.
    $Snapshots = @(@($Data['snapshots']) | Where-Object {
            $_ -is [System.Collections.IDictionary] -and $_['objects'] -is [array] -and $_['hasDetail'] -ne $false
        } | Sort-Object -Stable { ConvertTo-EntraOpsPrivilegeHistoryDate $_['commitDate'] })
    if ($Snapshots.Count -lt 2) {
        $Context | Add-Member -NotePropertyName SkipReason -NotePropertyValue 'The Privilege History data has fewer than two snapshots with objects to compare. Commit the Privileged EAM export (the history is built from the git history of the export) and generate the report data again.'
        return $Context
    }
    $Context.Previous = $Snapshots[-2]
    $Context.Latest = $Snapshots[-1]
    $Context
}

function ConvertTo-EntraOpsPrivilegeHistoryDate {
    <#
    .SYNOPSIS
        Converts the commit date of a Privilege History snapshot to a date, or [datetimeoffset]::MinValue.
    .DESCRIPTION
        The date is ISO text, or a date when an older PowerShell converted it. An empty or unreadable value
        returns MinValue, so the snapshot sorts first and is never taken for the newest one.
    #>
    [CmdletBinding()]
    [OutputType([datetimeoffset])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    if ($Value -is [datetimeoffset]) { return $Value }
    if ($Value -is [datetime]) { return [datetimeoffset]$Value }
    $Date = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse("$Value", [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$Date)) { return $Date }
    return [datetimeoffset]::MinValue
}
