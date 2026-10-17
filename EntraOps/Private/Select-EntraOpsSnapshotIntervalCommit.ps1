<#
.SYNOPSIS
    Thins a chronological commit list down to one commit per snapshot interval.

.DESCRIPTION
    Keeps the first and the last commit, and every commit that is at least one interval after the
    previously kept commit. A commit up to a quarter of the interval (at most 12 hours) early still
    counts as the next interval: snapshot jobs that run on the interval's cadence finish a few minutes
    earlier or later on every run, and a strict comparison would drop every other snapshot whenever
    the next run finishes earlier than the previously kept one.

.PARAMETER Commit
    Commits sorted from oldest to newest. Each needs a Date property ([datetimeoffset]).

.PARAMETER Years
    Years of the interval.

.PARAMETER Months
    Months of the interval.

.PARAMETER Days
    Days of the interval (weeks already converted to days).
#>
function Select-EntraOpsSnapshotIntervalCommit {
    [CmdletBinding()]
    [OutputType([object[]])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Commit,

        [Parameter(Mandatory = $false)]
        [int]$Years = 0,

        [Parameter(Mandatory = $false)]
        [int]$Months = 0,

        [Parameter(Mandatory = $false)]
        [int]$Days = 0
    )

    if ($Commit.Count -le 2 -or ($Years -le 0 -and $Months -le 0 -and $Days -le 0)) { return , @($Commit) }

    $MaxSlack = [timespan]::FromHours(12)
    $Kept = [System.Collections.Generic.List[object]]::new()
    $LastKeptDate = $null
    for ($Index = 0; $Index -lt $Commit.Count; $Index++) {
        $Current = $Commit[$Index]
        $IsLast = ($Index -eq $Commit.Count - 1)
        $Keep = $null -eq $LastKeptDate -or $IsLast
        if (-not $Keep) {
            $NextDate = [datetimeoffset]$LastKeptDate
            if ($Years -gt 0) { $NextDate = $NextDate.AddYears($Years) }
            if ($Months -gt 0) { $NextDate = $NextDate.AddMonths($Months) }
            if ($Days -gt 0) { $NextDate = $NextDate.AddDays($Days) }
            $Slack = [timespan]::FromTicks([math]::Min(($NextDate - $LastKeptDate).Ticks / 4, $MaxSlack.Ticks))
            $Keep = $Current.Date -ge ($NextDate - $Slack)
        }
        if ($Keep) {
            $Kept.Add($Current)
            $LastKeptDate = [datetimeoffset]$Current.Date
        }
    }
    return , $Kept.ToArray()
}
