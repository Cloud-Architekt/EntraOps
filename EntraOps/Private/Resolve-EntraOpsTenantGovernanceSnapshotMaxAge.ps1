<#
.SYNOPSIS
    Resolves the maximum age (in hours) of a Tenant Governance snapshot that the Configuration Analyzer
    accepts as current.

.DESCRIPTION
    Uses ConfigurationAnalyzer.MaxTenantGovernanceSnapshotAgeHours when it is set. Otherwise the limit is
    derived from TenantGovernanceSnapshot.SnapshotScheduledCron, so a weekly or monthly snapshot schedule
    does not mark every report run between two snapshots as stale:
    - day-of-month field restricted (e.g. "0 6 1 * *"): 750 hours (31 days + 6 hours)
    - day-of-week field restricted (e.g. "0 6 * * 5"): 174 hours (7 days + 6 hours)
    - otherwise (daily or no schedule): 30 hours
    The additional 6 hours cover the collection of a snapshot job after its start.

.PARAMETER Config
    The parsed EntraOps configuration (EntraOpsConfig.json). May be $null.
#>
function Resolve-EntraOpsTenantGovernanceSnapshotMaxAge {
    [CmdletBinding()]
    [OutputType([int])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Config
    )

    $ConfiguredMaxAge = $null
    if ($null -ne $Config -and $null -ne $Config.ConfigurationAnalyzer) {
        $ConfiguredMaxAge = $Config.ConfigurationAnalyzer.MaxTenantGovernanceSnapshotAgeHours
    }
    if ($null -ne $ConfiguredMaxAge -and -not [string]::IsNullOrWhiteSpace("$ConfiguredMaxAge")) {
        $ParsedMaxAge = 0
        if (-not [int]::TryParse("$ConfiguredMaxAge", [ref]$ParsedMaxAge) -or $ParsedMaxAge -lt 1 -or $ParsedMaxAge -gt 8760) {
            throw "ConfigurationAnalyzer.MaxTenantGovernanceSnapshotAgeHours must be a whole number between 1 and 8760 (or null to derive it from the snapshot schedule), but is '$ConfiguredMaxAge'."
        }
        return $ParsedMaxAge
    }

    $Cron = ''
    if ($null -ne $Config -and $null -ne $Config.TenantGovernanceSnapshot) {
        $Cron = "$($Config.TenantGovernanceSnapshot.SnapshotScheduledCron)".Trim()
    }
    $CronFields = @($Cron -split '\s+' | Where-Object { $_ })
    if ($CronFields.Count -eq 5) {
        if ($CronFields[2] -notin @('*', '?')) { return 750 }
        if ($CronFields[4] -notin @('*', '?')) { return 174 }
    }
    return 30
}
