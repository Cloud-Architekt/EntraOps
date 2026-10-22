<#
.SYNOPSIS
    Returns the capture time and age of the published Tenant Governance snapshot from its manifest.

.DESCRIPTION
    Reads CapturedDateTime of TenantGovernance/Snapshots/.SnapshotManifest.json. Returns $null when the
    manifest is missing, unreadable or has no valid CapturedDateTime; the Configuration Analyzer generator
    reports those cases itself.

.PARAMETER ManifestPath
    Path to .SnapshotManifest.json.
#>
function Get-EntraOpsTenantGovernanceSnapshotAge {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath
    )

    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { return $null }
    try {
        $Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -Depth 20 -ErrorAction Stop
    } catch {
        Write-Verbose "Tenant Governance snapshot manifest $ManifestPath could not be read: $($_.Exception.Message)"
        return $null
    }

    $CapturedDateTime = $null
    if ($Manifest.CapturedDateTime -is [datetimeoffset]) {
        $CapturedDateTime = $Manifest.CapturedDateTime
    } elseif ($Manifest.CapturedDateTime -is [datetime]) {
        $CapturedDateTime = [datetimeoffset]$Manifest.CapturedDateTime
    } else {
        $ParsedCapturedDateTime = [datetimeoffset]::MinValue
        if ([datetimeoffset]::TryParse([string]$Manifest.CapturedDateTime, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$ParsedCapturedDateTime)) {
            $CapturedDateTime = $ParsedCapturedDateTime
        }
    }
    if ($null -eq $CapturedDateTime) { return $null }

    return [pscustomobject]@{
        CapturedDateTime = $CapturedDateTime
        AgeHours         = ((Get-Date).ToUniversalTime() - $CapturedDateTime.UtcDateTime).TotalHours
    }
}
