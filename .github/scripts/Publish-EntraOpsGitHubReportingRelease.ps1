#Requires -Version 7.4
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ReportsPath = './Reports',

    [Parameter(Mandatory = $false)]
    [AllowEmptyString()]
    [string]$ReleasesToKeep = '10'
)

$ErrorActionPreference = 'Stop'
$Timestamp = (Get-Date).ToUniversalTime()
$Tag = "reporting-$($Timestamp.ToString('yyyyMMdd-HHmmss'))"
$ArchivePath = Join-Path (Get-Location) 'EntraOps-Reporting.zip'
if (Test-Path -LiteralPath $ArchivePath) { Remove-Item -LiteralPath $ArchivePath -Force }

& zip -r $ArchivePath $ReportsPath -x '*.spec.mjs'
if ($LASTEXITCODE -ne 0) { throw "Report archive creation failed with exit code $LASTEXITCODE." }
# Tag the commit the reports were generated from: the next run uses its Privileged EAM export as EAM Dashboard change notification baseline
$TargetCommit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($TargetCommit)) { throw "Could not resolve the report commit (exit code $LASTEXITCODE)." }
$TargetCommit = $TargetCommit.Trim()
& gh release create $Tag $ArchivePath --target $TargetCommit --title "EntraOps Reporting $Tag" --notes "Automated EntraOps Privileged EAM reporting generated on $($Timestamp.ToString('yyyy-MM-dd HH:mm')) UTC." --latest
if ($LASTEXITCODE -ne 0) { throw "GitHub reporting release creation failed with exit code $LASTEXITCODE." }

if ([string]::IsNullOrWhiteSpace($ReleasesToKeep)) { return }
$Keep = 0
if (-not [int]::TryParse($ReleasesToKeep, [ref]$Keep)) {
    Write-Warning "ReportingReleasesToKeep is not a number ('$ReleasesToKeep') - skipping release pruning."
    return
}
if ($Keep -lt 1) {
    Write-Warning 'ReportingReleasesToKeep is 0 - skipping pruning to avoid deleting every reporting release.'
    return
}

$ReleaseJson = & gh release list --limit 1000 --json tagName
if ($LASTEXITCODE -ne 0) { throw "Could not list GitHub releases (exit code $LASTEXITCODE)." }
$OldTags = @($ReleaseJson | ConvertFrom-Json | ForEach-Object tagName | Where-Object { $_ -like 'reporting-*' } | Sort-Object -Descending | Select-Object -Skip $Keep)
foreach ($OldTag in $OldTags) {
    Write-Host "Pruning release $OldTag"
    & gh release delete $OldTag --cleanup-tag --yes
    if ($LASTEXITCODE -ne 0) { throw "Could not delete GitHub release '$OldTag' (exit code $LASTEXITCODE)." }
}
