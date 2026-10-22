<#
.SYNOPSIS
    Remove the environment-specific generated data of the EntraOps Reporting static web apps.

.DESCRIPTION
    Deletes the generated (tenant/environment-specific) dataset files written by
    New-EntraOpsReportingData and its individual app generators:

        * Classification Explorer (Reports/ClassificationExplorer):
            - data-manifest.json
            - data/classification-data.js
            - data/attack-paths.js
            - data/tier-map.js
        * Tier Breach Analyzer (Reports/TierBreachAnalyzer):
            - data/tier-breach-data.js
        * EAM Dashboard (Reports/EamDashboard):
            - data/eam-dashboard-data.js
        * Privileged Assets (Reports/PrivilegedAssets):
            - data/privileged-assets-data.js
        * Privilege History (Reports/PrivilegeHistory):
            - data/privilege-history-data.js
        * Access Path Map (Reports/AccessPathMap):
            - data/access-path-map-data.js
        * Configuration Analyzer (Reports/ConfigurationAnalyzer):
            - data/configuration-analyzer-data.js
        * Access Package Flow (Reports/AccessPackageFlow):
            - data/access-package-assignments-data.js

    Only these known generated files are removed; the app shell (index.html, css/, js/,
    assets/) and the data/ folders themselves are left in place. Use this before sharing
    or committing the repository to make sure no tenant-specific data is left behind, or
    to reset an app back to its "no dataset found" state.

.PARAMETER EntraOpsRoot
    Path to the EntraOps repository root. Defaults to the repository this module lives in.

.PARAMETER ClassificationExplorerAppRoot
    Path to the Classification Explorer app folder. Defaults to Reports/ClassificationExplorer
    under EntraOpsRoot.

.PARAMETER TierBreachAnalyzerAppRoot
    Path to the Tier Breach Analyzer app folder. Defaults to Reports/TierBreachAnalyzer under
    EntraOpsRoot.

.PARAMETER EamDashboardAppRoot
    Path to the EAM Dashboard app folder. Defaults to Reports/EamDashboard under EntraOpsRoot.

.PARAMETER PrivilegedAssetsAppRoot
    Path to the Privileged Assets app folder. Defaults to Reports/PrivilegedAssets
    under EntraOpsRoot.

.PARAMETER PrivilegeHistoryAppRoot
    Path to the Privilege History app folder. Defaults to Reports/PrivilegeHistory under EntraOpsRoot.

.PARAMETER AccessPathMapAppRoot
    Path to the Access Path Map app folder. Defaults to Reports/AccessPathMap under
    EntraOpsRoot.

.PARAMETER ConfigurationAnalyzerAppRoot
    Path to the Configuration Analyzer app folder. Defaults to
    Reports/ConfigurationAnalyzer under EntraOpsRoot.

.PARAMETER AccessPackageFlowAppRoot
    Path to the Access Package Flow app folder. Defaults to Reports/AccessPackageFlow under
    EntraOpsRoot.

.PARAMETER SkipClassificationExplorer
    Do not remove Classification Explorer generated data.

.PARAMETER SkipTierBreachAnalyzer
    Do not remove Tier Breach Analyzer generated data.

.PARAMETER SkipEamDashboard
    Do not remove EAM Dashboard generated data.

.PARAMETER SkipPrivilegedAssets
    Do not remove Privileged Assets generated data.

.PARAMETER SkipPrivilegeHistory
    Do not remove Privilege History generated data.

.PARAMETER SkipAccessPathMap
    Do not remove Access Path Map generated data.

.PARAMETER SkipConfigurationAnalyzer
    Do not remove Configuration Analyzer generated data.

.PARAMETER SkipAccessPackageFlow
    Do not remove Access Package Flow generated data.

.PARAMETER PassThru
    Emit an object for every generated file found (with its removal status) to the pipeline.

.EXAMPLE
    Remove-EntraOpsReportingData

    Removes the generated datasets of all reporting apps in this repository checkout.

.EXAMPLE
    Remove-EntraOpsReportingData -SkipTierBreachAnalyzer -WhatIf

    Shows what would be removed for the Classification Explorer only, without deleting anything.
#>

function Remove-EntraOpsReportingData {

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$EntraOpsRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$ClassificationExplorerAppRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$TierBreachAnalyzerAppRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$EamDashboardAppRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$PrivilegedAssetsAppRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$PrivilegeHistoryAppRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$AccessPathMapAppRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$ConfigurationAnalyzerAppRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$AccessPackageFlowAppRoot,

        [Parameter(Mandatory = $false)]
        [switch]$SkipClassificationExplorer,

        [Parameter(Mandatory = $false)]
        [switch]$SkipTierBreachAnalyzer,

        [Parameter(Mandatory = $false)]
        [switch]$SkipEamDashboard,

        [Parameter(Mandatory = $false)]
        [switch]$SkipPrivilegedAssets,

        [Parameter(Mandatory = $false)]
        [switch]$SkipPrivilegeHistory,

        [Parameter(Mandatory = $false)]
        [switch]$SkipAccessPathMap,

        [Parameter(Mandatory = $false)]
        [switch]$SkipConfigurationAnalyzer,

        [Parameter(Mandatory = $false)]
        [switch]$SkipAccessPackageFlow,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    # Resolve the repository root relative to the module location. Prefer the module's
    # own ModuleBase (always populated for exported module functions) over $PSScriptRoot,
    # which can be empty depending on how the function was invoked/loaded.
    $ModuleRoot = $MyInvocation.MyCommand.Module.ModuleBase
    if ([string]::IsNullOrWhiteSpace($ModuleRoot) -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $ModuleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    }
    if ([string]::IsNullOrWhiteSpace($ModuleRoot)) {
        throw "Unable to resolve the EntraOps module location. Import the module with 'Import-Module <path-to-EntraOps> -Force' and try again."
    }
    $RepositoryRoot = if (-not [string]::IsNullOrWhiteSpace($Global:EntraOpsBaseFolder)) { $Global:EntraOpsBaseFolder } else { Split-Path -Parent $ModuleRoot }
    if ([string]::IsNullOrWhiteSpace($EntraOpsRoot)) { $EntraOpsRoot = $RepositoryRoot }

    if ([string]::IsNullOrWhiteSpace($ClassificationExplorerAppRoot)) {
        $ClassificationExplorerAppRoot = Join-Path $EntraOpsRoot 'Reports/ClassificationExplorer'
    }
    if ([string]::IsNullOrWhiteSpace($TierBreachAnalyzerAppRoot)) {
        $TierBreachAnalyzerAppRoot = Join-Path $EntraOpsRoot 'Reports/TierBreachAnalyzer'
    }
    if ([string]::IsNullOrWhiteSpace($EamDashboardAppRoot)) {
        $EamDashboardAppRoot = Join-Path $EntraOpsRoot 'Reports/EamDashboard'
    }
    if ([string]::IsNullOrWhiteSpace($PrivilegedAssetsAppRoot)) {
        $PrivilegedAssetsAppRoot = Join-Path $EntraOpsRoot 'Reports/PrivilegedAssets'
    }
    if ([string]::IsNullOrWhiteSpace($PrivilegeHistoryAppRoot)) {
        $PrivilegeHistoryAppRoot = Join-Path $EntraOpsRoot 'Reports/PrivilegeHistory'
    }
    if ([string]::IsNullOrWhiteSpace($AccessPathMapAppRoot)) {
        $AccessPathMapAppRoot = Join-Path $EntraOpsRoot 'Reports/AccessPathMap'
    }
    if ([string]::IsNullOrWhiteSpace($ConfigurationAnalyzerAppRoot)) {
        $ConfigurationAnalyzerAppRoot = Join-Path $EntraOpsRoot 'Reports/ConfigurationAnalyzer'
    }
    if ([string]::IsNullOrWhiteSpace($AccessPackageFlowAppRoot)) {
        $AccessPackageFlowAppRoot = Join-Path $EntraOpsRoot 'Reports/AccessPackageFlow'
    }

    $candidateFiles = [System.Collections.Generic.List[string]]::new()

    if (-not $SkipClassificationExplorer) {
        $candidateFiles.Add((Join-Path $ClassificationExplorerAppRoot 'data-manifest.json'))
        $candidateFiles.Add((Join-Path $ClassificationExplorerAppRoot 'data/classification-data.js'))
        $candidateFiles.Add((Join-Path $ClassificationExplorerAppRoot 'data/attack-paths.js'))
        $candidateFiles.Add((Join-Path $ClassificationExplorerAppRoot 'data/tier-map.js'))
    }

    if (-not $SkipTierBreachAnalyzer) {
        $candidateFiles.Add((Join-Path $TierBreachAnalyzerAppRoot 'data/tier-breach-data.js'))
    }

    if (-not $SkipEamDashboard) {
        $candidateFiles.Add((Join-Path $EamDashboardAppRoot 'data/eam-dashboard-data.js'))
    }

    if (-not $SkipPrivilegedAssets) {
        $candidateFiles.Add((Join-Path $PrivilegedAssetsAppRoot 'data/privileged-assets-data.js'))
    }

    if (-not $SkipPrivilegeHistory) {
        $candidateFiles.Add((Join-Path $PrivilegeHistoryAppRoot 'data/privilege-history-data.js'))
    }

    if (-not $SkipAccessPathMap) {
        $candidateFiles.Add((Join-Path $AccessPathMapAppRoot 'data/access-path-map-data.js'))
    }

    if (-not $SkipConfigurationAnalyzer) {
        $candidateFiles.Add((Join-Path $ConfigurationAnalyzerAppRoot 'data/configuration-analyzer-data.js'))
    }

    if (-not $SkipAccessPackageFlow) {
        $candidateFiles.Add((Join-Path $AccessPackageFlowAppRoot 'data/access-package-assignments-data.js'))
    }

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($file in $candidateFiles) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            Write-Verbose "Skipped (not found): $file"
            $results.Add([pscustomobject]@{ Path = $file; Removed = $false; Reason = 'NotFound' })
            continue
        }

        if ($PSCmdlet.ShouldProcess($file, 'Remove generated EntraOps Reporting data file')) {
            Remove-Item -LiteralPath $file -Force
            Write-Verbose "Removed $file"
            $results.Add([pscustomobject]@{ Path = $file; Removed = $true; Reason = 'Removed' })
        } else {
            $results.Add([pscustomobject]@{ Path = $file; Removed = $false; Reason = 'Skipped' })
        }
    }

    $removedCount = @($results | Where-Object { $_.Removed }).Count
    if ($removedCount -eq 0) {
        Write-Host "No generated EntraOps Reporting data files were removed."
    } else {
        Write-Host "Removed $removedCount generated EntraOps Reporting data file(s)."
    }

    if ($PassThru) { $results }
}
