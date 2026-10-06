<#
.SYNOPSIS
    Generate (refresh) data for all EntraOps Reporting static web apps in a single call.

.DESCRIPTION
    Convenience wrapper around the Classification Explorer, Tier Breach Analyzer, EAM Dashboard,
    Privileged Assets, Privilege History, Configuration Analyzer, Access Package Flow, and Access Path Map generators. It runs all
    applicable generators in one call, so the whole
    EntraOps Reporting portal (Reports/index.html + all sub-apps) can be refreshed with a
    single cmdlet. Use Remove-EntraOpsReportingData to clear the generated data again.

.PARAMETER EntraOpsRoot
    Path to the EntraOps repository root. Used as the classification-logic source
    (Classification/Templates) for the Classification Explorer and as the PrivilegedEAM
    source root for the Tier Breach Analyzer. Defaults to the repository this module lives in.

.PARAMETER ConfigFilePath
    Configuration file used for Privilege History and Tenant Governance feature settings. Defaults
    to EntraOpsConfig.json below EntraOpsRoot.

.PARAMETER ClassificationExplorerRepoRoot
    Path to the repository that contains the classified roles and permission catalogs (the
    AzurePrivilegedIAM repository). Forwarded as -RepoRoot to New-EntraOpsClassificationExplorerData.
    When omitted, that cmdlet auto-detects the location.

.PARAMETER ClassificationExplorerAppRoot
    Path to the Classification Explorer app folder. Defaults to Reports/ClassificationExplorer
    under EntraOpsRoot.

.PARAMETER TierBreachImportPath
    Folder with the Privileged EAM export. Forwarded as -ImportPath to
    New-EntraOpsTierBreachAnalyzerData. Defaults to <EntraOpsRoot>/PrivilegedEAM.

.PARAMETER TierBreachAnalyzerAppRoot
    Path to the Tier Breach Analyzer app folder. Defaults to Reports/TierBreachAnalyzer under
    EntraOpsRoot.

.PARAMETER EamDashboardImportPath
    Folder with the Privileged EAM export. Forwarded as -ImportPath to
    New-EntraOpsPrivilegedEamDashboardData. Defaults to <EntraOpsRoot>/PrivilegedEAM.

.PARAMETER EamDashboardAppRoot
    Path to the EAM Dashboard app folder. Defaults to Reports/EamDashboard under
    EntraOpsRoot.

.PARAMETER EamDashboardResolveLinkedIdentityObjectIds
    Forwarded to New-EntraOpsPrivilegedEamDashboardData. Resolves linked identity
    IDs outside the Privileged EAM export through Microsoft Graph when enabled.
    When omitted, the EAM Dashboard generator defaults this option to `$true`.

.PARAMETER PrivilegedAssetsAppRoot
    Path to the Privileged Assets app folder. Defaults to Reports/PrivilegedAssets
    under EntraOpsRoot. The Privileged EAM export is read from the EAM Dashboard import path.

.PARAMETER PrivilegedAssetsResolveRelatedObjectIds
    Forwarded as -ResolveRelatedObjectIds to New-EntraOpsPrivilegedAssetsData. When omitted,
    the generator falls back to `PrivilegedAssets.ResolveRelatedObjectIds` in
    EntraOpsConfig.json, or $true.

.PARAMETER SkipPrivilegedAssets
    Do not generate Privileged Assets data.

.PARAMETER AccessPathMapTenantId
    Tenant id forwarded to New-EntraOpsAccessPathMapData (used to build role node ids
    matching the BloodHound OpenGraph export). Defaults to the ObjectTenantId found in the export.

.PARAMETER AccessPathMapImportPath
    Folder with the Privileged EAM export. Forwarded as -ImportPath to
    New-EntraOpsAccessPathMapData. Defaults to <EntraOpsRoot>/PrivilegedEAM.

.PARAMETER AccessPathMapAppRoot
    Path to the Access Path Map app folder. Defaults to Reports/AccessPathMap under
    EntraOpsRoot.

.PARAMETER AccessPathMapResolveObjectIdsOutsidePrivilegedEAM
    Forwarded as -ResolveObjectIdsOutsidePrivilegedEAM to New-EntraOpsAccessPathMapData (resolves edge
    endpoints outside the Privileged EAM export via Microsoft Graph instead of showing them as an
    unresolved placeholder). When omitted, New-EntraOpsAccessPathMapData falls back to the
    `AccessPathMap.ResolveObjectIdsOutsidePrivilegedEAM` setting in EntraOpsConfig.json, or $true.

.PARAMETER SkipClassificationExplorer
    Do not generate Classification Explorer data.

.PARAMETER SkipExplorerHistory
    Do not derive the Classification Explorer change history (git log over the classification
    source files). When omitted, New-EntraOpsClassificationExplorerData falls back to the
    inverse of `ClassificationExplorer.GenerateChangeHistory` in EntraOpsConfig.json. A missing
    setting or configuration file defaults generation to $false because deriving history from the
    AzurePrivilegedIAM git log is slow and rarely meaningful. Pass -SkipExplorerHistory:$false to
    generate it for an individual invocation.

.PARAMETER SkipTierBreachAnalyzer
    Do not generate Tier Breach Analyzer data.

.PARAMETER SkipEamDashboard
    Do not generate EAM Dashboard data.

.PARAMETER SkipAccessPathMap
    Do not generate Access Path Map data.

.PARAMETER PrivilegeHistoryImportPath
    Folder with the Privileged EAM export whose git history is walked. Forwarded as
    -ImportPath to New-EntraOpsPrivilegedEamPrivilegeHistoryData. Defaults to
    <EntraOpsRoot>/PrivilegedEAM.

.PARAMETER PrivilegeHistoryAppRoot
    Path to the Privilege History app folder. Defaults to Reports/PrivilegeHistory under
    EntraOpsRoot.

.PARAMETER PrivilegeHistoryTimeRangeInDays
    Only consider commits from the last N days for the Privilege History dataset. Forwarded as
    -TimeRangeInDays to New-EntraOpsPrivilegedEamPrivilegeHistoryData. Defaults to the
    `PrivilegeHistory.TimeRangeInDays` setting in EntraOpsConfig.json, or the full git history
    ($null) when that config file/setting is not present.

.PARAMETER PrivilegeHistorySnapshotInterval
    Minimum spacing between two consecutive Privilege History snapshots, as an ISO 8601
    duration (`P1D` daily, `P1W` weekly, `P2W` bi-weekly, `P1M` monthly, `P3M` quarterly,
    `P1Y` yearly, ...). Forwarded as -SnapshotInterval to
    New-EntraOpsPrivilegedEamPrivilegeHistoryData. Defaults to the
    `PrivilegeHistory.SnapshotInterval` setting in EntraOpsConfig.json, or `P2W` (bi-weekly)
    when that config file/setting is not present.

.PARAMETER SkipPrivilegeHistory
    Do not generate the Privilege History data, regardless of the
    `PrivilegeHistory.EnablePrivilegeHistory` setting in EntraOpsConfig.json.

.PARAMETER ConfigurationAnalyzerImportPath
    Folder with the Tenant Governance snapshot export whose git history is walked.
    Forwarded as -ImportPath to New-EntraOpsTenantGovernanceConfigurationAnalyzerData.
    Defaults to <EntraOpsRoot>/TenantGovernance/Snapshots.

.PARAMETER ConfigurationAnalyzerAppRoot
    Path to the Configuration Analyzer app folder. Defaults to
    Reports/ConfigurationAnalyzer under EntraOpsRoot.

.PARAMETER SkipConfigurationAnalyzer
    Do not generate the Configuration Analyzer data. When not skipped, the data is only
    generated if the Tenant Governance snapshot folder exists (or
    `TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot` is set to true in
    EntraOpsConfig.json), so repositories without the feature stay untouched.

.PARAMETER SkipAccessPackageFlow
    Do not generate Graph-backed group and resource enrichment for Access Package Flow.

.PARAMETER PassThru
    Emit the result object of each generator (one per app) to the pipeline.

.PARAMETER FailureAction
    Controls whether failures from optional generators stop the combined run or are reported as
    warnings. Continue preserves the interactive convenience behavior; Stop is intended for CI.

.PARAMETER AllowStaleTenantGovernanceSnapshot
    Allow Configuration Analyzer generation from a successful snapshot older than its maximum age.

.PARAMETER AllowPartialTenantGovernanceSnapshot
    Allow Configuration Analyzer generation from a partial snapshot with preserved stale resource types.

.EXAMPLE
    New-EntraOpsReportingData

    Regenerates the data for all reporting apps in this repository checkout.

.EXAMPLE
    New-EntraOpsReportingData -ClassificationExplorerRepoRoot "C:\Repos\AzurePrivilegedIAM" -WhatIf

    Shows what would be generated for all apps without changing any files.

.EXAMPLE
    New-EntraOpsReportingData -SkipClassificationExplorer

    Regenerates only the Tier Breach Analyzer data.
#>

function New-EntraOpsReportingData {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$EntraOpsRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$ConfigFilePath,

        [Parameter(Mandatory = $false)]
        [System.String]$ClassificationExplorerRepoRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$ClassificationExplorerAppRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$TierBreachImportPath,

        [Parameter(Mandatory = $false)]
        [System.String]$TierBreachAnalyzerAppRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$EamDashboardImportPath,

        [Parameter(Mandatory = $false)]
        [System.String]$EamDashboardAppRoot,

        [Parameter(Mandatory = $false)]
        [System.Nullable[bool]]$EamDashboardResolveLinkedIdentityObjectIds,

        [Parameter(Mandatory = $false)]
        [System.String]$PrivilegedAssetsAppRoot,

        [Parameter(Mandatory = $false)]
        [System.Nullable[bool]]$PrivilegedAssetsResolveRelatedObjectIds,

        [Parameter(Mandatory = $false)]
        [switch]$SkipPrivilegedAssets,

        [Parameter(Mandatory = $false)]
        [System.String]$AccessPathMapTenantId,

        [Parameter(Mandatory = $false)]
        [System.String]$AccessPathMapImportPath,

        [Parameter(Mandatory = $false)]
        [System.String]$AccessPathMapAppRoot,

        [Parameter(Mandatory = $false)]
        [System.Nullable[bool]]$AccessPathMapResolveObjectIdsOutsidePrivilegedEAM,

        [Parameter(Mandatory = $false)]
        [System.String]$PrivilegeHistoryImportPath,

        [Parameter(Mandatory = $false)]
        [System.String]$PrivilegeHistoryAppRoot,

        [Parameter(Mandatory = $false)]
        [System.Nullable[int]]$PrivilegeHistoryTimeRangeInDays,

        [Parameter(Mandatory = $false)]
        [System.String]$PrivilegeHistorySnapshotInterval,

        [Parameter(Mandatory = $false)]
        [switch]$SkipClassificationExplorer,

        [Parameter(Mandatory = $false)]
        [switch]$SkipExplorerHistory,

        [Parameter(Mandatory = $false)]
        [switch]$SkipTierBreachAnalyzer,

        [Parameter(Mandatory = $false)]
        [switch]$SkipEamDashboard,

        [Parameter(Mandatory = $false)]
        [switch]$SkipAccessPathMap,

        [Parameter(Mandatory = $false)]
        [switch]$SkipPrivilegeHistory,

        [Parameter(Mandatory = $false)]
        [System.String]$ConfigurationAnalyzerImportPath,

        [Parameter(Mandatory = $false)]
        [System.String]$ConfigurationAnalyzerAppRoot,

        [Parameter(Mandatory = $false)]
        [switch]$SkipConfigurationAnalyzer,

        [Parameter(Mandatory = $false)]
        [switch]$SkipAccessPackageFlow,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Continue', 'Stop')]
        [string]$FailureAction = 'Continue',

        [Parameter(Mandatory = $false)]
        [switch]$AllowStaleTenantGovernanceSnapshot,

        [Parameter(Mandatory = $false)]
        [switch]$AllowPartialTenantGovernanceSnapshot
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
    $RepositoryRoot = Split-Path -Parent $ModuleRoot
    if ([string]::IsNullOrWhiteSpace($EntraOpsRoot)) { $EntraOpsRoot = $RepositoryRoot }

    Write-Verbose "Using EntraOps repository root: $EntraOpsRoot"

    # Privilege History defaults come from EntraOpsConfig.json ("PrivilegeHistory": { "EnablePrivilegeHistory":
    # true|false, "TimeRangeInDays": <int>|null }) so it can be toggled without changing
    # calling scripts/workflows. Enabled by default when the config file/section is absent;
    # -SkipPrivilegeHistory always wins over the config setting.
    $EnablePrivilegeHistory = $true
    $ConfigPrivilegeHistoryTimeRangeInDays = $null
    $ConfigPrivilegeHistorySnapshotInterval = $null
    if ([string]::IsNullOrWhiteSpace($ConfigFilePath)) {
        $ConfigFilePath = Join-Path $EntraOpsRoot 'EntraOpsConfig.json'
    } else {
        $ConfigFilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigFilePath)
    }
    if (Test-Path -LiteralPath $ConfigFilePath -PathType Leaf) {
        try {
            $EntraOpsConfig = Get-Content -LiteralPath $ConfigFilePath -Raw | ConvertFrom-Json
            if ($null -ne $EntraOpsConfig.PrivilegeHistory) {
                if ($null -ne $EntraOpsConfig.PrivilegeHistory.EnablePrivilegeHistory) {
                    $EnablePrivilegeHistory = [bool]$EntraOpsConfig.PrivilegeHistory.EnablePrivilegeHistory
                }
                if ($null -ne $EntraOpsConfig.PrivilegeHistory.TimeRangeInDays) {
                    $ConfigPrivilegeHistoryTimeRangeInDays = [int]$EntraOpsConfig.PrivilegeHistory.TimeRangeInDays
                }
                if (-not [string]::IsNullOrWhiteSpace($EntraOpsConfig.PrivilegeHistory.SnapshotInterval)) {
                    $ConfigPrivilegeHistorySnapshotInterval = [string]$EntraOpsConfig.PrivilegeHistory.SnapshotInterval
                }
            }
        } catch {
            Write-Warning "Failed to read PrivilegeHistory settings from ${ConfigFilePath}: $($_.Exception.Message). Using defaults (enabled, full history, bi-weekly)."
        }
    }
    if (-not $PSBoundParameters.ContainsKey('PrivilegeHistoryTimeRangeInDays')) {
        $PrivilegeHistoryTimeRangeInDays = $ConfigPrivilegeHistoryTimeRangeInDays
    }
    if (-not $PSBoundParameters.ContainsKey('PrivilegeHistorySnapshotInterval')) {
        $PrivilegeHistorySnapshotInterval = $ConfigPrivilegeHistorySnapshotInterval
    }

    $results = [System.Collections.Generic.List[object]]::new()

    Write-Verbose "Starting reporting data generation. Skipped apps: TierBreachAnalyzer=$SkipTierBreachAnalyzer; EamDashboard=$SkipEamDashboard; PrivilegedAssets=$SkipPrivilegedAssets; PrivilegeHistory=$SkipPrivilegeHistory; ConfigurationAnalyzer=$SkipConfigurationAnalyzer; AccessPackageFlow=$SkipAccessPackageFlow; AccessPathMap=$SkipAccessPathMap; ClassificationExplorer=$SkipClassificationExplorer."

    if (-not $SkipTierBreachAnalyzer) {
        $TierBreachParams = @{
            RepoRoot = $EntraOpsRoot
            Verbose  = $VerbosePreference -eq 'Continue'
            WhatIf   = $WhatIfPreference
            Confirm  = $false
        }
        if (-not [string]::IsNullOrWhiteSpace($TierBreachImportPath)) { $TierBreachParams.ImportPath = $TierBreachImportPath }
        if (-not [string]::IsNullOrWhiteSpace($TierBreachAnalyzerAppRoot)) { $TierBreachParams.AppRoot = $TierBreachAnalyzerAppRoot }
        if ($PassThru) { $TierBreachParams.PassThru = $true }

        Write-Verbose "Generating Tier Breach Analyzer data..."
        $TierBreachResult = New-EntraOpsTierBreachAnalyzerData @TierBreachParams
        $results.Add([pscustomobject]@{ App = 'TierBreachAnalyzer'; Result = $TierBreachResult })
        Write-Verbose "Completed Tier Breach Analyzer data generation."
    }

    if (-not $SkipEamDashboard) {
        $EamDashboardParams = @{
            RepoRoot = $EntraOpsRoot
            Verbose  = $VerbosePreference -eq 'Continue'
            WhatIf   = $WhatIfPreference
            Confirm  = $false
        }
        if (-not [string]::IsNullOrWhiteSpace($EamDashboardImportPath)) { $EamDashboardParams.ImportPath = $EamDashboardImportPath }
        if (-not [string]::IsNullOrWhiteSpace($EamDashboardAppRoot)) { $EamDashboardParams.AppRoot = $EamDashboardAppRoot }
        if ($null -ne $EamDashboardResolveLinkedIdentityObjectIds) { $EamDashboardParams.ResolveLinkedIdentityObjectIds = $EamDashboardResolveLinkedIdentityObjectIds }
        if ($PassThru) { $EamDashboardParams.PassThru = $true }

        Write-Verbose "Generating EAM Dashboard data..."
        $EamDashboardResult = New-EntraOpsPrivilegedEamDashboardData @EamDashboardParams
        $results.Add([pscustomobject]@{ App = 'EamDashboard'; Result = $EamDashboardResult })
        Write-Verbose "Completed EAM Dashboard data generation."
    }

    if (-not $SkipPrivilegedAssets) {
        $PrivilegedAssetsParams = @{
            RepoRoot       = $EntraOpsRoot
            ConfigFilePath = $ConfigFilePath
            Verbose        = $VerbosePreference -eq 'Continue'
            WhatIf         = $WhatIfPreference
            Confirm        = $false
        }
        if (-not [string]::IsNullOrWhiteSpace($EamDashboardImportPath)) { $PrivilegedAssetsParams.ImportPath = $EamDashboardImportPath }
        if (-not [string]::IsNullOrWhiteSpace($PrivilegedAssetsAppRoot)) { $PrivilegedAssetsParams.AppRoot = $PrivilegedAssetsAppRoot }
        if ($null -ne $PrivilegedAssetsResolveRelatedObjectIds) { $PrivilegedAssetsParams.ResolveRelatedObjectIds = $PrivilegedAssetsResolveRelatedObjectIds }
        if ($PassThru) { $PrivilegedAssetsParams.PassThru = $true }

        Write-Verbose "Generating Privileged Assets data..."
        $PrivilegedAssetsResult = New-EntraOpsPrivilegedAssetsData @PrivilegedAssetsParams
        $results.Add([pscustomobject]@{ App = 'PrivilegedAssets'; Result = $PrivilegedAssetsResult })
        Write-Verbose "Completed Privileged Assets data generation."
    }

    if (-not $SkipPrivilegeHistory -and $EnablePrivilegeHistory) {
        $PrivilegeHistoryParams = @{
            RepoRoot = $EntraOpsRoot
            Verbose  = $VerbosePreference -eq 'Continue'
            WhatIf   = $WhatIfPreference
            Confirm  = $false
        }
        if (-not [string]::IsNullOrWhiteSpace($PrivilegeHistoryImportPath)) { $PrivilegeHistoryParams.ImportPath = $PrivilegeHistoryImportPath }
        if (-not [string]::IsNullOrWhiteSpace($PrivilegeHistoryAppRoot)) { $PrivilegeHistoryParams.AppRoot = $PrivilegeHistoryAppRoot }
        if ($null -ne $PrivilegeHistoryTimeRangeInDays) { $PrivilegeHistoryParams.TimeRangeInDays = $PrivilegeHistoryTimeRangeInDays }
        if (-not [string]::IsNullOrWhiteSpace($PrivilegeHistorySnapshotInterval)) { $PrivilegeHistoryParams.SnapshotInterval = $PrivilegeHistorySnapshotInterval }
        if ($PassThru) { $PrivilegeHistoryParams.PassThru = $true }

        Write-Verbose "Generating Privilege History data..."
        try {
            $PrivilegeHistoryResult = New-EntraOpsPrivilegedEamPrivilegeHistoryData @PrivilegeHistoryParams
            $results.Add([pscustomobject]@{ App = 'PrivilegeHistory'; Result = $PrivilegeHistoryResult })
        } catch {
            if ($FailureAction -eq 'Stop') { throw }
            Write-Warning "Skipped Privilege History data: $($_.Exception.Message)"
        }
    } elseif (-not $SkipPrivilegeHistory -and -not $EnablePrivilegeHistory) {
        Write-Verbose "Skipping Privilege History data (PrivilegeHistory.EnablePrivilegeHistory is false in $ConfigFilePath)."
    }

    # Only generate the snapshot-based apps (Configuration Analyzer, Access Package Flow) when
    # the Tenant Governance Snapshot feature is in use: the snapshot folder exists (working
    # tree) or the feature is enabled in EntraOpsConfig.json. Resolved outside the skip blocks
    # because both apps share these checks (for example -SkipConfigurationAnalyzer alone must
    # not disable the Access Package Flow enrichment).
    $TgSnapshotFolder = if (-not [string]::IsNullOrWhiteSpace($ConfigurationAnalyzerImportPath)) { $ConfigurationAnalyzerImportPath } else { Join-Path $EntraOpsRoot 'TenantGovernance/Snapshots' }
    $TgEnabledInConfig = $false
    try {
        if ($null -ne $EntraOpsConfig.TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot) {
            $TgEnabledInConfig = [bool]$EntraOpsConfig.TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot
        }
    } catch { $TgEnabledInConfig = $false }

    if (-not $SkipConfigurationAnalyzer) {
        if ((Test-Path -LiteralPath $TgSnapshotFolder -PathType Container) -or $TgEnabledInConfig) {
            $ConfigurationAnalyzerParams = @{
                RepoRoot = $EntraOpsRoot
                Verbose  = $VerbosePreference -eq 'Continue'
                WhatIf   = $WhatIfPreference
                Confirm  = $false
            }
            if (-not [string]::IsNullOrWhiteSpace($ConfigurationAnalyzerImportPath)) { $ConfigurationAnalyzerParams.ImportPath = $ConfigurationAnalyzerImportPath }
            if (-not [string]::IsNullOrWhiteSpace($ConfigurationAnalyzerAppRoot)) { $ConfigurationAnalyzerParams.AppRoot = $ConfigurationAnalyzerAppRoot }
            if ($AllowStaleTenantGovernanceSnapshot) { $ConfigurationAnalyzerParams.AllowStaleSnapshot = $true }
            if ($AllowPartialTenantGovernanceSnapshot) { $ConfigurationAnalyzerParams.AllowPartialSnapshot = $true }
            if ($PassThru) { $ConfigurationAnalyzerParams.PassThru = $true }

            Write-Verbose "Generating Configuration Analyzer data..."
            try {
                $ConfigurationAnalyzerResult = New-EntraOpsTenantGovernanceConfigurationAnalyzerData @ConfigurationAnalyzerParams
                $results.Add([pscustomobject]@{ App = 'ConfigurationAnalyzer'; Result = $ConfigurationAnalyzerResult })
            } catch {
                if ($FailureAction -eq 'Stop') { throw }
                Write-Warning "Skipped Configuration Analyzer data: $($_.Exception.Message)"
            }
        } else {
            Write-Verbose "Skipping Configuration Analyzer data (no Tenant Governance snapshot folder at $TgSnapshotFolder and TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot is not enabled)."
        }
    }

    if (-not $SkipAccessPathMap) {
        $AccessPathParams = @{
            RepoRoot = $EntraOpsRoot
            Verbose  = $VerbosePreference -eq 'Continue'
            WhatIf   = $WhatIfPreference
            Confirm  = $false
        }
        if (-not [string]::IsNullOrWhiteSpace($AccessPathMapTenantId)) { $AccessPathParams.TenantId = $AccessPathMapTenantId }
        if (-not [string]::IsNullOrWhiteSpace($AccessPathMapImportPath)) { $AccessPathParams.ImportPath = $AccessPathMapImportPath }
        if (-not [string]::IsNullOrWhiteSpace($AccessPathMapAppRoot)) { $AccessPathParams.AppRoot = $AccessPathMapAppRoot }
        if ($null -ne $AccessPathMapResolveObjectIdsOutsidePrivilegedEAM) { $AccessPathParams.ResolveObjectIdsOutsidePrivilegedEAM = $AccessPathMapResolveObjectIdsOutsidePrivilegedEAM }
        if ($PassThru) { $AccessPathParams.PassThru = $true }

        Write-Verbose "Generating Access Path Map data..."
        $AccessPathResult = New-EntraOpsAccessPathMapData @AccessPathParams
        $results.Add([pscustomobject]@{ App = 'AccessPathMap'; Result = $AccessPathResult })
    }

    if (-not $SkipAccessPackageFlow -and ((Test-Path -LiteralPath $TgSnapshotFolder -PathType Container) -or $TgEnabledInConfig)) {
        $AccessPackageFlowParams = @{
            RepoRoot = $EntraOpsRoot
            Verbose  = $VerbosePreference -eq 'Continue'
            WhatIf   = $WhatIfPreference
            Confirm  = $false
        }
        if (-not [string]::IsNullOrWhiteSpace($ConfigurationAnalyzerImportPath)) { $AccessPackageFlowParams.SnapshotPath = $ConfigurationAnalyzerImportPath }
        if ($PassThru) { $AccessPackageFlowParams.PassThru = $true }

        Write-Verbose "Generating Access Package Flow enrichment data..."
        try {
            $AccessPackageFlowResult = New-EntraOpsAccessPackageFlowData @AccessPackageFlowParams
            $results.Add([pscustomobject]@{ App = 'AccessPackageFlow'; Result = $AccessPackageFlowResult })
        } catch {
            if ($FailureAction -eq 'Stop') { throw }
            Write-Warning "Skipped Access Package Flow enrichment: $($_.Exception.Message)"
        }
    }

    if (-not $SkipClassificationExplorer) {
        $ClassificationExplorerParams = @{
            EntraOpsRoot = $EntraOpsRoot
            Verbose      = $VerbosePreference -eq 'Continue'
            WhatIf       = $WhatIfPreference
            Confirm      = $false
        }
        if (-not [string]::IsNullOrWhiteSpace($ClassificationExplorerRepoRoot)) { $ClassificationExplorerParams.RepoRoot = $ClassificationExplorerRepoRoot }
        if (-not [string]::IsNullOrWhiteSpace($ClassificationExplorerAppRoot)) { $ClassificationExplorerParams.AppRoot = $ClassificationExplorerAppRoot }
        if ($PSBoundParameters.ContainsKey('SkipExplorerHistory')) { $ClassificationExplorerParams.SkipHistory = $SkipExplorerHistory }
        if ($PassThru) { $ClassificationExplorerParams.PassThru = $true }

        Write-Verbose "Generating Classification Explorer data..."
        $ClassificationExplorerResult = New-EntraOpsClassificationExplorerData @ClassificationExplorerParams
        $results.Add([pscustomobject]@{ App = 'ClassificationExplorer'; Result = $ClassificationExplorerResult })
    }

    if ($results.Count -eq 0) {
        Write-Host "No EntraOps Reporting data was generated (all apps skipped)."
    } else {
        Write-Host "Generated EntraOps Reporting data for: $(($results.App) -join ', ')."
    }

    if ($PassThru) { $results }
}
