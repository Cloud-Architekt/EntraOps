function Invoke-EntraOpsReportingGeneration {
    <#
    .SYNOPSIS
        Generates the configured EntraOps reports for any automation host.

    .DESCRIPTION
        Converts AutomatedReportingGeneration settings into one fail-fast reporting run, manages a
        shared EntraOps connection for Graph-backed reports, and optionally removes an externally
        prepared classification repository checkout. CI-specific checkout, authentication bootstrap,
        browser setup, artifact upload, and release publication remain outside the module.

    .PARAMETER ConfigFilePath
        Path to the EntraOps configuration file with the AutomatedReportingGeneration settings. Default is
        ./EntraOpsConfig.json. The file must exist.

    .PARAMETER ClassificationRepositoryPath
        Path to an AzurePrivilegedIAM checkout prepared outside the module. When the folder exists, it is used as
        repository root of the Classification Explorer. Default is ./.reporting/AzurePrivilegedIAM.

    .PARAMETER AuthenticationType
        Authentication type passed to Connect-EntraOps when a selected report needs Microsoft Graph. Default is
        AlreadyAuthenticated. The connection made by this cmdlet is disconnected after the run.

    .PARAMETER AllowStaleTenantGovernanceSnapshot
        Generates Configuration Analyzer data from a Tenant Governance snapshot older than its maximum age
        without applying ConfigurationAnalyzer.StaleTenantGovernanceSnapshotAction. Default is false. The
        maximum age is ConfigurationAnalyzer.MaxTenantGovernanceSnapshotAgeHours, or derived from
        TenantGovernanceSnapshot.SnapshotScheduledCron when not set (daily 30 hours, weekly 174 hours,
        monthly 750 hours).

    .PARAMETER AllowPartialTenantGovernanceSnapshot
        Allows Configuration Analyzer data from a partially successful Tenant Governance snapshot. Defaults to
        ConfigurationAnalyzer.AllowPartialTenantGovernanceSnapshot of the configuration file (true when not set).

    .PARAMETER RemoveClassificationRepositoryAfterRun
        Removes the folder of -ClassificationRepositoryPath after the run, also when the generation fails.

    .PARAMETER Force
        Generates the reports even when AutomatedReportingGeneration.ApplyAutomatedReportingGeneration is
        disabled. Without it, the cmdlet returns the status Disabled.

    .EXAMPLE
        Generate the configured reports with the existing Azure context.
        Invoke-EntraOpsReportingGeneration -ConfigFilePath ./EntraOpsConfig.json

    .EXAMPLE
        Generate the reports although automated reporting is disabled, and remove the prepared AzurePrivilegedIAM checkout afterwards.
        Invoke-EntraOpsReportingGeneration -Force -RemoveClassificationRepositoryAfterRun
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$ConfigFilePath = './EntraOpsConfig.json',

        [Parameter(Mandatory = $false)]
        [string]$ClassificationRepositoryPath = './.reporting/AzurePrivilegedIAM',

        [Parameter(Mandatory = $false)]
        [ValidateSet('UserInteractive', 'SystemAssignedMSI', 'UserAssignedMSI', 'FederatedCredentials', 'AlreadyAuthenticated', 'DeviceAuthentication')]
        [string]$AuthenticationType = 'AlreadyAuthenticated',

        [Parameter(Mandatory = $false)]
        [Nullable[bool]]$AllowStaleTenantGovernanceSnapshot,

        [Parameter(Mandatory = $false)]
        [Nullable[bool]]$AllowPartialTenantGovernanceSnapshot,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveClassificationRepositoryAfterRun,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    $ErrorActionPreference = 'Stop'
    $ResolvedConfigFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigFilePath)
    if (-not (Test-Path -LiteralPath $ResolvedConfigFile -PathType Leaf)) {
        throw "EntraOps configuration file '$ResolvedConfigFile' does not exist."
    }
    $Config = Get-Content -LiteralPath $ResolvedConfigFile -Raw | ConvertFrom-Json -Depth 100 -ErrorAction Stop
    $ReportingConfig = $Config.AutomatedReportingGeneration
    if (-not $Force -and $ReportingConfig.ApplyAutomatedReportingGeneration -ne $true) {
        Write-Verbose 'Automated reporting generation is disabled in the configuration.'
        return [pscustomobject]@{ Status = 'Disabled'; Reports = @() }
    }

    $GenerateClassificationExplorer = $ReportingConfig.GenerateClassificationExplorer -ne $false
    $GenerateTierBreachAnalyzer = $ReportingConfig.GenerateTierBreachAnalyzer -ne $false
    $GenerateEamDashboard = $ReportingConfig.GenerateEamDashboard -ne $false
    $GeneratePrivilegedAssets = $ReportingConfig.GeneratePrivilegedAssets -ne $false
    $GenerateAccessPathMap = $ReportingConfig.GenerateAccessPathMap -ne $false
    $GeneratePrivilegeHistory = $ReportingConfig.GeneratePrivilegeHistory -ne $false -and $Config.PrivilegeHistory.EnablePrivilegeHistory -ne $false
    $GenerateConfigurationAnalyzer = $ReportingConfig.GenerateConfigurationAnalyzer -ne $false
    $GenerateAccessPackageFlow = $ReportingConfig.GenerateAccessPackageFlow -ne $false
    $ResolveEamDashboardObjects = $Config.EamDashboard.ResolveLinkedIdentityObjectIds -ne $false
    $ResolvePrivilegedAssetsObjects = $Config.PrivilegedAssets.ResolveRelatedObjectIds -ne $false
    $ResolveAccessPathObjects = $Config.AccessPathMap.ResolveObjectIdsOutsidePrivilegedEAM -ne $false

    if ($null -eq $AllowPartialTenantGovernanceSnapshot) {
        $AllowPartialTenantGovernanceSnapshot = $Config.ConfigurationAnalyzer.AllowPartialTenantGovernanceSnapshot -ne $false
    }
    if ($null -eq $AllowStaleTenantGovernanceSnapshot) {
        $AllowStaleTenantGovernanceSnapshot = $false
    }

    # Stale snapshot settings are only validated when the Configuration Analyzer is generated, so an
    # invalid value never blocks the other reports of a run that does not use it.
    $MaxSnapshotAgeHours = $null
    if ($GenerateConfigurationAnalyzer) {
        $StaleSnapshotAction = "$($Config.ConfigurationAnalyzer.StaleTenantGovernanceSnapshotAction)".Trim()
        if ([string]::IsNullOrWhiteSpace($StaleSnapshotAction)) { $StaleSnapshotAction = 'Warn' }
        if ($StaleSnapshotAction -notin @('Warn', 'Skip', 'Fail')) {
            throw "ConfigurationAnalyzer.StaleTenantGovernanceSnapshotAction must be 'Warn', 'Skip' or 'Fail', but is '$StaleSnapshotAction'."
        }
        $MaxSnapshotAgeHours = Resolve-EntraOpsTenantGovernanceSnapshotMaxAge -Config $Config

        $SnapshotManifestPath = Join-Path $EntraOpsBaseFolder 'TenantGovernance/Snapshots/.SnapshotManifest.json'
        if (-not (Test-Path -LiteralPath $SnapshotManifestPath -PathType Leaf)) {
            Write-Warning "Skipping Configuration Analyzer generation because no Tenant Governance snapshot manifest exists at $SnapshotManifestPath. Enable and run the Tenant Governance snapshot automation first."
            $GenerateConfigurationAnalyzer = $false
        } elseif (-not $AllowStaleTenantGovernanceSnapshot) {
            # Checked before connecting, so a stale snapshot never fails the run after the other reports were generated.
            $SnapshotAge = Get-EntraOpsTenantGovernanceSnapshotAge -ManifestPath $SnapshotManifestPath
            if ($null -ne $SnapshotAge -and $SnapshotAge.AgeHours -gt $MaxSnapshotAgeHours) {
                $StaleMessage = "Tenant Governance snapshot captured $($SnapshotAge.CapturedDateTime.UtcDateTime.ToString('u')) is $([math]::Round($SnapshotAge.AgeHours, 1)) hour(s) old, exceeding the $MaxSnapshotAgeHours-hour limit."
                switch ($StaleSnapshotAction) {
                    'Warn' {
                        Write-Warning "$StaleMessage Configuration Analyzer data is generated from it and marked as stale (ConfigurationAnalyzer.StaleTenantGovernanceSnapshotAction = Warn)."
                    }
                    'Skip' {
                        Write-Warning "$StaleMessage Skipping Configuration Analyzer generation (ConfigurationAnalyzer.StaleTenantGovernanceSnapshotAction = Skip)."
                        $GenerateConfigurationAnalyzer = $false
                    }
                    'Fail' {
                        throw "$StaleMessage Run a new Tenant Governance snapshot, raise ConfigurationAnalyzer.MaxTenantGovernanceSnapshotAgeHours, or pass -AllowStaleTenantGovernanceSnapshot."
                    }
                }
            }
            # The decision is taken once here. Configuration Analyzer is generated after the other reports, so
            # the generator must not fail the run when the snapshot crosses the limit in the meantime; it still
            # marks a stale snapshot in the report.
            $AllowStaleTenantGovernanceSnapshot = $true
        }
    }

    $NeedsConnection = $GenerateEamDashboard -or
    ($GeneratePrivilegedAssets -and $ResolvePrivilegedAssetsObjects) -or
    ($GenerateAccessPathMap -and $ResolveAccessPathObjects) -or
    $GenerateConfigurationAnalyzer -or $GenerateAccessPackageFlow
    $ConnectedHere = $false
    $ResolvedClassificationRepositoryPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ClassificationRepositoryPath)

    try {
        if ($NeedsConnection) {
            $ConnectParameters = @{
                AuthenticationType = $AuthenticationType
                TenantName         = [string]$Config.TenantName
                ConfigFilePath     = $ResolvedConfigFile
                NoWelcome          = $true
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$Config.TenantId)) {
                $ConnectParameters.TenantId = [string]$Config.TenantId
            }
            Connect-EntraOps @ConnectParameters
            $ConnectedHere = $true
        }

        $ReportingParameters = @{
            ConfigFilePath                                    = $ResolvedConfigFile
            SkipClassificationExplorer                        = -not $GenerateClassificationExplorer
            SkipTierBreachAnalyzer                            = -not $GenerateTierBreachAnalyzer
            SkipEamDashboard                                  = -not $GenerateEamDashboard
            SkipPrivilegedAssets                              = -not $GeneratePrivilegedAssets
            SkipAccessPathMap                                 = -not $GenerateAccessPathMap
            SkipPrivilegeHistory                              = -not $GeneratePrivilegeHistory
            SkipConfigurationAnalyzer                         = -not $GenerateConfigurationAnalyzer
            SkipAccessPackageFlow                             = -not $GenerateAccessPackageFlow
            EamDashboardResolveLinkedIdentityObjectIds        = $ResolveEamDashboardObjects
            PrivilegedAssetsResolveRelatedObjectIds           = $ResolvePrivilegedAssetsObjects
            AccessPathMapResolveObjectIdsOutsidePrivilegedEAM = $ResolveAccessPathObjects
            AllowStaleTenantGovernanceSnapshot                = [bool]$AllowStaleTenantGovernanceSnapshot
            AllowPartialTenantGovernanceSnapshot              = [bool]$AllowPartialTenantGovernanceSnapshot
            FailureAction                                     = 'Stop'
            PassThru                                          = $true
        }
        if ($null -ne $MaxSnapshotAgeHours) {
            $ReportingParameters.ConfigurationAnalyzerMaxSnapshotAgeHours = $MaxSnapshotAgeHours
        }
        if (Test-Path -LiteralPath $ResolvedClassificationRepositoryPath -PathType Container) {
            $ReportingParameters.ClassificationExplorerRepoRoot = $ResolvedClassificationRepositoryPath
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$Config.TenantId)) {
            $ReportingParameters.AccessPathMapTenantId = [string]$Config.TenantId
        }
        if ($null -ne $Config.PrivilegeHistory.TimeRangeInDays) {
            $ReportingParameters.PrivilegeHistoryTimeRangeInDays = [int]$Config.PrivilegeHistory.TimeRangeInDays
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$Config.PrivilegeHistory.SnapshotInterval)) {
            $ReportingParameters.PrivilegeHistorySnapshotInterval = [string]$Config.PrivilegeHistory.SnapshotInterval
        }
        if ($null -ne $Config.ClassificationExplorer.GenerateChangeHistory) {
            $ReportingParameters.SkipExplorerHistory = -not [bool]$Config.ClassificationExplorer.GenerateChangeHistory
        }

        $Reports = @(New-EntraOpsReportingData @ReportingParameters)
        return [pscustomobject]@{
            Status  = 'Generated'
            Reports = $Reports
        }
    } finally {
        if ($ConnectedHere) {
            Disconnect-EntraOps | Out-Null
        }
        if ($RemoveClassificationRepositoryAfterRun -and (Test-Path -LiteralPath $ResolvedClassificationRepositoryPath)) {
            # Only a folder inside the working folder is removed
            if (Test-EntraOpsPathWithinRoot -Path $ResolvedClassificationRepositoryPath -Root $EntraOpsBaseFolder) {
                Remove-Item -LiteralPath $ResolvedClassificationRepositoryPath -Recurse -Force -ErrorAction SilentlyContinue
            } else {
                Write-Warning "Classification repository '$ResolvedClassificationRepositoryPath' is not inside the EntraOps working folder '$EntraOpsBaseFolder' and was not removed."
            }
        }
    }
}
