function Invoke-EntraOpsReportingGeneration {
    <#
    .SYNOPSIS
        Generates the configured EntraOps reports for any automation host.

    .DESCRIPTION
        Converts AutomatedReportingGeneration settings into one fail-fast reporting run, manages a
        shared EntraOps connection for Graph-backed reports, and optionally removes an externally
        prepared classification repository checkout. CI-specific checkout, authentication bootstrap,
        browser setup, artifact upload, and release publication remain outside the module.
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

    if ($GenerateConfigurationAnalyzer) {
        $SnapshotManifestPath = Join-Path $EntraOpsBaseFolder 'TenantGovernance/Snapshots/.SnapshotManifest.json'
        if (-not (Test-Path -LiteralPath $SnapshotManifestPath -PathType Leaf)) {
            Write-Warning "Skipping Configuration Analyzer generation because no Tenant Governance snapshot manifest exists at $SnapshotManifestPath. Enable and run the Tenant Governance snapshot automation first."
            $GenerateConfigurationAnalyzer = $false
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
            Remove-Item -LiteralPath $ResolvedClassificationRepositoryPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
