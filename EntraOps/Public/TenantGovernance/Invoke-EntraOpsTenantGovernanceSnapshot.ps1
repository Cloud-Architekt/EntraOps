function Invoke-EntraOpsTenantGovernanceSnapshot {
    <#
    .SYNOPSIS
        Runs the configured Tenant Governance snapshot operation for any automation host.

    .DESCRIPTION
        Loads Tenant Governance settings from EntraOpsConfig.json, establishes the EntraOps
        connection when requested, executes the snapshot state machine, reports partial snapshot
        diagnostics, and validates published artifacts. CI-specific authentication and source-control
        publication remain the responsibility of the calling pipeline.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$ConfigFilePath = './EntraOpsConfig.json',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Start', 'Collect', 'RunAndWait')]
        [string]$Operation = 'RunAndWait',

        [Parameter(Mandatory = $false)]
        [object]$TimeoutInSeconds = 3300,

        [Parameter(Mandatory = $false)]
        [ValidateSet('UserInteractive', 'SystemAssignedMSI', 'UserAssignedMSI', 'FederatedCredentials', 'AlreadyAuthenticated', 'DeviceAuthentication')]
        [string]$AuthenticationType = 'AlreadyAuthenticated',

        [Parameter(Mandatory = $false)]
        [switch]$SkipConnect,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    $ErrorActionPreference = 'Stop'
    $ResolvedConfigFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigFilePath)
    if (-not (Test-Path -LiteralPath $ResolvedConfigFile -PathType Leaf)) {
        throw "EntraOps configuration file '$ResolvedConfigFile' does not exist."
    }
    $ResolvedTimeoutInSeconds = 0
    if (-not [int]::TryParse([string]$TimeoutInSeconds, [ref]$ResolvedTimeoutInSeconds) -or $ResolvedTimeoutInSeconds -lt 1 -or $ResolvedTimeoutInSeconds -gt 86400) {
        Write-Warning "Invalid TimeoutInSeconds value '$TimeoutInSeconds'; using 3300 seconds."
        $ResolvedTimeoutInSeconds = 3300
    }

    $Config = Get-Content -LiteralPath $ResolvedConfigFile -Raw | ConvertFrom-Json -Depth 100 -ErrorAction Stop
    if (-not $Force -and $Config.TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot -ne $true) {
        Write-Verbose 'Tenant Governance snapshot generation is disabled in the configuration.'
        return [pscustomobject]@{
            Operation         = $Operation
            Status            = 'Disabled'
            SnapshotPublished = $false
        }
    }

    $ConnectedHere = $false
    try {
        if (-not $SkipConnect) {
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

        $SnapshotParameters = @{
            Operation        = $Operation
            TimeoutInSeconds = $ResolvedTimeoutInSeconds
        }
        if ($null -ne $Config.TenantGovernanceSnapshot.ResourcesToInclude) {
            $SnapshotParameters.ResourcesToInclude = @($Config.TenantGovernanceSnapshot.ResourcesToInclude)
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$Config.TenantGovernanceSnapshot.SnapshotDisplayNamePrefix)) {
            $SnapshotParameters.SnapshotDisplayNamePrefix = [string]$Config.TenantGovernanceSnapshot.SnapshotDisplayNamePrefix
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$Config.TenantGovernanceSnapshot.SnapshotResourceFileNaming)) {
            $SnapshotParameters.SnapshotResourceFileNaming = [string]$Config.TenantGovernanceSnapshot.SnapshotResourceFileNaming
        }

        Write-Host "Executing Tenant Governance snapshot operation: $Operation"
        $SnapshotOutput = @(Save-EntraOpsTenantGovernanceSnapshotJson @SnapshotParameters)
        foreach ($Message in @($SnapshotOutput | Where-Object { $_ -is [string] })) {
            Write-Host $Message
        }
        $SnapshotResult = @($SnapshotOutput | Where-Object { $_ -isnot [string] }) | Select-Object -Last 1
        if ($null -eq $SnapshotResult) {
            throw 'Tenant Governance snapshot operation returned no result object.'
        }

        $SnapshotJobId = if ($SnapshotResult.SnapshotId) { $SnapshotResult.SnapshotId } else { $SnapshotResult.SnapshotJobId }
        $SnapshotPublished = -not [string]::IsNullOrWhiteSpace([string]$SnapshotResult.SnapshotJobStatus)
        $Report = $null
        if ($SnapshotPublished) {
            $ReportParameters = @{ ConfigFilePath = $ResolvedConfigFile }
            if ([string]::IsNullOrWhiteSpace([string]$SnapshotJobId)) {
                $ReportParameters.RecentJobsCount = 1
            } else {
                $ReportParameters.SnapshotJobId = $SnapshotJobId
            }
            $Report = Get-EntraOpsTenantGovernanceSnapshotReport @ReportParameters
            if ($Report.SnapshotManifest -and -not [bool]$Report.SnapshotManifest.IsComplete) {
                $PublishedCount = @($Report.SnapshotManifest.PublishedResourceTypes).Count
                $StaleCount = @($Report.SnapshotManifest.StaleResourceTypes).Count
                # Save-EntraOpsTenantGovernanceSnapshotJson already warned
                Write-Verbose "Tenant Governance snapshot job $($Report.SnapshotManifest.SnapshotId) was $($Report.SnapshotManifest.SnapshotJobStatus); $PublishedCount resource type(s) were published and $StaleCount type(s) with Graph errors were preserved as stale."
            }
            if (@($Report.MissingOrEmptyResourceTypes).Count -gt 0) {
                Write-Warning "$(@($Report.MissingOrEmptyResourceTypes).Count) configured resource type(s) currently have no data on disk. This can be valid when the tenant has no objects of those types: $($Report.MissingOrEmptyResourceTypes -join ', ')"
            }
            Test-EntraOpsGeneratedArtifacts -PrivilegedEamPath '' -TenantGovernancePath (Join-Path $EntraOpsBaseFolder 'TenantGovernance/Snapshots') | Write-Host
        }

        return [pscustomobject]@{
            Operation         = $Operation
            Status            = if ($SnapshotPublished) { 'Published' } elseif ($SnapshotResult.Status) { $SnapshotResult.Status } else { $SnapshotResult.LastKnownStatus }
            SnapshotJobId     = $SnapshotJobId
            SnapshotPublished = $SnapshotPublished
            Snapshot          = $SnapshotResult
            Report            = $Report
        }
    } finally {
        if ($ConnectedHere) {
            Disconnect-EntraOps | Out-Null
        }
    }
}
