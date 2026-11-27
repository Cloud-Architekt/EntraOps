<#
.SYNOPSIS
    Generate (refresh) the dataset for the EntraOps Configuration Analyzer static web app.

.DESCRIPTION
    Walks the git history of the Tenant Governance snapshot folder
    (TenantGovernance/Snapshots/<resourceType>/<category>/<name>.json, written by
    Save-EntraOpsTenantGovernanceSnapshotJson and committed by the
    Pull-EntraOpsTenantGovernance workflow) and builds one snapshot per commit that
    changed it, so the Configuration Analyzer app can show configuration drift over
    time: which resources were added, modified or removed between any two snapshots,
    including property-level diffs, and a Conditional Access Sankey visualization of
    the policy set at any point in time.

    For every commit, only the git tree listing (file path + blob hash) is recorded -
    that is enough for the app to derive added/modified/removed resources between any
    two snapshots. The actual resource JSON content is embedded only for up to
    -MaxDetailedSnapshots snapshots (evenly spread across the full range, always
    including the oldest and newest), and content blobs are de-duplicated by git blob
    hash across all snapshots, so unchanged resources are stored exactly once no
    matter how many snapshots reference them.

    When the working tree contains snapshot files that differ from the newest commit
    (or the folder has never been committed at all), an additional "(working tree)"
    snapshot with the current on-disk state is appended, so the app is usable before
    the first commit and always reflects the latest captured state.

    Generates data/configuration-analyzer-data.js exposing
    `window.ENTRAOPS_CONFIGANALYZER_DATA` so the static web app works both when served
    over HTTP and when opened directly from the file system. The Configuration
    Analyzer app shows setup instructions instead of failing until this file exists.

    Git history is the only source of historic data (there is no separate time-series store).
    Without git, or outside a git working copy, the current snapshot folder is used as one
    snapshot without history and drift (-HistorySource Folder, the automatic fallback).

.PARAMETER RepoRoot
    Path to the EntraOps repository root (and git working copy) that contains the
    TenantGovernance snapshot folder (alias: -Path). Defaults to the repository this module lives in.

.PARAMETER ImportPath
    Folder with the Tenant Governance snapshot export whose git history is walked.
    Defaults to <RepoRoot>/TenantGovernance/Snapshots. Must be inside the git working
    copy of RepoRoot.

.PARAMETER AppRoot
    Path to the Configuration Analyzer app folder (where the generated content is
    written). Defaults to Reports/ConfigurationAnalyzer in the EntraOps repository.

.PARAMETER OutFile
    Output file. Defaults to <AppRoot>/data/configuration-analyzer-data.js.

.PARAMETER TimeRangeInDays
    Only consider commits from the last N days. Default ($null) considers the full git
    history of the snapshot folder (every commit that changed it).

.PARAMETER SnapshotInterval
    Minimum spacing between two consecutive snapshots, as an ISO 8601 duration: `P<n>D`
    (days), `P<n>W` (weeks), `P<n>M` (months) or `P<n>Y` (years). Commits closer
    together than the interval are skipped; the oldest and the most recent commit in
    range are always kept. Default `None`: keep every commit, since configuration
    changes (unlike privilege trends) are individually interesting.

.PARAMETER MaxDetailedSnapshots
    Only up to this many snapshots (evenly spread across the full range, always
    including the oldest and newest) embed the full resource JSON content (used for
    property-level diffs and the Conditional Access Sankey); the rest keep their file
    listing (enough for added/modified/removed counts) but no content. Default 30.
    Use 0 to embed content for every snapshot (only recommended for short histories).

.PARAMETER ResolveGroupMembersForPrivilegedAssets
    Resolve groups targeted by Conditional Access IncludeGroups and authentication method policy
    IncludeTargets through their PIM-aware transitive membership. The most privileged member found
    in the local PrivilegedEAM export determines the group's access tier. Defaults to
    ConfigurationAnalyzer.ResolveGroupMembersForPrivilegedAssets in EntraOpsConfig.json, or true
    when no setting is present. Requires an active Microsoft Graph connection.

.PARAMETER MaxSnapshotAgeHours
Maximum age of the successful Tenant Governance snapshot manifest. Default 30 hours.
Use -AllowStaleSnapshot to generate a report from an older known-good snapshot; the report then
marks the snapshot as stale (snapshotHealth.isStale). New-EntraOpsReportingData passes a limit
derived from ConfigurationAnalyzer.MaxTenantGovernanceSnapshotAgeHours or the snapshot schedule.

.PARAMETER AllowStaleSnapshot
Allow report generation when the snapshot manifest is older than -MaxSnapshotAgeHours.
Snapshot completeness is validated separately; use -AllowPartialSnapshot as well when both
overrides are intentionally required.

.PARAMETER AllowPartialSnapshot
Allow the current mixed snapshot tree to be analyzed when the latest attempt was partially
successful. Preserved resource types remain marked stale in snapshotManifest.
This switch only gates the current snapshot. Historical partially successful commits are part of
the timeline regardless of this switch whenever they published resource files: their published
resource types contain freshly captured files, while stale resource types keep their previous,
unchanged files. Historical commits that published no resource type (manifest-only) are excluded,
because they would present an older tree at the partial job time. Changes to stale or retained
resources therefore become visible only in a later snapshot.

.PARAMETER SkipWorkingTree
    Do not append the "(working tree)" snapshot for uncommitted on-disk changes.

.PARAMETER HistorySource
    Where the snapshots come from: Git (the git history of the snapshot folder, plus uncommitted changes),
    Folder (the current snapshot folder as one snapshot, without history and drift) or Auto (default: Git
    when git is available and the folder is in a git working copy, otherwise Folder with a note in the output).

.PARAMETER PassThru
    Emit the generated payload object to the pipeline.

.EXAMPLE
    New-EntraOpsTenantGovernanceConfigurationAnalyzerData

    Regenerates the Configuration Analyzer dataset from the full git history of the
    TenantGovernance/Snapshots folder of this repository.

.EXAMPLE
    New-EntraOpsTenantGovernanceConfigurationAnalyzerData -TimeRangeInDays 90 -Verbose -WhatIf

    Shows what would be generated from the last 90 days of history without changing
    any files.

.EXAMPLE
    New-EntraOpsTenantGovernanceConfigurationAnalyzerData -AllowPartialSnapshot

    Includes the current mixed snapshot tree after a partially successful capture. Historical
    partial commits that published resource files are included with or without this switch;
    manifest-only commits remain excluded from the timeline.
#>

function New-EntraOpsTenantGovernanceConfigurationAnalyzerData {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('Path')]
        [System.String]$RepoRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$ImportPath,

        [Parameter(Mandatory = $false)]
        [System.String]$AppRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$OutFile,

        [Parameter(Mandatory = $false)]
        [System.Nullable[int]]$TimeRangeInDays,

        [Parameter(Mandatory = $false)]
        [System.String]$SnapshotInterval = 'None',

        [Parameter(Mandatory = $false)]
        [int]$MaxDetailedSnapshots = 30,

        [Parameter(Mandatory = $false)]
        [System.Nullable[bool]]$ResolveGroupMembersForPrivilegedAssets,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 8760)]
        [int]$MaxSnapshotAgeHours = 30,

        [Parameter(Mandatory = $false)]
        [switch]$AllowStaleSnapshot,

        [Parameter(Mandatory = $false)]
        [switch]$AllowPartialSnapshot,

        [Parameter(Mandatory = $false)]
        [switch]$SkipWorkingTree,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Auto', 'Git', 'Folder')]
        [System.String]$HistorySource = 'Auto',

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    # ---- Snapshot interval thinning (same semantics as Privilege History) ----------
    function ConvertTo-SnapshotIntervalComponents {
        param([string]$Interval)
        if ([string]::IsNullOrWhiteSpace($Interval)) { return $null }
        if ($Interval -in @('P0D', 'PT0S', 'None', 'none')) { return $null }
        if ($Interval -notmatch '^P(?:(?<y>\d+)Y)?(?:(?<mo>\d+)M)?(?:(?<w>\d+)W)?(?:(?<d>\d+)D)?$') {
            throw "Invalid -SnapshotInterval '$Interval'. Expected an ISO 8601 duration such as 'P1D' (daily), 'P1W' (weekly) or 'P1M' (monthly). Use 'P0D' or 'None' to keep every commit."
        }
        $years = if ($Matches['y']) { [int]$Matches['y'] } else { 0 }
        $months = if ($Matches['mo']) { [int]$Matches['mo'] } else { 0 }
        $weeks = if ($Matches['w']) { [int]$Matches['w'] } else { 0 }
        $daysOnly = if ($Matches['d']) { [int]$Matches['d'] } else { 0 }
        $days = ($weeks * 7) + $daysOnly
        if ($years -eq 0 -and $months -eq 0 -and $days -eq 0) { return $null }
        return [ordered]@{ Years = $years; Months = $months; Days = $days }
    }

    $SnapshotIntervalComponents = ConvertTo-SnapshotIntervalComponents -Interval $SnapshotInterval

    # Resolve the app/repository location relative to the module location:
    # <repo>/EntraOps/Public/<subfolder> -> <repo>/Reports/ConfigurationAnalyzer
    $ModuleRoot = $MyInvocation.MyCommand.Module.ModuleBase
    if ([string]::IsNullOrWhiteSpace($ModuleRoot) -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $ModuleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    }
    if ([string]::IsNullOrWhiteSpace($ModuleRoot)) {
        throw "Unable to resolve the EntraOps module location. Import the module with 'Import-Module <path-to-EntraOps> -Force' and try again."
    }
    $RepositoryRoot = if (-not [string]::IsNullOrWhiteSpace($Global:EntraOpsBaseFolder)) { $Global:EntraOpsBaseFolder } else { Split-Path -Parent $ModuleRoot }

    if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $RepoRoot = $RepositoryRoot }
    if ([string]::IsNullOrWhiteSpace($AppRoot)) { $AppRoot = Join-Path $RepoRoot 'Reports/ConfigurationAnalyzer' }
    if (-not (Test-Path -LiteralPath $AppRoot -PathType Container)) {
        throw "Configuration Analyzer app folder not found: $AppRoot. Import the EntraOps module from a repository checkout that contains Reports/ConfigurationAnalyzer, or run Install-EntraOpsReportingFolder to download the Reports folder."
    }
    if ([string]::IsNullOrWhiteSpace($ImportPath)) { $ImportPath = Join-Path $RepoRoot 'TenantGovernance/Snapshots' }
    if ([string]::IsNullOrWhiteSpace($OutFile)) { $OutFile = Join-Path $AppRoot 'data/configuration-analyzer-data.js' }

    $ConfigFilePath = Join-Path $RepoRoot 'EntraOpsConfig.json'
    if (-not $PSBoundParameters.ContainsKey('ResolveGroupMembersForPrivilegedAssets')) {
        $ResolveGroupMembersForPrivilegedAssets = $true
        if (Test-Path -LiteralPath $ConfigFilePath -PathType Leaf) {
            try {
                $Config = Get-Content -LiteralPath $ConfigFilePath -Raw | ConvertFrom-Json
                if ($null -ne $Config.ConfigurationAnalyzer -and $null -ne $Config.ConfigurationAnalyzer.ResolveGroupMembersForPrivilegedAssets) {
                    $ResolveGroupMembersForPrivilegedAssets = [bool]$Config.ConfigurationAnalyzer.ResolveGroupMembersForPrivilegedAssets
                }
            } catch {
                Write-Warning "Failed to read ConfigurationAnalyzer settings from ${ConfigFilePath}: $($_.Exception.Message). Group membership resolution remains enabled."
            }
        }
    }

    # The excluded risk flags of PIM Request Flow and Access Package Flow are finding rules: the report data of
    # New-EntraOpsReportFindingData leaves them out (Findings.ExcludedRules), so they are not embedded here.
    $ConditionalAccessAnalysisExcludedFindings = @()
    $EidscaExcludedFindings = @()
    if (Test-Path -LiteralPath $ConfigFilePath -PathType Leaf) {
        try {
            $Config = Get-Content -LiteralPath $ConfigFilePath -Raw | ConvertFrom-Json
            if ($null -ne $Config.ConfigurationAnalyzer -and $null -ne $Config.ConfigurationAnalyzer.ConditionalAccessAnalysisExcludedFindings) {
                $ConditionalAccessAnalysisExcludedFindings = @($Config.ConfigurationAnalyzer.ConditionalAccessAnalysisExcludedFindings | Where-Object { $_ -is [string] -and -not [string]::IsNullOrWhiteSpace($_) })
            }
            if ($null -ne $Config.ConfigurationAnalyzer -and $null -ne $Config.ConfigurationAnalyzer.EidscaExcludedFindings) {
                $EidscaExcludedFindings = @($Config.ConfigurationAnalyzer.EidscaExcludedFindings | Where-Object { $_ -is [string] -and -not [string]::IsNullOrWhiteSpace($_) })
            }
        } catch {
            Write-Warning "Failed to read report finding exclusions from ${ConfigFilePath}: $($_.Exception.Message). No findings will be excluded."
        }
    }

    $ManifestPath = Join-Path $ImportPath '.SnapshotManifest.json'
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "Tenant Governance snapshot manifest not found: $ManifestPath. Run a successful Save-EntraOpsTenantGovernanceSnapshotJson capture before generating Configuration Analyzer data."
    }
    try {
        $SnapshotManifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -Depth 10
    } catch {
        throw "Tenant Governance snapshot manifest is invalid: $ManifestPath. Error: $($_.Exception.Message)"
    }
    # A rejected later attempt (for example duplicate canonical identities) is recorded only in the
    # last-attempt manifest; its diagnostics are shown next to the published snapshot's own.
    $LastAttemptManifest = $null
    $LastAttemptManifestPath = Join-Path $ImportPath '.LastAttemptManifest.json'
    if (Test-Path -LiteralPath $LastAttemptManifestPath -PathType Leaf) {
        try {
            $LastAttemptManifest = Get-Content -LiteralPath $LastAttemptManifestPath -Raw | ConvertFrom-Json -Depth 10
        } catch {
            Write-Warning "Tenant Governance last-attempt manifest is invalid and ignored: $LastAttemptManifestPath. Error: $($_.Exception.Message)"
        }
    }
    $LastAttemptDiagnostics = @()
    if ($LastAttemptManifest -and -not [string]::IsNullOrWhiteSpace($LastAttemptManifest.SnapshotId) -and $LastAttemptManifest.SnapshotId -ne $SnapshotManifest.SnapshotId) {
        $LastAttemptDiagnostics = @($LastAttemptManifest.Diagnostics)
    }

    # Reports must not turn structurally duplicated resources into duplicated policies/findings.
    # Validate immutable identities and manifest counts here as well as in the workflow so direct,
    # interactive report generation has the same safety boundary.
    $SnapshotIdentityPaths = @{}
    $SnapshotFileCounts = @{}
    $SnapshotResourceFiles = @(Get-ChildItem -LiteralPath $ImportPath -Filter '*.json' -File -Recurse | Where-Object { -not $_.Name.StartsWith('.') -and $_.FullName -notmatch '[\\/]\.(?:staging|backup)-' })
    foreach ($SnapshotResourceFile in $SnapshotResourceFiles) {
        # -AsHashtable accepts valid Graph payloads containing empty JSON
        # property names, which ConvertFrom-Json otherwise rejects.
        try { $SnapshotResource = [System.IO.File]::ReadAllText($SnapshotResourceFile.FullName) | ConvertFrom-Json -AsHashtable -Depth 100 -ErrorAction Stop }
        catch { throw "Tenant Governance resource JSON is invalid: $($SnapshotResourceFile.FullName). Error: $($_.Exception.Message)" }
        $SnapshotResourceType = "$($SnapshotResource.resourceType)".Trim().ToLowerInvariant()
        $RelativeResourcePath = [System.IO.Path]::GetRelativePath($ImportPath, $SnapshotResourceFile.FullName) -replace '\\', '/'
        $FolderResourceType = ($RelativeResourcePath -split '/')[0].ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($SnapshotResourceType)) {
            $SnapshotResourceType = $FolderResourceType
        } elseif ($SnapshotResourceType -ne $FolderResourceType) {
            throw "Tenant Governance resource '$RelativeResourcePath' declares resourceType '$SnapshotResourceType', which does not match its top-level folder '$FolderResourceType'."
        }
        if (-not $SnapshotFileCounts.ContainsKey($SnapshotResourceType)) { $SnapshotFileCounts[$SnapshotResourceType] = 0 }
        $SnapshotFileCounts[$SnapshotResourceType]++
        $SnapshotResourceId = "$($SnapshotResource.properties.Id)".Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($SnapshotResourceId)) { continue }
        $SnapshotIdentity = "$SnapshotResourceType|$SnapshotResourceId"
        if ($SnapshotIdentityPaths.ContainsKey($SnapshotIdentity)) {
            throw "Tenant Governance snapshot contains duplicate canonical identity '$SnapshotIdentity' in '$($SnapshotIdentityPaths[$SnapshotIdentity])' and '$($SnapshotResourceFile.FullName)'. Capture a complete snapshot or remove the structural duplication before generating reports."
        }
        $SnapshotIdentityPaths[$SnapshotIdentity] = $SnapshotResourceFile.FullName
    }
    $ManifestCountProperties = @($SnapshotManifest.PublishedResourceTypeCounts.PSObject.Properties)
    $ManifestCountResourceTypes = @($ManifestCountProperties | ForEach-Object { $_.Name.ToLowerInvariant() })
    foreach ($CountProperty in $ManifestCountProperties) {
        $CountResourceType = $CountProperty.Name.ToLowerInvariant()
        $ActualFileCount = if ($SnapshotFileCounts.ContainsKey($CountResourceType)) { $SnapshotFileCounts[$CountResourceType] } else { 0 }
        if ([int]$CountProperty.Value -ne $ActualFileCount) {
            throw "Tenant Governance manifest count for '$CountResourceType' is $($CountProperty.Value), but $ActualFileCount resource file(s) exist. Refusing to generate a potentially misleading report."
        }
    }
    foreach ($CountResourceType in $SnapshotFileCounts.Keys) {
        if ($ManifestCountResourceTypes -notcontains $CountResourceType) {
            throw "Tenant Governance resource type '$CountResourceType' has $($SnapshotFileCounts[$CountResourceType]) file(s) but no PublishedResourceTypeCounts manifest entry. Refusing to generate a potentially misleading report."
        }
    }
    # partiallySuccessful with IsComplete: only the known limitation of the snapshot export (KnownLimitationResourceTypes).
    $IsCompleteSnapshot = $SnapshotManifest.IsComplete -eq $true -and $SnapshotManifest.SnapshotJobStatus -in @('completed', 'succeeded', 'partiallySuccessful')
    $IsSupportedPartialSnapshot = $SnapshotManifest.SnapshotJobStatus -eq 'partiallySuccessful' -and @($SnapshotManifest.ResourceTypeStates).Count -gt 0
    if (-not $IsCompleteSnapshot -and -not ($AllowPartialSnapshot -and $IsSupportedPartialSnapshot)) {
        throw "Tenant Governance snapshot manifest does not describe a successful complete capture (status: '$($SnapshotManifest.SnapshotJobStatus)'). Use -AllowPartialSnapshot to explicitly analyze a mixed snapshot with stale resource types."
    }
    if (-not $IsCompleteSnapshot) {
        $StaleTypes = @($SnapshotManifest.StaleResourceTypes | Where-Object { $_ })
        $TypesWithErrors = @($SnapshotManifest.PublishedWithErrorsResourceTypes | Where-Object { $_ })
        $PartialDetails = @(
            if ($StaleTypes.Count) { "stale resource types (kept from the previous snapshot): $($StaleTypes -join ', ')" }
            if ($TypesWithErrors.Count) {
                $RetainedTotal = [int](@($SnapshotManifest.ResourceTypeStates | ForEach-Object { [int]$_.RetainedResourceCount }) | Measure-Object -Sum).Sum
                $RetainedNote = if ($RetainedTotal -gt 0) { 'resources that could not be exported are kept from the previous snapshot' } else { 'references that could not be resolved are missing in the exported resources' }
                "resource types with per-resource export errors ($RetainedNote): $($TypesWithErrors -join ', ')"
            }
        )
        Write-Warning "Generating Configuration Analyzer data from a partial Tenant Governance snapshot$(if ($PartialDetails.Count) { ". $($PartialDetails -join '; ')" } else { ' (Microsoft Graph reported errors without resource types)' })."
    }
    # Same parser as the pre-check in Invoke-EntraOpsReportingGeneration, so both agree on the snapshot age.
    $SnapshotAge = Get-EntraOpsTenantGovernanceSnapshotAge -ManifestPath $ManifestPath
    if ($null -eq $SnapshotAge) {
        throw "Tenant Governance snapshot manifest has no valid CapturedDateTime: $ManifestPath."
    }
    $CapturedDateTime = $SnapshotAge.CapturedDateTime
    $SnapshotAgeHours = $SnapshotAge.AgeHours
    $IsStaleSnapshot = $SnapshotAgeHours -gt $MaxSnapshotAgeHours
    if ($IsStaleSnapshot -and -not $AllowStaleSnapshot) {
        throw "Tenant Governance snapshot is $([math]::Round($SnapshotAgeHours, 1)) hour(s) old, exceeding the $MaxSnapshotAgeHours-hour limit. Run a new snapshot or use -AllowStaleSnapshot explicitly."
    }
    if ($IsStaleSnapshot) {
        Write-Warning "Generating Configuration Analyzer data from a stale Tenant Governance snapshot ($([math]::Round($SnapshotAgeHours, 1)) hour(s) old, limit $MaxSnapshotAgeHours hour(s)). The report shows it as stale."
    }

    # Snapshot history from git, or (without git) the current snapshot folder as one snapshot.
    $ImportPathFull = [System.IO.Path]::GetFullPath($ImportPath)
    $UseGit = $HistorySource -ne 'Folder'
    if ($UseGit) {
        $GitIssue = $null
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
            $GitIssue = 'git was not found on PATH'
        } else {
            $GitRoot = (git -C $RepoRoot rev-parse --show-toplevel 2>$null)
            if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($GitRoot)) { $GitIssue = "$RepoRoot is not inside a git working copy" }
            else {
                # A snapshot folder outside the working copy has no git history either: Auto uses the folder, Git fails.
                $GitRootPath = [System.IO.Path]::GetFullPath($GitRoot.Trim())
                $ImportFullPath = [System.IO.Path]::GetFullPath($ImportPath)
                if (-not ($ImportFullPath.Equals($GitRootPath, [System.StringComparison]::OrdinalIgnoreCase) -or
                        $ImportFullPath.StartsWith($GitRootPath + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase))) {
                    $GitIssue = "ImportPath ($ImportPath) is not inside the git working copy ($GitRootPath)"
                }
            }
        }
        if ($GitIssue) {
            if ($HistorySource -eq 'Git') { throw "$GitIssue. The Configuration Analyzer reads historic Tenant Governance snapshots from the git history (-HistorySource Git)." }
            $FolderReason = $GitIssue
            $UseGit = $false
        }
    }
    # Snapshot state/manifest files are bookkeeping (see
    # Save-EntraOpsTenantGovernanceSnapshotJson), not captured resources.
    $ExcludedFileNames = @('.PendingSnapshotJob.json', '.SnapshotManifest.json', '.LastAttemptManifest.json')
    $snapshots = [System.Collections.Generic.List[object]]::new()

    if (-not $UseGit) {
        $RelPath = [System.IO.Path]::GetRelativePath($RepoRoot, $ImportPathFull) -replace '\\', '/'
        $FolderFiles = @(Get-ChildItem -LiteralPath $ImportPath -Recurse -File -Filter '*.json' | Where-Object { $ExcludedFileNames -notcontains $_.Name } | Sort-Object FullName)
        if ($FolderFiles.Count -gt 0) {
            $Hashes = @(Get-EntraOpsGitBlobHash -LiteralPath @($FolderFiles.FullName))
            $snapshots.Add([ordered]@{
                    commitSha   = '(snapshot folder)'
                    commitDate  = $CapturedDateTime.ToUniversalTime().ToString('o')
                    subject     = 'Current snapshot folder (no git history)'
                    hasDetail   = $false
                    resources   = @(for ($Index = 0; $Index -lt $FolderFiles.Count; $Index++) {
                            [ordered]@{ p = ($FolderFiles[$Index].FullName.Substring($ImportPathFull.Length).TrimStart('\', '/') -replace '\\', '/'); h = $Hashes[$Index] }
                        })
                    workingTree = $true
                })
        }
    } else {
        $GitRoot = $GitRoot.Trim()

        # Git-relative path (forward slashes) of the snapshot folder, used as the pathspec
        # for `git log` / `git ls-tree`.
        $GitRootFull = [System.IO.Path]::GetFullPath($GitRoot)
        # Compare with a trailing separator so a sibling folder such as <root>-2 does not pass as
        # being inside <root>.
        if (-not ($ImportPathFull.Equals($GitRootFull, [System.StringComparison]::OrdinalIgnoreCase) -or
                $ImportPathFull.StartsWith($GitRootFull + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase))) {
            throw "ImportPath ($ImportPath) is not inside the git working copy ($GitRootFull)."
        }
        $RelPath = $ImportPathFull.Substring($GitRootFull.Length).TrimStart('\', '/') -replace '\\', '/'
        if ([string]::IsNullOrWhiteSpace($RelPath)) {
            throw "ImportPath resolved to the git working copy root; expected a subfolder such as TenantGovernance/Snapshots."
        }

        # ---- Enumerate commits that published snapshots --------------------------------
        $logArgs = @('-C', $GitRoot, 'log', "--format=%H%x1f%cI%x1f%s")
        if ($TimeRangeInDays) {
            $since = (Get-Date).ToUniversalTime().AddDays(-1 * [Math]::Abs($TimeRangeInDays)).ToString('o')
            $logArgs += "--since=$since"
        }
        $logArgs += @('--', $RelPath)
        # Start/Collect polls and rejected attempts update only bookkeeping files. They must
        # not take a sampling interval away from the completed capture that follows them.
        # Keep .SnapshotManifest.json in the history: a successful capture can publish a new
        # manifest even when all resource content is unchanged.
        foreach ($BookkeepingFile in @('.PendingSnapshotJob.json', '.LastAttemptManifest.json')) {
            $logArgs += ":(top,exclude,literal)$RelPath/$BookkeepingFile"
        }

        $logOutput = & git @logArgs
        if ($LASTEXITCODE -ne 0) {
            throw "git log failed with exit code $LASTEXITCODE while enumerating history of $RelPath."
        }

        $commits = @($logOutput | Where-Object { $_ } | ForEach-Object {
                $parts = $_ -split "`u{1f}"
                [pscustomobject]@{ Sha = $parts[0]; Date = [datetimeoffset]::Parse($parts[1]); Subject = $parts[2] }
            }) | Sort-Object -Property Date

        # A fully-stale partial snapshot (e.g. Graph returned no parseable per-type errors) commits only
        # its manifest, preserving the last known-good resources unchanged - do not present that as a
        # historical capture at the partial job time. A mixed partial snapshot still publishes real,
        # changed resource files for its non-stale types (stale types simply keep their previous blob
        # hash, so they never appear as a diff), so it must not be dropped from history wholesale.
        $commits = @($commits | Where-Object {
                $manifestAtCommit = & git -C $GitRoot show "$($_.Sha):$RelPath/.SnapshotManifest.json" 2>$null
                if ($LASTEXITCODE -ne 0 -or -not $manifestAtCommit) { return $true }
                try {
                    $commitManifest = ($manifestAtCommit -join "`n") | ConvertFrom-Json -Depth 10
                    return -not ($commitManifest.IsComplete -eq $false -and @($commitManifest.PublishedResourceTypes).Count -eq 0)
                } catch {
                    return $true
                }
            })

        if (-not $commits) {
            Write-Warning "No commits touching $RelPath were found$(if ($TimeRangeInDays) { " in the last $TimeRangeInDays day(s)" }). The dataset will only contain the current working tree state (if any)."
        }
        Write-Verbose "Found $($commits.Count) commit(s) touching $RelPath."

        # ---- Thin commits down to the requested snapshot interval ----------------------
        if ($null -ne $SnapshotIntervalComponents -and $commits.Count -gt 2) {
            $thinned = Select-EntraOpsSnapshotIntervalCommit -Commit @($commits) -Years $SnapshotIntervalComponents.Years -Months $SnapshotIntervalComponents.Months -Days $SnapshotIntervalComponents.Days
            Write-Verbose "Snapshot interval '$SnapshotInterval' reduced $($commits.Count) commit(s) to $($thinned.Count) snapshot(s)."
            $commits = $thinned
        }

        # ---- Build one snapshot (file path + blob hash listing) per commit -------------
        foreach ($commit in $commits) {
            # -z: NUL-separated entries, so file names with special characters parse reliably.
            $lsTree = & git -C $GitRoot ls-tree -r -z $commit.Sha -- $RelPath
            if ($LASTEXITCODE -ne 0) {
                Write-Verbose "Skipped commit $($commit.Sha): git ls-tree failed."
                continue
            }
            $resources = [System.Collections.Generic.List[object]]::new()
            foreach ($entry in ($lsTree -join "`n") -split "`0") {
                if ([string]::IsNullOrWhiteSpace($entry)) { continue }
                # "<mode> <type> <hash>\t<path>"
                $tabIdx = $entry.IndexOf("`t")
                if ($tabIdx -lt 0) { continue }
                $metaParts = $entry.Substring(0, $tabIdx) -split '\s+'
                if ($metaParts.Count -lt 3 -or $metaParts[1] -ne 'blob') { continue }
                $path = $entry.Substring($tabIdx + 1)
                if (-not $path.EndsWith('.json', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
                $leaf = Split-Path -Leaf $path
                if ($ExcludedFileNames -contains $leaf) { continue }
                # Store the path relative to the snapshot folder - the app derives
                # resource type/category/name from its segments.
                $rel = $path.Substring($RelPath.Length).TrimStart('/')
                $resources.Add([ordered]@{ p = $rel; h = $metaParts[2] })
            }
            if ($resources.Count -eq 0) {
                Write-Verbose "Skipped commit $($commit.Sha): no snapshot resource files."
                continue
            }
            $snapshots.Add([ordered]@{
                    commitSha  = $commit.Sha
                    commitDate = $commit.Date.ToString('o')
                    subject    = $commit.Subject
                    hasDetail  = $false
                    resources  = @($resources)
                })
        }
    }

    # ---- Append the current working tree state when it adds information -------------
    if ($UseGit -and -not $SkipWorkingTree -and (Test-Path -LiteralPath $ImportPath -PathType Container)) {
        $wtFiles = @(Get-ChildItem -LiteralPath $ImportPath -Recurse -File -Filter '*.json' |
            Where-Object { $ExcludedFileNames -notcontains $_.Name } | Sort-Object FullName)
        if ($wtFiles.Count -gt 0) {
            $wtResources = [System.Collections.Generic.List[object]]::new()
            # git hash-object computes the same blob hash a commit would produce, so
            # working-tree files de-duplicate against committed blob content. Chunked to
            # stay clear of command-line length limits.
            $wtHashByFile = @{}
            for ($i = 0; $i -lt $wtFiles.Count; $i += 50) {
                $chunk = @($wtFiles | Select-Object -Skip $i -First 50)
                $hashes = & git -C $GitRoot hash-object -- @($chunk.FullName)
                if ($LASTEXITCODE -ne 0) { throw "git hash-object failed while hashing working tree snapshot files." }
                $hashes = @($hashes)
                for ($j = 0; $j -lt $chunk.Count; $j++) { $wtHashByFile[$chunk[$j].FullName] = $hashes[$j] }
            }
            foreach ($file in $wtFiles) {
                $rel = $file.FullName.Substring($ImportPathFull.Length).TrimStart('\', '/') -replace '\\', '/'
                $wtResources.Add([ordered]@{ p = $rel; h = $wtHashByFile[$file.FullName] })
            }

            # Only append when it differs from the newest committed snapshot.
            $differs = $true
            if ($snapshots.Count -gt 0) {
                $newest = $snapshots[$snapshots.Count - 1]
                $newestMap = @{}
                foreach ($r in $newest.resources) { $newestMap[$r.p] = $r.h }
                if ($newestMap.Count -eq $wtResources.Count) {
                    $differs = $false
                    foreach ($r in $wtResources) {
                        if ($newestMap[$r.p] -ne $r.h) { $differs = $true; break }
                    }
                }
            }
            if ($differs) {
                $snapshots.Add([ordered]@{
                        commitSha   = '(working tree)'
                        commitDate  = (Get-Date).ToUniversalTime().ToString('o')
                        subject     = 'Uncommitted working tree state'
                        hasDetail   = $false
                        resources   = @($wtResources)
                        workingTree = $true
                    })
                Write-Verbose "Appended working tree state with $($wtResources.Count) resource file(s)."
            }
        }
    }

    # ---- Pick which snapshots embed full resource content ---------------------------
    $detailIdx = [System.Collections.Generic.HashSet[int]]::new()
    if ($snapshots.Count -gt 0) {
        if ($MaxDetailedSnapshots -le 0 -or $snapshots.Count -le $MaxDetailedSnapshots) {
            for ($i = 0; $i -lt $snapshots.Count; $i++) { [void]$detailIdx.Add($i) }
        } else {
            for ($i = 0; $i -lt $MaxDetailedSnapshots; $i++) {
                $pos = if ($MaxDetailedSnapshots -eq 1) { $snapshots.Count - 1 } else { [Math]::Round($i * ($snapshots.Count - 1) / ($MaxDetailedSnapshots - 1)) }
                [void]$detailIdx.Add([int]$pos)
            }
        }
    }

    # ---- Load the unique blob contents referenced by the detailed snapshots ---------
    # De-duplicated by git blob hash: an unchanged resource shared by 20 snapshots is
    # embedded exactly once.
    $blobs = [ordered]@{}
    $wtContentByHash = @{}
    $SkippedBlobCount = 0
    foreach ($idx in ($detailIdx | Sort-Object)) {
        $snap = $snapshots[$idx]
        $snap.hasDetail = $true
        $isWorkingTree = $snap.Contains('workingTree')
        foreach ($r in $snap.resources) {
            if ($blobs.Contains($r.h)) { continue }
            try {
                if ($isWorkingTree) {
                    $raw = Get-Content -LiteralPath (Join-Path $ImportPath $r.p) -Raw
                } elseif ($wtContentByHash.ContainsKey($r.h)) {
                    $raw = $wtContentByHash[$r.h]
                } else {
                    $raw = (& git -C $GitRoot cat-file blob $r.h) -join "`n"
                    if ($LASTEXITCODE -ne 0) { throw "git cat-file failed for blob $($r.h)." }
                }
                # Snapshot JSON can contain an empty property name (for example in
                # cross-tenant access policy resources). PSCustomObject parsing rejects
                # that valid JSON shape, while hashtable parsing preserves it.
                $blobs[$r.h] = $raw | ConvertFrom-Json -AsHashtable
            } catch {
                Write-Verbose "Could not load/parse blob $($r.h) ($($r.p)): $($_.Exception.Message)"
                $blobs[$r.h] = $null
                $SkippedBlobCount++
            }
        }
    }

    Write-Verbose "Embedded $($blobs.Count) unique resource content blob(s) for $($detailIdx.Count) detailed snapshot(s); $SkippedBlobCount could not be parsed."

    $ResolvedGroupTiers = [ordered]@{}
    $ResolvedDeviceTiers = [ordered]@{}
    $ResolvedPolicyGroupIds = [ordered]@{}
    # Groups and approvers are looked up in the connected tenant, partly by display name: with a connection to another
    # tenant than the one of the snapshot, groups of the same name there would end up in this tenant's report.
    if ($ResolveGroupMembersForPrivilegedAssets -and [string]::IsNullOrWhiteSpace([string]$SnapshotManifest.TenantId)) {
        Write-Warning "The Tenant Governance snapshot records no tenant (captured with EntraOps before 1.2.0), so EntraOps cannot check that the members of its groups are resolved in the same tenant. Capture a new snapshot (Save-EntraOpsTenantGovernanceSnapshotJson) to record it."
    }
    if ($ResolveGroupMembersForPrivilegedAssets -and -not [string]::IsNullOrWhiteSpace([string]$SnapshotManifest.TenantId)) {
        $ConnectedTenantId = [string]$Global:TenantIdContext
        if ([string]::IsNullOrWhiteSpace($ConnectedTenantId) -and (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue)) {
            $ConnectedTenantId = [string](Get-MgContext -ErrorAction SilentlyContinue).TenantId
        }
        if (-not [string]::IsNullOrWhiteSpace($ConnectedTenantId) -and $ConnectedTenantId -ne [string]$SnapshotManifest.TenantId) {
            Write-Warning "The members of groups in policies are not resolved: the Tenant Governance snapshot belongs to tenant $($SnapshotManifest.TenantId), but the connection is to tenant $ConnectedTenantId. Connect to the tenant of the snapshot (Connect-EntraOps) and generate the Configuration Analyzer data again."
            $ResolveGroupMembersForPrivilegedAssets = $false
        }
    }
    if ($ResolveGroupMembersForPrivilegedAssets) {
        $PrivilegedEamPath = Join-Path $RepoRoot 'PrivilegedEAM'
        if (-not (Test-Path -LiteralPath $PrivilegedEamPath -PathType Container)) {
            Write-Warning "Group membership resolution was requested, but the Privileged EAM export was not found at $PrivilegedEamPath."
        } else {
            # Rank values are purely relational (comparisons/sorting) - canonical Enterprise Access
            # Model order: ControlPlane < ManagementPlane < WorkloadPlane < UserAccess.
            $TierRank = @{ ControlPlane = 0; ManagementPlane = 1; WorkloadPlane = 2; UserAccess = 3 }
            $TierByObjectId = @{}
            $PrivilegedEamObjects = Get-EntraOpsPrivilegedEamDashboardObjects -ImportPath $PrivilegedEamPath
            foreach ($Object in $PrivilegedEamObjects) {
                $ObjectId = "$($Object.objectId)"
                if (-not $ObjectId) { continue }
                $ObjectTierNames = @("$($Object.objectAdminTierLevelName)") +
                @($Object.classification | ForEach-Object { "$($_.adminTierLevelName)" }) +
                @($Object.roleAssignments | ForEach-Object { $_.classification } | ForEach-Object { "$($_.adminTierLevelName)" })
                foreach ($TierName in $ObjectTierNames | Where-Object { $TierRank.ContainsKey($_) }) {
                    if (-not $TierByObjectId.ContainsKey($ObjectId) -or $TierRank[$TierName] -lt $TierRank[$TierByObjectId[$ObjectId]]) {
                        $TierByObjectId[$ObjectId] = $TierName
                    }
                }
            }

            foreach ($Object in $PrivilegedEamObjects) {
                $TierName = "$($Object.objectAdminTierLevelName)"
                if (-not $TierRank.ContainsKey($TierName)) { continue }
                foreach ($DeviceId in @($Object.ownedDevices) + @($Object.associatedPawDevice) | Where-Object { $_ }) {
                    $DeviceId = "$DeviceId"
                    if (-not $ResolvedDeviceTiers.Contains($DeviceId) -or $TierRank[$TierName] -lt $TierRank[$ResolvedDeviceTiers[$DeviceId].tierName]) {
                        $ResolvedDeviceTiers[$DeviceId] = [ordered]@{
                            tierName    = $TierName
                            displayName = $DeviceId
                        }
                    }
                }
            }

            $IncludedGroupReferences = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $AssignmentPolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            # The requestor and approver groups of an assignment policy are read live from Microsoft Graph, so only the
            # policies of the latest snapshot are looked up. A policy that is only in older snapshots was deleted in the
            # tenant: its lookup would answer 404 in every run for as long as it stays in the git history.
            $LatestSnapshot = if ($snapshots.Count -gt 0) { $snapshots[$snapshots.Count - 1] } else { $null }
            foreach ($Snapshot in @($snapshots | Where-Object { $_.hasDetail })) {
                $IsLatestSnapshot = [object]::ReferenceEquals($Snapshot, $LatestSnapshot)
                foreach ($Resource in @($Snapshot.resources)) {
                    $Blob = $blobs[$Resource.h]
                    if ($null -eq $Blob -or $null -eq $Blob.properties) { continue }
                    $ResourceType = "$($Blob.resourceType)".ToLowerInvariant()
                    if ($ResourceType -eq 'microsoft.entra.conditionalaccesspolicy') {
                        # Excluded groups as well: the finding rule EO.4003 evaluates the Control Plane members a
                        # policy excludes, and the Conditional Access Analysis shows their tier.
                        foreach ($Group in @(@($Blob.properties.IncludeGroups) + @($Blob.properties.ExcludeGroups))) {
                            if ($Group) { [void]$IncludedGroupReferences.Add("$Group") }
                        }
                    } elseif ($ResourceType -eq 'microsoft.entra.rolesetting') {
                        # PIM activation approvers that are groups (display names; users are user principal names), so
                        # the approver checks (EO.1008) can compare the least protected member of an approver group.
                        # Every approver is looked up as a group: a group name can contain '@' too, and a user
                        # principal name matches no group.
                        foreach ($Approver in @($Blob.properties.ActivateApprover)) {
                            if ($Approver) { [void]$IncludedGroupReferences.Add("$Approver") }
                        }
                    } elseif ($ResourceType.StartsWith('microsoft.entra.authenticationmethodpolicy') -and $ResourceType -ne 'microsoft.entra.authenticationmethodpolicy') {
                        foreach ($Target in @($Blob.properties.IncludeTargets)) {
                            if ($null -ne $Target -and $Target.Id) { [void]$IncludedGroupReferences.Add("$($Target.Id)") }
                        }
                    } elseif ($IsLatestSnapshot -and $ResourceType -eq 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy') {
                        $PolicyId = "$($Blob.properties.Id)"
                        if ($PolicyId) { [void]$AssignmentPolicyIds.Add($PolicyId) }
                    }
                }
            }

            # Inside New-EntraOpsReportingData the run's cache is used, which the Access Package Flow data shares: a
            # deleted policy is requested and reported once per run. Called on its own, this generator reports them.
            $OwnsReportingRunCache = Start-EntraOpsReportingRunCache
            foreach ($PolicyId in $AssignmentPolicyIds) {
                try {
                    # $null for a deleted policy, which is reported once per run by Complete-EntraOpsReportingRunCache
                    $Policy = Get-EntraOpsAccessPackageAssignmentPolicyForReport -PolicyId $PolicyId
                    if ($null -eq $Policy) { continue }
                    $PolicyGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    $UserSets = @($Policy.requestorSettings.allowedRequestors) + @($Policy.requestApprovalSettings.approvalStages | ForEach-Object { $_.primaryApprovers })
                    foreach ($UserSet in $UserSets) {
                        if ("$($UserSet.'@odata.type')" -eq '#microsoft.graph.groupMembers' -and $UserSet.id) {
                            [void]$PolicyGroupIds.Add("$($UserSet.id)")
                            [void]$IncludedGroupReferences.Add("$($UserSet.id)")
                        }
                    }
                    if ($PolicyGroupIds.Count -gt 0) { $ResolvedPolicyGroupIds[$PolicyId] = @($PolicyGroupIds) }
                } catch {
                    Write-Warning "Could not resolve requestor and approver groups for access package assignment policy ${PolicyId}: $($_.Exception.Message)"
                }
            }
            if ($OwnsReportingRunCache) { Complete-EntraOpsReportingRunCache }

            foreach ($GroupReference in $IncludedGroupReferences) {
                if ($GroupReference -in @('All', 'None', 'GuestsOrExternalUsers', 'All_Users')) { continue }
                $Groups = @()
                if ($GroupReference -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
                    try {
                        $Groups = @(Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/v1.0/groups/${GroupReference}?`$select=id,displayName" -OutputType PSObject -ThrowOnFailure)
                    } catch {
                        Write-Warning "Could not resolve group id '${GroupReference}': $($_.Exception.Message)"
                        continue
                    }
                } else {
                    # OData string-literal escaping first ('' for '), then percent-encoding so
                    # characters like & / # / % cannot truncate the query string (which would
                    # silently drop the $filter and enumerate every group in the tenant).
                    $EscapedReference = ConvertTo-EntraOpsODataStringLiteral -Value $GroupReference
                    try {
                        $Groups = @(Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/v1.0/groups?`$filter=displayName eq '$EscapedReference'&`$select=id,displayName" -OutputType PSObject -ThrowOnFailure)
                    } catch {
                        Write-Warning "Could not resolve group '$GroupReference': $($_.Exception.Message)"
                        continue
                    }
                }

                foreach ($Group in $Groups | Where-Object { $_.Id }) {
                    try {
                        $Members = @(Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId $Group.Id | Where-Object { $null -ne $_ })
                        $PrivilegedMembers = @($Members | Where-Object { $TierByObjectId.ContainsKey("$($_.Id)") })
                        $BestTier = @($PrivilegedMembers | ForEach-Object { $TierByObjectId["$($_.Id)"] } | Sort-Object { $TierRank[$_] } | Select-Object -First 1)[0]
                        if (-not $BestTier) { $BestTier = 'UserAccess' }
                        $TierNames = @($PrivilegedMembers | ForEach-Object { $TierByObjectId["$($_.Id)"] } | Sort-Object { $TierRank[$_] } -Unique)
                        if ($TierNames.Count -eq 0) { $TierNames = @('UserAccess') }
                        $ResolvedGroupTiers[$Group.Id] = [ordered]@{
                            tierName              = $BestTier
                            tierNames             = $TierNames
                            displayName           = "$($Group.DisplayName)"
                            totalMembers          = $Members.Count
                            # Members that can act themselves (users and service principals, not nested groups).
                            principalCount        = @($Members | Where-Object { "$($_.'@odata.type')" -ne '#microsoft.graph.group' }).Count
                            privilegedMemberCount = $PrivilegedMembers.Count
                            members               = @($PrivilegedMembers | ForEach-Object { [ordered]@{ id = "$($_.Id)"; displayName = "$($_.DisplayName)"; tierName = $TierByObjectId["$($_.Id)"]; objectType = "$($_.'@odata.type')" -replace '^#microsoft\.graph\.', '' } })
                        }
                    } catch {
                        Write-Warning "Could not resolve transitive members of group '$($Group.DisplayName)': $($_.Exception.Message)"
                    }
                }
            }
            Write-Verbose "Resolved $($ResolvedGroupTiers.Count) referenced group(s) for Privileged Assets and Conditional Access."
        }
    }

    # Compact manifest extract instead of the full raw manifest: enough for the app to
    # surface the health of the analyzed snapshot (partial captures with stale resource
    # types) without embedding manifest internals nothing reads.
    $SnapshotHealth = [ordered]@{
        status                  = if ($null -ne $SnapshotManifest.SnapshotJobStatus) { "$($SnapshotManifest.SnapshotJobStatus)" } else { $null }
        capturedDateTime        = if ($null -ne $CapturedDateTime) { $CapturedDateTime.ToString('o') } else { $null }
        isComplete              = $SnapshotManifest.IsComplete -eq $true
        isStale                 = [bool]$IsStaleSnapshot
        ageHours                = [math]::Round($SnapshotAgeHours, 1)
        maxAgeHours             = $MaxSnapshotAgeHours
        staleResourceTypes      = @($SnapshotManifest.StaleResourceTypes | Where-Object { $_ } | ForEach-Object { "$_" })
        resourceTypeStates      = @($SnapshotManifest.ResourceTypeStates | ForEach-Object {
                [ordered]@{
                    resourceType          = "$($_.ResourceType)"
                    status                = "$($_.Status)"
                    retainedResourceCount = if ($null -ne $_.RetainedResourceCount) { [int]$_.RetainedResourceCount } else { 0 }
                    publishedSnapshotId   = if ($_.PublishedSnapshotId) { "$($_.PublishedSnapshotId)" } else { $null }
                    publishedSource       = if ($_.PublishedSource) { "$($_.PublishedSource)" } else { $null }
                    attemptSnapshotId     = if ($_.AttemptSnapshotId) { "$($_.AttemptSnapshotId)" } else { $null }
                }
            })
        diagnostics             = @(
            @($SnapshotManifest.Diagnostics | ForEach-Object {
                    [ordered]@{
                        resourceType      = "$($_.ResourceType)"
                        errorCategory     = "$($_.ErrorCategory)"
                        errorCode         = if ($_.ErrorCode) { "$($_.ErrorCode)" } else { $null }
                        occurrences       = [int]$_.Occurrences
                        message           = "$($_.Message)"
                        remediationHint   = "$($_.RemediationHint)"
                        attemptSnapshotId = $null
                        knownLimitation   = $(if ($null -eq $_) { $false } elseif ($null -ne $_.PSObject.Properties['KnownLimitation']) { [bool]$_.KnownLimitation } else { Test-EntraOpsTenantGovernanceKnownExportLimitation -ResourceType "$($_.ResourceType)" -ErrorCategory "$($_.ErrorCategory)" -ErrorCode "$($_.ErrorCode)" -Message "$($_.Message)" })
                    }
                })
            @($LastAttemptDiagnostics | ForEach-Object {
                    [ordered]@{
                        resourceType      = "$($_.ResourceType)"
                        errorCategory     = "$($_.ErrorCategory)"
                        errorCode         = if ($_.ErrorCode) { "$($_.ErrorCode)" } else { $null }
                        occurrences       = [int]$_.Occurrences
                        message           = "[Last attempt $($LastAttemptManifest.SnapshotId)] $($_.Message)"
                        remediationHint   = "$($_.RemediationHint)"
                        attemptSnapshotId = "$($LastAttemptManifest.SnapshotId)"
                    }
                })
        )
        errorDetailsUnavailable = $SnapshotManifest.ErrorDetailsUnavailable -eq $true
    }

    $payload = [ordered]@{
        tenantName                                = Get-EntraOpsReportingTenantName -RepoRoot $RepoRoot
        generatedAt                               = (Get-Date).ToUniversalTime().ToString('o')
        snapshotFolder                            = $RelPath
        historySource                             = $(if ($UseGit) { 'git' } else { 'folder' })
        snapshotHealth                            = $SnapshotHealth
        timeRangeInDays                           = $TimeRangeInDays
        snapshotInterval                          = $SnapshotInterval
        snapshots                                 = @($snapshots)
        blobs                                     = $blobs
        resolvedGroupTiers                        = $ResolvedGroupTiers
        resolvedPolicyGroupIds                    = $ResolvedPolicyGroupIds
        resolvedDeviceTiers                       = $ResolvedDeviceTiers
        conditionalAccessAnalysisExcludedFindings = $ConditionalAccessAnalysisExcludedFindings
        eidscaExcludedFindings                    = $EidscaExcludedFindings
    }

    $json = $payload | ConvertTo-Json -Depth 25 -Compress
    $content = "// Auto-generated by New-EntraOpsTenantGovernanceConfigurationAnalyzerData - do not edit by hand.`n" +
    "window.ENTRAOPS_CONFIGANALYZER_DATA = $json;`n"

    if ($PSCmdlet.ShouldProcess($OutFile, 'Write Configuration Analyzer dataset')) {
        Save-EntraOpsReportDataFile -Content $content -LiteralPath $OutFile

        Write-Host "Snapshots written:      $($snapshots.Count)"
        Write-Host "Detailed snapshots:     $($detailIdx.Count)"
        Write-Host "Unique content blobs:   $($blobs.Count)"
        if (-not $UseGit) { Write-Host "History source:         current snapshot only, no history and drift ($(if ($FolderReason) { $FolderReason } else { '-HistorySource Folder' }))" }
        if ($SkippedBlobCount -gt 0) {
            Write-Warning "$SkippedBlobCount content blob(s) could not be parsed; affected resources have no property-level diff data."
        }
        Write-Host "Wrote $OutFile"
    }

    if ($PassThru) { $payload }
}
