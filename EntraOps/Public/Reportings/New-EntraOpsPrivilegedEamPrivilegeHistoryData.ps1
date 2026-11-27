<#
.SYNOPSIS
    Generate (refresh) the dataset for the EntraOps Privilege History static web app.

.DESCRIPTION
    Walks the git history of the Privileged EAM export folder (PrivilegedEAM/<RbacSystem>/
    <RbacSystem>.json, written by Save-EntraOpsPrivilegedEAMJson and committed by the
    Push-EntraOpsPrivilegedEAM workflow) and builds one snapshot per commit that changed
    it, so the Privilege History app can show trends over time: unique privileged role
    assignments and users per Enterprise Access Model tier, total privileged assets and
    tier breaches (an object whose own tier is less privileged than a role assignment it
    holds; an unclassified object counts as User Access, like the Tier Breach finding rules).

    By default, only one snapshot every two weeks is kept (-SnapshotInterval 'P2W') - the
    oldest and most recent commit in range are always included regardless of spacing.
    Use -SnapshotInterval to pick a coarser or finer cadence (daily/weekly/monthly/yearly,
    or any custom multiple such as bi-weekly/quarterly), or 'P0D'/'None' to keep every
    commit.

    For every matching commit, the exact PrivilegedEAM/ tree at that commit is restored to
    a temporary folder (git archive) and transformed with the same
    Get-EntraOpsPrivilegedEamDashboardObjects logic used by
    New-EntraOpsPrivilegedEamDashboardData, so Privilege History snapshots and the live EAM
    Dashboard dataset use identical computed columns.

    Generates data/privilege-history-data.js exposing `window.ENTRAOPS_PRIVILEGEHISTORY_DATA` so the
    static web app works both when served over HTTP and when opened directly from the file
    system. The Privilege History app shows setup instructions instead of failing until this
    file exists, so the feature has no effect until it has been generated at least once.

    Git history is the only source of historic data (there is no separate time-series store).
    When the export in the working tree differs from the newest commit (or was never committed), it is
    added as the newest snapshot ("(working tree)"), so the report and the Privilege History findings
    include an export that is not committed yet. Without git, outside a git working copy, or without a
    commit of the export, the current Privileged EAM export is the only snapshot (-HistorySource Folder,
    the automatic fallback): the report then has no trend.

.PARAMETER RepoRoot
    Path to the EntraOps repository root (and git working copy) that contains the
    PrivilegedEAM export folder (alias: -Path). Defaults to the EntraOps working folder ($EntraOpsBaseFolder).

.PARAMETER ImportPath
    Folder with the Privileged EAM export whose git history is walked. Defaults to
    <RepoRoot>/PrivilegedEAM. Must be inside the git working copy of RepoRoot.

.PARAMETER AppRoot
    Path to the Privilege History app folder (where the generated content is written).
    Defaults to Reports/PrivilegeHistory in the EntraOps repository.

.PARAMETER OutFile
    Output file. Defaults to <AppRoot>/data/privilege-history-data.js.

.PARAMETER TenantId
    Home tenant id forwarded to Get-EntraOpsPrivilegedEamDashboardObjects for every
    snapshot (used to detect foreign objects for the PrivilegedType column). Defaults to
    the most common ObjectTenantId per snapshot when omitted.

.PARAMETER TimeRangeInDays
    Only consider commits from the last N days. Default ($null) considers the full git
    history of the PrivilegedEAM folder (every commit that changed it).

.PARAMETER SnapshotInterval
    Minimum spacing between two consecutive snapshots, as an ISO 8601 duration: `P<n>D` (days),
    `P<n>W` (weeks), `P<n>M` (months) or `P<n>Y` (years) - e.g. `P1D` (daily), `P1W` (weekly),
    `P2W` (bi-weekly), `P1M` (monthly), `P3M` (quarterly), `P1Y` (yearly). Commits closer together
    than the interval are skipped; the oldest and the most recent commit in range are always kept
    so the dataset covers the full requested window and always reflects the latest state. Months
    and years use calendar arithmetic (28-31 day months, leap years), not a fixed day count.
    Default `P2W` (bi-weekly). Use `P0D`, `` (empty string) or `None` to keep every commit
    (previous behavior - no thinning).

.PARAMETER MaxDetailedSnapshots
    Only up to this many snapshots (evenly spread across the full range, always
    including the oldest and newest) keep their per-object detail (used by the Privilege
    History snapshot detail/compare views); the rest keep their trend numbers
    (assets/users/role assignments/tier breaches per tier) but drop object-level detail,
    so the generated file stays a reasonable size regardless of how far back the git
    history goes. Default 60. Use 0 to keep full detail for every snapshot (only
    recommended for short histories).

.PARAMETER HistorySource
    Where the snapshots come from: Git (one snapshot per commit of the export folder, plus the uncommitted
    export), Folder (the current export as one snapshot, without trend) or Auto (default: Git when git is
    available, the folder is in a git working copy and the export has commits, otherwise Folder with a note in
    the output).

.PARAMETER PassThru
    Emit the generated payload object to the pipeline.

.EXAMPLE
    New-EntraOpsPrivilegedEamPrivilegeHistoryData

    Regenerates the Privilege History dataset from the full git history of the PrivilegedEAM
    folder of this repository.

.EXAMPLE
    New-EntraOpsPrivilegedEamPrivilegeHistoryData -TimeRangeInDays 90 -Verbose -WhatIf

    Shows what would be generated from the last 90 days of history without changing any
    files.
#>

function New-EntraOpsPrivilegedEamPrivilegeHistoryData {

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
        [System.String]$TenantId,

        [Parameter(Mandatory = $false)]
        [System.Nullable[int]]$TimeRangeInDays,

        [Parameter(Mandatory = $false)]
        [System.String]$SnapshotInterval = 'P2W',

        [Parameter(Mandatory = $false)]
        [int]$MaxDetailedSnapshots = 60,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Auto', 'Git', 'Folder')]
        [System.String]$HistorySource = 'Auto',

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    # Tier order used for trend series and the tier-breach calculation (higher index
    # = less privileged). Matches TIER_ORDER in Reports/PrivilegeHistory/js/app.js.
    $TierOrder = @('ControlPlane', 'ManagementPlane', 'WorkloadPlane', 'UserAccess', 'Unclassified')

    function ConvertTo-TierRank {
        param([string]$TierName)
        $idx = [array]::IndexOf($TierOrder, $TierName)
        if ($idx -lt 0) { return $TierOrder.Length - 1 } # Unclassified = least privileged
        return $idx
    }

    # ---- Snapshot interval (bi-weekly by default) ----------------------------------
    # Parses a simplified ISO 8601 duration - only the date components matter (Y/M/W/D);
    # there is no time-of-day granularity since snapshots are one per commit. Using
    # calendar arithmetic (AddYears/AddMonths) for Y/M rather than a fixed day count means
    # "monthly"/"yearly" line up with real calendar months/years regardless of length.
    function ConvertTo-SnapshotIntervalComponents {
        param([string]$Interval)
        if ([string]::IsNullOrWhiteSpace($Interval)) { return $null }
        if ($Interval -in @('P0D', 'PT0S', 'None', 'none')) { return $null }
        if ($Interval -notmatch '^P(?:(?<y>\d+)Y)?(?:(?<mo>\d+)M)?(?:(?<w>\d+)W)?(?:(?<d>\d+)D)?$') {
            throw "Invalid -SnapshotInterval '$Interval'. Expected an ISO 8601 duration such as 'P1D' (daily), 'P1W' (weekly), 'P2W' (bi-weekly), 'P1M' (monthly), 'P3M' (quarterly) or 'P1Y' (yearly). Use 'P0D' or 'None' to keep every commit."
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
    # <repo>/EntraOps/Public/<subfolder> -> <repo>/Reports/PrivilegeHistory
    $ModuleRoot = $MyInvocation.MyCommand.Module.ModuleBase
    if ([string]::IsNullOrWhiteSpace($ModuleRoot) -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $ModuleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    }
    if ([string]::IsNullOrWhiteSpace($ModuleRoot)) {
        throw "Unable to resolve the EntraOps module location. Import the module with 'Import-Module <path-to-EntraOps> -Force' and try again."
    }
    $RepositoryRoot = if (-not [string]::IsNullOrWhiteSpace($Global:EntraOpsBaseFolder)) { $Global:EntraOpsBaseFolder } else { Split-Path -Parent $ModuleRoot }

    if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $RepoRoot = $RepositoryRoot }
    if ([string]::IsNullOrWhiteSpace($AppRoot)) { $AppRoot = Join-Path $RepoRoot 'Reports/PrivilegeHistory' }
    if (-not (Test-Path -LiteralPath $AppRoot -PathType Container)) {
        throw "Privilege History app folder not found: $AppRoot. Import the EntraOps module from a repository checkout that contains Reports/PrivilegeHistory, or run Install-EntraOpsReportingFolder to download the Reports folder."
    }
    if ([string]::IsNullOrWhiteSpace($ImportPath)) { $ImportPath = Join-Path $RepoRoot 'PrivilegedEAM' }
    if ([string]::IsNullOrWhiteSpace($OutFile)) { $OutFile = Join-Path $AppRoot 'data/privilege-history-data.js' }

    # Snapshots from the git history, or (without git) the current export as the only snapshot.
    $UseGit = $HistorySource -ne 'Folder'
    $FolderReason = '-HistorySource Folder'
    if ($UseGit) {
        $GitIssue = $null
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
            $GitIssue = 'git was not found on PATH'
        } else {
            $GitRoot = (git -C $RepoRoot rev-parse --show-toplevel 2>$null)
            if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($GitRoot)) { $GitIssue = "$RepoRoot is not inside a git working copy" }
            else {
                # A Privileged EAM export outside the working copy has no git history either: Auto uses the folder, Git fails.
                $GitRootPath = [System.IO.Path]::GetFullPath($GitRoot.Trim())
                $ImportFullPath = [System.IO.Path]::GetFullPath($ImportPath)
                if (-not ($ImportFullPath.Equals($GitRootPath, [System.StringComparison]::OrdinalIgnoreCase) -or
                        $ImportFullPath.StartsWith($GitRootPath + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase))) {
                    $GitIssue = "ImportPath ($ImportPath) is not inside the git working copy ($GitRootPath)"
                }
            }
        }
        if ($GitIssue) {
            if ($HistorySource -eq 'Git') { throw "$GitIssue. Privilege History reads historic Privileged EAM data from the git history (-HistorySource Git)." }
            $FolderReason = $GitIssue
            $UseGit = $false
        }
    }

    if (-not (Test-Path -LiteralPath $ImportPath)) {
        Write-Warning "Privileged EAM import path not found: $ImportPath. Continuing - older commits may still contain it."
    }
    $ImportPathFull = [System.IO.Path]::GetFullPath($ImportPath)

    if ($UseGit) {
        $GitRoot = $GitRoot.Trim()

        # Git-relative path (forward slashes) of the PrivilegedEAM folder, used as the
        # pathspec for `git log` / `git archive`.
        $GitRootFull = [System.IO.Path]::GetFullPath($GitRoot)
        # Compare with a trailing separator so a sibling folder such as <root>-2 does not pass as
        # being inside <root>.
        if (-not ($ImportPathFull.Equals($GitRootFull, [System.StringComparison]::OrdinalIgnoreCase) -or
                $ImportPathFull.StartsWith($GitRootFull + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase))) {
            throw "ImportPath ($ImportPath) is not inside the git working copy ($GitRootFull)."
        }
        $RelPath = $ImportPathFull.Substring($GitRootFull.Length).TrimStart('\', '/') -replace '\\', '/'
        if ([string]::IsNullOrWhiteSpace($RelPath)) {
            throw "ImportPath resolved to the git working copy root; expected a subfolder such as PrivilegedEAM."
        }

        # ---- Enumerate commits that touched the PrivilegedEAM export -------------------
        # A repository without any commit has no HEAD, and git log fails there.
        $null = & git -C $GitRoot rev-parse --verify --quiet HEAD 2>$null
        $HasHead = $LASTEXITCODE -eq 0
        $commits = @()
        if ($HasHead) {
            $logArgs = @('-C', $GitRoot, 'log', '--format=%H%x1f%cI')
            if ($TimeRangeInDays) {
                $since = (Get-Date).ToUniversalTime().AddDays(-1 * [Math]::Abs($TimeRangeInDays)).ToString('o')
                $logArgs += "--since=$since"
            }
            $logArgs += @('--', $RelPath)

            $logOutput = & git @logArgs
            if ($LASTEXITCODE -ne 0) {
                throw "git log failed with exit code $LASTEXITCODE while enumerating history of $RelPath."
            }

            $commits = @($logOutput | Where-Object { $_ } | ForEach-Object {
                    $parts = $_ -split "`u{1f}"
                    [pscustomobject]@{ Sha = $parts[0]; Date = [datetimeoffset]::Parse($parts[1]) }
                }) | Sort-Object -Property Date
        }
        $global:LASTEXITCODE = 0

        if (-not $commits) {
            $InRange = if ($TimeRangeInDays) { " in the last $TimeRangeInDays day(s)" } else { '' }
            if ($HistorySource -eq 'Git') {
                Write-Warning "No commits touching $RelPath were found$InRange. The dataset only contains the uncommitted Privileged EAM export (if any)."
            } else {
                # Auto: an export without commits has no history, the same as without git.
                $FolderReason = "$RelPath has no commits$InRange"
                $UseGit = $false
            }
        }

        Write-Verbose "Found $($commits.Count) commit(s) touching $RelPath."

        # ---- Thin commits down to the requested snapshot interval ----------------------
        # Applied before any git archive/expand work happens (not just before the output is
        # written), so a coarse interval (the default is bi-weekly) also speeds up generation
        # over long, frequently-committed histories - not only the size of the resulting file.
        # Shared with the Configuration Analyzer: a commit slightly earlier than one interval after the previously kept one
        # still counts, so a job that runs on the interval's cadence keeps every snapshot.
        if ($null -ne $SnapshotIntervalComponents -and $commits.Count -gt 2) {
            $thinned = Select-EntraOpsSnapshotIntervalCommit -Commit @($commits) -Years $SnapshotIntervalComponents.Years -Months $SnapshotIntervalComponents.Months -Days $SnapshotIntervalComponents.Days
            Write-Verbose "Snapshot interval '$SnapshotInterval' reduced $($commits.Count) commit(s) to $($thinned.Count) snapshot(s) (oldest and newest are always kept)."
            $commits = $thinned
        }

        # ---- Append the uncommitted export when it differs from HEAD --------------------
        # Like the Configuration Analyzer: git hash-object computes the blob hash a commit would store, so an
        # export that matches HEAD adds no snapshot and an export that is not committed yet is the newest one.
        $WorkingTreeFiles = @(if ($UseGit -and (Test-Path -LiteralPath $ImportPath -PathType Container)) {
                Get-ChildItem -LiteralPath $ImportPath -Recurse -File -Filter '*.json' | Sort-Object FullName
            })
        if ($WorkingTreeFiles.Count -gt 0) {
            $WorkingTreeHash = @{}
            for ($i = 0; $i -lt $WorkingTreeFiles.Count; $i += 50) {
                $Chunk = @($WorkingTreeFiles | Select-Object -Skip $i -First 50)
                $Hashes = @(& git -C $GitRoot hash-object -- @($Chunk.FullName))
                if ($LASTEXITCODE -ne 0) { throw "git hash-object failed while hashing the Privileged EAM export in $ImportPath." }
                for ($j = 0; $j -lt $Chunk.Count; $j++) {
                    $WorkingTreeHash[($Chunk[$j].FullName.Substring($ImportPathFull.Length).TrimStart('\', '/') -replace '\\', '/')] = $Hashes[$j]
                }
            }
            $HeadHash = @{}
            if ($HasHead) {
                $LsTree = & git -C $GitRoot ls-tree -r -z HEAD -- $RelPath
                if ($LASTEXITCODE -ne 0) { throw "git ls-tree failed while reading the committed Privileged EAM export of $RelPath." }
                foreach ($Entry in ($LsTree -join "`n") -split "`0") {
                    # "<mode> <type> <hash>\t<path>"
                    $TabIndex = $Entry.IndexOf("`t")
                    if ($TabIndex -lt 0) { continue }
                    $Meta = $Entry.Substring(0, $TabIndex).Trim() -split '\s+'
                    $EntryPath = $Entry.Substring($TabIndex + 1)
                    if ($Meta.Count -lt 3 -or $Meta[1] -ne 'blob' -or -not $EntryPath.EndsWith('.json', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
                    $HeadHash[$EntryPath.Substring($RelPath.Length).TrimStart('/')] = $Meta[2]
                }
            }
            $Differs = $HeadHash.Count -ne $WorkingTreeHash.Count -or @($WorkingTreeHash.Keys | Where-Object { $HeadHash[$_] -ne $WorkingTreeHash[$_] }).Count -gt 0
            if ($Differs) {
                $WorkingTreeDate = [datetimeoffset](($WorkingTreeFiles | Measure-Object -Property LastWriteTimeUtc -Maximum).Maximum)
                if ($commits.Count -gt 0 -and $WorkingTreeDate -le @($commits)[-1].Date) { $WorkingTreeDate = [datetimeoffset](Get-Date).ToUniversalTime() }
                $commits = @($commits) + [pscustomobject]@{ Sha = '(working tree)'; Date = $WorkingTreeDate; Path = $ImportPathFull }
                Write-Verbose "Added the uncommitted Privileged EAM export ($($WorkingTreeFiles.Count) file(s)) as the newest snapshot."
            }
        }
    }

    if (-not $UseGit) {
        # The current export as one snapshot, dated by its newest file.
        $ExportFiles = @(Get-ChildItem -LiteralPath $ImportPath -Recurse -File -Filter '*.json' -ErrorAction SilentlyContinue)
        $commits = @(if ($ExportFiles.Count) {
                [pscustomobject]@{ Sha = '(current export)'; Date = [datetimeoffset](($ExportFiles | Measure-Object -Property LastWriteTimeUtc -Maximum).Maximum); Path = $ImportPathFull }
            })
    }

    $snapshots = [System.Collections.Generic.List[object]]::new()
    $allRbacSystems = [System.Collections.Generic.HashSet[string]]::new()

    $processed = 0
    foreach ($commit in $commits) {
        $processed++
        Write-Verbose "[$processed/$($commits.Count)] Processing commit $($commit.Sha) ($($commit.Date))..."

        $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "EntraOpsPrivilegeHistory_$([guid]::NewGuid().ToString('N'))"
        $tmpZip = "$tmpDir.zip"
        try {
            if ($commit.PSObject.Properties['Path']) {
                # Without git: the current export folder.
                $commitImportPath = $commit.Path
            } else {
                New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

                # Let git write the zip itself (--output) instead of redirecting stdout:
                # PowerShell redirection only preserves raw bytes on PS >= 7.5, so on older
                # supported versions (the module floor is 7.4) `> $tmpZip` corrupts the archive.
                & git -C $GitRoot archive --format=zip --output=$tmpZip $commit.Sha -- $RelPath 2>$null
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $tmpZip) -or (Get-Item -LiteralPath $tmpZip).Length -eq 0) {
                    Write-Verbose "  Skipped: $RelPath did not exist at commit $($commit.Sha)."
                    continue
                }

                Expand-Archive -LiteralPath $tmpZip -DestinationPath $tmpDir -Force
                $commitImportPath = Join-Path $tmpDir $RelPath
            }
            if (-not (Test-Path -LiteralPath $commitImportPath -PathType Container)) {
                Write-Verbose "  Skipped: no PrivilegedEAM data at commit $($commit.Sha)."
                continue
            }

            $objects = Get-EntraOpsPrivilegedEamDashboardObjects -ImportPath $commitImportPath -TenantId $TenantId
            if (@($objects).Count -eq 0) {
                Write-Verbose "  Skipped: no privileged objects at commit $($commit.Sha)."
                continue
            }

            $rbacSystems = @(@($objects | ForEach-Object { $_.roleSystem }) | Where-Object { $_ } | Select-Object -Unique | Sort-Object)
            $rbacSystems | ForEach-Object { [void]$allRbacSystems.Add($_) }

            # ---- Aggregates -----------------------------------------------------------
            $totalAssignments = 0
            $tierBreaches = 0
            $usersByTier = @{}
            $assetsByTier = @{}
            $assignmentsByTier = @{}
            $seenAssignmentIds = @{}
            $seenAssetIds = @{}
            $totalUsers = 0
            $totalGroups = 0
            $totalServicePrincipals = 0

            foreach ($obj in $objects) {
                $objTier = $obj.objectAdminTierLevelName
                if (-not $objTier) { $objTier = 'Unclassified' }
                $objRank = ConvertTo-TierRank -TierName $objTier
                # Tier breaches of the chart compare an unclassified object as User Access (like EO.1001 to EO.1003) and
                # count every role assignment, also delegated permissions and Microsoft first-party apps (EO.8002 leaves them out):
                # its tier is unknown, so only a role above User Access is a breach.
                $breachRank = if ($objTier -eq 'Unclassified') { ConvertTo-TierRank -TierName 'UserAccess' } else { $objRank }

                # An object can appear once per RBAC system it holds roles in (same shape
                # as the live EAM Dashboard export), so only count each objectId once for
                # the per-tier asset/user/group/service-principal breakdowns.
                if (-not $seenAssetIds.ContainsKey($obj.objectId)) {
                    $seenAssetIds[$obj.objectId] = $true
                    switch ($obj.objectType) {
                        'user' { $totalUsers++; $usersByTier[$objTier] = [int]$usersByTier[$objTier] + 1 }
                        'group' { $totalGroups++ }
                        'serviceprincipal' { $totalServicePrincipals++ }
                    }
                    # "Privileged assets by tier" counts every non-group object once, mirroring
                    # the "Classification of privileged identities" tiles in the live dashboard.
                    if ($obj.objectType -ne 'group') {
                        $assetsByTier[$objTier] = [int]$assetsByTier[$objTier] + 1
                    }
                }

                foreach ($ra in @($obj.roleAssignments)) {
                    $assignmentKey = if ($ra.roleAssignmentInstanceId) { "$($ra.roleAssignmentInstanceId)" } else { "$($ra.roleAssignmentId)" }
                    if (-not $assignmentKey -or -not $seenAssignmentIds.ContainsKey($assignmentKey)) {
                        if ($assignmentKey) { $seenAssignmentIds[$assignmentKey] = $true }
                        $totalAssignments++
                    }

                    $raTiers = @(@($ra.classification) | ForEach-Object { $_.adminTierLevelName } | Where-Object { $_ } | Select-Object -Unique)
                    if ($raTiers.Count -eq 0) { $raTiers = @('Unclassified') }
                    foreach ($t in $raTiers) {
                        $assignmentsByTier[$t] = [int]$assignmentsByTier[$t] + 1
                        # Tier breach: the object's own (less privileged / higher-rank) tier
                        # can reach a role classified into a MORE privileged (lower-rank) tier.
                        if ((ConvertTo-TierRank -TierName $t) -lt $breachRank) { $tierBreaches++ }
                    }
                }
            }

            $objectTierSeries = @($TierOrder | ForEach-Object {
                    [ordered]@{
                        tier   = $_
                        assets = [int]$assetsByTier[$_]
                        users  = [int]$usersByTier[$_]
                    }
                })
            $accessTierSeries = @($TierOrder | ForEach-Object {
                    [ordered]@{
                        tier            = $_
                        roleAssignments = [int]$assignmentsByTier[$_]
                    }
                })

            # Lightweight per-object detail (enough to filter/drill-down and diff two
            # snapshots) - not the full live-dashboard schema, to keep repository size
            # bounded across potentially many historic commits.
            $snapshotObjects = @($objects | ForEach-Object {
                    $snapshotObject = $_
                    [ordered]@{
                        objectId                 = $_.objectId
                        objectType               = $_.objectType
                        objectDisplayName        = $_.objectDisplayName
                        objectAdminTierLevelName = $_.objectAdminTierLevelName
                        roleSystem               = $_.roleSystem
                        # Service principal of a Microsoft first-party application, and a Microsoft client whose delegated
                        # permissions the tenant grants by consent (Graph CLI): the drift rules EO.8002 and EO.8003 tell them apart.
                        isMicrosoftFirstParty    = $_.objectType -eq 'serviceprincipal' -and (Test-EntraOpsMicrosoftFirstParty -AppOwnerOrganizationId "$($_.originTenantId)" -AppId "$($_.objectUserPrincipalName)")
                        isMicrosoftConsentClient = $_.objectType -eq 'serviceprincipal' -and (Test-EntraOpsMicrosoftConsentClient -AppId "$($_.objectUserPrincipalName)")
                        roleAssignments          = @(@($_.roleAssignments) | ForEach-Object {
                                [ordered]@{
                                    roleAssignmentInstanceId = $_.roleAssignmentInstanceId
                                    roleAssignmentId   = $_.roleAssignmentId
                                    roleDefinitionName = $_.roleDefinitionName
                                    # Dashboard role assignments carry no roleSystem of their own - it belongs to the parent object.
                                    roleSystem         = $snapshotObject.roleSystem
                                    roleAssignmentType = $_.roleAssignmentType
                                    pimAssignmentType  = $_.pimAssignmentType
                                    # Delegated (an application acting for the signed-in user), Application, BuiltInRole, ...
                                    roleType           = "$($_.roleType)"
                                    # The resource application of a delegated permission (for example Microsoft Graph).
                                    resourceName       = $(if ("$($_.roleType)" -eq 'Delegated') { "$($_.roleAssignmentScopeName)" } else { $null })
                                    classification     = @(@($_.classification) | ForEach-Object {
                                            [ordered]@{ adminTierLevelName = $_.adminTierLevelName; service = $_.service }
                                        })
                                }
                            })
                    }
                })

            $snapshots.Add([ordered]@{
                    commitSha   = $commit.Sha
                    commitDate  = $commit.Date.ToString('o')
                    rbacSystems = $rbacSystems
                    totals      = [ordered]@{
                        assets            = @($objects | Where-Object { $_.objectType -ne 'group' } | ForEach-Object { $_.objectId } | Select-Object -Unique).Count
                        users             = $totalUsers
                        groups            = $totalGroups
                        servicePrincipals = $totalServicePrincipals
                        roleAssignments   = $totalAssignments
                        tierBreaches      = $tierBreaches
                    }
                    objectTier  = $objectTierSeries
                    accessTier  = $accessTierSeries
                    hasDetail   = $true
                    objects     = $snapshotObjects
                })
            # Not a commit: the export of the working folder (uncommitted, or without git history).
            if ($commit.PSObject.Properties['Path']) { $snapshots[$snapshots.Count - 1]['workingTree'] = $true }
        } finally {
            if (Test-Path -LiteralPath $tmpZip) { Remove-Item -LiteralPath $tmpZip -Force -ErrorAction SilentlyContinue }
            if (Test-Path -LiteralPath $tmpDir) { Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    # The per-snapshot "objects" list (used for snapshot detail & compare) is the only
    # part of the payload that scales with the number of role assignments; the trend
    # aggregates (objectTier/accessTier/totals) are cheap and always kept for every
    # snapshot. To keep the generated file loadable in a browser regardless of how far
    # back the git history goes, only up to -MaxDetailedSnapshots (evenly spread across
    # the full range, always including the oldest and newest) keep their "objects";
    # older/thinned-out snapshots keep their trend numbers but drop object-level detail.
    if ($snapshots.Count -gt $MaxDetailedSnapshots -and $MaxDetailedSnapshots -gt 0) {
        $keepIdx = [System.Collections.Generic.HashSet[int]]::new()
        for ($i = 0; $i -lt $MaxDetailedSnapshots; $i++) {
            $pos = if ($MaxDetailedSnapshots -eq 1) { 0 } else { [Math]::Round($i * ($snapshots.Count - 1) / ($MaxDetailedSnapshots - 1)) }
            [void]$keepIdx.Add([int]$pos)
        }
        for ($i = 0; $i -lt $snapshots.Count; $i++) {
            if (-not $keepIdx.Contains($i)) {
                $snapshots[$i]['hasDetail'] = $false
                $snapshots[$i]['objects'] = @()
            }
        }
        Write-Verbose "Kept full snapshot detail for $($keepIdx.Count) of $($snapshots.Count) snapshot(s) (-MaxDetailedSnapshots $MaxDetailedSnapshots); the rest keep trend numbers only."
    }

    $payload = [ordered]@{
        tenantName       = Get-EntraOpsReportingTenantName -RepoRoot $RepoRoot
        generatedAt      = (Get-Date).ToUniversalTime().ToString('o')
        tierOrder        = $TierOrder
        rbacSystems      = @($allRbacSystems | Sort-Object)
        timeRangeInDays  = $TimeRangeInDays
        snapshotInterval = $SnapshotInterval
        historySource    = $(if ($UseGit) { 'git' } else { 'folder' })
        snapshots        = @($snapshots)
    }

    $json = $payload | ConvertTo-Json -Depth 14 -Compress
    $content = "// Auto-generated by New-EntraOpsPrivilegedEamPrivilegeHistoryData - do not edit by hand.`n" +
    "window.ENTRAOPS_PRIVILEGEHISTORY_DATA = $json;`n"

    if ($PSCmdlet.ShouldProcess($OutFile, 'Write Privilege History dataset')) {
        Save-EntraOpsReportDataFile -Content $content -LiteralPath $OutFile

        Write-Host "Commits processed:  $($commits.Count)"
        Write-Host "Snapshots written:  $($snapshots.Count)"
        if (-not $UseGit) {
            # Informational, not a warning: a working folder without git history is a supported setup (-HistorySource Auto).
            Write-Host "History source:     current export only, no trend ($FolderReason)"
        }
        Write-Host "Wrote $OutFile"
    }

    if ($PassThru) { $payload }
}
