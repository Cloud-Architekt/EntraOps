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
    holds).

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

    Requires the repository to be a git working copy (git history is the only source of
    historic data - there is no separate time-series store).

.PARAMETER RepoRoot
    Path to the EntraOps repository root (and git working copy) that contains the
    PrivilegedEAM export folder. Defaults to the repository this module lives in.

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

    function Add-SnapshotInterval {
        param([datetimeoffset]$Date, [System.Collections.Specialized.OrderedDictionary]$Interval)
        $result = $Date
        if ($Interval.Years -gt 0) { $result = $result.AddYears($Interval.Years) }
        if ($Interval.Months -gt 0) { $result = $result.AddMonths($Interval.Months) }
        if ($Interval.Days -gt 0) { $result = $result.AddDays($Interval.Days) }
        return $result
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
    if ([string]::IsNullOrWhiteSpace($AppRoot)) { $AppRoot = Join-Path $RepositoryRoot 'Reports/PrivilegeHistory' }
    if (-not (Test-Path -LiteralPath $AppRoot -PathType Container)) {
        throw "Privilege History app folder not found: $AppRoot. Import the EntraOps module from a repository checkout that contains Reports/PrivilegeHistory, or run Install-EntraOpsReportingFolder to download the Reports folder."
    }
    if ([string]::IsNullOrWhiteSpace($ImportPath)) { $ImportPath = Join-Path $RepoRoot 'PrivilegedEAM' }
    if ([string]::IsNullOrWhiteSpace($OutFile)) { $OutFile = Join-Path $AppRoot 'data/privilege-history-data.js' }

    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw "git was not found on PATH. Privilege History reads historic Privileged EAM data from the git history, so git is required."
    }

    $GitRoot = (git -C $RepoRoot rev-parse --show-toplevel 2>$null)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($GitRoot)) {
        throw "$RepoRoot is not inside a git working copy. Privilege History requires the PrivilegedEAM export to be tracked in git history."
    }
    $GitRoot = $GitRoot.Trim()

    if (-not (Test-Path -LiteralPath $ImportPath)) {
        Write-Warning "Privileged EAM import path not found: $ImportPath. Continuing - older commits may still contain it."
    }

    # Git-relative path (forward slashes) of the PrivilegedEAM folder, used as the
    # pathspec for `git log` / `git archive`.
    $ImportPathFull = [System.IO.Path]::GetFullPath($ImportPath)
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

    if (-not $commits) {
        Write-Warning "No commits touching $RelPath were found$(if ($TimeRangeInDays) { " in the last $TimeRangeInDays day(s)" }). Generating an empty Privilege History dataset."
    }

    Write-Verbose "Found $($commits.Count) commit(s) touching $RelPath."

    # ---- Thin commits down to the requested snapshot interval ----------------------
    # Applied before any git archive/expand work happens (not just before the output is
    # written), so a coarse interval (the default is bi-weekly) also speeds up generation
    # over long, frequently-committed histories - not only the size of the resulting file.
    if ($null -ne $SnapshotIntervalComponents -and $commits.Count -gt 2) {
        $thinned = [System.Collections.Generic.List[object]]::new()
        $lastKeptDate = $null
        for ($ci = 0; $ci -lt $commits.Count; $ci++) {
            $commit = $commits[$ci]
            $isLast = ($ci -eq $commits.Count - 1)
            if ($null -eq $lastKeptDate -or $isLast -or $commit.Date -ge (Add-SnapshotInterval -Date $lastKeptDate -Interval $SnapshotIntervalComponents)) {
                $thinned.Add($commit)
                $lastKeptDate = $commit.Date
            }
        }
        Write-Verbose "Snapshot interval '$SnapshotInterval' reduced $($commits.Count) commit(s) to $($thinned.Count) snapshot(s) (oldest and newest are always kept)."
        $commits = $thinned
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
                        if ((ConvertTo-TierRank -TierName $t) -lt $objRank) { $tierBreaches++ }
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
                    [ordered]@{
                        objectId                 = $_.objectId
                        objectType               = $_.objectType
                        objectDisplayName        = $_.objectDisplayName
                        objectAdminTierLevelName = $_.objectAdminTierLevelName
                        roleSystem               = $_.roleSystem
                        roleAssignments          = @(@($_.roleAssignments) | ForEach-Object {
                                [ordered]@{
                                    roleAssignmentInstanceId = $_.roleAssignmentInstanceId
                                    roleAssignmentId   = $_.roleAssignmentId
                                    roleDefinitionName = $_.roleDefinitionName
                                    roleSystem         = $_.roleSystem
                                    roleAssignmentType = $_.roleAssignmentType
                                    pimAssignmentType  = $_.pimAssignmentType
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
        snapshots        = @($snapshots)
    }

    $json = $payload | ConvertTo-Json -Depth 14 -Compress
    $content = "// Auto-generated by New-EntraOpsPrivilegedEamPrivilegeHistoryData - do not edit by hand.`n" +
    "window.ENTRAOPS_PRIVILEGEHISTORY_DATA = $json;`n"

    if ($PSCmdlet.ShouldProcess($OutFile, 'Write Privilege History dataset')) {
        Save-EntraOpsReportDataFile -Content $content -LiteralPath $OutFile

        Write-Host "Commits processed:  $($commits.Count)"
        Write-Host "Snapshots written:  $($snapshots.Count)"
        Write-Host "Wrote $OutFile"
    }

    if ($PassThru) { $payload }
}
