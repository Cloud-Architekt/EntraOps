<#
.SYNOPSIS
    Create an EntraOps Tenant Governance snapshot and persist each captured resource as an
    individual JSON file tracked in Git.

.DESCRIPTION
    Wraps Get-EntraOpsTenantGovernanceSnapshot to capture the configured Microsoft Entra resources
    and stores each captured resource as its own file under <EntraOpsBaseFolder>/TenantGovernance/Snapshots,
    organized in subfolders:
      <ExportFolder>/<resourceType>/<first segment of displayName>/<remaining displayName>.json
    For example, a resource with resourceType "microsoft.entra.conditionalaccesspolicy" and
    displayName "AADConditionalAccessPolicy-Workplace 3 - Allow non-compliant Browser with MFA and
    Session Controls" is stored at:
      <ExportFolder>/microsoft.entra.conditionalaccesspolicy/AADConditionalAccessPolicy/Workplace 3 - Allow non-compliant Browser with MFA and Session Controls.json
    The displayName is split on its first "-" only: everything before it becomes the subfolder,
    everything after it (which may itself contain further "-" characters) becomes the file name.
    Every path segment is normalized (see ConvertTo-EntraOpsSafeFilePathSegment) so the resulting
    files can be created, committed, and checked out on Windows, Linux, and macOS alike, regardless
    of the platform the snapshot was collected on.
    Resource-type folders are staged and replaced as a unit, so resources removed from the tenant do
    not remain as stale files. Historical point-in-time versions aren't kept as separate files but
    are tracked through the repository's Git commit history instead, the same approach used for
    PrivilegedEAM data and Privilege History (see Reports/PrivilegeHistory/README.md).

    Snapshot metadata (SnapshotId, DisplayName, CapturedDateTime, ResourcesToInclude, ResourceCount,
    resource-type counts, and completion status) is persisted in <ExportFolder>/.SnapshotManifest.json
    and also shown as a summary in the command output. The latest attempt is recorded separately in
    <ExportFolder>/.LastAttemptManifest.json. When Graph reports a partiallySuccessful job, resource
    types without Graph errors are published from staging. A type whose only errors are per-resource
    export failures (for example Request_ResourceNotFound for one access package policy) still
    returns every resource that did export: those are published, and the previously published file
    of each resource the attempt did not return is retained so a failed export never shows up as a
    deleted resource in Git history. Such types are marked PublishedWithErrors with their
    RetainedResourceCount. Types whose backing workload could not be reached (ConnectionError) or that
    returned no resource at all retain their prior files and are marked PreservedStale with their
    published and attempted snapshot Ids. If Graph provides no parseable per-type errors, no
    downloaded types are published; all existing files are preserved as stale and the operation
    completes with a warning instead of failing the workflow.

    Before creating the snapshot, prerequisites (the "ConfigurationMonitoring.Read.All" permission
    and the Microsoft Tenant Configuration Management service principal) are validated
    automatically. If they are not met, run Register-EntraOpsTenantGovernanceServicePrincipal and/or
    New-EntraOpsWorkloadIdentity first (see Test-EntraOpsTenantGovernancePrerequisite to troubleshoot).

    Large snapshots can take a while to complete on the Microsoft Graph side. Use -Operation Start
    to create a job and persist its Id, then -Operation Collect in a later run to check it once and
    download completed results. Use -Operation RunAndWait for an interactive create-and-wait execution.

.PARAMETER ExportFolder
    Folder where the per-resource snapshot files are stored. Default is <EntraOpsBaseFolder>/TenantGovernance/Snapshots.

.PARAMETER ResourcesToInclude
    Array of Microsoft Entra resource types to include in the snapshot. Defaults to
    TenantGovernanceSnapshot.ResourcesToInclude of the loaded EntraOpsConfig, otherwise to the recommended
    tenant governance resource set.

.PARAMETER SnapshotDisplayNamePrefix
    Prefix used for the snapshot's display name on the Microsoft Graph side (visible in the admin
    center / when listing snapshot jobs via Graph). Defaults to TenantGovernanceSnapshot.SnapshotDisplayNamePrefix
    of the loaded EntraOpsConfig, otherwise "EntraOps TG". The Microsoft Graph
    UTCM API only allows alphabets, numbers, and spaces in the resulting display name (any other
    characters, e.g. hyphens, are stripped automatically) and enforces a length between 8 and 32
    characters (longer names are truncated automatically). Purely cosmetic - it has no effect on
    the local file name or on how the snapshot is retrieved.

.PARAMETER TimeoutInSeconds
    Maximum time (in seconds) to wait for the snapshot job to complete. Default is 900 (15 minutes).
    If the wait expires, the still-running job Id is persisted as a pending job so it can be
    retrieved later with -Operation Collect.

.PARAMETER Operation
    Explicit snapshot operation:
    - Start: create a new job, persist its Id, and return without checking or downloading it.
    - Collect: check the persisted job once; download it only when complete. Never creates a job.
    - RunAndWait: create a new job and poll until complete. Intended for manual use.
    Start and RunAndWait refuse to proceed while a pending job exists. Collect is a successful no-op when
    no job is pending, which makes scheduled collection retries safe after an earlier retry succeeds.

.PARAMETER SkipWaitForCompletion
    Deprecated compatibility alias for -Operation Start. Do not combine it with -Operation.

.PARAMETER SkipPrerequisiteCheck
    Skip the automatic prerequisite validation (Test-EntraOpsTenantGovernancePrerequisite) before
    creating the snapshot job. Default is $false.

.PARAMETER SnapshotResourceFileNaming
    Controls the file name used for each persisted resource file (the folder structure - resourceType
    then the first displayName segment - is unaffected). Defaults to
    TenantGovernanceSnapshot.SnapshotResourceFileNaming of the loaded EntraOpsConfig, otherwise
    "DisplayName". Possible values:
    - "DisplayName" (default without configuration): the file is named after the remainder of the resource's displayName
      (everything after its first "-"), e.g. "Legacy 1 - Block legacy auth.json". Human-readable, but
      the file is effectively renamed/re-created if the resource's displayName changes.
    - "ResourceId": the file is named after the resource's underlying Id (typically a GUID), e.g.
      "e9f699a0-fb3f-48da-84c6-6351163b2109.json". Stable across renames, so Git history tracks
      changes to the same resource as diffs to the same file instead of a rename. Falls back to
      DisplayName-based naming for resource types that don't expose an Id.

.EXAMPLE
    Save-EntraOpsTenantGovernanceSnapshotJson

.EXAMPLE
    Save a snapshot of Conditional Access and Named Locations only.
    Save-EntraOpsTenantGovernanceSnapshotJson -ResourcesToInclude @("microsoft.entra.conditionalAccessPolicy","microsoft.entra.namedLocationPolicy")

.EXAMPLE
    Start a snapshot job without waiting (e.g. a scheduled run at 06:00), then check and save it in a
    later, separate run (e.g. scheduled collector runs at 07:00, 07:30, and 08:00).
    Save-EntraOpsTenantGovernanceSnapshotJson -Operation Start
    # ... in a separate, later run ...
    Save-EntraOpsTenantGovernanceSnapshotJson -Operation Collect

.EXAMPLE
    Create a snapshot and wait for it during a manual run.
    Save-EntraOpsTenantGovernanceSnapshotJson -Operation RunAndWait -TimeoutInSeconds 3300
#>
function Save-EntraOpsTenantGovernanceSnapshotJson {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$ExportFolder = "$EntraOpsBaseFolder/TenantGovernance/Snapshots"
        ,
        [Parameter(Mandatory = $false)]
        [Array]$ResourcesToInclude = (Get-EntraOpsTenantGovernanceResourceDefinition).DefaultResources
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$SnapshotDisplayNamePrefix = "EntraOps TG"
        ,
        [Parameter(Mandatory = $false)]
        [System.Int32]$TimeoutInSeconds = 900
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Start', 'Collect', 'RunAndWait')]
        [System.String]$Operation = 'RunAndWait'
        ,
        [Parameter(Mandatory = $false)]
        [switch]$SkipWaitForCompletion
        ,
        [Parameter(Mandatory = $false)]
        [switch]$SkipPrerequisiteCheck
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet('DisplayName', 'ResourceId')]
        [System.String]$SnapshotResourceFileNaming = 'DisplayName'
    )

    $ErrorActionPreference = "Stop"

    # Settings not passed as parameters fall back to the configuration loaded by Connect-EntraOps -ConfigFilePath
    $TenantGovernanceConfig = if ($null -ne $Global:EntraOpsConfig) { $Global:EntraOpsConfig.TenantGovernanceSnapshot }
    if ($null -ne $TenantGovernanceConfig) {
        if (-not $PSBoundParameters.ContainsKey('ResourcesToInclude') -and @($TenantGovernanceConfig.ResourcesToInclude | Where-Object { $_ }).Count -gt 0) {
            $ResourcesToInclude = @($TenantGovernanceConfig.ResourcesToInclude | Where-Object { $_ })
            Write-Verbose "Using ResourcesToInclude from EntraOpsConfig ($($ResourcesToInclude.Count) resource types)"
        }
        if (-not $PSBoundParameters.ContainsKey('SnapshotDisplayNamePrefix') -and -not [string]::IsNullOrWhiteSpace([string]$TenantGovernanceConfig.SnapshotDisplayNamePrefix)) {
            $SnapshotDisplayNamePrefix = [string]$TenantGovernanceConfig.SnapshotDisplayNamePrefix
            Write-Verbose "Using SnapshotDisplayNamePrefix '$SnapshotDisplayNamePrefix' from EntraOpsConfig"
        }
        if (-not $PSBoundParameters.ContainsKey('SnapshotResourceFileNaming') -and -not [string]::IsNullOrWhiteSpace([string]$TenantGovernanceConfig.SnapshotResourceFileNaming)) {
            if ([string]$TenantGovernanceConfig.SnapshotResourceFileNaming -notin @('DisplayName', 'ResourceId')) {
                throw "Invalid TenantGovernanceSnapshot.SnapshotResourceFileNaming '$($TenantGovernanceConfig.SnapshotResourceFileNaming)' in EntraOpsConfig. Use 'DisplayName' or 'ResourceId'."
            }
            $SnapshotResourceFileNaming = [string]$TenantGovernanceConfig.SnapshotResourceFileNaming
            Write-Verbose "Using SnapshotResourceFileNaming '$SnapshotResourceFileNaming' from EntraOpsConfig"
        }
    }
    # --- Path safety: ensure ExportFolder is under the expected base directory ---
    $ResolvedExportFolder = [System.IO.Path]::GetFullPath($ExportFolder)
    $ResolvedBaseFolder = [System.IO.Path]::GetFullPath($EntraOpsBaseFolder)
    if (-not (Test-EntraOpsPathWithinRoot -Path $ExportFolder -Root $EntraOpsBaseFolder)) {
        throw "Security check failed: ExportFolder '$ResolvedExportFolder' is not under the expected base directory '$ResolvedBaseFolder'. Aborting to prevent accidental data loss."
    }

    if (-not (Test-Path -Path $ExportFolder)) {
        New-Item -Path $ExportFolder -ItemType Directory -Force | Out-Null
    }

    $PendingJobFilePath = Join-Path -Path $ExportFolder -ChildPath ".PendingSnapshotJob.json"
    $SnapshotManifestFilePath = Join-Path -Path $ExportFolder -ChildPath ".SnapshotManifest.json"
    $LastAttemptManifestFilePath = Join-Path -Path $ExportFolder -ChildPath ".LastAttemptManifest.json"

    if ($SkipWaitForCompletion) {
        if ($PSBoundParameters.ContainsKey('Operation')) {
            throw "SkipWaitForCompletion is a deprecated alias for -Operation Start and cannot be combined with -Operation."
        }
        Write-Warning "SkipWaitForCompletion is deprecated. Use -Operation Start instead."
        $Operation = 'Start'
    }

    #region Read pending job state
    $PendingJob = $null
    if (Test-Path -Path $PendingJobFilePath -ErrorAction SilentlyContinue) {
        try {
            $PendingJob = Get-Content -Path $PendingJobFilePath -Raw | ConvertFrom-Json
        } catch {
            throw "Failed to read pending snapshot job state file $PendingJobFilePath. Refusing to create or collect a snapshot until the state is repaired. Error: $_"
        }
    }
    #endregion

    #region Execute the requested state-machine operation
    $HasPendingJob = $PendingJob -and -not [string]::IsNullOrWhiteSpace($PendingJob.SnapshotJobId)
    if ($Operation -eq 'Collect') {
        if (-not $HasPendingJob) {
            Write-Output "No pending Tenant Governance snapshot job exists. Nothing to collect."
            return [PSCustomObject]@{ Operation = 'Collect'; Status = 'NoPendingJob' }
        }

        Write-Output "Checking pending snapshot job $($PendingJob.SnapshotJobId) started at $($PendingJob.CreatedDateTime)..."
        $Snapshot = Get-EntraOpsTenantGovernanceSnapshot -SnapshotJobId $PendingJob.SnapshotJobId -ResourcesToInclude @($PendingJob.ResourcesToInclude) -SkipWaitForCompletion -SkipPrerequisiteCheck:$SkipPrerequisiteCheck
    } else {
        if ($HasPendingJob) {
            throw "Pending snapshot job $($PendingJob.SnapshotJobId) already exists. Run -Operation Collect before starting another job."
        }

        $Timestamp = (Get-Date).ToUniversalTime()
        $SnapshotDisplayName = "$($SnapshotDisplayNamePrefix) $($Timestamp.ToString('yyyyMMddHHmmss'))"
        $SnapshotDisplayName = ($SnapshotDisplayName -replace '[^a-zA-Z0-9 ]', ' ') -replace '\s+', ' '
        $SnapshotDisplayName = $SnapshotDisplayName.Trim()
        if ($SnapshotDisplayName.Length -gt 32) {
            $SnapshotDisplayName = $SnapshotDisplayName.Substring(0, 32).TrimEnd()
        }
        if ($SnapshotDisplayName.Length -lt 8) {
            $SnapshotDisplayName = $SnapshotDisplayName.PadRight(8, '0')
        }

        $Snapshot = Get-EntraOpsTenantGovernanceSnapshot -ResourcesToInclude $ResourcesToInclude -SnapshotDisplayName $SnapshotDisplayName -TimeoutInSeconds $TimeoutInSeconds -SkipWaitForCompletion:($Operation -eq 'Start') -SkipPrerequisiteCheck:$SkipPrerequisiteCheck
    }
    #endregion

    #region If the snapshot job is still pending, persist its state and return without touching the main snapshot file
    if ($Snapshot.Status -ne "Completed") {
        $PendingJobOutputObject = [ordered]@{
            SnapshotJobId       = $Snapshot.SnapshotId
            SnapshotDisplayName = $Snapshot.DisplayName
            CreatedDateTime     = if ($HasPendingJob) { $PendingJob.CreatedDateTime } else { $Snapshot.CreatedDateTime }
            ResourcesToInclude  = @($Snapshot.ResourcesToInclude)
            LastCheckedDateTime = (Get-Date).ToUniversalTime().ToString('o')
            LastKnownStatus     = $Snapshot.Status
            LastPollingError    = $Snapshot.PollingError
        }
        $PendingJobOutputObject | ConvertTo-Json -Depth 10 | Out-File -Path $PendingJobFilePath -Encoding utf8
        Write-Output "Snapshot job $($Snapshot.SnapshotId) is $($Snapshot.Status). State saved to $PendingJobFilePath. Collect it later with Save-EntraOpsTenantGovernanceSnapshotJson -Operation Collect."
        return $PendingJobOutputObject
    }

    #endregion

    $SnapshotJobStatus = if ([string]::IsNullOrWhiteSpace($Snapshot.SnapshotJobStatus)) { 'completed' } else { $Snapshot.SnapshotJobStatus }

    $ParsedErrorDetails = @(@($Snapshot.ErrorDetails) | Where-Object { $_ } | ConvertFrom-EntraOpsTenantGovernanceSnapshotErrorDetail)
    $SnapshotDiagnostics = @(
        $ParsedErrorDetails |
        Group-Object ResourceType, ErrorCategory, ErrorCode, NormalizedMessage |
        ForEach-Object {
            $First = $_.Group[0]
            [PSCustomObject][ordered]@{
                ResourceType    = if ($First.ResourceType) { $First.ResourceType.ToLowerInvariant() } else { $null }
                ErrorCategory   = $First.ErrorCategory
                ErrorCode       = $First.ErrorCode
                Occurrences     = $_.Count
                Message         = $First.NormalizedMessage
                RemediationHint = switch ($First.ErrorCategory) {
                    'ConnectionError' { 'Retry the snapshot and verify the backing workload/API is available.' }
                    'ExportError' { 'Review the resource-type permission, referenced object and UTCM support, then retry.' }
                    default { 'Inspect the protected workflow diagnostics or query the snapshot job with Get-EntraOpsTenantGovernanceSnapshotReport.' }
                }
            }
        }
    )
    [string[]]$ResourceTypesWithErrors = @(
        $ParsedErrorDetails |
        ForEach-Object { $_.ResourceType } |
        Where-Object { $_ } |
        ForEach-Object { $_.ToLowerInvariant() } |
        Select-Object -Unique
    )
    # Graph does not guarantee errorDetails order. Keep the manifest's StaleResourceTypes stable
    # when the same resource types fail in a different order on a later run.
    [Array]::Sort($ResourceTypesWithErrors, [StringComparer]::Ordinal)
    $RequestedResourceTypes = @(
        @($Snapshot.ResourcesToInclude) |
        Where-Object { $_ } |
        ForEach-Object { $_.ToLowerInvariant() } |
        Select-Object -Unique
    )
    $UnorderedAttemptResourceTypeCounts = @{}
    foreach ($Resource in @($Snapshot.Resources)) {
        $ResourceType = if ($Resource.resourceType) { $Resource.resourceType.ToLowerInvariant() } else { 'unknown' }
        if (-not $UnorderedAttemptResourceTypeCounts.ContainsKey($ResourceType)) { $UnorderedAttemptResourceTypeCounts[$ResourceType] = 0 }
        $UnorderedAttemptResourceTypeCounts[$ResourceType]++
    }
    # UTCM reports per-resource export failures at the type level while still returning every
    # resource of that type that did export. Only a type whose errors are all ExportError and that
    # returned at least one resource qualifies; a ConnectionError means the whole workload was
    # unreachable and the returned set cannot be trusted.
    [string[]]$ResourceTypesWithRetainedResources = @(
        foreach ($ResourceType in $ResourceTypesWithErrors) {
            $Categories = @($ParsedErrorDetails | Where-Object { $_.ResourceType -and $_.ResourceType.ToLowerInvariant() -eq $ResourceType } | ForEach-Object { $_.ErrorCategory } | Select-Object -Unique)
            if ($Categories.Count -gt 0 -and @($Categories | Where-Object { $_ -ne 'ExportError' }).Count -eq 0 -and [int]$UnorderedAttemptResourceTypeCounts[$ResourceType] -gt 0) {
                $ResourceType
            }
        }
    )
    [string[]]$StaleResourceTypes = @($ResourceTypesWithErrors | Where-Object { $ResourceTypesWithRetainedResources -notcontains $_ })
    if ($SnapshotJobStatus -eq 'partiallySuccessful' -and $ResourceTypesWithErrors.Count -eq 0) {
        $PreviousManifest = $null
        if (Test-Path -Path $SnapshotManifestFilePath -ErrorAction SilentlyContinue) {
            try {
                $PreviousManifest = Get-Content -Path $SnapshotManifestFilePath -Raw | ConvertFrom-Json -Depth 10
            } catch {
                Write-Warning "The previous snapshot manifest could not be read. Existing resource files remain preserved, but their source snapshot cannot be identified. Error: $_"
            }
        }
        $PreviousResourceTypeStates = @{}
        foreach ($PreviousState in @($PreviousManifest.ResourceTypeStates)) {
            if ($PreviousState.ResourceType) { $PreviousResourceTypeStates[$PreviousState.ResourceType.ToLowerInvariant()] = $PreviousState }
        }
        $PreviousCompleteSnapshotId = if ($PreviousManifest.IsComplete -eq $true) { $PreviousManifest.SnapshotId } else { $null }
        $PublishedResourceTypeCounts = [ordered]@{}
        foreach ($ResourceType in $RequestedResourceTypes) {
            $PublishedResourceFolder = Join-Path -Path $ExportFolder -ChildPath $ResourceType
            $PublishedResourceTypeCounts[$ResourceType] = if (Test-Path -Path $PublishedResourceFolder -PathType Container) {
                @(Get-ChildItem -Path $PublishedResourceFolder -Filter '*.json' -File -Recurse -ErrorAction SilentlyContinue).Count
            } else { 0 }
        }
        $AmbiguousResourceTypeStates = @(
            foreach ($ResourceType in $RequestedResourceTypes) {
                $PreviousState = $PreviousResourceTypeStates[$ResourceType]
                $PublishedSnapshotId = if ($PreviousState.PublishedSnapshotId) { $PreviousState.PublishedSnapshotId } else { $PreviousCompleteSnapshotId }
                [PSCustomObject][ordered]@{
                    ResourceType           = $ResourceType
                    Status                 = 'PreservedStale'
                    CapturedResourceCount  = 0
                    AttemptResourceCount   = 0
                    PublishedResourceCount = $PublishedResourceTypeCounts[$ResourceType]
                    PublishedSnapshotId    = $PublishedSnapshotId
                    PublishedSource        = if ($PublishedSnapshotId) { 'Snapshot' } else { 'UnknownLegacySnapshot' }
                    AttemptSnapshotId      = $Snapshot.SnapshotId
                }
            }
        )
        $AmbiguousPartialManifest = [ordered]@{
            SnapshotId                  = $Snapshot.SnapshotId
            SnapshotDisplayName         = $Snapshot.DisplayName
            SnapshotJobStatus           = $SnapshotJobStatus
            CapturedDateTime            = $Snapshot.CreatedDateTime
            ResourcesToInclude          = @($Snapshot.ResourcesToInclude)
            CapturedResourceCount       = $Snapshot.ResourceCount
            AttemptResourceTypeCounts   = [ordered]@{}
            PublishedResourceTypeCounts = $PublishedResourceTypeCounts
            ResourceTypeFileCounts      = $PublishedResourceTypeCounts
            PublishedResourceTypes      = @()
            StaleResourceTypes          = @($RequestedResourceTypes)
            ResourceTypeStates          = @($AmbiguousResourceTypeStates)
            Diagnostics                 = @($SnapshotDiagnostics)
            ErrorDetailsUnavailable     = $SnapshotDiagnostics.Count -eq 0
            IsComplete                  = $false
        }
        $AmbiguousPartialManifest | ConvertTo-Json -Depth 10 | Set-Content -Path $LastAttemptManifestFilePath -Encoding utf8
        $AmbiguousPartialManifest | ConvertTo-Json -Depth 10 | Set-Content -Path $SnapshotManifestFilePath -Encoding utf8
        if (Test-Path -Path $PendingJobFilePath -ErrorAction SilentlyContinue) {
            Remove-Item -Path $PendingJobFilePath -Force
        }
        Write-Warning "Tenant Governance snapshot job $($Snapshot.SnapshotId) completed as '$SnapshotJobStatus', but Graph returned no parseable resource-type errors. No downloaded resource types were published; all existing resource files were preserved as stale."
        return [PSCustomObject]@{
            TenantId            = $Global:TenantIdContext
            TenantName          = $Global:TenantNameContext
            SnapshotId          = $Snapshot.SnapshotId
            SnapshotDisplayName = $Snapshot.DisplayName
            SnapshotJobStatus   = $SnapshotJobStatus
            CapturedDateTime    = $Snapshot.CreatedDateTime
            ResourcesToInclude  = @($Snapshot.ResourcesToInclude)
            ResourceCount       = $Snapshot.ResourceCount
        }
    }

    $PublishableResourceTypes = @($RequestedResourceTypes | Where-Object { $StaleResourceTypes -notcontains $_ })
    $StagingFolder = Join-Path -Path $ExportFolder -ChildPath ".staging-$($Snapshot.SnapshotId)"
    $BackupFolder = Join-Path -Path $ExportFolder -ChildPath ".backup-$($Snapshot.SnapshotId)"

    # Recover an interrupted earlier promotion of this same job before rebuilding its staging area.
    if (Test-Path -Path $BackupFolder -ErrorAction SilentlyContinue) {
        foreach ($BackupResourceFolder in @(Get-ChildItem -Path $BackupFolder -Directory -ErrorAction SilentlyContinue)) {
            $PublishedResourceFolder = Join-Path -Path $ExportFolder -ChildPath $BackupResourceFolder.Name
            if (-not (Test-Path -Path $PublishedResourceFolder -ErrorAction SilentlyContinue)) {
                Move-Item -Path $BackupResourceFolder.FullName -Destination $PublishedResourceFolder -Force
            }
        }
        Remove-Item -Path $BackupFolder -Recurse -Force
    }
    if (Test-Path -Path $StagingFolder -ErrorAction SilentlyContinue) {
        Remove-Item -Path $StagingFolder -Recurse -Force
    }

    #region Stage each captured resource as an individual file under <resourceType>/<displayName segment 1>/<displayName segment 2>.json
    # File names are resolved for all resources first: normalization and case-insensitive filesystems
    # both map several display names onto the same file name, and which of the colliding resources
    # keeps the plain name must not depend on the order in which Graph returned them.

    # Collections whose Graph order is unstable but semantically irrelevant, keyed by lowercase
    # resource type. Keep this registry resource-specific: identically named collections in another
    # resource type can be positional (for example, role-setting approvalStages) and must retain
    # Graph's order.
    $CollectionPathsToSortByResourceType = @{
        'microsoft.entra.administrativeunit'  = @('properties.Members', 'properties.ScopedRoleMembers')
        'microsoft.entra.group'               = @('properties.Members')
        'microsoft.entra.authorizationpolicy' = @('properties.PermissionGrantPolicyIdsAssignedToDefaultUserRole')
    }
    $StagedResources = [System.Collections.Generic.List[object]]::new()
    $CapturedResourceIdentities = @{}
    Write-Output "Saving $($Snapshot.ResourceCount) resource(s) under $ExportFolder (organized by resource type and display name)..."
    foreach ($Resource in @($Snapshot.Resources)) {
        $ResourceType = if ($Resource.resourceType) { $Resource.resourceType } else { "unknown" }
        $DisplayName = if ($Resource.displayName) { $Resource.displayName } else { "Unnamed" }

        # UTCM sometimes appends nested hashtable .ToString() values to partner display names.
        # Partners have no independent display name; their tenant ID is the stable identity.
        if ($ResourceType -eq 'microsoft.entra.crossTenantAccessPolicyConfigurationPartner') {
            $PartnerTenantId = $Resource.properties.partnerTenantId
            if ([string]::IsNullOrWhiteSpace([string]$PartnerTenantId) -and $DisplayName -match '(?i)\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b') {
                $PartnerTenantId = $Matches[0]
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$PartnerTenantId)) {
                $DisplayName = "AADCrossTenantAccessPolicyConfigurationPartner-$PartnerTenantId"
                if ($Resource -is [System.Collections.IDictionary]) {
                    $Resource['displayName'] = $DisplayName
                } else {
                    $Resource.displayName = $DisplayName
                }
            }
        }

        # Split the displayName on its first "-" only: everything before becomes the subfolder,
        # everything after (which may itself contain further "-" characters) becomes the file name.
        $DelimiterIndex = $DisplayName.IndexOf('-')
        if ($DelimiterIndex -ge 0) {
            $CategorySegment = $DisplayName.Substring(0, $DelimiterIndex).Trim()
            $NameSegment = $DisplayName.Substring($DelimiterIndex + 1).Trim()
        } else {
            $CategorySegment = "General"
            $NameSegment = $DisplayName.Trim()
        }
        if ([string]::IsNullOrWhiteSpace($CategorySegment)) { $CategorySegment = "General" }
        if ([string]::IsNullOrWhiteSpace($NameSegment)) { $NameSegment = $DisplayName.Trim() }

        # Determine the leaf file name based on -SnapshotResourceFileNaming. "ResourceId" falls back
        # to the DisplayName-based name segment if the resource doesn't expose a usable Id (e.g.
        # singleton resources keyed by IsSingleInstance rather than Id).
        $FileNameSegment = $NameSegment
        if ($SnapshotResourceFileNaming -eq 'ResourceId') {
            $ResourceId = $Resource.properties.Id
            if (-not [string]::IsNullOrWhiteSpace($ResourceId)) {
                $FileNameSegment = $ResourceId
            } else {
                Write-Verbose "Resource '$DisplayName' has no usable Id; falling back to DisplayName-based file naming."
            }
        }

        # Normalize each path segment so the resulting file can be created, committed, and checked
        # out on every platform (see ConvertTo-EntraOpsSafeFilePathSegment) and so oversized display
        # names cannot exceed the filesystem's per-component length limit.
        # Resource type identifiers are case-insensitive. Canonicalize their directory name because
        # publication and manifest processing use lowercase identifiers; otherwise a mixed-case
        # resource type stages into a different directory on case-sensitive filesystems.
        $SafeResourceType = ConvertTo-EntraOpsSafeFilePathSegment -Segment $ResourceType.ToLowerInvariant() -FallbackName 'unknown'
        $SafeCategorySegment = ConvertTo-EntraOpsSafeFilePathSegment -Segment $CategorySegment -FallbackName 'General'
        $SafeFileNameSegment = ConvertTo-EntraOpsSafeFilePathSegment -Segment $FileNameSegment -FallbackName 'Unnamed'

        $ResourceFolder = Join-Path -Path (Join-Path -Path $StagingFolder -ChildPath $SafeResourceType) -ChildPath $SafeCategorySegment
        $ResourceFilePath = Join-Path -Path $ResourceFolder -ChildPath "$SafeFileNameSegment.json"

        # Property names are sorted at every nesting level. Collection order is retained unless the
        # collection is registered above as a known semantic set.
        $CanonicalResourceType = $ResourceType.ToLowerInvariant()
        [string[]]$CollectionPathsToSort = @()
        if ($CollectionPathsToSortByResourceType.ContainsKey($CanonicalResourceType)) {
            $CollectionPathsToSort = $CollectionPathsToSortByResourceType[$CanonicalResourceType]
        }
        $SortedResource = ConvertTo-EntraOpsSortedObject -InputObject $Resource -CollectionPathsToSort $CollectionPathsToSort
        $ResourceJson = $SortedResource | ConvertTo-Json -Depth 10
        # The Id stays stable while the resource is edited or renamed, so it is preferred over the
        # content as the discriminator seed for resources that need one.
        $ResourceIdentifier = [string]$Resource.properties.Id
        if (-not [string]::IsNullOrWhiteSpace($ResourceIdentifier)) {
            $CanonicalIdentity = "$($ResourceType.ToLowerInvariant())|$($ResourceIdentifier.Trim().ToLowerInvariant())"
            if ($CapturedResourceIdentities.ContainsKey($CanonicalIdentity)) {
                # This condition is deterministic for the job, so retrying the same job can never
                # succeed. Release the pending-job state and record the failure so the next Start
                # can create a new job and the report/analyzer can show why this one was rejected.
                $DuplicateMessage = "Snapshot job $($Snapshot.SnapshotId) returned duplicate canonical resource identity '$CanonicalIdentity' for '$DisplayName' and '$($CapturedResourceIdentities[$CanonicalIdentity])'. No snapshot resource folders were published."
                $DuplicateAttemptManifest = [ordered]@{
                    SnapshotId                  = $Snapshot.SnapshotId
                    SnapshotDisplayName         = $Snapshot.DisplayName
                    SnapshotJobStatus           = $SnapshotJobStatus
                    CapturedDateTime            = $Snapshot.CreatedDateTime
                    ResourcesToInclude          = @($Snapshot.ResourcesToInclude)
                    CapturedResourceCount       = $Snapshot.ResourceCount
                    AttemptResourceTypeCounts   = [ordered]@{}
                    PublishedResourceTypeCounts = [ordered]@{}
                    ResourceTypeFileCounts      = [ordered]@{}
                    PublishedResourceTypes      = @()
                    StaleResourceTypes          = @($RequestedResourceTypes)
                    ResourceTypeStates          = @()
                    Diagnostics                 = @(
                        [PSCustomObject][ordered]@{
                            ResourceType    = $ResourceType.ToLowerInvariant()
                            ErrorCategory   = 'DuplicateResourceIdentity'
                            ErrorCode       = 'DuplicateCanonicalIdentity'
                            Occurrences     = 1
                            Message         = $DuplicateMessage
                            RemediationHint = 'Microsoft Graph returned two resources with the same id for this resource type. Inspect the tenant objects, then start a new snapshot job; the rejected job is not retried.'
                        }
                    )
                    ErrorDetailsUnavailable     = $false
                    IsComplete                  = $false
                }
                $DuplicateAttemptManifest | ConvertTo-Json -Depth 10 | Set-Content -Path $LastAttemptManifestFilePath -Encoding utf8
                if (Test-Path -Path $StagingFolder -ErrorAction SilentlyContinue) {
                    Remove-Item -Path $StagingFolder -Recurse -Force
                }
                if (Test-Path -Path $PendingJobFilePath -ErrorAction SilentlyContinue) {
                    Remove-Item -Path $PendingJobFilePath -Force
                }
                throw $DuplicateMessage
            }
            $CapturedResourceIdentities[$CanonicalIdentity] = $DisplayName
        }
        $StagedResources.Add([PSCustomObject]@{
                ResourceType        = $ResourceType
                DisplayName         = $DisplayName
                SafeFileNameSegment = $SafeFileNameSegment
                ResourceFolder      = $ResourceFolder
                ResourceFilePath    = $ResourceFilePath
                ResourceFilePathKey = $ResourceFilePath.ToLowerInvariant()
                DiscriminatorSeed   = if ([string]::IsNullOrWhiteSpace($ResourceIdentifier)) { $ResourceJson } else { $ResourceIdentifier }
                Json                = $ResourceJson
            })
    }

    $ResourceFilePathCounts = @{}
    foreach ($StagedResource in $StagedResources) {
        $ResourceFilePathCounts[$StagedResource.ResourceFilePathKey] = 1 + [int]$ResourceFilePathCounts[$StagedResource.ResourceFilePathKey]
    }

    # Allocate a unique path for every resource before writing anything: a discriminated name can
    # itself collide with another resource's natural name, so every candidate is checked against all
    # paths allocated so far. Allocation runs in a deterministic order to keep the outcome
    # independent of the order in which Graph returned the resources.
    $AllocatedFilePathKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($StagedResource in @($StagedResources | Sort-Object -Property ResourceFilePathKey, DiscriminatorSeed)) {
        $SafeFileNameSegment = $StagedResource.SafeFileNameSegment
        $ResourceFilePath = $StagedResource.ResourceFilePath
        $NeedsDiscriminator = $ResourceFilePathCounts[$StagedResource.ResourceFilePathKey] -gt 1
        $Attempt = 0

        while ($true) {
            if ($NeedsDiscriminator) {
                $DiscriminatorBytes = [System.Security.Cryptography.MD5]::HashData([System.Text.Encoding]::UTF8.GetBytes("$($StagedResource.DiscriminatorSeed)|$Attempt"))
                $Discriminator = ([System.BitConverter]::ToString($DiscriminatorBytes) -replace '-', '').Substring(0, 8)
                $SafeFileNameSegment = ConvertTo-EntraOpsSafeFilePathSegment -Segment "$($StagedResource.SafeFileNameSegment) $Discriminator" -FallbackName $Discriminator
                $ResourceFilePath = Join-Path -Path $StagedResource.ResourceFolder -ChildPath "$SafeFileNameSegment.json"
            }

            if ($AllocatedFilePathKeys.Add($ResourceFilePath.ToLowerInvariant())) {
                break
            }

            $NeedsDiscriminator = $true
            $Attempt++
            if ($Attempt -gt 100) {
                throw "Failed to allocate a unique file name for resource '$($StagedResource.DisplayName)' ($($StagedResource.ResourceType)) after $Attempt attempts. Re-run with -SnapshotResourceFileNaming ResourceId."
            }
        }

        if ($SafeFileNameSegment -ne $StagedResource.SafeFileNameSegment) {
            Write-Warning "Resource '$($StagedResource.DisplayName)' ($($StagedResource.ResourceType)) resolves to the same file name as another resource of this snapshot. It was saved as '$SafeFileNameSegment.json' instead. Use -SnapshotResourceFileNaming ResourceId for unique and rename-stable file names."
        }

        if (-not (Test-Path -LiteralPath $StagedResource.ResourceFolder)) {
            New-Item -Path $StagedResource.ResourceFolder -ItemType Directory -Force | Out-Null
        }
        $StagedResource.Json | Out-File -LiteralPath $ResourceFilePath -Encoding utf8
    }
    #endregion

    #region Build per-resource-type publication metadata
    # Snapshot resources arrive in an arbitrary order. Rebuild the count dictionary with ordinally
    # sorted keys so ConvertTo-Json emits byte-stable manifest metadata.
    $AttemptResourceTypeCounts = [ordered]@{}
    [string[]]$AttemptResourceTypeKeys = @($UnorderedAttemptResourceTypeCounts.Keys)
    [Array]::Sort($AttemptResourceTypeKeys, [StringComparer]::Ordinal)
    foreach ($ResourceType in $AttemptResourceTypeKeys) {
        $AttemptResourceTypeCounts[$ResourceType] = $UnorderedAttemptResourceTypeCounts[$ResourceType]
    }

    $PreviousManifest = $null
    if (Test-Path -Path $SnapshotManifestFilePath -ErrorAction SilentlyContinue) {
        try {
            $PreviousManifest = Get-Content -Path $SnapshotManifestFilePath -Raw | ConvertFrom-Json -Depth 10
        } catch {
            Write-Warning "The previous snapshot manifest could not be read. Stale resource files will still be preserved, but their source snapshot cannot be identified. Error: $_"
        }
    }
    $PreviousResourceTypeStates = @{}
    foreach ($PreviousState in @($PreviousManifest.ResourceTypeStates)) {
        if ($PreviousState.ResourceType) { $PreviousResourceTypeStates[$PreviousState.ResourceType.ToLowerInvariant()] = $PreviousState }
    }

    #endregion

    #region Promote the staged resource types and roll back all promoted directories if publication fails
    $PromotionRecords = [System.Collections.Generic.List[object]]::new()
    $RetainedResourceCounts = @{}
    try {
        New-Item -Path $BackupFolder -ItemType Directory -Force | Out-Null
        foreach ($ResourceType in $PublishableResourceTypes) {
            $SafeResourceType = ConvertTo-EntraOpsSafeFilePathSegment -Segment $ResourceType -FallbackName 'unknown'
            $StagedResourceFolder = Join-Path -Path $StagingFolder -ChildPath $SafeResourceType
            $PublishedResourceFolder = Join-Path -Path $ExportFolder -ChildPath $SafeResourceType
            $ResourceBackupFolder = Join-Path -Path $BackupFolder -ChildPath $SafeResourceType

            if (Test-Path -Path $PublishedResourceFolder -ErrorAction SilentlyContinue) {
                Move-Item -Path $PublishedResourceFolder -Destination $ResourceBackupFolder -Force
            }
            $PromotionRecords.Add([PSCustomObject]@{
                    PublishedFolder = $PublishedResourceFolder
                    BackupFolder    = $ResourceBackupFolder
                })
            if (Test-Path -Path $StagedResourceFolder -ErrorAction SilentlyContinue) {
                Move-Item -Path $StagedResourceFolder -Destination $PublishedResourceFolder -Force
            }

            if ($ResourceTypesWithRetainedResources -notcontains $ResourceType) { continue }
            $RetainedResourceCounts[$ResourceType] = 0
            if (-not (Test-Path -Path $ResourceBackupFolder -PathType Container -ErrorAction SilentlyContinue)) { continue }
            # Match retained files by resource identity, not file name: a resource that was renamed
            # in this attempt would otherwise be kept twice and fail the duplicate-identity check.
            $RetainedResourceIdentities = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $PreviousResourceFiles = @(
                foreach ($PreviousFile in @(Get-ChildItem -LiteralPath $ResourceBackupFolder -Filter '*.json' -File -Recurse)) {
                    $PreviousResourceId = $null
                    # -AsHashtable: Graph emits empty property names in some payloads, which ConvertFrom-Json
                    # otherwise rejects, leaving the resource without an identity and retaining it twice.
                    try { $PreviousResourceId = [string](Get-Content -LiteralPath $PreviousFile.FullName -Raw | ConvertFrom-Json -AsHashtable -Depth 100).properties.Id } catch { $PreviousResourceId = $null }
                    $HasPreviousResourceId = -not [string]::IsNullOrWhiteSpace($PreviousResourceId)
                    $ExpectedIdFileName = if ($HasPreviousResourceId) {
                        ConvertTo-EntraOpsSafeFilePathSegment -Segment $PreviousResourceId -FallbackName 'Unnamed'
                    } else { $null }
                    [PSCustomObject]@{
                        File          = $PreviousFile
                        ResourceId    = $PreviousResourceId
                        HasResourceId = $HasPreviousResourceId
                        IsIdNamed     = $HasPreviousResourceId -and [System.IO.Path]::GetFileNameWithoutExtension($PreviousFile.Name).Equals($ExpectedIdFileName, [System.StringComparison]::OrdinalIgnoreCase)
                    }
                }
            )
            foreach ($PreviousResourceFile in @($PreviousResourceFiles | Sort-Object @{ Expression = { if ($_.IsIdNamed) { 0 } else { 1 } } }, @{ Expression = { $_.File.FullName } })) {
                $PreviousFile = $PreviousResourceFile.File
                $PreviousResourceId = $PreviousResourceFile.ResourceId
                $HasPreviousResourceId = $PreviousResourceFile.HasResourceId
                if ($HasPreviousResourceId) {
                    $PreviousIdentity = "$ResourceType|$($PreviousResourceId.Trim().ToLowerInvariant())"
                    if ($CapturedResourceIdentities.ContainsKey($PreviousIdentity) -or -not $RetainedResourceIdentities.Add($PreviousIdentity)) { continue }
                }
                $RelativePath = $PreviousFile.FullName.Substring($ResourceBackupFolder.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
                $RetainedFilePath = Join-Path -Path $PublishedResourceFolder -ChildPath $RelativePath
                if (Test-Path -LiteralPath $RetainedFilePath) {
                    # Without an identity the same path is the only evidence of the same resource.
                    if (-not $HasPreviousResourceId) { continue }
                    # A different resource now owns this display-name path; keep the failed one
                    # under a discriminated name derived from its stable identity.
                    $DiscriminatorBytes = [System.Security.Cryptography.MD5]::HashData([System.Text.Encoding]::UTF8.GetBytes("$PreviousResourceId|retained"))
                    $Discriminator = ([System.BitConverter]::ToString($DiscriminatorBytes) -replace '-', '').Substring(0, 8)
                    $RetainedFileName = ConvertTo-EntraOpsSafeFilePathSegment -Segment "$([System.IO.Path]::GetFileNameWithoutExtension($RetainedFilePath)) $Discriminator" -FallbackName $Discriminator
                    $RetainedFilePath = Join-Path -Path (Split-Path -Path $RetainedFilePath -Parent) -ChildPath "$RetainedFileName.json"
                    if (Test-Path -LiteralPath $RetainedFilePath) { continue }
                    Write-Warning "Retained resource '$PreviousResourceId' ($ResourceType) no longer owns its file name; it was kept as '$RetainedFileName.json'."
                }
                $RetainedFolder = Split-Path -Path $RetainedFilePath -Parent
                if (-not (Test-Path -LiteralPath $RetainedFolder)) { New-Item -Path $RetainedFolder -ItemType Directory -Force | Out-Null }
                Copy-Item -LiteralPath $PreviousFile.FullName -Destination $RetainedFilePath -Force
                $RetainedResourceCounts[$ResourceType]++
            }
            if ($RetainedResourceCounts[$ResourceType] -gt 0) {
                Write-Warning "Resource type '$ResourceType' was published with export errors. $($RetainedResourceCounts[$ResourceType]) resource file(s) the snapshot job did not return were retained from the previously published snapshot."
            }
        }

        # Validation scans every published resource folder, including preserved-stale and no-longer
        # configured types. Heal only the unambiguous naming migration case: one exact ID-named file
        # plus one or more legacy display-name aliases for the same canonical resource identity.
        $PublishedIdentityFiles = @{}
        foreach ($PublishedFile in @(Get-ChildItem -LiteralPath $ExportFolder -Filter '*.json' -File -Recurse | Where-Object { $_.FullName -notmatch '[\\/]\.(?:staging|backup)-' })) {
            $PublishedResource = $null
            try { $PublishedResource = Get-Content -LiteralPath $PublishedFile.FullName -Raw | ConvertFrom-Json -AsHashtable -Depth 100 } catch { continue }
            $PublishedResourceType = ([string]$PublishedResource.resourceType).Trim().ToLowerInvariant()
            $PublishedResourceId = ([string]$PublishedResource.properties.Id).Trim().ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($PublishedResourceType) -or [string]::IsNullOrWhiteSpace($PublishedResourceId)) { continue }
            $PublishedIdentity = "$PublishedResourceType|$PublishedResourceId"
            $ExpectedIdFileName = ConvertTo-EntraOpsSafeFilePathSegment -Segment $PublishedResourceId -FallbackName 'Unnamed'
            if (-not $PublishedIdentityFiles.ContainsKey($PublishedIdentity)) { $PublishedIdentityFiles[$PublishedIdentity] = [System.Collections.Generic.List[object]]::new() }
            $PublishedIdentityFiles[$PublishedIdentity].Add([PSCustomObject]@{
                    File      = $PublishedFile
                    IsIdNamed = [System.IO.Path]::GetFileNameWithoutExtension($PublishedFile.Name).Equals($ExpectedIdFileName, [System.StringComparison]::OrdinalIgnoreCase)
                })
        }
        foreach ($PublishedIdentity in @($PublishedIdentityFiles.Keys | Sort-Object)) {
            $IdentityFiles = @($PublishedIdentityFiles[$PublishedIdentity])
            if ($IdentityFiles.Count -lt 2) { continue }
            $IdNamedFiles = @($IdentityFiles | Where-Object { $_.IsIdNamed })
            if ($IdNamedFiles.Count -ne 1) { continue }
            foreach ($LegacyFile in @($IdentityFiles | Where-Object { -not $_.IsIdNamed })) {
                Remove-Item -LiteralPath $LegacyFile.File.FullName -Force
                Write-Warning "Removed legacy Tenant Governance alias '$($LegacyFile.File.Name)' for '$PublishedIdentity'; the ID-named copy was retained."
            }
        }
    } catch {
        for ($Index = $PromotionRecords.Count - 1; $Index -ge 0; $Index--) {
            $PromotionRecord = $PromotionRecords[$Index]
            if (Test-Path -Path $PromotionRecord.PublishedFolder -ErrorAction SilentlyContinue) {
                Remove-Item -Path $PromotionRecord.PublishedFolder -Recurse -Force
            }
            if (Test-Path -Path $PromotionRecord.BackupFolder -ErrorAction SilentlyContinue) {
                Move-Item -Path $PromotionRecord.BackupFolder -Destination $PromotionRecord.PublishedFolder -Force
            }
        }
        foreach ($TemporaryFolder in @($StagingFolder, $BackupFolder)) {
            if (Test-Path -Path $TemporaryFolder -ErrorAction SilentlyContinue) {
                Remove-Item -Path $TemporaryFolder -Recurse -Force
            }
        }
        throw "Failed to publish Tenant Governance snapshot resources. Existing resource folders were restored and pending job state was preserved. Error: $_"
    }
    #endregion

    #region Build published counts and per-resource-type states after successful promotion
    $PublishedResourceTypeCounts = [ordered]@{}
    foreach ($ResourceType in $RequestedResourceTypes) {
        $PublishedResourceFolder = Join-Path -Path $ExportFolder -ChildPath $ResourceType
        $PublishedResourceTypeCounts[$ResourceType] = if (Test-Path -Path $PublishedResourceFolder -PathType Container) {
            @(Get-ChildItem -Path $PublishedResourceFolder -Filter '*.json' -File -Recurse -ErrorAction SilentlyContinue).Count
        } else { 0 }
    }

    $ResourceTypeStates = @(
        foreach ($ResourceType in $RequestedResourceTypes) {
            $IsStale = $StaleResourceTypes -contains $ResourceType
            $IsRetained = $ResourceTypesWithRetainedResources -contains $ResourceType
            $PreviousState = $PreviousResourceTypeStates[$ResourceType]
            $PreviousCompleteSnapshotId = if ($PreviousManifest.IsComplete -eq $true) { $PreviousManifest.SnapshotId } else { $null }
            $PublishedSnapshotId = if ($IsStale) {
                if ($PreviousState.PublishedSnapshotId) { $PreviousState.PublishedSnapshotId } else { $PreviousCompleteSnapshotId }
            } else { $Snapshot.SnapshotId }
            [PSCustomObject][ordered]@{
                ResourceType           = $ResourceType
                Status                 = if ($IsStale) { 'PreservedStale' } elseif ($IsRetained) { 'PublishedWithErrors' } else { 'Published' }
                CapturedResourceCount  = if ($AttemptResourceTypeCounts.Contains($ResourceType)) { $AttemptResourceTypeCounts[$ResourceType] } else { 0 }
                AttemptResourceCount   = if ($AttemptResourceTypeCounts.Contains($ResourceType)) { $AttemptResourceTypeCounts[$ResourceType] } else { 0 }
                PublishedResourceCount = $PublishedResourceTypeCounts[$ResourceType]
                RetainedResourceCount  = if ($RetainedResourceCounts.ContainsKey($ResourceType)) { [int]$RetainedResourceCounts[$ResourceType] } else { 0 }
                PublishedSnapshotId    = $PublishedSnapshotId
                PublishedSource        = if ($PublishedSnapshotId) { 'Snapshot' } else { 'UnknownLegacySnapshot' }
                AttemptSnapshotId      = $Snapshot.SnapshotId
                Diagnostics            = @($SnapshotDiagnostics | Where-Object { $_.ResourceType -eq $ResourceType })
            }
        }
    )
    #endregion

    #region Build the command summary and persisted snapshot manifests
    $SnapshotSummary = [PSCustomObject]@{
        TenantId            = $Global:TenantIdContext
        TenantName          = $Global:TenantNameContext
        SnapshotId          = $Snapshot.SnapshotId
        SnapshotDisplayName = $Snapshot.DisplayName
        SnapshotJobStatus   = $SnapshotJobStatus
        CapturedDateTime    = $Snapshot.CreatedDateTime
        ResourcesToInclude  = $Snapshot.ResourcesToInclude
        ResourceCount       = $Snapshot.ResourceCount
    }

    $SnapshotManifest = [ordered]@{
        SnapshotId                       = $Snapshot.SnapshotId
        SnapshotDisplayName              = $Snapshot.DisplayName
        SnapshotJobStatus                = $SnapshotJobStatus
        CapturedDateTime                 = $Snapshot.CreatedDateTime
        ResourcesToInclude               = @($Snapshot.ResourcesToInclude)
        CapturedResourceCount            = $Snapshot.ResourceCount
        AttemptResourceTypeCounts        = $AttemptResourceTypeCounts
        PublishedResourceTypeCounts      = $PublishedResourceTypeCounts
        ResourceTypeFileCounts           = $PublishedResourceTypeCounts
        PublishedResourceTypes           = @($PublishableResourceTypes)
        PublishedWithErrorsResourceTypes = @($ResourceTypesWithRetainedResources)
        StaleResourceTypes               = @($StaleResourceTypes)
        ResourceTypeStates               = @($ResourceTypeStates)
        Diagnostics                      = @($SnapshotDiagnostics)
        ErrorDetailsUnavailable          = $ParsedErrorDetails.Count -eq 0 -and $SnapshotJobStatus -eq 'partiallySuccessful'
        IsComplete                       = $SnapshotJobStatus -in @('completed', 'succeeded') -and $ResourceTypesWithErrors.Count -eq 0
    }
    $SnapshotManifest | ConvertTo-Json -Depth 10 | Set-Content -Path $LastAttemptManifestFilePath -Encoding utf8
    $SnapshotManifest | ConvertTo-Json -Depth 10 | Set-Content -Path $SnapshotManifestFilePath -Encoding utf8

    foreach ($TemporaryFolder in @($StagingFolder, $BackupFolder)) {
        if (Test-Path -Path $TemporaryFolder -ErrorAction SilentlyContinue) {
            Remove-Item -Path $TemporaryFolder -Recurse -Force
        }
    }
    if (Test-Path -Path $PendingJobFilePath -ErrorAction SilentlyContinue) {
        Remove-Item -Path $PendingJobFilePath -Force
    }

    if ($SnapshotManifest.IsComplete) {
        Write-Output "Tenant Governance snapshot completed. $($Snapshot.ResourceCount) resource(s) captured and saved under $ExportFolder. Commit and push these files to track this point-in-time in Git history."
    } else {
        Write-Warning "Tenant Governance snapshot job $($Snapshot.SnapshotId) completed as '$SnapshotJobStatus'. $($PublishableResourceTypes.Count) resource type(s) were published ($($ResourceTypesWithRetainedResources.Count) of them with per-resource export errors) and $($StaleResourceTypes.Count) type(s) with Graph errors were preserved as stale."
    }
    Write-Output ($SnapshotSummary | Format-List | Out-String)
    #endregion

    return $SnapshotSummary
}
