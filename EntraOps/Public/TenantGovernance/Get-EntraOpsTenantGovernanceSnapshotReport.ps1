<#
.SYNOPSIS
    Analyze EntraOps Tenant Governance (UTCM) snapshot health: compares the resource types
    configured in EntraOpsConfig.json against what has actually been persisted to disk, and
    (optionally) enriches the report with the underlying snapshot job details from Microsoft Graph.

.DESCRIPTION
    Helps troubleshoot runs of Save-EntraOpsTenantGovernanceSnapshotJson that reported a
    'partiallySuccessful' (or 'failed') snapshot job, e.g.:
      WARNING: Snapshot job 22222222-2222-2222-2222-222222222222 completed as 'partiallySuccessful' -
      one or more resource types may have failed to capture. Check the snapshot job details in the
      Microsoft Entra admin center for more information.

    The cmdlet performs two independent checks and correlates them:
    1. Disk inventory: enumerates <SnapshotFolder>/<resourceType>/... and compares the resource
       types found there against TenantGovernanceSnapshot.ResourcesToInclude in EntraOpsConfig.json,
       flagging configured resource types that have no folder ("Missing") or an empty folder
       ("Empty") on disk, as well as resource types found on disk that are no longer part of the
       current configuration ("NotInConfig").
    2. Microsoft Graph job details: retrieves the configurationSnapshotJob object(s) for either the
       explicitly supplied -SnapshotJobId value(s), or the most recent -RecentJobsCount jobs (via
       the List API), including the 'status', 'errorDetails' and requested 'resources' properties -
       none of which are returned by default and require an explicit $select. Microsoft Graph does
       not expose a per-resource-type success/failure list on the job itself, so as a best-effort
       diagnostic the cmdlet cross-references each job's requested resource types against the disk
       inventory (see above) to highlight which of the requested types are likely the ones that
       failed to capture in a 'partiallySuccessful' job.

    The raw 'errorDetails' strings returned by Graph are a single, hard-to-read blob per resource
    type (e.g. "microsoft.entra.conditionalAccessPolicy: Error exporting resource [...]. exceptionMessage(s):msg1 ,msg2 ,...").
    ConvertFrom-EntraOpsTenantGovernanceSnapshotErrorDetail splits each blob into one object per
    individual message (ResourceType, ErrorCategory, ErrorCode, Message, ReferencedObjectIds), and
    near-identical messages that only differ by object Id (e.g. dozens of "Resource '<id>' does not
    exist..." entries for different objects/policies) are deduplicated into a single ErrorSummary row
    with an occurrence count and the full list of affected Ids. For each 'partiallySuccessful'/'failed'
    job, this deduped summary is also printed to the console (grouped by resource type, with occurrence
    counts) using the same Show-EntraOpsWarningSummary display used by other EntraOps cmdlets.

    Requires the "ConfigurationMonitoring.Read.All" (or ReadWrite.All) Microsoft Graph permission to
    read snapshot job details - no write/create permission is needed for this read-only report.

.PARAMETER ConfigFilePath
    Path to the EntraOps config file used to determine the configured resource set. Default is
    <EntraOpsBaseFolder>/EntraOpsConfig.json. Falls back to the recommended default resource set
    (Get-EntraOpsTenantGovernanceResourceDefinition) if the file is missing or can't be parsed.

.PARAMETER SnapshotFolder
    Folder containing the per-resource snapshot files written by Save-EntraOpsTenantGovernanceSnapshotJson.
    Default is <EntraOpsBaseFolder>/TenantGovernance/Snapshots.

.PARAMETER SnapshotJobId
    One or more specific snapshot job Ids to retrieve from Microsoft Graph (e.g. the Id shown in a
    'partiallySuccessful' warning message). If omitted, the most recent -RecentJobsCount jobs are
    retrieved instead.

.PARAMETER RecentJobsCount
    Number of most recent snapshot jobs to retrieve from Microsoft Graph when -SnapshotJobId is not
    specified. Default is 5.

.PARAMETER SkipGraphJobDetails
    Skip the Microsoft Graph lookup entirely and only report the disk-vs-config comparison. Useful
    when not connected to Microsoft Graph, or to only check local file inventory.

.EXAMPLE
    Analyze the snapshot job referenced in a 'partiallySuccessful' warning message.
    Get-EntraOpsTenantGovernanceSnapshotReport -SnapshotJobId "22222222-2222-2222-2222-222222222222"

.EXAMPLE
    Check the 10 most recent snapshot jobs and compare them against the local snapshot folder.
    Get-EntraOpsTenantGovernanceSnapshotReport -RecentJobsCount 10

.EXAMPLE
    Only compare the local snapshot folder against EntraOpsConfig.json, without calling Microsoft Graph.
    Get-EntraOpsTenantGovernanceSnapshotReport -SkipGraphJobDetails

.EXAMPLE
    Drill into the deduped, per-resource-type error summary of the most recent job(s) instead of the console output.
    (Get-EntraOpsTenantGovernanceSnapshotReport).SnapshotJobs.ErrorSummary | Format-Table ResourceType, ErrorCode, Occurrences, Message -Wrap
#>
function Get-EntraOpsTenantGovernanceSnapshotReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$ConfigFilePath = "$EntraOpsBaseFolder/EntraOpsConfig.json"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$SnapshotFolder = "$EntraOpsBaseFolder/TenantGovernance/Snapshots"
        ,
        [Parameter(Mandatory = $false)]
        [System.String[]]$SnapshotJobId
        ,
        [Parameter(Mandatory = $false)]
        [System.Int32]$RecentJobsCount = 5
        ,
        [Parameter(Mandatory = $false)]
        [switch]$SkipGraphJobDetails
    )

    $ErrorActionPreference = "Stop"

    $SnapshotManifest = $null
    $SnapshotManifestPath = Join-Path $SnapshotFolder '.SnapshotManifest.json'
    if (Test-Path -Path $SnapshotManifestPath -ErrorAction SilentlyContinue) {
        try {
            $SnapshotManifest = Get-Content -Path $SnapshotManifestPath -Raw | ConvertFrom-Json -Depth 10
        } catch {
            Write-Warning "Failed to read/parse snapshot manifest '$SnapshotManifestPath'. Error: $_"
        }
    }
    $LastAttemptManifest = $null
    $LastAttemptManifestPath = Join-Path $SnapshotFolder '.LastAttemptManifest.json'
    if (Test-Path -Path $LastAttemptManifestPath -ErrorAction SilentlyContinue) {
        try {
            $LastAttemptManifest = Get-Content -Path $LastAttemptManifestPath -Raw | ConvertFrom-Json -Depth 10
        } catch {
            Write-Warning "Failed to read/parse latest-attempt manifest '$LastAttemptManifestPath'. Error: $_"
        }
    }

    #region Determine the configured resource set from EntraOpsConfig.json (fallback: recommended default set)
    $ConfiguredResources = $null
    if (Test-Path -Path $ConfigFilePath -ErrorAction SilentlyContinue) {
        try {
            $ConfigContent = Get-Content -Path $ConfigFilePath -Raw | ConvertFrom-Json -Depth 10
            $ConfiguredResources = @($ConfigContent.TenantGovernanceSnapshot.ResourcesToInclude) | Where-Object { $null -ne $_ }
        } catch {
            Write-Warning "Failed to read/parse config file '$ConfigFilePath'. Falling back to the recommended default resource set. Error: $_"
        }
    } else {
        Write-Warning "Config file '$ConfigFilePath' not found. Falling back to the recommended default resource set."
    }
    if (-not $ConfiguredResources -or $ConfiguredResources.Count -eq 0) {
        $ConfiguredResources = @((Get-EntraOpsTenantGovernanceResourceDefinition).DefaultResources)
    }
    # Graph normalizes resourceType to lower-case in the captured snapshot resources/folder names;
    # keep a lower-case lookup set for case-insensitive comparisons throughout.
    $ConfiguredResourcesLower = @($ConfiguredResources | ForEach-Object { $_.ToLowerInvariant() })
    #endregion

    #region Inventory of resource types actually present on disk under $SnapshotFolder
    $DiskInventory = [System.Collections.Generic.List[object]]::new()
    if (Test-Path -Path $SnapshotFolder -ErrorAction SilentlyContinue) {
        $ResourceTypeFolders = Get-ChildItem -Path $SnapshotFolder -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '.*' }
        foreach ($Folder in $ResourceTypeFolders) {
            $ResourceFiles = @(Get-ChildItem -Path $Folder.FullName -Filter "*.json" -File -Recurse -ErrorAction SilentlyContinue)
            $LastWriteTime = ($ResourceFiles | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1).LastWriteTimeUtc
            $DiskInventory.Add(
                [PSCustomObject]@{
                    ResourceType  = $Folder.Name
                    FileCount     = $ResourceFiles.Count
                    LastWriteTime = $LastWriteTime
                }
            )
        }
    } else {
        Write-Warning "Snapshot folder '$SnapshotFolder' not found. No resources have been saved to disk yet."
    }
    $DiskInventoryLookup = @{}
    foreach ($Entry in $DiskInventory) { $DiskInventoryLookup[$Entry.ResourceType.ToLowerInvariant()] = $Entry }
    #endregion

    #region Build resource coverage report: configured resources vs what's actually on disk
    $ResourceTypeStateLookup = @{}
    foreach ($ResourceTypeState in @($SnapshotManifest.ResourceTypeStates)) {
        if ($ResourceTypeState.ResourceType) { $ResourceTypeStateLookup[$ResourceTypeState.ResourceType.ToLowerInvariant()] = $ResourceTypeState }
    }
    $ResourceCoverage = foreach ($Resource in $ConfiguredResources) {
        $DiskEntry = $DiskInventoryLookup[$Resource.ToLowerInvariant()]
        $ResourceTypeState = $ResourceTypeStateLookup[$Resource.ToLowerInvariant()]
        $PublishedResourceCount = if ($null -ne $ResourceTypeState.PublishedResourceCount) {
            [int]$ResourceTypeState.PublishedResourceCount
        } elseif ($DiskEntry) { $DiskEntry.FileCount } else { 0 }
        $AttemptResourceCount = if ($null -ne $ResourceTypeState.AttemptResourceCount) {
            [int]$ResourceTypeState.AttemptResourceCount
        } elseif ($null -ne $ResourceTypeState.CapturedResourceCount) {
            [int]$ResourceTypeState.CapturedResourceCount
        } else { $null }
        $Status = if ($ResourceTypeState.Status -eq 'PreservedStale') {
            "Stale"
        } elseif ($ResourceTypeState.Status -eq 'PublishedWithErrors') {
            "PublishedWithErrors"
        } elseif ($ResourceTypeState.Status -eq 'Published' -and $PublishedResourceCount -eq 0) {
            "Empty"
        } elseif (-not $DiskEntry) {
            "Missing"
        } elseif ($DiskEntry.FileCount -eq 0) {
            "Empty"
        } else {
            "Present"
        }
        [PSCustomObject]@{
            ResourceType           = $Resource
            Status                 = $Status
            FileCount              = if ($DiskEntry) { $DiskEntry.FileCount } else { 0 }
            AttemptResourceCount   = $AttemptResourceCount
            PublishedResourceCount = $PublishedResourceCount
            RetainedResourceCount  = if ($null -ne $ResourceTypeState.RetainedResourceCount) { [int]$ResourceTypeState.RetainedResourceCount } else { 0 }
            LastWriteTime          = if ($DiskEntry) { $DiskEntry.LastWriteTime } else { $null }
            PublishedSnapshotId    = $ResourceTypeState.PublishedSnapshotId
            PublishedSource        = $ResourceTypeState.PublishedSource
            AttemptSnapshotId      = $ResourceTypeState.AttemptSnapshotId
            Diagnostics            = @($ResourceTypeState.Diagnostics)
        }
    }

    # Resource types found on disk that are no longer part of the currently configured resource set
    # (e.g. removed from EntraOpsConfig.json since the last successful snapshot).
    $UnconfiguredOnDisk = @(
        foreach ($Entry in $DiskInventory) {
            if ($ConfiguredResourcesLower -notcontains $Entry.ResourceType.ToLowerInvariant()) {
                [PSCustomObject]@{
                    ResourceType  = $Entry.ResourceType
                    Status        = "NotInConfig"
                    FileCount     = $Entry.FileCount
                    LastWriteTime = $Entry.LastWriteTime
                }
            }
        }
    )

    # An empty category can be valid (for example, a tenant may have no Android policy or
    # group lifecycle policy). It is inventory information, not evidence that a snapshot failed.
    $MissingOrEmptyResourceTypes = @($ResourceCoverage | Where-Object { $_.Status -in @("Missing", "Empty") } | Select-Object -ExpandProperty ResourceType)
    $StaleResourceTypes = @($ResourceCoverage | Where-Object { $_.Status -eq "Stale" } | Select-Object -ExpandProperty ResourceType)
    #endregion

    #region Retrieve snapshot job details from Microsoft Graph (either explicit Id(s), or the most recent jobs)
    $SnapshotJobs = [System.Collections.Generic.List[object]]::new()
    if (-not $SkipGraphJobDetails) {
        $MgContext = Get-MgContext -ErrorAction SilentlyContinue
        $IsRestOnlyMode = [bool]$__EntraOpsSession['UseInvokeRestMethodOnly']
        if (-not $MgContext -and -not $IsRestOnlyMode) {
            Write-Warning "No active Microsoft Graph session found. Run Connect-EntraOps or Connect-MgGraph (scope 'ConfigurationMonitoring.Read.All' or higher) to retrieve snapshot job details. Skipping Microsoft Graph lookup."
        } else {
            $JobIdsToQuery = @()
            if ($SnapshotJobId -and $SnapshotJobId.Count -gt 0) {
                $JobIdsToQuery = @($SnapshotJobId)
            } else {
                try {
                    $RecentJobsList = @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/admin/configurationManagement/configurationSnapshotJobs?`$orderby=createdDateTime desc&`$top=$RecentJobsCount" -OutputType PSObject -DisableCache -ThrowOnFailure -FirstPageOnly)
                    $JobIdsToQuery = @($RecentJobsList | Select-Object -ExpandProperty id)
                } catch {
                    Write-Warning "Failed to list recent Tenant Governance snapshot jobs from Microsoft Graph. Error: $_"
                }
            }

            foreach ($JobId in $JobIdsToQuery) {
                try {
                    # 'errorDetails' and 'resources' are not returned by default and require an explicit $select.
                    $JobDetail = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/admin/configurationManagement/configurationSnapshotJobs/$($JobId)?`$select=id,displayName,description,status,resources,errorDetails,createdDateTime,completedDateTime,resourceLocation,tenantId" -OutputType PSObject -DisableCache -ThrowOnFailure
                } catch {
                    Write-Warning "Failed to retrieve details of snapshot job '$JobId'. Error: $_"
                    continue
                }

                $RequestedResources = @($JobDetail.resources) | Where-Object { $null -ne $_ }

                # Parse the free-text 'errorDetails' blob(s) into one object per individual message
                # (ResourceType, ErrorCategory, ErrorCode, Message, ReferencedObjectIds) instead of
                # the raw, hard-to-read strings returned by Graph.
                $ParsedErrorDetails = @(@($JobDetail.errorDetails) | Where-Object { $_ } | ConvertFrom-EntraOpsTenantGovernanceSnapshotErrorDetail)

                # Graph does not expose a structured per-resource-type job outcome. Its errorDetails
                # are the authoritative signal for a resource type that failed or was only partially
                # captured; an empty folder alone can simply mean the tenant has no objects of that type.
                $ResourceTypesWithErrors = @(
                    $ParsedErrorDetails | ForEach-Object { $_.ResourceType } | Where-Object { $_ } | Select-Object -Unique
                )

                # Deduplicate near-identical messages that only differ by object Id (e.g. dozens of
                # "Resource '<id>' does not exist..." entries for different objects) into a single,
                # readable summary row with an occurrence count and the full list of affected Ids.
                $ErrorSummary = @(
                    $ParsedErrorDetails | Group-Object ResourceType, ErrorCategory, ErrorCode, NormalizedMessage | ForEach-Object {
                        $First = $_.Group[0]
                        [PSCustomObject]@{
                            ResourceType        = $First.ResourceType
                            ErrorCategory       = $First.ErrorCategory
                            ErrorCode           = $First.ErrorCode
                            Occurrences         = $_.Count
                            Message             = $First.NormalizedMessage
                            ReferencedObjectIds = @($_.Group | ForEach-Object { $_.ReferencedObjectIds } | Select-Object -Unique)
                        }
                    }
                )

                $SnapshotJobs.Add(
                    [PSCustomObject]@{
                        SnapshotId              = $JobDetail.id
                        DisplayName             = $JobDetail.displayName
                        Status                  = $JobDetail.status
                        CreatedDateTime         = $JobDetail.createdDateTime
                        CompletedDateTime       = $JobDetail.completedDateTime
                        RequestedResourceCount  = $RequestedResources.Count
                        ResourceTypesWithErrors = $ResourceTypesWithErrors
                        ErrorDetails            = $ParsedErrorDetails
                        ErrorSummary            = $ErrorSummary
                    }
                )
            }
        }
    }
    #endregion

    #region Emit warnings summarizing the actionable findings, then return the full report object
    if ($MissingOrEmptyResourceTypes.Count -gt 0) {
        Write-Verbose "$($MissingOrEmptyResourceTypes.Count) configured resource type(s) currently have no data on disk under '$SnapshotFolder': $($MissingOrEmptyResourceTypes -join ', ')"
    }
    $PersistedDiagnostics = @($SnapshotManifest.Diagnostics)
    # Literal prefix check: Graph messages often already start with "[<ErrorCode>]", and -like would
    # treat the brackets as a wildcard character class and never match.
    $GetErrorCodePrefix = {
        param($ErrorCode, $Message)
        if ([string]::IsNullOrWhiteSpace("$ErrorCode") -or "$Message".TrimStart().StartsWith("[$ErrorCode]", [System.StringComparison]::OrdinalIgnoreCase)) { return '' }
        return "[$ErrorCode] "
    }
    # A rejected attempt (for example duplicate canonical identities) is recorded only in the
    # last-attempt manifest so the last successful snapshot manifest stays intact. Surface its
    # diagnostics whenever that attempt is a different job than the published snapshot.
    $LastAttemptDiagnostics = @()
    if ($LastAttemptManifest -and -not [string]::IsNullOrWhiteSpace($LastAttemptManifest.SnapshotId) -and $LastAttemptManifest.SnapshotId -ne $SnapshotManifest.SnapshotId) {
        $LastAttemptDiagnostics = @($LastAttemptManifest.Diagnostics)
    }
    if ($SnapshotJobs.Count -eq 0 -and ($PersistedDiagnostics.Count -gt 0 -or $LastAttemptDiagnostics.Count -gt 0)) {
        $PersistedWarnings = @(
            foreach ($Diagnostic in $PersistedDiagnostics) {
                [PSCustomObject]@{
                    Type    = $Diagnostic.ResourceType
                    Message = "$(& $GetErrorCodePrefix $Diagnostic.ErrorCode $Diagnostic.Message)$($Diagnostic.Message)$(if ($Diagnostic.Occurrences -gt 1) { " ($($Diagnostic.Occurrences)x)" }) — $($Diagnostic.RemediationHint)"
                }
            }
            foreach ($Diagnostic in $LastAttemptDiagnostics) {
                [PSCustomObject]@{
                    Type    = $Diagnostic.ResourceType
                    Message = "[Last attempt $($LastAttemptManifest.SnapshotId)] $(& $GetErrorCodePrefix $Diagnostic.ErrorCode $Diagnostic.Message)$($Diagnostic.Message)$(if ($Diagnostic.Occurrences -gt 1) { " ($($Diagnostic.Occurrences)x)" }) — $($Diagnostic.RemediationHint)"
                }
            }
        )
        Show-EntraOpsWarningSummary -WarningMessages $PersistedWarnings
    }
    foreach ($Job in $SnapshotJobs) {
        if ($Job.Status -notin @("partiallySuccessful", "failed")) { continue }

        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
        Write-Host "  ⚠ Snapshot job $($Job.SnapshotId) ('$($Job.DisplayName)') - status: $($Job.Status)" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow

        if ($Job.ResourceTypesWithErrors.Count -gt 0) {
            Write-Host "  Resource type(s) with Graph-reported errors: $($Job.ResourceTypesWithErrors -join ', ')" -ForegroundColor Yellow
        }

        # Reuse the shared, grouped/deduped warning display (Type -> distinct Message with occurrence
        # counts) instead of dumping the raw errorDetails blob as a single hard-to-read line.
        $JobWarningMessages = [System.Collections.Generic.List[psobject]]::new()
        foreach ($ErrorEntry in $Job.ErrorSummary) {
            $Prefix = & $GetErrorCodePrefix $ErrorEntry.ErrorCode $ErrorEntry.Message
            $MessageText = "$Prefix$($ErrorEntry.Message)$(if ($ErrorEntry.Occurrences -gt 1) { " ($($ErrorEntry.Occurrences)x)" })"
            $JobWarningMessages.Add([PSCustomObject]@{ Type = $ErrorEntry.ResourceType; Message = $MessageText })
        }
        Show-EntraOpsWarningSummary -WarningMessages $JobWarningMessages
    }

    [PSCustomObject]@{
        TenantId                    = $Global:TenantIdContext
        GeneratedDateTime           = (Get-Date).ToUniversalTime().ToString("o")
        ConfigFilePath              = $ConfigFilePath
        SnapshotFolder              = $SnapshotFolder
        SnapshotManifest            = $SnapshotManifest
        LastAttemptManifest         = $LastAttemptManifest
        ConfiguredResourceCount     = $ConfiguredResources.Count
        MissingOrEmptyResourceTypes = $MissingOrEmptyResourceTypes
        StaleResourceTypes          = $StaleResourceTypes
        PersistedDiagnostics        = $PersistedDiagnostics
        LastAttemptDiagnostics      = $LastAttemptDiagnostics
        ErrorDetailsUnavailable     = $SnapshotManifest.ErrorDetailsUnavailable -eq $true
        ResourceCoverage            = @($ResourceCoverage | Sort-Object Status, ResourceType)
        UnconfiguredResourcesOnDisk = $UnconfiguredOnDisk
        SnapshotJobs                = @($SnapshotJobs)
    }
    #endregion
}
