<#
.SYNOPSIS
    Create and retrieve a Microsoft Entra Tenant Configuration Management (UTCM) snapshot.

.DESCRIPTION
    Uses the Microsoft Graph Tenant Configuration Management (also known as Universal Tenant
    Configuration Management, UTCM) API to create a point-in-time snapshot of the configured
    Microsoft Entra resources (e.g. Conditional Access policies, authentication methods,
    cross-tenant access policy, authorization policy, ...), waits for the snapshot job to
    complete and returns the captured resource configuration.

    Requires the "ConfigurationMonitoring.ReadWrite.All" Microsoft Graph application permission on
    the calling identity (the default permission granted by New-EntraOpsWorkloadIdentity) - this is
    Microsoft's documented least-privileged permission for the createSnapshot API, and
    "ConfigurationMonitoring.Read.All" alone is not sufficient to create a snapshot job. It also
    requires read permissions on the first-party "Microsoft Tenant Configuration Management" service
    principal for the requested resource types. Both prerequisites are configured by
    Register-EntraOpsTenantGovernanceServicePrincipal (called automatically by
    New-EntraOpsWorkloadIdentity when TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot is
    set to $true in the config file), and are validated automatically before the snapshot job is
    created via Test-EntraOpsTenantGovernancePrerequisite. If an existing workload identity was set
    up with an older EntraOps version that only granted "ConfigurationMonitoring.Read.All", re-apply
    the required permission via Register-EntraOpsTenantGovernanceServicePrincipal -GrantConfigurationMonitoringReadWrite.

    Reference: https://learn.microsoft.com/en-us/graph/api/configurationbaseline-createsnapshot

.NOTES
    UTCM enforces service limits on captured resources per tenant and keeps snapshot results
    server-side only for a limited period. The exact figures are set by the service and change
    independently of EntraOps, so verify them against https://learn.microsoft.com/en-us/graph/api/resources/unified-tenant-configuration-management-api-overview?view=graph-rest-1.0#api-limits
    before rollout. Daily or weekly scheduling (see TenantGovernanceSnapshot.SnapshotScheduledCron
    in the config file) suits a default ResourcesToInclude set. If ResourcesToInclude is extended with
    high-cardinality resource types (e.g. "microsoft.entra.user", "group", "servicePrincipal",
    "application"), prefer a weekly (or less frequent) cadence to stay within the resource limit.

.PARAMETER ResourcesToInclude
    Array of Microsoft Entra resource types (e.g. "microsoft.entra.conditionalAccessPolicy") to
    include in the snapshot. Defaults to the recommended tenant governance resource set.

.PARAMETER SnapshotDisplayName
    Display name of the snapshot. Default is "EntraOps TG <yyyyMMddHHmmss>". The
    Microsoft Graph UTCM API only allows alphabets, numbers, and spaces in this value - any other
    characters (e.g. hyphens) are stripped automatically.

.PARAMETER SnapshotDescription
    Description of the snapshot.

.PARAMETER TimeoutInSeconds
    Maximum time (in seconds) to wait for the snapshot job to complete. Default is 900 (15 minutes).
    When the timeout is reached, the job is not cancelled: a pending result object (Status is the
    last known job status) is returned so the job can be completed later with -SnapshotJobId.

.PARAMETER PollIntervalInSeconds
    Interval (in seconds) between polling attempts for the snapshot job status. Default is 10.

.PARAMETER SnapshotJobId
    Resume an existing snapshot job instead of creating a new one (e.g. a job Id returned by a
    previous call made with -SkipWaitForCompletion). When supplied, ResourcesToInclude,
    SnapshotDisplayName and SnapshotDescription are ignored for job creation purposes.

.PARAMETER SkipWaitForCompletion
    Return immediately after creating (or checking) the snapshot job instead of polling until it
    completes. Useful to split long-running snapshots (UTCM jobs for large resource sets can take
    up to an hour) across two separate runs: an initial run that starts the job with this switch,
    and a later run that completes it by passing the returned SnapshotId to -SnapshotJobId. The
    returned object's Status property indicates whether the job is still pending or has completed.

.PARAMETER SkipPrerequisiteCheck
    Skip the automatic prerequisite validation (Test-EntraOpsTenantGovernancePrerequisite) before
    creating the snapshot job. Default is $false.

.EXAMPLE
    Create a snapshot of the default tenant governance resources and wait for completion.
    Get-EntraOpsTenantGovernanceSnapshot

.EXAMPLE
    Create a snapshot of only Conditional Access policies and Named Locations.
    Get-EntraOpsTenantGovernanceSnapshot -ResourcesToInclude @("microsoft.entra.conditionalAccessPolicy","microsoft.entra.namedLocationPolicy")

.EXAMPLE
    Start a snapshot job without waiting for it to complete, then complete it in a later run.
    $Job = Get-EntraOpsTenantGovernanceSnapshot -SkipWaitForCompletion
    # ... in a separate, later run ...
    Get-EntraOpsTenantGovernanceSnapshot -SnapshotJobId $Job.SnapshotId
#>
function Get-EntraOpsTenantGovernanceSnapshot {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Array]$ResourcesToInclude = (Get-EntraOpsTenantGovernanceResourceDefinition).DefaultResources
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$SnapshotDisplayName = "EntraOps TG $((Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'))"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$SnapshotDescription = "EntraOps Tenant Governance snapshot of Microsoft Entra configuration"
        ,
        [Parameter(Mandatory = $false)]
        [System.Int32]$TimeoutInSeconds = 900
        ,
        [Parameter(Mandatory = $false)]
        [System.Int32]$PollIntervalInSeconds = 10
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$SnapshotJobId
        ,
        [Parameter(Mandatory = $false)]
        [switch]$SkipWaitForCompletion
        ,
        [Parameter(Mandatory = $false)]
        [switch]$SkipPrerequisiteCheck
    )

    $ErrorActionPreference = "Stop"

    # Job failures never succeed on a later collect: their error id lets callers release the pending job
    $NewTerminalSnapshotJobError = {
        param([string]$Message)
        [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new($Message),
            'EntraOpsTenantGovernanceSnapshotJobTerminal',
            [System.Management.Automation.ErrorCategory]::InvalidResult,
            $SnapshotJobId)
    }

    # Filter out any null values resulting from PowerShell array wrapping of $null
    $ResourcesToInclude = @($ResourcesToInclude) | Where-Object { $null -ne $_ }

    if ($ResourcesToInclude.Count -eq 0) {
        throw "ResourcesToInclude can not be empty. Provide at least one Microsoft Entra resource type (e.g. 'microsoft.entra.conditionalAccessPolicy')."
    }

    # The UTCM API only allows alphabets, numbers, and spaces in the snapshot displayName,
    # and enforces a length between 8 and 32 characters.
    # Sanitize defensively in case a caller-supplied name contains hyphens, other punctuation, or is too long.
    $SnapshotDisplayName = ($SnapshotDisplayName -replace '[^a-zA-Z0-9 ]', ' ') -replace '\s+', ' '
    $SnapshotDisplayName = $SnapshotDisplayName.Trim()
    if ($SnapshotDisplayName.Length -gt 32) {
        $SnapshotDisplayName = $SnapshotDisplayName.Substring(0, 32).TrimEnd()
    }
    if ($SnapshotDisplayName.Length -lt 8) {
        $SnapshotDisplayName = $SnapshotDisplayName.PadRight(8, '0')
    }

    #region Validate prerequisites (UTCM service principal + permissions)
    if (-not $SkipPrerequisiteCheck) {
        Write-Verbose "Validating Tenant Governance Snapshot prerequisites..."
        Test-EntraOpsTenantGovernancePrerequisite -ResourcesToInclude $ResourcesToInclude -ThrowOnFailure | Out-Null
    }
    #endregion

    #region Create the configuration snapshot job (or reuse an existing one via -SnapshotJobId)
    $CreatedNewSnapshotJob = [string]::IsNullOrEmpty($SnapshotJobId)
    if (-not [string]::IsNullOrEmpty($SnapshotJobId)) {
        Write-Verbose "Resuming existing Tenant Governance snapshot job $SnapshotJobId"
    } else {
        Write-Verbose "Creating Tenant Governance snapshot '$SnapshotDisplayName' for $(@($ResourcesToInclude).Count) resource type(s)..."
        $Body = @{
            displayName = $SnapshotDisplayName
            description = $SnapshotDescription
            resources   = @($ResourcesToInclude)
        } | ConvertTo-Json -Depth 10

        try {
            $CreatedSnapshotJob = Invoke-EntraOpsMsGraphQuery -Method "POST" -Body $Body -Uri "/beta/admin/configurationManagement/configurationSnapshots/createSnapshot" -OutputType PSObject -DisableCache -ThrowOnFailure
        } catch {
            throw "Failed to create Tenant Governance snapshot job. Error: $_"
        }

        $SnapshotJobId = $CreatedSnapshotJob.id
        if ([string]::IsNullOrEmpty($SnapshotJobId)) {
            throw "Failed to retrieve the snapshot job Id from the createSnapshot response."
        }
        Write-Verbose "Snapshot job created with Id $SnapshotJobId"
    }
    #endregion

    #region Wait for the snapshot job to complete (or return immediately if -SkipWaitForCompletion is set)
    $SnapshotJob = $null
    $LastPollingError = $null
    $SnapshotJobUri = "/beta/admin/configurationManagement/configurationSnapshotJobs/$($SnapshotJobId)?`$select=id,displayName,description,status,resources,errorDetails,createdDateTime,completedDateTime,resourceLocation,tenantId"
    if ($SkipWaitForCompletion -and $CreatedNewSnapshotJob) {
        $InitialStatus = if ([string]::IsNullOrWhiteSpace($CreatedSnapshotJob.status)) { 'notStarted' } else { $CreatedSnapshotJob.status }
        Write-Verbose "Snapshot job $SnapshotJobId was created (status: $InitialStatus). Complete it later with: Get-EntraOpsTenantGovernanceSnapshot -SnapshotJobId $SnapshotJobId"
        return [PSCustomObject]@{
            SnapshotId         = $SnapshotJobId
            Status             = $InitialStatus
            DisplayName        = $CreatedSnapshotJob.displayName
            Description        = $CreatedSnapshotJob.description
            CreatedDateTime    = if ($CreatedSnapshotJob.createdDateTime) { $CreatedSnapshotJob.createdDateTime } else { (Get-Date).ToUniversalTime().ToString("o") }
            ResourcesToInclude = @($ResourcesToInclude)
            ResourceCount      = $null
            Resources          = $null
            PollingError       = $null
        }
    }

    # Preserve the creation response as the last known state until the first status poll succeeds.
    # This retains useful metadata if every polling request fails.
    if ($CreatedNewSnapshotJob) {
        $SnapshotJob = $CreatedSnapshotJob
    }

    if ($SkipWaitForCompletion) {
        Write-Verbose "Checking status of snapshot job $SnapshotJobId (not waiting for completion)..."
        try {
            $SnapshotJob = Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri $SnapshotJobUri -OutputType PSObject -DisableCache -ThrowOnFailure
            $LastPollingError = $null
        } catch {
            throw "Failed to retrieve status of snapshot job $SnapshotJobId. Error: $_"
        }

        if ($SnapshotJob.status -eq "failed") {
            throw (& $NewTerminalSnapshotJobError "Tenant Governance snapshot job $SnapshotJobId failed. Error: $($SnapshotJob.error | Out-String)")
        }
        if ($SnapshotJob.status -notin @("succeeded", "completed", "partiallySuccessful")) {
            Write-Verbose "Snapshot job $SnapshotJobId has not completed yet (status: $($SnapshotJob.status)). Complete it later with: Get-EntraOpsTenantGovernanceSnapshot -SnapshotJobId $SnapshotJobId"
            return [PSCustomObject]@{
                SnapshotId         = $SnapshotJobId
                Status             = $SnapshotJob.status
                DisplayName        = $SnapshotJob.displayName
                Description        = $SnapshotJob.description
                CreatedDateTime    = if ($SnapshotJob.createdDateTime) { $SnapshotJob.createdDateTime } else { (Get-Date).ToUniversalTime().ToString("o") }
                ResourcesToInclude = @($ResourcesToInclude)
                ResourceCount      = $null
                Resources          = $null
                PollingError       = $null
            }
        }
        if ($SnapshotJob.status -eq "partiallySuccessful") {
            Write-Warning "Snapshot job $SnapshotJobId completed as 'partiallySuccessful' - one or more resource types may have failed to capture. Check the snapshot job details in the Microsoft Entra admin center for more information."
        }
    } else {
        Write-Verbose "Waiting for snapshot job to complete (timeout: $($TimeoutInSeconds)s)..."
        $StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        do {
            Start-Sleep -Seconds $PollIntervalInSeconds
            try {
                $SnapshotJob = Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri $SnapshotJobUri -OutputType PSObject -DisableCache -ThrowOnFailure
                $LastPollingError = $null
            } catch {
                $LastPollingError = $_
                Write-Warning "Failed to poll snapshot job status. Retrying... Error: $_"
            }
            $ElapsedSeconds = [math]::Floor($StopWatch.Elapsed.TotalSeconds)
            $SnapshotStatus = if ([string]::IsNullOrWhiteSpace($SnapshotJob.status)) { 'unknown' } else { $SnapshotJob.status }
            Write-Verbose "Snapshot job $SnapshotJobId status: $SnapshotStatus (elapsed: $ElapsedSeconds/$TimeoutInSeconds seconds)"
        } while (
            $SnapshotJob.status -notin @("succeeded", "completed", "partiallySuccessful", "failed") `
                -and $StopWatch.Elapsed.TotalSeconds -lt $TimeoutInSeconds
        )
        $StopWatch.Stop()

        if ($SnapshotJob.status -eq "failed") {
            throw (& $NewTerminalSnapshotJobError "Tenant Governance snapshot job $SnapshotJobId failed. Error: $($SnapshotJob.error | Out-String)")
        }
        if ($SnapshotJob.status -notin @("succeeded", "completed", "partiallySuccessful")) {
            # The local wait does not cancel the Graph job, so return a resumable pending result
            # instead of throwing - otherwise the job Id is lost and no state can be persisted.
            $LastKnownStatus = if ([string]::IsNullOrEmpty($SnapshotJob.status)) { "unknown" } else { $SnapshotJob.status }
            $PollingErrorMessage = if ($LastPollingError) { $LastPollingError.ToString() } else { $null }
            if ($PollingErrorMessage) {
                Write-Warning "Tenant Governance snapshot job $SnapshotJobId did not complete within $($TimeoutInSeconds) seconds and its completion could not be confirmed (last known status: $LastKnownStatus; last polling error: $PollingErrorMessage). The job was not cancelled - check it later with: Get-EntraOpsTenantGovernanceSnapshot -SnapshotJobId $SnapshotJobId"
            } else {
                Write-Warning "Tenant Governance snapshot job $SnapshotJobId did not complete within $($TimeoutInSeconds) seconds (last status: $LastKnownStatus). The job was not cancelled - check it later with: Get-EntraOpsTenantGovernanceSnapshot -SnapshotJobId $SnapshotJobId"
            }
            return [PSCustomObject]@{
                SnapshotId         = $SnapshotJobId
                Status             = $LastKnownStatus
                DisplayName        = $SnapshotJob.displayName
                Description        = $SnapshotJob.description
                CreatedDateTime    = if ($SnapshotJob.createdDateTime) { $SnapshotJob.createdDateTime } elseif ($CreatedSnapshotJob.createdDateTime) { $CreatedSnapshotJob.createdDateTime } else { (Get-Date).ToUniversalTime().ToString("o") }
                ResourcesToInclude = @($ResourcesToInclude)
                ResourceCount      = $null
                Resources          = $null
                PollingError       = $PollingErrorMessage
            }
        }
        if ($SnapshotJob.status -eq "partiallySuccessful") {
            Write-Warning "Snapshot job $SnapshotJobId completed as 'partiallySuccessful' - one or more resource types may have failed to capture. Check the snapshot job details in the Microsoft Entra admin center for more information."
        }
    }
    #endregion

    #region Retrieve the captured resources from the snapshot
    $ResourceLocation = $SnapshotJob.resourceLocation
    if ([string]::IsNullOrEmpty($ResourceLocation)) {
        throw (& $NewTerminalSnapshotJobError "Snapshot job $SnapshotJobId completed but no resourceLocation was returned.")
    }

    # resourceLocation can be returned as a fully qualified Graph URL or a relative path.
    if ($ResourceLocation -notlike "https://graph.microsoft.com/*" -and $ResourceLocation -notlike "/beta/*" -and $ResourceLocation -notlike "/v1.0/*") {
        $ResourceLocation = "/beta/" + $ResourceLocation.TrimStart('/')
    }

    try {
        $SnapshotResult = Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri $ResourceLocation -OutputType PSObject -DisableCache -ThrowOnFailure
    } catch {
        throw "Failed to retrieve snapshot resources from $ResourceLocation. Error: $_"
    }

    $SnapshotResources = @($SnapshotResult.resources)
    if ($null -eq $SnapshotResult -or $SnapshotResources.Count -eq 0) {
        throw (& $NewTerminalSnapshotJobError "Snapshot job $SnapshotJobId completed, but its resourceLocation returned no snapshot resources. Refusing to publish an empty snapshot.")
    }
    #endregion

    # The snapshot age counts from the job creation, not from the download of its results
    $CapturedDateTime = (Get-Date).ToUniversalTime().ToString("o")
    if ($null -ne $SnapshotJob.createdDateTime -and -not [string]::IsNullOrWhiteSpace("$($SnapshotJob.createdDateTime)")) {
        $JobCreatedDateTime = [datetimeoffset]::MinValue
        if ($SnapshotJob.createdDateTime -is [datetime]) {
            $CapturedDateTime = $SnapshotJob.createdDateTime.ToUniversalTime().ToString("o")
        } elseif ([datetimeoffset]::TryParse("$($SnapshotJob.createdDateTime)", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$JobCreatedDateTime)) {
            $CapturedDateTime = $JobCreatedDateTime.UtcDateTime.ToString("o")
        }
    }

    [PSCustomObject]@{
        SnapshotId         = $SnapshotJobId
        Status             = "Completed"
        SnapshotJobStatus  = $SnapshotJob.status
        DisplayName        = $SnapshotResult.displayName
        Description        = $SnapshotResult.description
        CreatedDateTime    = $CapturedDateTime
        ResourcesToInclude = @($ResourcesToInclude)
        ResourceCount      = $SnapshotResources.Count
        Resources          = $SnapshotResources
        ErrorDetails       = @($SnapshotJob.errorDetails)
        PollingError       = $null
    }
}
