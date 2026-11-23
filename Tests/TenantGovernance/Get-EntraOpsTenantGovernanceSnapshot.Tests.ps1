#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsPathWithinRoot.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Limit-EntraOpsFilePathSegmentLength.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/ConvertTo-EntraOpsSafeFilePathSegment.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/ConvertTo-EntraOpsSortedObject.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/ConvertFrom-EntraOpsTenantGovernanceSnapshotErrorDetail.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsTenantGovernanceResourceGraphState.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsTenantGovernanceStaleSince.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/TenantGovernance/Get-EntraOpsTenantGovernanceSnapshot.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/TenantGovernance/Save-EntraOpsTenantGovernanceSnapshotJson.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Show-EntraOpsWarningSummary.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsTenantGovernanceResourceDefinition.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/TenantGovernance/Get-EntraOpsTenantGovernanceSnapshotReport.ps1"

    function Test-EntraOpsTenantGovernancePrerequisite {}
    function Invoke-EntraOpsMsGraphQuery {}

    # Save-EntraOpsTenantGovernanceSnapshotJson falls back to the loaded configuration
    $script:PreviousEntraOpsConfig = Get-Variable EntraOpsConfig -Scope Global -ErrorAction SilentlyContinue
    $Global:EntraOpsConfig = $null
}

AfterAll {
    if ($script:PreviousEntraOpsConfig) {
        Set-Variable EntraOpsConfig -Scope Global -Value $script:PreviousEntraOpsConfig.Value
    } else {
        Remove-Variable EntraOpsConfig -Scope Global -ErrorAction SilentlyContinue
    }
}

Describe 'Save-EntraOpsTenantGovernanceSnapshotJson configuration fallback' {
    BeforeEach {
        $script:EntraOpsBaseFolder = Join-Path $TestDrive "EntraOpsConfigFallback-$([guid]::NewGuid().Guid)"
        $script:ExportFolder = Join-Path $script:EntraOpsBaseFolder 'TenantGovernance/Snapshots'
        New-Item -ItemType Directory -Path $script:EntraOpsBaseFolder -Force | Out-Null
        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{ SnapshotId = 'job-config'; Status = 'running'; DisplayName = $SnapshotDisplayName; CreatedDateTime = '2026-09-24T06:00:00Z'; ResourcesToInclude = $ResourcesToInclude }
        }
        $Global:EntraOpsConfig = @{
            TenantGovernanceSnapshot = @{
                ResourcesToInclude         = @('microsoft.entra.namedLocationPolicy')
                SnapshotDisplayNamePrefix  = 'Contoso Snap'
                SnapshotResourceFileNaming = 'ResourceId'
            }
        }
    }

    AfterEach {
        $Global:EntraOpsConfig = $null
    }

    It 'uses the prefix and resources of the loaded configuration' {
        Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -Operation Start -SkipPrerequisiteCheck | Out-Null

        Should -Invoke Get-EntraOpsTenantGovernanceSnapshot -Times 1 -Exactly -ParameterFilter {
            $SnapshotDisplayName -like 'Contoso Snap *' -and @($ResourcesToInclude) -join ',' -eq 'microsoft.entra.namedLocationPolicy'
        }
    }

    It 'prefers explicit parameters over the configuration' {
        Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -Operation Start -SnapshotDisplayNamePrefix 'Manual Run' -ResourcesToInclude @('microsoft.entra.conditionalAccessPolicy') -SkipPrerequisiteCheck | Out-Null

        Should -Invoke Get-EntraOpsTenantGovernanceSnapshot -Times 1 -Exactly -ParameterFilter {
            $SnapshotDisplayName -like 'Manual Run *' -and @($ResourcesToInclude) -join ',' -eq 'microsoft.entra.conditionalAccessPolicy'
        }
    }

    It 'uses the file naming of the loaded configuration' {
        $Type = 'microsoft.entra.namedlocationpolicy'
        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId = 'job-config-naming'; Status = 'Completed'; SnapshotJobStatus = 'succeeded'
                DisplayName = 'Test Snapshot'; CreatedDateTime = '2026-09-24T06:00:00Z'
                ResourcesToInclude = @($Type); ResourceCount = 1
                Resources = @([PSCustomObject]@{ resourceType = $Type; displayName = 'AADNamedLocationPolicy-Office'; properties = [PSCustomObject]@{ Id = 'location-1' } })
            }
        }

        Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null

        Test-Path -LiteralPath (Join-Path $script:ExportFolder "$Type/AADNamedLocationPolicy/location-1.json") | Should -BeTrue
    }

    It 'rejects an invalid file naming value in the configuration' {
        $Global:EntraOpsConfig.TenantGovernanceSnapshot.SnapshotResourceFileNaming = 'Guid'

        { Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -Operation Start -SkipPrerequisiteCheck } |
        Should -Throw "*Invalid TenantGovernanceSnapshot.SnapshotResourceFileNaming 'Guid'*"
    }
}

Describe 'Get-EntraOpsTenantGovernanceSnapshot timeout handling' {
    BeforeEach {
        Mock Start-Sleep {}
        Mock Test-EntraOpsTenantGovernancePrerequisite {}
    }

    It 'returns resumable state with the Graph creation time when the wait expires' {
        $GraphCreatedDateTime = '2026-08-30T10:11:12Z'
        Mock Invoke-EntraOpsMsGraphQuery {
            param ($Method)

            if ($Method -eq 'POST') {
                return [PSCustomObject]@{
                    id              = 'job-timeout'
                    status          = 'notStarted'
                    displayName     = 'Test Snapshot'
                    description     = 'Test snapshot'
                    createdDateTime = $GraphCreatedDateTime
                }
            }

            return [PSCustomObject]@{
                id              = 'job-timeout'
                status          = 'running'
                displayName     = 'Test Snapshot'
                description     = 'Test snapshot'
                createdDateTime = $GraphCreatedDateTime
            }
        }

        $Result = Get-EntraOpsTenantGovernanceSnapshot `
            -ResourcesToInclude @('microsoft.entra.conditionalAccessPolicy') `
            -TimeoutInSeconds 0 `
            -PollIntervalInSeconds 0 `
            -SkipPrerequisiteCheck `
            -WarningAction SilentlyContinue

        $Result.SnapshotId | Should -Be 'job-timeout'
        $Result.Status | Should -Be 'running'
        $Result.CreatedDateTime | Should -Be $GraphCreatedDateTime
        $Result.PollingError | Should -BeNullOrEmpty
    }

    It 'retains the creation response and latest error when every poll fails' {
        Mock Invoke-EntraOpsMsGraphQuery {
            param ($Method)

            if ($Method -eq 'POST') {
                return [PSCustomObject]@{
                    id              = 'job-poll-failure'
                    status          = 'notStarted'
                    displayName     = 'Test Snapshot'
                    description     = 'Test snapshot'
                    createdDateTime = '2026-08-30T10:11:12Z'
                }
            }

            throw 'simulated polling outage'
        }

        $Warnings = @()
        $Result = Get-EntraOpsTenantGovernanceSnapshot `
            -ResourcesToInclude @('microsoft.entra.conditionalAccessPolicy') `
            -TimeoutInSeconds 0 `
            -PollIntervalInSeconds 0 `
            -SkipPrerequisiteCheck `
            -WarningVariable Warnings `
            -WarningAction SilentlyContinue

        $Result.SnapshotId | Should -Be 'job-poll-failure'
        $Result.Status | Should -Be 'notStarted'
        $Result.CreatedDateTime | Should -Be '2026-08-30T10:11:12Z'
        $Result.PollingError | Should -Match 'simulated polling outage'
        $Warnings[-1].Message | Should -Match 'completion could not be confirmed'
        $Warnings[-1].Message | Should -Not -Match 'still running'
    }

    It 'can resume a pending job and return its completed resources' {
        Mock Invoke-EntraOpsMsGraphQuery {
            param ($Method, $Uri)

            if ($Uri -like '*/configurationSnapshotJobs/*') {
                return [PSCustomObject]@{
                    id               = 'job-completed'
                    status           = 'succeeded'
                    displayName      = 'Test Snapshot'
                    description      = 'Test snapshot'
                    createdDateTime  = '2026-08-30T10:11:12Z'
                    resourceLocation = '/beta/admin/configurationManagement/configurationSnapshots/job-completed'
                    errorDetails     = @()
                }
            }

            return [PSCustomObject]@{
                displayName = 'Test Snapshot'
                description = 'Test snapshot'
                resources   = @([PSCustomObject]@{ id = 'resource-1' })
            }
        }

        $Result = Get-EntraOpsTenantGovernanceSnapshot `
            -SnapshotJobId 'job-completed' `
            -ResourcesToInclude @('microsoft.entra.conditionalAccessPolicy') `
            -SkipWaitForCompletion `
            -SkipPrerequisiteCheck

        $Result.Status | Should -Be 'Completed'
        $Result.SnapshotJobStatus | Should -Be 'succeeded'
        $Result.ResourceCount | Should -Be 1
        $Result.Resources[0].id | Should -Be 'resource-1'
        # The snapshot age counts from the job creation, not from the later download of its results
        $Result.CreatedDateTime | Should -Be ([datetime]::new(2026, 8, 30, 10, 11, 12, [System.DateTimeKind]::Utc).ToString('o'))
    }

    It 'marks a failed snapshot job as terminal' {
        Mock Invoke-EntraOpsMsGraphQuery {
            [PSCustomObject]@{ id = 'job-failed'; status = 'failed'; error = 'simulated job failure' }
        }

        $ErrorRecord = $null
        try {
            Get-EntraOpsTenantGovernanceSnapshot -SnapshotJobId 'job-failed' -ResourcesToInclude @('microsoft.entra.conditionalAccessPolicy') -SkipWaitForCompletion -SkipPrerequisiteCheck
        } catch {
            $ErrorRecord = $_
        }

        $ErrorRecord.FullyQualifiedErrorId | Should -BeLike 'EntraOpsTenantGovernanceSnapshotJobTerminal*'
        $ErrorRecord.Exception.Message | Should -Match 'job-failed failed'
    }

    It 'does not mark a failed status request as terminal' {
        Mock Invoke-EntraOpsMsGraphQuery { throw 'simulated polling outage' }

        $ErrorRecord = $null
        try {
            Get-EntraOpsTenantGovernanceSnapshot -SnapshotJobId 'job-transient' -ResourcesToInclude @('microsoft.entra.conditionalAccessPolicy') -SkipWaitForCompletion -SkipPrerequisiteCheck
        } catch {
            $ErrorRecord = $_
        }

        $ErrorRecord | Should -Not -BeNullOrEmpty
        $ErrorRecord.FullyQualifiedErrorId | Should -Not -BeLike 'EntraOpsTenantGovernanceSnapshotJobTerminal*'
    }
}

Describe 'Save-EntraOpsTenantGovernanceSnapshotJson pending state' {
    BeforeEach {
        $script:EntraOpsBaseFolder = Join-Path $TestDrive 'EntraOps'
        $script:ExportFolder = Join-Path $script:EntraOpsBaseFolder 'TenantGovernance/Snapshots'
        New-Item -ItemType Directory -Path $script:EntraOpsBaseFolder -Force | Out-Null
    }

    It 'persists the resumable job without publishing snapshot resources' {
        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId         = 'job-timeout'
                Status             = 'unknown'
                DisplayName        = 'Test Snapshot'
                CreatedDateTime    = '2026-08-30T10:11:12Z'
                ResourcesToInclude = @('microsoft.entra.conditionalAccessPolicy')
                ResourceCount      = $null
                Resources          = $null
                PollingError       = 'simulated polling outage'
            }
        }

        # The cmdlet also emits progress strings, so select the result object like the workflow does.
        $PreviousTenantIdContext = $Global:TenantIdContext
        $PreviousTenantNameContext = $Global:TenantNameContext
        try {
            $Global:TenantIdContext = '00000000-0000-0000-0000-000000000001'
            $Global:TenantNameContext = 'contoso.onmicrosoft.com'
            $Output = Save-EntraOpsTenantGovernanceSnapshotJson `
                -ExportFolder $script:ExportFolder `
                -ResourcesToInclude @('microsoft.entra.conditionalAccessPolicy') `
                -TimeoutInSeconds 0 `
                -SkipPrerequisiteCheck
        } finally {
            $Global:TenantIdContext = $PreviousTenantIdContext
            $Global:TenantNameContext = $PreviousTenantNameContext
        }
        $Result = @($Output | Where-Object { $_ -isnot [string] }) | Select-Object -Last 1

        $PendingJobPath = Join-Path $script:ExportFolder '.PendingSnapshotJob.json'
        $PendingJob = Get-Content -Path $PendingJobPath -Raw | ConvertFrom-Json

        $Result.SnapshotJobId | Should -Be 'job-timeout'
        $PendingJob.CreatedDateTime.ToUniversalTime().ToString('o') | Should -Be '2026-08-30T10:11:12.0000000Z'
        $PendingJob.LastKnownStatus | Should -Be 'unknown'
        $PendingJob.LastPollingError | Should -Match 'simulated polling outage'
        # The tenant of the job, which Invoke-EntraOpsAssessment compares with the connected tenant
        $PendingJob.TenantId | Should -Be '00000000-0000-0000-0000-000000000001'
        $PendingJob.TenantName | Should -Be 'contoso.onmicrosoft.com'
        Test-Path (Join-Path $script:ExportFolder '.SnapshotManifest.json') | Should -BeFalse
        @(Get-ChildItem -Path $script:ExportFolder -Recurse -Force -Filter '*.json').Count | Should -Be 1
    }

    It 'releases a pending job that can never be collected and records the failure' {
        # A failed job would otherwise block every later Start ("already exists") and Collect (same failure).
        $script:ExportFolder = Join-Path $script:EntraOpsBaseFolder 'TenantGovernance/SnapshotsTerminal'
        New-Item -ItemType Directory -Path $script:ExportFolder -Force | Out-Null
        $PendingJobPath = Join-Path $script:ExportFolder '.PendingSnapshotJob.json'
        @{ SnapshotJobId = 'job-terminal'; SnapshotDisplayName = 'Test Snapshot'; ResourcesToInclude = @('microsoft.entra.conditionalAccessPolicy'); CreatedDateTime = '2026-10-17T06:00:00Z' } |
            ConvertTo-Json | Set-Content -LiteralPath $PendingJobPath -Encoding utf8
        Mock Get-EntraOpsTenantGovernanceSnapshot {
            throw [System.Management.Automation.ErrorRecord]::new(
                [System.InvalidOperationException]::new('Tenant Governance snapshot job job-terminal failed.'),
                'EntraOpsTenantGovernanceSnapshotJobTerminal', 'InvalidResult', 'job-terminal')
        }

        { Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') -Operation Collect -SkipPrerequisiteCheck -WarningAction SilentlyContinue } |
            Should -Throw '*job-terminal failed*'

        Test-Path -LiteralPath $PendingJobPath | Should -BeFalse
        $LastAttempt = Get-Content -LiteralPath (Join-Path $script:ExportFolder '.LastAttemptManifest.json') -Raw | ConvertFrom-Json
        $LastAttempt.SnapshotId | Should -Be 'job-terminal'
        $LastAttempt.IsComplete | Should -BeFalse
        $LastAttempt.Diagnostics[0].ErrorCode | Should -Be 'SnapshotJobNotCollectable'
        Test-Path -LiteralPath (Join-Path $script:ExportFolder '.SnapshotManifest.json') | Should -BeFalse
    }

    It 'does not collect or release the pending job of another tenant' {
        $script:ExportFolder = Join-Path $script:EntraOpsBaseFolder 'TenantGovernance/SnapshotsOtherTenant'
        New-Item -ItemType Directory -Path $script:ExportFolder -Force | Out-Null
        $PendingJobPath = Join-Path $script:ExportFolder '.PendingSnapshotJob.json'
        @{ SnapshotJobId = 'job-fabrikam'; ResourcesToInclude = @('microsoft.entra.conditionalAccessPolicy'); CreatedDateTime = '2026-10-17T06:00:00Z'; TenantId = '00000000-0000-0000-0000-000000000002'; TenantName = 'fabrikam.onmicrosoft.com' } |
            ConvertTo-Json | Set-Content -LiteralPath $PendingJobPath -Encoding utf8
        Mock Get-EntraOpsTenantGovernanceSnapshot { throw 'must not be called' }

        $PreviousTenantIdContext = $Global:TenantIdContext
        try {
            $Global:TenantIdContext = '00000000-0000-0000-0000-000000000001'
            { Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') -Operation Collect -SkipPrerequisiteCheck } |
                Should -Throw '*belongs to tenant fabrikam.onmicrosoft.com*The pending job is kept.'
        } finally {
            $Global:TenantIdContext = $PreviousTenantIdContext
        }

        Should -Invoke Get-EntraOpsTenantGovernanceSnapshot -Times 0
        Test-Path -LiteralPath $PendingJobPath | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:ExportFolder '.LastAttemptManifest.json') | Should -BeFalse
    }

    It 'keeps a pending job when its status can not be retrieved' {
        $script:ExportFolder = Join-Path $script:EntraOpsBaseFolder 'TenantGovernance/SnapshotsTransient'
        New-Item -ItemType Directory -Path $script:ExportFolder -Force | Out-Null
        $PendingJobPath = Join-Path $script:ExportFolder '.PendingSnapshotJob.json'
        @{ SnapshotJobId = 'job-transient'; ResourcesToInclude = @('microsoft.entra.conditionalAccessPolicy'); CreatedDateTime = '2026-10-17T06:00:00Z' } |
            ConvertTo-Json | Set-Content -LiteralPath $PendingJobPath -Encoding utf8
        Mock Get-EntraOpsTenantGovernanceSnapshot { throw 'Failed to retrieve status of snapshot job job-transient.' }

        { Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') -Operation Collect -SkipPrerequisiteCheck } |
            Should -Throw '*Failed to retrieve status*'

        Test-Path -LiteralPath $PendingJobPath | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:ExportFolder '.LastAttemptManifest.json') | Should -BeFalse
    }
}

Describe 'Save-EntraOpsTenantGovernanceSnapshotJson expired pending job' {
    BeforeEach {
        $script:EntraOpsBaseFolder = Join-Path $TestDrive "EntraOpsExpired-$([guid]::NewGuid().Guid)"
        $script:ExportFolder = Join-Path $script:EntraOpsBaseFolder 'TenantGovernance/Snapshots'
        New-Item -ItemType Directory -Path $script:ExportFolder -Force | Out-Null
        $script:PendingJobPath = Join-Path $script:ExportFolder '.PendingSnapshotJob.json'
        $script:LastAttemptPath = Join-Path $script:ExportFolder '.LastAttemptManifest.json'
        $script:WritePendingJob = {
            param([double]$AgeInHours)
            @{ SnapshotJobId = 'job-stuck'; SnapshotDisplayName = 'Stuck Snapshot'; ResourcesToInclude = @('microsoft.entra.conditionalAccessPolicy'); CreatedDateTime = (Get-Date).ToUniversalTime().AddHours(-$AgeInHours).ToString('o'); LastKnownStatus = 'notStarted' } |
                ConvertTo-Json | Set-Content -LiteralPath $script:PendingJobPath -Encoding utf8
        }
        $script:GraphCalls = [System.Collections.Generic.List[string]]::new()
        Mock Invoke-EntraOpsMsGraphQuery {
            param($Method, $Uri)
            $script:GraphCalls.Add("$Method $Uri")
        }
    }

    It 'releases a job that is still notStarted after PendingJobMaxAgeInHours on Collect and fails' {
        & $script:WritePendingJob 96
        Mock Get-EntraOpsTenantGovernanceSnapshot { [PSCustomObject]@{ SnapshotId = 'job-stuck'; Status = 'notStarted'; ResourcesToInclude = $ResourcesToInclude } }

        { Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -Operation Collect -SkipPrerequisiteCheck -WarningAction SilentlyContinue } |
            Should -Throw "*job-stuck is still 'notStarted' 96 hour(s)*next run starts a new snapshot job*"

        Test-Path -LiteralPath $script:PendingJobPath | Should -BeFalse
        $LastAttempt = Get-Content -LiteralPath $script:LastAttemptPath -Raw | ConvertFrom-Json
        $LastAttempt.SnapshotId | Should -Be 'job-stuck'
        $LastAttempt.SnapshotJobStatus | Should -Be 'notStarted'
        $LastAttempt.Diagnostics[0].ErrorCode | Should -Be 'SnapshotJobTimedOut'
        @($script:GraphCalls) | Should -Be @('DELETE /beta/admin/configurationManagement/configurationSnapshotJobs/job-stuck')
    }

    It 'keeps a job younger than PendingJobMaxAgeInHours on Collect' {
        & $script:WritePendingJob 2
        Mock Get-EntraOpsTenantGovernanceSnapshot { [PSCustomObject]@{ SnapshotId = 'job-stuck'; Status = 'running'; ResourcesToInclude = $ResourcesToInclude } }

        $Result = @(Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -Operation Collect -SkipPrerequisiteCheck) | Where-Object { $_ -isnot [string] }

        $Result.LastKnownStatus | Should -Be 'running'
        Test-Path -LiteralPath $script:PendingJobPath | Should -BeTrue
        Test-Path -LiteralPath $script:LastAttemptPath | Should -BeFalse
        $script:GraphCalls.Count | Should -Be 0
    }

    It 'never releases a job by its age with PendingJobMaxAgeInHours 0 from the configuration' {
        & $script:WritePendingJob 500
        Mock Get-EntraOpsTenantGovernanceSnapshot { [PSCustomObject]@{ SnapshotId = 'job-stuck'; Status = 'notStarted'; ResourcesToInclude = $ResourcesToInclude } }
        $Global:EntraOpsConfig = @{ TenantGovernanceSnapshot = @{ PendingJobMaxAgeInHours = 0 } }
        try {
            $null = Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('microsoft.entra.conditionalAccessPolicy') -Operation Collect -SkipPrerequisiteCheck
        } finally {
            $Global:EntraOpsConfig = $null
        }

        Test-Path -LiteralPath $script:PendingJobPath | Should -BeTrue
        $script:GraphCalls.Count | Should -Be 0
    }

    It 'replaces an expired job on Start, also when Microsoft Graph cannot delete it' {
        & $script:WritePendingJob 30
        Mock Invoke-EntraOpsMsGraphQuery {
            param($Method)
            if ($Method -eq 'DELETE') { throw 'Forbidden' }
        }
        Mock Get-EntraOpsTenantGovernanceSnapshot { [PSCustomObject]@{ SnapshotId = 'job-new'; Status = 'notStarted'; DisplayName = $SnapshotDisplayName; CreatedDateTime = (Get-Date).ToUniversalTime().ToString('o'); ResourcesToInclude = $ResourcesToInclude } }

        $Output = @(Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('microsoft.entra.conditionalAccessPolicy') -Operation Start -SkipPrerequisiteCheck -WarningVariable Warnings -WarningAction SilentlyContinue)

        (Get-Content -LiteralPath $script:PendingJobPath -Raw | ConvertFrom-Json).SnapshotJobId | Should -Be 'job-new'
        (Get-Content -LiteralPath $script:LastAttemptPath -Raw | ConvertFrom-Json).Diagnostics[0].ErrorCode | Should -Be 'SnapshotJobTimedOut'
        ($Output | Where-Object { $_ -is [string] }) -join "`n" | Should -Match 'Released the expired snapshot job job-stuck'
        ($Warnings -join "`n") | Should -Match 'could not be deleted in Microsoft Graph'
        Should -Invoke Get-EntraOpsTenantGovernanceSnapshot -Times 1 -Exactly -ParameterFilter { [string]::IsNullOrEmpty($SnapshotJobId) }
    }

    It 'still refuses to start while a recent job is pending' {
        & $script:WritePendingJob 3
        Mock Get-EntraOpsTenantGovernanceSnapshot { throw 'must not be called' }

        { Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('microsoft.entra.conditionalAccessPolicy') -Operation Start -SkipPrerequisiteCheck } |
            Should -Throw '*job-stuck already exists*older than PendingJobMaxAgeInHours (24)*'

        Test-Path -LiteralPath $script:PendingJobPath | Should -BeTrue
        $script:GraphCalls.Count | Should -Be 0
    }

    It 'rejects an invalid PendingJobMaxAgeInHours in the configuration' {
        $Global:EntraOpsConfig = @{ TenantGovernanceSnapshot = @{ PendingJobMaxAgeInHours = 'daily' } }
        try {
            { Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -Operation Collect -SkipPrerequisiteCheck } |
                Should -Throw "*Invalid TenantGovernanceSnapshot.PendingJobMaxAgeInHours 'daily'*"
        } finally {
            $Global:EntraOpsConfig = $null
        }
    }
}

Describe 'Save-EntraOpsTenantGovernanceSnapshotJson file name normalization' {
    BeforeEach {
        $script:EntraOpsBaseFolder = Join-Path $TestDrive 'EntraOpsNaming'
        $script:ExportFolder = Join-Path $script:EntraOpsBaseFolder 'TenantGovernance/Snapshots'
        New-Item -ItemType Directory -Path $script:EntraOpsBaseFolder -Force | Out-Null
    }

    It 'persists resources whose display name contains reserved or wildcard characters' {
        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId         = 'job-naming'
                Status             = 'Completed'
                SnapshotJobStatus  = 'succeeded'
                DisplayName        = 'Test Snapshot'
                CreatedDateTime    = '2026-08-30T10:11:12Z'
                ResourcesToInclude = @('microsoft.entra.conditionalaccesspolicy', 'microsoft.entra.rolesetting')
                ResourceCount      = 2
                ErrorDetails       = @()
                Resources          = @(
                    [PSCustomObject]@{
                        resourceType = 'microsoft.entra.conditionalaccesspolicy'
                        displayName  = 'AADConditionalAccessPolicy-Admin 4: Require MFA for all roles'
                        properties   = [PSCustomObject]@{ Id = 'policy-1' }
                    }
                    [PSCustomObject]@{
                        resourceType = 'microsoft.entra.rolesetting'
                        displayName  = 'AADRoleSetting-[EMEA Device Administrator]'
                        properties   = [PSCustomObject]@{ Id = 'setting-1' }
                    }
                )
            }
        }

        Save-EntraOpsTenantGovernanceSnapshotJson `
            -ExportFolder $script:ExportFolder `
            -ResourcesToInclude @('microsoft.entra.conditionalaccesspolicy', 'microsoft.entra.rolesetting') `
            -SkipPrerequisiteCheck | Out-Null

        $PolicyFile = Join-Path $script:ExportFolder 'microsoft.entra.conditionalaccesspolicy/AADConditionalAccessPolicy/Admin 4_ Require MFA for all roles.json'
        $RoleSettingFile = Join-Path $script:ExportFolder 'microsoft.entra.rolesetting/AADRoleSetting/_EMEA Device Administrator_.json'

        Test-Path -LiteralPath $PolicyFile | Should -BeTrue
        Test-Path -LiteralPath $RoleSettingFile | Should -BeTrue
        (Get-Content -LiteralPath $RoleSettingFile -Raw | ConvertFrom-Json).properties.Id | Should -Be 'setting-1'
    }

    It 'keeps resources whose normalized file names collide as separate files' {
        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId         = 'job-collision'
                Status             = 'Completed'
                SnapshotJobStatus  = 'succeeded'
                DisplayName        = 'Test Snapshot'
                CreatedDateTime    = '2026-08-30T10:11:12Z'
                ResourcesToInclude = @('microsoft.entra.conditionalaccesspolicy')
                ResourceCount      = 3
                ErrorDetails       = @()
                Resources          = @(
                    [PSCustomObject]@{
                        resourceType = 'microsoft.entra.conditionalaccesspolicy'
                        displayName  = 'AADConditionalAccessPolicy-Admin: Require MFA'
                        properties   = [PSCustomObject]@{ Id = 'policy-1' }
                    }
                    [PSCustomObject]@{
                        resourceType = 'microsoft.entra.conditionalaccesspolicy'
                        displayName  = 'AADConditionalAccessPolicy-Admin_ Require MFA'
                        properties   = [PSCustomObject]@{ Id = 'policy-2' }
                    }
                    # Same display name as the first resource, so only the content separates them.
                    [PSCustomObject]@{
                        resourceType = 'microsoft.entra.conditionalaccesspolicy'
                        displayName  = 'AADConditionalAccessPolicy-Admin: Require MFA'
                        properties   = [PSCustomObject]@{ Id = 'policy-3' }
                    }
                )
            }
        }

        Save-EntraOpsTenantGovernanceSnapshotJson `
            -ExportFolder $script:ExportFolder `
            -ResourcesToInclude @('microsoft.entra.conditionalaccesspolicy') `
            -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null

        $PolicyFolder = Join-Path $script:ExportFolder 'microsoft.entra.conditionalaccesspolicy/AADConditionalAccessPolicy'
        $PolicyFiles = @(Get-ChildItem -LiteralPath $PolicyFolder -Filter '*.json' -File)
        $PolicyFiles.Count | Should -Be 3
        @($PolicyFiles | ForEach-Object { (Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json).properties.Id } | Sort-Object) | Should -Be @('policy-1', 'policy-2', 'policy-3')
    }

    It 'keeps a resource whose display name equals another resource generated file name' {
        function Invoke-CollisionSnapshot ([object[]]$Resources, [string]$ExportFolder) {
            Mock Get-EntraOpsTenantGovernanceSnapshot {
                [PSCustomObject]@{
                    SnapshotId         = 'job-generated-name'
                    Status             = 'Completed'
                    SnapshotJobStatus  = 'succeeded'
                    DisplayName        = 'Test Snapshot'
                    CreatedDateTime    = '2026-08-30T10:11:12Z'
                    ResourcesToInclude = @('microsoft.entra.conditionalaccesspolicy')
                    ResourceCount      = $Resources.Count
                    ErrorDetails       = @()
                    Resources          = $Resources
                }
            }.GetNewClosure()

            Save-EntraOpsTenantGovernanceSnapshotJson `
                -ExportFolder $ExportFolder `
                -ResourcesToInclude @('microsoft.entra.conditionalaccesspolicy') `
                -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null

            @(Get-ChildItem -LiteralPath (Join-Path $ExportFolder 'microsoft.entra.conditionalaccesspolicy/AADConditionalAccessPolicy') -Filter '*.json' -File)
        }

        $CollidingResources = @(
            [PSCustomObject]@{
                resourceType = 'microsoft.entra.conditionalaccesspolicy'
                displayName  = 'AADConditionalAccessPolicy-Admin: Require MFA'
                properties   = [PSCustomObject]@{ Id = 'policy-1' }
            }
            [PSCustomObject]@{
                resourceType = 'microsoft.entra.conditionalaccesspolicy'
                displayName  = 'AADConditionalAccessPolicy-Admin_ Require MFA'
                properties   = [PSCustomObject]@{ Id = 'policy-2' }
            }
        )

        # Discover a generated file name first, then let a third resource claim exactly that name.
        $GeneratedName = (Invoke-CollisionSnapshot -Resources $CollidingResources -ExportFolder (Join-Path $script:EntraOpsBaseFolder 'Snapshots-Probe'))[0].BaseName
        $AdversarialResources = @(
            $CollidingResources
            [PSCustomObject]@{
                resourceType = 'microsoft.entra.conditionalaccesspolicy'
                displayName  = "AADConditionalAccessPolicy-$GeneratedName"
                properties   = [PSCustomObject]@{ Id = 'policy-3' }
            }
        )

        $PolicyFiles = Invoke-CollisionSnapshot -Resources $AdversarialResources -ExportFolder (Join-Path $script:EntraOpsBaseFolder 'Snapshots-Adversarial')
        $PolicyFiles.Count | Should -Be 3
        @($PolicyFiles | ForEach-Object { (Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json).properties.Id } | Sort-Object) | Should -Be @('policy-1', 'policy-2', 'policy-3')
    }

    It 'keeps the file name stable when a colliding resource changes its content' {
        function Invoke-ContentChangeSnapshot ([object[]]$Resources, [string]$ExportFolder) {
            Mock Get-EntraOpsTenantGovernanceSnapshot {
                [PSCustomObject]@{
                    SnapshotId         = 'job-content-change'
                    Status             = 'Completed'
                    SnapshotJobStatus  = 'succeeded'
                    DisplayName        = 'Test Snapshot'
                    CreatedDateTime    = '2026-08-30T10:11:12Z'
                    ResourcesToInclude = @('microsoft.entra.conditionalaccesspolicy')
                    ResourceCount      = $Resources.Count
                    ErrorDetails       = @()
                    Resources          = $Resources
                }
            }.GetNewClosure()

            Save-EntraOpsTenantGovernanceSnapshotJson `
                -ExportFolder $ExportFolder `
                -ResourcesToInclude @('microsoft.entra.conditionalaccesspolicy') `
                -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null

            @(Get-ChildItem -LiteralPath (Join-Path $ExportFolder 'microsoft.entra.conditionalaccesspolicy/AADConditionalAccessPolicy') -Filter '*.json' -File | ForEach-Object { $_.Name } | Sort-Object)
        }

        $BeforeChange = Invoke-ContentChangeSnapshot -ExportFolder (Join-Path $script:EntraOpsBaseFolder 'Snapshots-Before') -Resources @(
            [PSCustomObject]@{
                resourceType = 'microsoft.entra.conditionalaccesspolicy'
                displayName  = 'AADConditionalAccessPolicy-Admin: Require MFA'
                properties   = [PSCustomObject]@{ Id = 'policy-1'; State = 'enabled' }
            }
            [PSCustomObject]@{
                resourceType = 'microsoft.entra.conditionalaccesspolicy'
                displayName  = 'AADConditionalAccessPolicy-Admin_ Require MFA'
                properties   = [PSCustomObject]@{ Id = 'policy-2'; State = 'enabled' }
            }
        )
        $AfterChange = Invoke-ContentChangeSnapshot -ExportFolder (Join-Path $script:EntraOpsBaseFolder 'Snapshots-After') -Resources @(
            [PSCustomObject]@{
                resourceType = 'microsoft.entra.conditionalaccesspolicy'
                displayName  = 'AADConditionalAccessPolicy-Admin: Require MFA'
                properties   = [PSCustomObject]@{ Id = 'policy-1'; State = 'disabled' }
            }
            [PSCustomObject]@{
                resourceType = 'microsoft.entra.conditionalaccesspolicy'
                displayName  = 'AADConditionalAccessPolicy-Admin_ Require MFA'
                properties   = [PSCustomObject]@{ Id = 'policy-2'; State = 'enabled' }
            }
        )

        $AfterChange | Should -Be $BeforeChange
    }

    It 'resolves colliding file names independently of the order Graph returns the resources in' {
        $Resources = @(
            [PSCustomObject]@{
                resourceType = 'microsoft.entra.conditionalaccesspolicy'
                displayName  = 'AADConditionalAccessPolicy-Admin: Require MFA'
                properties   = [PSCustomObject]@{ Id = 'policy-1' }
            }
            [PSCustomObject]@{
                resourceType = 'microsoft.entra.conditionalaccesspolicy'
                displayName  = 'AADConditionalAccessPolicy-Admin_ Require MFA'
                properties   = [PSCustomObject]@{ Id = 'policy-2' }
            }
        )

        $FileNamesPerOrder = @(
            foreach ($OrderedResources in @($Resources, @($Resources[1], $Resources[0]))) {
                $OrderExportFolder = Join-Path $script:EntraOpsBaseFolder "TenantGovernance/Snapshots-$([guid]::NewGuid())"
                Mock Get-EntraOpsTenantGovernanceSnapshot {
                    [PSCustomObject]@{
                        SnapshotId         = 'job-order'
                        Status             = 'Completed'
                        SnapshotJobStatus  = 'succeeded'
                        DisplayName        = 'Test Snapshot'
                        CreatedDateTime    = '2026-08-30T10:11:12Z'
                        ResourcesToInclude = @('microsoft.entra.conditionalaccesspolicy')
                        ResourceCount      = 2
                        ErrorDetails       = @()
                        Resources          = $OrderedResources
                    }
                }.GetNewClosure()

                Save-EntraOpsTenantGovernanceSnapshotJson `
                    -ExportFolder $OrderExportFolder `
                    -ResourcesToInclude @('microsoft.entra.conditionalaccesspolicy') `
                    -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null

                $PolicyFolder = Join-Path $OrderExportFolder 'microsoft.entra.conditionalaccesspolicy/AADConditionalAccessPolicy'
                , @(Get-ChildItem -LiteralPath $PolicyFolder -Filter '*.json' -File | ForEach-Object { $_.Name } | Sort-Object)
            }
        )

        $FileNamesPerOrder[0] | Should -Be $FileNamesPerOrder[1]
        $FileNamesPerOrder[0].Count | Should -Be 2
        # Every colliding resource carries a discriminator, so none of them owns the plain name.
        $FileNamesPerOrder[0] | ForEach-Object { $_ | Should -Match ' [0-9A-F]{8}\.json$' }
    }
}

Describe 'ConvertTo-EntraOpsSafeFilePathSegment' {
    It 'replaces characters that are invalid in a file name on any supported platform' {
        ConvertTo-EntraOpsSafeFilePathSegment -Segment 'Admin 4: Require MFA' | Should -Be 'Admin 4_ Require MFA'
        ConvertTo-EntraOpsSafeFilePathSegment -Segment 'Policy/Sub\Name' | Should -Be 'Policy_Sub_Name'
        ConvertTo-EntraOpsSafeFilePathSegment -Segment "Line`tBreak" | Should -Be 'Line_Break'
    }

    It 'replaces PowerShell wildcard characters that break path resolution' {
        ConvertTo-EntraOpsSafeFilePathSegment -Segment '[EMEA Device Administrator]' | Should -Be '_EMEA Device Administrator_'
        ConvertTo-EntraOpsSafeFilePathSegment -Segment 'Policy*Name?' | Should -Be 'Policy_Name_'
    }

    It 'removes trailing dots and whitespace that Windows silently strips' {
        ConvertTo-EntraOpsSafeFilePathSegment -Segment '  Named location.  ' | Should -Be 'Named location'
    }

    It 'escapes Windows reserved device names' {
        ConvertTo-EntraOpsSafeFilePathSegment -Segment 'nul' | Should -Be '_nul'
        ConvertTo-EntraOpsSafeFilePathSegment -Segment 'COM1' | Should -Be '_COM1'
        ConvertTo-EntraOpsSafeFilePathSegment -Segment 'CON.txt' | Should -Be '_CON.txt'
        ConvertTo-EntraOpsSafeFilePathSegment -Segment 'lpt9.backup.json' | Should -Be '_lpt9.backup.json'
        ConvertTo-EntraOpsSafeFilePathSegment -Segment 'COM¹.log' | Should -Be '_COM¹.log'
    }

    It 'normalizes Unicode to form C so macOS and Windows produce the same file name' {
        $Decomposed = "Break-glass accou" + [char]0x006E + [char]0x0303 + 't'
        ConvertTo-EntraOpsSafeFilePathSegment -Segment $Decomposed | Should -Be $Decomposed.Normalize([System.Text.NormalizationForm]::FormC)
    }

    It 'falls back to the provided name when nothing usable remains' {
        ConvertTo-EntraOpsSafeFilePathSegment -Segment '   ' -FallbackName 'General' | Should -Be 'General'
    }

    It 'caps the segment length' {
        (ConvertTo-EntraOpsSafeFilePathSegment -Segment ('x' * 300)).Length | Should -Be 100
    }

    It 'caps multibyte segments by UTF-8 bytes without splitting Unicode text elements' {
        $CjkResult = ConvertTo-EntraOpsSafeFilePathSegment -Segment ('界' * 100)
        [System.Text.Encoding]::UTF8.GetByteCount($CjkResult) | Should -BeLessOrEqual 100
        $CjkResult | Should -Match '_[0-9A-F]{8}$'

        $EmojiResult = ConvertTo-EntraOpsSafeFilePathSegment -Segment ('😀' * 100)
        [System.Text.Encoding]::UTF8.GetByteCount($EmojiResult) | Should -BeLessOrEqual 100
        $EmojiResult | Should -Not -Match ([char]0xFFFD)
        $EmojiResult | Should -Match '_[0-9A-F]{8}$'
    }
}

Describe 'Save-EntraOpsTenantGovernanceSnapshotJson collection ordering' {
    BeforeEach {
        $script:EntraOpsBaseFolder = Join-Path $TestDrive 'EntraOpsCollectionOrdering'
        $script:ExportFolder = Join-Path $script:EntraOpsBaseFolder 'TenantGovernance/Snapshots'
        New-Item -ItemType Directory -Path $script:EntraOpsBaseFolder -Force | Out-Null
    }

    It 'sorts known unordered collections while preserving positional approval stages' {
        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId         = 'job-collection-order'
                Status             = 'Completed'
                SnapshotJobStatus  = 'succeeded'
                DisplayName        = 'Test Snapshot'
                CreatedDateTime    = '2026-09-03T10:11:12Z'
                ResourcesToInclude = @('microsoft.entra.administrativeUnit', 'microsoft.entra.authorizationPolicy', 'microsoft.entra.roleSetting')
                ResourceCount      = 3
                ErrorDetails       = @()
                Resources          = @(
                    [PSCustomObject]@{
                        resourceType = 'microsoft.entra.administrativeUnit'
                        displayName  = 'AADAdministrativeUnit-Tier0-ControlPlane'
                        properties   = [PSCustomObject]@{
                            Id                = 'admin-unit-1'
                            Members           = @(
                                [PSCustomObject]@{ Identity = 'ZuluGroup'; Type = 'Group' }
                                [PSCustomObject]@{ Identity = 'AlphaUser@contoso.com'; Type = 'User' }
                            )
                            ScopedRoleMembers = @(
                                [PSCustomObject]@{
                                    RoleName       = 'User Administrator'
                                    RoleMemberInfo = [PSCustomObject]@{ Identity = 'Microsoft.Azure.SyncFabric'; Type = 'ServicePrincipal' }
                                }
                                [PSCustomObject]@{
                                    RoleName       = 'Groups Administrator'
                                    RoleMemberInfo = [PSCustomObject]@{ Identity = 'Microsoft.Azure.SyncFabric'; Type = 'ServicePrincipal' }
                                }
                            )
                        }
                    }
                    [PSCustomObject]@{
                        resourceType = 'microsoft.entra.authorizationPolicy'
                        displayName  = 'AADAuthorizationPolicy'
                        properties   = [PSCustomObject]@{
                            PermissionGrantPolicyIdsAssignedToDefaultUserRole = @(
                                'ManagePermissionGrantsForSelf.microsoft-user-default-recommended'
                                'ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team'
                                'ManagePermissionGrantsForSelf.microsoft-user-default-allow-consent-apps'
                                'ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat'
                            )
                        }
                    }
                    [PSCustomObject]@{
                        resourceType = 'microsoft.entra.roleSetting'
                        displayName  = 'AADRoleSetting-Global Administrator'
                        properties   = [PSCustomObject]@{
                            Id      = 'role-setting-1'
                            setting = [PSCustomObject]@{
                                approvalStages = @(
                                    [PSCustomObject]@{ displayName = 'Second approval stage' }
                                    [PSCustomObject]@{ displayName = 'First approval stage' }
                                )
                            }
                        }
                    }
                )
            }
        }

        Save-EntraOpsTenantGovernanceSnapshotJson `
            -ExportFolder $script:ExportFolder `
            -ResourcesToInclude @('microsoft.entra.administrativeUnit', 'microsoft.entra.authorizationPolicy', 'microsoft.entra.roleSetting') `
            -SkipPrerequisiteCheck | Out-Null

        # Resource-type folders are canonical lowercase even though the API identifiers above use
        # mixed casing. This is significant on the case-sensitive Linux CI filesystem.
        $AdministrativeUnitPath = Join-Path $script:ExportFolder 'microsoft.entra.administrativeunit/AADAdministrativeUnit/Tier0-ControlPlane.json'
        $AdministrativeUnit = Get-Content -LiteralPath $AdministrativeUnitPath -Raw | ConvertFrom-Json
        $AuthorizationPolicy = Get-Content -LiteralPath (Join-Path $script:ExportFolder 'microsoft.entra.authorizationpolicy/General/AADAuthorizationPolicy.json') -Raw | ConvertFrom-Json
        $RoleSetting = Get-Content -LiteralPath (Join-Path $script:ExportFolder 'microsoft.entra.rolesetting/AADRoleSetting/Global Administrator.json') -Raw | ConvertFrom-Json

        (Get-Item -LiteralPath $AdministrativeUnitPath).Directory.Parent.Name | Should -BeExactly 'microsoft.entra.administrativeunit'
        @($AdministrativeUnit.properties.Members.Identity) | Should -Be @('AlphaUser@contoso.com', 'ZuluGroup')
        @($AdministrativeUnit.properties.ScopedRoleMembers.RoleName) | Should -Be @('Groups Administrator', 'User Administrator')
        @($AuthorizationPolicy.properties.PermissionGrantPolicyIdsAssignedToDefaultUserRole) | Should -Be @(
            'ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat'
            'ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team'
            'ManagePermissionGrantsForSelf.microsoft-user-default-allow-consent-apps'
            'ManagePermissionGrantsForSelf.microsoft-user-default-recommended'
        )
        @($RoleSetting.properties.setting.approvalStages.displayName) | Should -Be @(
            'Second approval stage'
            'First approval stage'
        )
    }

    It 'writes resource counts and stale resource types in deterministic order' {
        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId         = 'job-manifest-order'
                Status             = 'Completed'
                SnapshotJobStatus  = 'partiallySuccessful'
                DisplayName        = 'Test Snapshot'
                CreatedDateTime    = '2026-09-04T10:11:12Z'
                ResourcesToInclude = @(
                    'microsoft.entra.authorizationPolicy'
                    'microsoft.entra.administrativeUnit'
                    'microsoft.entra.conditionalAccessPolicy'
                    'microsoft.intune.deviceCompliancePolicyWindows10'
                )
                ResourceCount      = 2
                ErrorDetails       = @(
                    'microsoft.intune.deviceCompliancePolicyWindows10: Errors encountered while establishing connection with underlying workload'
                    'microsoft.entra.conditionalAccessPolicy: Errors encountered while establishing connection with underlying workload'
                )
                Resources          = @(
                    [PSCustomObject]@{
                        resourceType = 'microsoft.entra.authorizationPolicy'
                        displayName  = 'AADAuthorizationPolicy'
                        properties   = [PSCustomObject]@{ IsSingleInstance = 'Yes' }
                    }
                    [PSCustomObject]@{
                        resourceType = 'microsoft.entra.administrativeUnit'
                        displayName  = 'AADAdministrativeUnit-Test'
                        properties   = [PSCustomObject]@{ Id = 'admin-unit-1' }
                    }
                )
            }
        }

        $PreviousTenantIdContext = $Global:TenantIdContext
        $PreviousTenantNameContext = $Global:TenantNameContext
        try {
            $Global:TenantIdContext = '00000000-0000-0000-0000-000000000001'
            $Global:TenantNameContext = 'contoso.onmicrosoft.com'
            Save-EntraOpsTenantGovernanceSnapshotJson `
                -ExportFolder $script:ExportFolder `
                -ResourcesToInclude @('unused-by-mock') `
                -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null
        } finally {
            $Global:TenantIdContext = $PreviousTenantIdContext
            $Global:TenantNameContext = $PreviousTenantNameContext
        }

        $Manifest = Get-Content -LiteralPath (Join-Path $script:ExportFolder '.SnapshotManifest.json') -Raw | ConvertFrom-Json
        # The tenant of the snapshot: Invoke-EntraOpsAssessment never uses the snapshot of another tenant in a shared folder.
        $Manifest.TenantId | Should -Be '00000000-0000-0000-0000-000000000001'
        $Manifest.TenantName | Should -Be 'contoso.onmicrosoft.com'
        @($Manifest.AttemptResourceTypeCounts.PSObject.Properties.Name) | Should -Be @(
            'microsoft.entra.administrativeunit'
            'microsoft.entra.authorizationpolicy'
        )
        @($Manifest.StaleResourceTypes) | Should -Be @(
            'microsoft.entra.conditionalaccesspolicy'
            'microsoft.intune.devicecompliancepolicywindows10'
        )
        @($Manifest.Diagnostics).Count | Should -Be 2
        $Manifest.Diagnostics[0].ErrorCategory | Should -Be 'ConnectionError'
        $Manifest.Diagnostics[0].RemediationHint | Should -Match 'Retry the snapshot'
    }

    It 'publishes a resource type with per-resource export errors and retains the resources the job did not return' {
        $TypeFolder = Join-Path $script:ExportFolder 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy/AADEntitlementManagementAccessPackageAssignmentPolicy'
        New-Item -ItemType Directory -Path $TypeFolder -Force | Out-Null
        # Previously published: one policy that exports again, one that will fail to export, and one
        # that was renamed in the tenant (same Id, new display name).
        foreach ($Previous in @(
                @{ Name = 'Still exported.json'; Id = 'policy-ok'; Version = 1 }
                @{ Name = 'Broken reference.json'; Id = 'policy-broken'; Version = 1 }
                @{ Name = 'Old name.json'; Id = 'policy-renamed'; Version = 1 }
            )) {
            [ordered]@{ resourceType = 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy'; properties = [ordered]@{ Id = $Previous.Id; Version = $Previous.Version } } |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $TypeFolder $Previous.Name) -Encoding utf8
        }
        [ordered]@{
            SnapshotId = 'job-previous'; SnapshotJobStatus = 'succeeded'; IsComplete = $true
            ResourceTypeStates = @([ordered]@{ ResourceType = 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy'; Status = 'Published'; PublishedSnapshotId = 'job-previous' })
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $script:ExportFolder '.SnapshotManifest.json') -Encoding utf8

        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId         = 'job-export-errors'
                Status             = 'Completed'
                SnapshotJobStatus  = 'partiallySuccessful'
                DisplayName        = 'Test Snapshot'
                CreatedDateTime    = '2026-09-07T10:11:12Z'
                ResourcesToInclude = @('microsoft.entra.entitlementManagementAccessPackageAssignmentPolicy', 'microsoft.securityandcompliance.deviceConfigurationPolicy')
                ResourceCount      = 2
                ErrorDetails       = @(
                    "microsoft.entra.entitlementManagementAccessPackageAssignmentPolicy: Error exporting resource [microsoft.entra.entitlementManagementAccessPackageAssignmentPolicy]. exceptionMessage(s):[Request_ResourceNotFound] : Resource '11111111-1111-1111-1111-111111111111' does not exist or one of its queried reference-property objects are not present. ,"
                    'microsoft.securityandcompliance.deviceConfigurationPolicy: Errors encountered while establishing connection with underlying workload'
                )
                Resources          = @(
                    [PSCustomObject]@{ resourceType = 'microsoft.entra.entitlementManagementAccessPackageAssignmentPolicy'; displayName = 'AADEntitlementManagementAccessPackageAssignmentPolicy-Still exported'; properties = [PSCustomObject]@{ Id = 'policy-ok'; Version = 2 } }
                    [PSCustomObject]@{ resourceType = 'microsoft.entra.entitlementManagementAccessPackageAssignmentPolicy'; displayName = 'AADEntitlementManagementAccessPackageAssignmentPolicy-New name'; properties = [PSCustomObject]@{ Id = 'policy-renamed'; Version = 2 } }
                )
            }
        }

        Save-EntraOpsTenantGovernanceSnapshotJson `
            -ExportFolder $script:ExportFolder `
            -ResourcesToInclude @('unused-by-mock') `
            -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null

        (Get-Content -LiteralPath (Join-Path $TypeFolder 'Still exported.json') -Raw | ConvertFrom-Json).properties.Version | Should -Be 2
        (Get-Content -LiteralPath (Join-Path $TypeFolder 'Broken reference.json') -Raw | ConvertFrom-Json).properties.Version | Should -Be 1
        Test-Path -LiteralPath (Join-Path $TypeFolder 'New name.json') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $TypeFolder 'Old name.json') | Should -BeFalse
        @(Get-ChildItem -LiteralPath $TypeFolder -Filter '*.json').Count | Should -Be 3

        $Manifest = Get-Content -LiteralPath (Join-Path $script:ExportFolder '.SnapshotManifest.json') -Raw | ConvertFrom-Json
        @($Manifest.PublishedResourceTypes) | Should -Contain 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy'
        @($Manifest.PublishedWithErrorsResourceTypes) | Should -Be @('microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy')
        @($Manifest.StaleResourceTypes) | Should -Be @('microsoft.securityandcompliance.deviceconfigurationpolicy')
        $Manifest.IsComplete | Should -BeFalse
        $State = @($Manifest.ResourceTypeStates | Where-Object { $_.ResourceType -eq 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy' })[0]
        $State.Status | Should -Be 'PublishedWithErrors'
        $State.PublishedSnapshotId | Should -Be 'job-export-errors'
        $State.PublishedResourceCount | Should -Be 3
        $State.RetainedResourceCount | Should -Be 1
        $State.Diagnostics[0].ErrorCode | Should -Be 'Request_ResourceNotFound'
        $StaleState = @($Manifest.ResourceTypeStates | Where-Object { $_.ResourceType -eq 'microsoft.securityandcompliance.deviceconfigurationpolicy' })[0]
        $StaleState.Status | Should -Be 'PreservedStale'
    }

    It 'keeps StaleSince while a resource type stays stale and names the stale age in the warning' {
        $KeptType = 'microsoft.securityandcompliance.deviceconfigurationpolicy'
        $NewType = 'microsoft.securityandcompliance.deviceconditionalaccesspolicy'
        $script:EntraOpsBaseFolder = Join-Path $TestDrive 'EntraOpsStaleSince'
        $script:ExportFolder = Join-Path $script:EntraOpsBaseFolder 'TenantGovernance/Snapshots'
        New-Item -ItemType Directory -Path $script:ExportFolder -Force | Out-Null
        [ordered]@{
            SnapshotId = 'job-previous'; SnapshotJobStatus = 'partiallySuccessful'; IsComplete = $false
            ResourceTypeStates = @(
                [ordered]@{ ResourceType = $KeptType; Status = 'PreservedStale'; StaleSince = '2026-08-01T00:00:00.0000000Z' }
                [ordered]@{ ResourceType = $NewType; Status = 'Published'; PublishedSnapshotId = 'job-previous' }
            )
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $script:ExportFolder '.SnapshotManifest.json') -Encoding utf8

        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId = 'job-stale-since'; Status = 'Completed'; SnapshotJobStatus = 'partiallySuccessful'
                DisplayName = 'Test Snapshot'; CreatedDateTime = '2026-09-07T10:11:12Z'
                ResourcesToInclude = @('microsoft.securityandcompliance.deviceConfigurationPolicy', 'microsoft.securityandcompliance.deviceConditionalAccessPolicy', 'microsoft.entra.conditionalAccessPolicy')
                ResourceCount = 1
                ErrorDetails = @(
                    'microsoft.securityandcompliance.deviceConfigurationPolicy: Errors encountered while establishing connection with underlying workload'
                    'microsoft.securityandcompliance.deviceConditionalAccessPolicy: Errors encountered while establishing connection with underlying workload'
                )
                Resources = @([PSCustomObject]@{ resourceType = 'microsoft.entra.conditionalAccessPolicy'; displayName = 'CA-Policy'; properties = [PSCustomObject]@{ Id = 'ca-1' } })
            }
        }

        Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') `
            -SkipPrerequisiteCheck -WarningVariable Warnings -WarningAction SilentlyContinue | Out-Null

        $Manifest = Get-Content -LiteralPath (Join-Path $script:ExportFolder '.SnapshotManifest.json') -Raw | ConvertFrom-Json
        $ToUtc = { param($Value) if ($Value -is [datetime]) { $Value.ToUniversalTime().ToString('o') } elseif ($Value) { [datetimeoffset]::Parse("$Value", [cultureinfo]::InvariantCulture).UtcDateTime.ToString('o') } }
        $States = @{}
        foreach ($State in $Manifest.ResourceTypeStates) { $States[$State.ResourceType] = $State }
        & $ToUtc $States[$KeptType].StaleSince | Should -Be '2026-08-01T00:00:00.0000000Z'
        & $ToUtc $States[$NewType].StaleSince | Should -Be '2026-09-07T10:11:12.0000000Z'
        $States['microsoft.entra.conditionalaccesspolicy'].StaleSince | Should -BeNullOrEmpty
        $StaleWarning = @($Warnings | Where-Object { "$_" -like '*preserved as stale*' })
        $StaleWarning.Count | Should -Be 1
        "$($StaleWarning[0])" | Should -BeLike "*$KeptType (stale since 2026-08-01, * day(s))*"
        "$($StaleWarning[0])" | Should -BeLike "*$NewType (stale since 2026-09-07, * day(s))*"
    }

    It 'deduplicates legacy and ID-named files for a resource retained after an export error' {
        $Type = 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy'
        $script:EntraOpsBaseFolder = Join-Path $TestDrive 'EntraOpsDuplicateRetention'
        $script:ExportFolder = Join-Path $script:EntraOpsBaseFolder 'TenantGovernance/Snapshots'
        $TypeFolder = Join-Path $script:ExportFolder "$Type/AADEntitlementManagementAccessPackageAssignmentPolicy"
        New-Item -ItemType Directory -Path $TypeFolder -Force | Out-Null
        foreach ($Name in @('a5d169ad-aaee-4a27-8186-235de07c5347.json', 'Initial Policy.json')) {
            [ordered]@{ resourceType = $Type; properties = [ordered]@{ Id = 'a5d169ad-aaee-4a27-8186-235de07c5347' } } |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $TypeFolder $Name) -Encoding utf8
        }

        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId = 'job-deduplicate-retained'; Status = 'Completed'; SnapshotJobStatus = 'partiallySuccessful'
                DisplayName = 'Test Snapshot'; CreatedDateTime = '2026-09-07T10:11:12Z'
                ResourcesToInclude = @($Type); ResourceCount = 1
                ErrorDetails = @("${Type}: Error exporting resource [$Type]. exceptionMessage(s):[Request_ResourceNotFound] : Resource 'missing' does not exist. ,")
                Resources = @([PSCustomObject]@{ resourceType = $Type; displayName = 'AADEntitlementManagementAccessPackageAssignmentPolicy-Still exported'; properties = [PSCustomObject]@{ Id = 'policy-returned' } })
            }
        }

        Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null

        $Files = @(Get-ChildItem -LiteralPath $TypeFolder -Filter '*.json')
        $Files.Count | Should -Be 2
        $RetainedIds = @(foreach ($File in $Files) { (Get-Content -LiteralPath $File.FullName -Raw | ConvertFrom-Json).properties.Id }) | Sort-Object -Unique
        $RetainedIds | Should -Be @('a5d169ad-aaee-4a27-8186-235de07c5347', 'policy-returned')
        Test-Path -LiteralPath (Join-Path $TypeFolder 'Initial Policy.json') | Should -BeFalse
    }

    It 'prefers a non-GUID ID-named file over an earlier-sorting legacy alias during retention' {
        $Type = 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy'
        $ResourceId = 'policy-missing'
        $script:EntraOpsBaseFolder = Join-Path $TestDrive 'EntraOpsNonGuidDuplicateRetention'
        $script:ExportFolder = Join-Path $script:EntraOpsBaseFolder 'TenantGovernance/Snapshots'
        $TypeFolder = Join-Path $script:ExportFolder "$Type/AADEntitlementManagementAccessPackageAssignmentPolicy"
        New-Item -ItemType Directory -Path $TypeFolder -Force | Out-Null
        [ordered]@{ resourceType = $Type; properties = [ordered]@{ Id = $ResourceId; Version = 1 } } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $TypeFolder 'AAA Legacy Alias.json') -Encoding utf8
        [ordered]@{ resourceType = $Type; properties = [ordered]@{ Id = $ResourceId; Version = 2 } } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $TypeFolder "$ResourceId.json") -Encoding utf8

        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId = 'job-non-guid-deduplicate-retained'; Status = 'Completed'; SnapshotJobStatus = 'partiallySuccessful'
                DisplayName = 'Test Snapshot'; CreatedDateTime = '2026-09-08T10:11:12Z'
                ResourcesToInclude = @($Type); ResourceCount = 1
                ErrorDetails = @("${Type}: Error exporting resource [$Type]. exceptionMessage(s):[Request_ResourceNotFound] : Resource '$ResourceId' does not exist. ,")
                Resources = @([PSCustomObject]@{ resourceType = $Type; displayName = 'AADEntitlementManagementAccessPackageAssignmentPolicy-Returned'; properties = [PSCustomObject]@{ Id = 'returned-policy' } })
            }
        }

        Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null

        $RetainedFile = Join-Path $TypeFolder "$ResourceId.json"
        @(Get-ChildItem -LiteralPath $TypeFolder -Filter '*.json').Count | Should -Be 2
        Test-Path -LiteralPath $RetainedFile | Should -BeTrue
        (Get-Content -LiteralPath $RetainedFile -Raw | ConvertFrom-Json).properties.Version | Should -Be 2
        Test-Path -LiteralPath (Join-Path $TypeFolder 'AAA Legacy Alias.json') | Should -BeFalse
    }

    It 'deduplicates legacy aliases in a preserved-stale resource type' {
        $Type = 'microsoft.securityandcompliance.deviceconfigurationpolicy'
        $ResourceId = '11111111-1111-1111-1111-111111111111'
        $script:EntraOpsBaseFolder = Join-Path $TestDrive 'EntraOpsDuplicateStale'
        $script:ExportFolder = Join-Path $script:EntraOpsBaseFolder 'TenantGovernance/Snapshots'
        $TypeFolder = Join-Path $script:ExportFolder "$Type/General"
        New-Item -ItemType Directory -Path $TypeFolder -Force | Out-Null
        foreach ($Name in @("$ResourceId.json", 'Legacy Policy.json')) {
            [ordered]@{ resourceType = $Type; properties = [ordered]@{ Id = $ResourceId } } |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $TypeFolder $Name) -Encoding utf8
        }

        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId = 'job-deduplicate-stale'; Status = 'Completed'; SnapshotJobStatus = 'partiallySuccessful'
                DisplayName = 'Test Snapshot'; CreatedDateTime = '2026-09-07T10:11:12Z'
                ResourcesToInclude = @($Type); ResourceCount = 0
                ErrorDetails = @("${Type}: Errors encountered while establishing connection with underlying workload")
                Resources = @()
            }
        }

        Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null

        @(Get-ChildItem -LiteralPath $TypeFolder -Filter '*.json').Count | Should -Be 1
        Test-Path -LiteralPath (Join-Path $TypeFolder "$ResourceId.json") | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $TypeFolder 'Legacy Policy.json') | Should -BeFalse
    }

    It 'resolves identities of resources whose JSON contains an empty property name' {
        $Type = 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy'
        $script:EntraOpsBaseFolder = Join-Path $TestDrive 'EntraOpsEmptyPropertyName'
        $script:ExportFolder = Join-Path $script:EntraOpsBaseFolder 'TenantGovernance/Snapshots'
        $TypeFolder = Join-Path $script:ExportFolder "$Type/AADEntitlementManagementAccessPackageAssignmentPolicy"
        New-Item -ItemType Directory -Path $TypeFolder -Force | Out-Null
        # Graph emits an empty property name for these policies; ConvertFrom-Json rejects it without -AsHashtable.
        foreach ($Previous in @(
                @{ Name = 'Initial Policy.json'; Id = 'policy-returned' }
                @{ Name = 'Initial Policy-2.json'; Id = 'policy-missing' }
            )) {
            "{`"resourceType`":`"$Type`",`"properties`":{`"Id`":`"$($Previous.Id)`",`"`":`"nested`"}}" |
            Set-Content -LiteralPath (Join-Path $TypeFolder $Previous.Name) -Encoding utf8
        }

        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId = 'job-empty-property-name'; Status = 'Completed'; SnapshotJobStatus = 'partiallySuccessful'
                DisplayName = 'Test Snapshot'; CreatedDateTime = '2026-09-08T10:11:12Z'
                ResourcesToInclude = @($Type); ResourceCount = 1
                ErrorDetails = @("${Type}: Error exporting resource [$Type]. exceptionMessage(s):[Request_ResourceNotFound] : Resource 'policy-missing' does not exist. ,")
                Resources = @([PSCustomObject]@{ resourceType = $Type; displayName = 'AADEntitlementManagementAccessPackageAssignmentPolicy-Initial Policy'; properties = [PSCustomObject]@{ Id = 'policy-returned' } })
            }
        }

        Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') -SnapshotResourceFileNaming ResourceId -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null

        $Files = @(Get-ChildItem -LiteralPath $TypeFolder -Filter '*.json')
        $Files.Count | Should -Be 2
        Test-Path -LiteralPath (Join-Path $TypeFolder 'policy-returned.json') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $TypeFolder 'Initial Policy.json') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $TypeFolder 'Initial Policy-2.json') | Should -BeTrue
    }

    It 'does not let a new resource that reuses a failed resource display-name path replace the retained file' {
        $TypeFolder = Join-Path $script:ExportFolder 'microsoft.entra.namedlocationpolicy/AADNamedLocationPolicy'
        New-Item -ItemType Directory -Path $TypeFolder -Force | Out-Null
        [ordered]@{ resourceType = 'microsoft.entra.namedlocationpolicy'; properties = [ordered]@{ Id = 'location-old'; Version = 1 } } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $TypeFolder 'Office.json') -Encoding utf8

        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId = 'job-path-reuse'; Status = 'Completed'; SnapshotJobStatus = 'partiallySuccessful'
                DisplayName = 'Test Snapshot'; CreatedDateTime = '2026-09-07T10:11:12Z'
                ResourcesToInclude = @('microsoft.entra.namedLocationPolicy'); ResourceCount = 1
                ErrorDetails = @("microsoft.entra.namedLocationPolicy: Error exporting resource [microsoft.entra.namedLocationPolicy]. exceptionMessage(s):[Request_ResourceNotFound] : Resource 'location-old' does not exist. ,")
                # A different resource now carries the display name of the one that failed to export.
                Resources = @([PSCustomObject]@{ resourceType = 'microsoft.entra.namedLocationPolicy'; displayName = 'AADNamedLocationPolicy-Office'; properties = [PSCustomObject]@{ Id = 'location-new'; Version = 7 } })
            }
        }

        Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null

        $Files = @(Get-ChildItem -LiteralPath $TypeFolder -Filter '*.json')
        $Files.Count | Should -Be 2
        (Get-Content -LiteralPath (Join-Path $TypeFolder 'Office.json') -Raw | ConvertFrom-Json).properties.Id | Should -Be 'location-new'
        $Retained = @($Files | Where-Object { $_.Name -ne 'Office.json' })[0]
        $Retained.Name | Should -Match '^Office [0-9A-F]{8}\.json$'
        (Get-Content -LiteralPath $Retained.FullName -Raw | ConvertFrom-Json).properties.Id | Should -Be 'location-old'
        $Manifest = Get-Content -LiteralPath (Join-Path $script:ExportFolder '.SnapshotManifest.json') -Raw | ConvertFrom-Json
        $Manifest.ResourceTypeStates[0].RetainedResourceCount | Should -Be 1
        $Manifest.ResourceTypeStates[0].PublishedResourceCount | Should -Be 2
    }

    It 'keeps a resource type stale when export errors leave it without any returned resource' {
        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId = 'job-export-errors-empty'; Status = 'Completed'; SnapshotJobStatus = 'partiallySuccessful'
                DisplayName = 'Test Snapshot'; CreatedDateTime = '2026-09-07T10:11:12Z'
                ResourcesToInclude = @('microsoft.entra.namedLocationPolicy'); ResourceCount = 0
                ErrorDetails = @("microsoft.entra.namedLocationPolicy: Error exporting resource [microsoft.entra.namedLocationPolicy]. exceptionMessage(s):[Request_ResourceNotFound] : Resource '11111111-1111-1111-1111-111111111111' does not exist. ,")
                Resources = @()
            }
        }

        Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null

        $Manifest = Get-Content -LiteralPath (Join-Path $script:ExportFolder '.SnapshotManifest.json') -Raw | ConvertFrom-Json
        @($Manifest.StaleResourceTypes) | Should -Be @('microsoft.entra.namedlocationpolicy')
        @($Manifest.PublishedWithErrorsResourceTypes).Count | Should -Be 0
        $Manifest.ResourceTypeStates[0].Status | Should -Be 'PreservedStale'
    }

    It 'keeps the capture time of the published snapshot when a run publishes nothing' {
        # Otherwise every partial run without parseable errors would reset the snapshot age
        New-Item -ItemType Directory -Path $script:ExportFolder -Force | Out-Null
        [ordered]@{ SnapshotId = 'job-published'; CapturedDateTime = '2026-09-01T06:00:00.0000000Z'; IsComplete = $true; ResourceTypeStates = @() } |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $script:ExportFolder '.SnapshotManifest.json')
        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId = 'job-nothing-published'; Status = 'Completed'; SnapshotJobStatus = 'partiallySuccessful'
                DisplayName = 'Test Snapshot'; CreatedDateTime = '2026-09-20T06:00:00.0000000Z'
                ResourcesToInclude = @('microsoft.entra.namedLocationPolicy'); ResourceCount = 1; ErrorDetails = @()
                Resources = @([PSCustomObject]@{ resourceType = 'microsoft.entra.namedlocationpolicy'; displayName = 'Location'; properties = [PSCustomObject]@{ Id = 'loc-1' } })
            }
        }

        Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null

        $Manifest = Get-Content -LiteralPath (Join-Path $script:ExportFolder '.SnapshotManifest.json') -Raw | ConvertFrom-Json
        $Manifest.SnapshotId | Should -Be 'job-nothing-published'
        ([datetime]$Manifest.CapturedDateTime).ToUniversalTime() | Should -Be ([datetime]::new(2026, 9, 1, 6, 0, 0, [System.DateTimeKind]::Utc))
        ([datetime]$Manifest.AttemptDateTime).ToUniversalTime() | Should -Be ([datetime]::new(2026, 9, 20, 6, 0, 0, [System.DateTimeKind]::Utc))
    }

    It 'rejects duplicate canonical resource identities before publication' {
        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId = 'job-duplicate-identity'; Status = 'Completed'; SnapshotJobStatus = 'succeeded'
                DisplayName = 'Test Snapshot'; CreatedDateTime = '2026-09-04T10:11:12Z'
                ResourcesToInclude = @('microsoft.entra.conditionalaccesspolicy'); ResourceCount = 2; ErrorDetails = @()
                Resources = @(
                    [PSCustomObject]@{ resourceType = 'microsoft.entra.conditionalaccesspolicy'; displayName = 'AADConditionalAccessPolicy-First'; properties = [PSCustomObject]@{ Id = 'same-id' } }
                    [PSCustomObject]@{ resourceType = 'microsoft.entra.conditionalaccesspolicy'; displayName = 'AADConditionalAccessPolicy-Renamed'; properties = [PSCustomObject]@{ Id = 'same-id' } }
                )
            }
        }

        { Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') -SkipPrerequisiteCheck } |
        Should -Throw '*duplicate canonical resource identity*'
        Test-Path -LiteralPath (Join-Path $script:ExportFolder 'microsoft.entra.conditionalaccesspolicy') | Should -BeFalse
        @(Get-ChildItem -LiteralPath $script:ExportFolder -Directory -Force -Filter '.staging-*').Count | Should -Be 0
    }

    It 'releases the pending job and records a diagnostic when a collected job has duplicate identities' {
        # The duplicate is deterministic for the job, so a retained pending state would make every
        # later scheduled Start ("already exists") and Collect (same duplicate) fail forever.
        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId = 'job-duplicate-identity'; Status = 'Completed'; SnapshotJobStatus = 'succeeded'
                DisplayName = 'Test Snapshot'; CreatedDateTime = '2026-09-04T10:11:12Z'
                ResourcesToInclude = @('microsoft.entra.conditionalaccesspolicy'); ResourceCount = 2; ErrorDetails = @()
                Resources = @(
                    [PSCustomObject]@{ resourceType = 'microsoft.entra.conditionalaccesspolicy'; displayName = 'AADConditionalAccessPolicy-First'; properties = [PSCustomObject]@{ Id = 'same-id' } }
                    [PSCustomObject]@{ resourceType = 'microsoft.entra.conditionalaccesspolicy'; displayName = 'AADConditionalAccessPolicy-Renamed'; properties = [PSCustomObject]@{ Id = 'same-id' } }
                )
            }
        }
        New-Item -ItemType Directory -Path $script:ExportFolder -Force | Out-Null
        @{ SnapshotJobId = 'job-duplicate-identity'; ResourcesToInclude = @('microsoft.entra.conditionalaccesspolicy'); CreatedDateTime = '2026-09-04T10:11:12Z' } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $script:ExportFolder '.PendingSnapshotJob.json') -Encoding utf8

        { Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') -Operation Collect -SkipPrerequisiteCheck } |
        Should -Throw '*duplicate canonical resource identity*'

        Test-Path -LiteralPath (Join-Path $script:ExportFolder '.PendingSnapshotJob.json') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:ExportFolder 'microsoft.entra.conditionalaccesspolicy') | Should -BeFalse
        @(Get-ChildItem -LiteralPath $script:ExportFolder -Directory -Force -Filter '.staging-*').Count | Should -Be 0
        $LastAttempt = Get-Content -LiteralPath (Join-Path $script:ExportFolder '.LastAttemptManifest.json') -Raw | ConvertFrom-Json
        $LastAttempt.SnapshotId | Should -Be 'job-duplicate-identity'
        $LastAttempt.IsComplete | Should -BeFalse
        @($LastAttempt.Diagnostics).Count | Should -Be 1
        $LastAttempt.Diagnostics[0].ErrorCategory | Should -Be 'DuplicateResourceIdentity'
        $LastAttempt.Diagnostics[0].ResourceType | Should -Be 'microsoft.entra.conditionalaccesspolicy'
    }
}

Describe 'Get-EntraOpsTenantGovernanceResourceGraphState' {
    BeforeAll {
        # The file-level stub has no parameters; this one lets the parameter filters below see the requested Uri.
        function Invoke-EntraOpsMsGraphQuery { param($Method, $Uri, $OutputType, [switch]$DisableCache, [switch]$ThrowOnFailure, $MaxRetries, [switch]$SuppressNotFoundWarning, [switch]$SuppressForbiddenWarning) }
        # Same shape as the error Invoke-EntraOpsMsGraphQuery -ThrowOnFailure throws for a non-retryable answer
        function New-TestGraphException([int]$StatusCode) {
            $Exception = [System.InvalidOperationException]::new("Microsoft Graph query failed: HTTP $StatusCode")
            $Exception.Data['StatusCode'] = $StatusCode
            $Exception
        }
    }

    It 'requests the resource by its own Id from the v1.0 assignmentPolicies endpoint and reports Exists' {
        Mock Invoke-EntraOpsMsGraphQuery { [PSCustomObject]@{ id = 'policy-1' } }

        $State = Get-EntraOpsTenantGovernanceResourceGraphState -ResourceType 'microsoft.entra.entitlementManagementAccessPackageAssignmentPolicy' -ResourceId 'policy-1'

        $State.State | Should -Be 'Exists'
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter {
            $Uri -eq '/v1.0/identityGovernance/entitlementManagement/assignmentPolicies/policy-1' -and $ThrowOnFailure -and $DisableCache
        }
    }

    It 'reports NotFound only for HTTP 404' {
        Mock Invoke-EntraOpsMsGraphQuery { throw (New-TestGraphException -StatusCode 404) }
        (Get-EntraOpsTenantGovernanceResourceGraphState -ResourceType 'microsoft.entra.conditionalaccesspolicy' -ResourceId 'policy-1').State | Should -Be 'NotFound'
    }

    It 'reports Unknown for HTTP <StatusCode>' -ForEach @(@{ StatusCode = 429 }, @{ StatusCode = 500 }, @{ StatusCode = 503 }, @{ StatusCode = 403 }) {
        Mock Invoke-EntraOpsMsGraphQuery { throw (New-TestGraphException -StatusCode $StatusCode) }
        $State = Get-EntraOpsTenantGovernanceResourceGraphState -ResourceType 'microsoft.entra.conditionalaccesspolicy' -ResourceId 'policy-1'
        $State.State | Should -Be 'Unknown'
        $State.StatusCode | Should -Be $StatusCode
    }

    It 'reports Unknown for an error without status code (network error, persistent throttling) and for an empty answer' {
        Mock Invoke-EntraOpsMsGraphQuery { throw 'An error occurred while sending the request.' }
        (Get-EntraOpsTenantGovernanceResourceGraphState -ResourceType 'microsoft.entra.conditionalaccesspolicy' -ResourceId 'policy-1').State | Should -Be 'Unknown'
        Mock Invoke-EntraOpsMsGraphQuery { $null }
        (Get-EntraOpsTenantGovernanceResourceGraphState -ResourceType 'microsoft.entra.conditionalaccesspolicy' -ResourceId 'policy-1').State | Should -Be 'Unknown'
    }

    It 'reports Unsupported without a Graph request for a type without a known endpoint' {
        Mock Invoke-EntraOpsMsGraphQuery { throw 'must not be called' }
        (Get-EntraOpsTenantGovernanceResourceGraphState -ResourceType 'microsoft.entra.crossTenantAccessPolicyConfigurationPartner' -ResourceId 'tenant-1').State | Should -Be 'Unsupported'
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly
    }

    It 'escapes the Id so it stays one path segment' {
        Mock Invoke-EntraOpsMsGraphQuery { [PSCustomObject]@{ id = 'x' } }
        $null = Get-EntraOpsTenantGovernanceResourceGraphState -ResourceType 'microsoft.entra.namedlocationpolicy' -ResourceId '../../users?$top=1'
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -eq '/v1.0/identity/conditionalAccess/namedLocations/..%2F..%2Fusers%3F%24top%3D1' }
    }
}

Describe 'Save-EntraOpsTenantGovernanceSnapshotJson removal of deleted retained resources' {
    BeforeAll {
        # The file-level stub has no parameters; this one lets the parameter filters below see the requested Uri.
        function Invoke-EntraOpsMsGraphQuery { param($Method, $Uri, $OutputType, [switch]$DisableCache, [switch]$ThrowOnFailure, $MaxRetries, [switch]$SuppressNotFoundWarning, [switch]$SuppressForbiddenWarning) }
        $script:PolicyType = 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy'
        $script:CaType = 'microsoft.entra.conditionalaccesspolicy'
        $script:ReturnedPolicyId = '11111111-1111-1111-1111-111111111111'
        $script:DeletedPolicyId = '22222222-2222-2222-2222-222222222222'
        $script:ExistingPolicyId = '33333333-3333-3333-3333-333333333333'

        function New-TestGraphException([int]$StatusCode) {
            $Exception = [System.InvalidOperationException]::new("Microsoft Graph query failed: HTTP $StatusCode")
            $Exception.Data['StatusCode'] = $StatusCode
            $Exception
        }

        # Earlier published files of the policy type: one returned again, one deleted in the tenant, one that still exists
        # but fails to export because it references a deleted object.
        function Initialize-TestPolicyFolder {
            $script:PolicyFolder = Join-Path $script:ExportFolder "$script:PolicyType/AADEntitlementManagementAccessPackageAssignmentPolicy"
            New-Item -ItemType Directory -Path $script:PolicyFolder -Force | Out-Null
            foreach ($Previous in @(
                    @{ Name = 'Returned.json'; Id = $script:ReturnedPolicyId }
                    @{ Name = 'Deleted.json'; Id = $script:DeletedPolicyId }
                    @{ Name = 'Broken reference.json'; Id = $script:ExistingPolicyId }
                )) {
                [ordered]@{ displayName = "AADEntitlementManagementAccessPackageAssignmentPolicy-$($Previous.Name -replace '\.json$')"; resourceType = $script:PolicyType; properties = [ordered]@{ Id = $Previous.Id } } |
                ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $script:PolicyFolder $Previous.Name) -Encoding utf8
            }
        }

        function New-TestPolicySnapshot {
            [PSCustomObject]@{
                SnapshotId = 'job-removal'; Status = 'Completed'; SnapshotJobStatus = 'partiallySuccessful'
                DisplayName = 'Test Snapshot'; CreatedDateTime = '2026-11-17T10:11:12Z'
                ResourcesToInclude = @('microsoft.entra.entitlementManagementAccessPackageAssignmentPolicy'); ResourceCount = 1
                # The message is ambiguous: deleted policy or deleted referenced object
                ErrorDetails = @(
                    "microsoft.entra.entitlementManagementAccessPackageAssignmentPolicy: Error exporting resource [microsoft.entra.entitlementManagementAccessPackageAssignmentPolicy]. exceptionMessage(s):[Request_ResourceNotFound] : Resource '$script:DeletedPolicyId' does not exist or one of its queried reference-property objects are not present. ,[Request_ResourceNotFound] : Resource '44444444-4444-4444-4444-444444444444' does not exist or one of its queried reference-property objects are not present. ,"
                )
                Resources = @([PSCustomObject]@{ resourceType = 'microsoft.entra.entitlementManagementAccessPackageAssignmentPolicy'; displayName = 'AADEntitlementManagementAccessPackageAssignmentPolicy-Returned'; properties = [PSCustomObject]@{ Id = $script:ReturnedPolicyId } })
            }
        }
    }

    BeforeEach {
        $script:EntraOpsBaseFolder = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $script:ExportFolder = Join-Path $script:EntraOpsBaseFolder 'TenantGovernance/Snapshots'
        New-Item -ItemType Directory -Path $script:ExportFolder -Force | Out-Null
    }

    It 'removes the file of a resource Graph answers 404 for, keeps one Graph returns and records the removal in the manifest' {
        Initialize-TestPolicyFolder
        Mock Get-EntraOpsTenantGovernanceSnapshot { New-TestPolicySnapshot }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like "*/$script:DeletedPolicyId") { throw (New-TestGraphException -StatusCode 404) }
            [PSCustomObject]@{ id = ($Uri -split '/')[-1] }
        }

        Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null

        Test-Path -LiteralPath (Join-Path $script:PolicyFolder 'Deleted.json') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:PolicyFolder 'Broken reference.json') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:PolicyFolder 'Returned.json') | Should -BeTrue
        # Control request for the returned policy plus one request per policy the job did not return
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -eq "/v1.0/identityGovernance/entitlementManagement/assignmentPolicies/$script:ReturnedPolicyId" }
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -eq "/v1.0/identityGovernance/entitlementManagement/assignmentPolicies/$script:DeletedPolicyId" }
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -eq "/v1.0/identityGovernance/entitlementManagement/assignmentPolicies/$script:ExistingPolicyId" }
        # The GUID of the error message that is no snapshot resource is never requested
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly -ParameterFilter { $Uri -like '*44444444-4444-4444-4444-444444444444*' }

        $Manifest = Get-Content -LiteralPath (Join-Path $script:ExportFolder '.SnapshotManifest.json') -Raw | ConvertFrom-Json
        @($Manifest.RemovedResources).Count | Should -Be 1
        $Manifest.RemovedResources[0].ResourceType | Should -Be $script:PolicyType
        $Manifest.RemovedResources[0].ResourceId | Should -Be $script:DeletedPolicyId
        $Manifest.RemovedResources[0].DisplayName | Should -Be 'AADEntitlementManagementAccessPackageAssignmentPolicy-Deleted'
        $Manifest.RemovedResources[0].File | Should -Be "$script:PolicyType/AADEntitlementManagementAccessPackageAssignmentPolicy/Deleted.json"
        $Manifest.RemovedResources[0].Reason | Should -Be 'NotFound'
        $Manifest.RemovedResources[0].Detail | Should -Match '404'
        $State = $Manifest.ResourceTypeStates | Where-Object { $_.ResourceType -eq $script:PolicyType }
        $State.Status | Should -Be 'PublishedWithErrors'
        $State.RetainedResourceCount | Should -Be 1
        $State.RemovedResourceCount | Should -Be 1
        $State.PublishedResourceCount | Should -Be 2
    }

    It 'keeps the file when the check answers HTTP <StatusCode>' -ForEach @(@{ StatusCode = 429 }, @{ StatusCode = 500 }, @{ StatusCode = 403 }) {
        Initialize-TestPolicyFolder
        Mock Get-EntraOpsTenantGovernanceSnapshot { New-TestPolicySnapshot }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like "*/$script:ReturnedPolicyId") { return [PSCustomObject]@{ id = $script:ReturnedPolicyId } }
            throw (New-TestGraphException -StatusCode $StatusCode)
        }

        Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') -SkipPrerequisiteCheck -WarningVariable Warnings -WarningAction SilentlyContinue | Out-Null

        Test-Path -LiteralPath (Join-Path $script:PolicyFolder 'Deleted.json') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:PolicyFolder 'Broken reference.json') | Should -BeTrue
        @($Warnings | Where-Object { "$_" -match 'could not be checked' }).Count | Should -Be 1
        $Manifest = Get-Content -LiteralPath (Join-Path $script:ExportFolder '.SnapshotManifest.json') -Raw | ConvertFrom-Json
        @($Manifest.RemovedResources).Count | Should -Be 0
        ($Manifest.ResourceTypeStates | Where-Object { $_.ResourceType -eq $script:PolicyType }).RetainedResourceCount | Should -Be 2
    }

    It 'keeps every file of the type when the control request for a returned resource is not answered with the resource' {
        Initialize-TestPolicyFolder
        Mock Get-EntraOpsTenantGovernanceSnapshot { New-TestPolicySnapshot }
        # Every request answers 404, also for the policy the job just returned: the 404s can't be trusted.
        Mock Invoke-EntraOpsMsGraphQuery { throw (New-TestGraphException -StatusCode 404) }

        Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null

        Test-Path -LiteralPath (Join-Path $script:PolicyFolder 'Deleted.json') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:PolicyFolder 'Broken reference.json') | Should -BeTrue
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly
        @((Get-Content -LiteralPath (Join-Path $script:ExportFolder '.SnapshotManifest.json') -Raw | ConvertFrom-Json).RemovedResources).Count | Should -Be 0
    }

    It 'keeps a Conditional Access policy whose export failed because a referenced group was deleted' {
        $CaFolder = Join-Path $script:ExportFolder "$script:CaType/AADConditionalAccessPolicy"
        New-Item -ItemType Directory -Path $CaFolder -Force | Out-Null
        foreach ($Previous in @(@{ Name = '100 - Block unknown platforms.json'; Id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' }, @{ Name = '101 - Require MFA.json'; Id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' })) {
            [ordered]@{ resourceType = $script:CaType; properties = [ordered]@{ Id = $Previous.Id } } |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $CaFolder $Previous.Name) -Encoding utf8
        }
        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId = 'job-ca-group'; Status = 'Completed'; SnapshotJobStatus = 'partiallySuccessful'
                DisplayName = 'Test Snapshot'; CreatedDateTime = '2026-11-17T10:11:12Z'
                ResourcesToInclude = @('microsoft.entra.conditionalAccessPolicy'); ResourceCount = 1
                ErrorDetails = @("microsoft.entra.conditionalAccessPolicy: Error exporting resource [microsoft.entra.conditionalAccessPolicy]. exceptionMessage(s):Couldn't find ExcludedGroup 'cccccccc-cccc-cccc-cccc-cccccccccccc', that is defined in policy '100 - Block unknown platforms'. Skipping group. [Request_ResourceNotFound] : Resource 'cccccccc-cccc-cccc-cccc-cccccccccccc' does not exist or one of its queried reference-property objects are not present. ,")
                Resources = @([PSCustomObject]@{ resourceType = 'microsoft.entra.conditionalAccessPolicy'; displayName = 'AADConditionalAccessPolicy-101 - Require MFA'; properties = [PSCustomObject]@{ Id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' } })
            }
        }
        # The policy exists; only the referenced group is gone
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like '*cccccccc-cccc-cccc-cccc-cccccccccccc*') { throw (New-TestGraphException -StatusCode 404) }
            [PSCustomObject]@{ id = ($Uri -split '/')[-1] }
        }

        Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null

        Test-Path -LiteralPath (Join-Path $CaFolder '100 - Block unknown platforms.json') | Should -BeTrue
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -eq '/v1.0/identity/conditionalAccess/policies/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' }
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly -ParameterFilter { $Uri -like '*cccccccc-cccc-cccc-cccc-cccccccccccc*' }
        $Manifest = Get-Content -LiteralPath (Join-Path $script:ExportFolder '.SnapshotManifest.json') -Raw | ConvertFrom-Json
        @($Manifest.RemovedResources).Count | Should -Be 0
        $Manifest.ResourceTypeStates[0].RetainedResourceCount | Should -Be 1
    }

    It 'keeps retained files of a resource type without a known direct endpoint unchecked' {
        $Type = 'microsoft.entra.group'
        $GroupFolder = Join-Path $script:ExportFolder "$Type/AADGroup"
        New-Item -ItemType Directory -Path $GroupFolder -Force | Out-Null
        [ordered]@{ resourceType = $Type; properties = [ordered]@{ Id = 'group-missing' } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $GroupFolder 'Missing.json') -Encoding utf8
        Mock Get-EntraOpsTenantGovernanceSnapshot {
            [PSCustomObject]@{
                SnapshotId = 'job-unsupported'; Status = 'Completed'; SnapshotJobStatus = 'partiallySuccessful'
                DisplayName = 'Test Snapshot'; CreatedDateTime = '2026-11-17T10:11:12Z'
                ResourcesToInclude = @('microsoft.entra.group'); ResourceCount = 1
                ErrorDetails = @("microsoft.entra.group: Error exporting resource [microsoft.entra.group]. exceptionMessage(s):[Request_ResourceNotFound] : Resource 'group-missing' does not exist. ,")
                Resources = @([PSCustomObject]@{ resourceType = 'microsoft.entra.group'; displayName = 'AADGroup-Returned'; properties = [PSCustomObject]@{ Id = 'group-returned' } })
            }
        }
        Mock Invoke-EntraOpsMsGraphQuery { throw (New-TestGraphException -StatusCode 404) }

        Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $script:ExportFolder -ResourcesToInclude @('unused-by-mock') -SkipPrerequisiteCheck -WarningAction SilentlyContinue | Out-Null

        Test-Path -LiteralPath (Join-Path $GroupFolder 'Missing.json') | Should -BeTrue
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly
    }
}

Describe 'ConvertTo-EntraOpsSortedObject' {
    It 'sorts administrative-unit members alphabetically and independently of Graph response order' {
        $Members = @(
            [PSCustomObject]@{ Identity = 'RestrictedAuGroup'; Type = 'Group' }
            [PSCustomObject]@{ Identity = 'cloudadmin@contoso.com'; Type = 'User' }
            [PSCustomObject]@{ Identity = 'admBrk0-01@contoso.com'; Type = 'User' }
            [PSCustomObject]@{ Identity = 'AdeleV@contoso.com'; Type = 'User' }
        )

        $Forward = ConvertTo-EntraOpsSortedObject -InputObject ([PSCustomObject]@{ Members = $Members }) -CollectionPathsToSort 'Members'
        $Reverse = ConvertTo-EntraOpsSortedObject -InputObject ([PSCustomObject]@{ Members = @($Members[3..0]) }) -CollectionPathsToSort 'Members'

        @($Forward.Members.Identity) | Should -Be @(
            'AdeleV@contoso.com'
            'admBrk0-01@contoso.com'
            'cloudadmin@contoso.com'
            'RestrictedAuGroup'
        )
        ($Forward | ConvertTo-Json -Depth 10) | Should -Be ($Reverse | ConvertTo-Json -Depth 10)
    }

    It 'sorts scalar collection values alphabetically' {
        $Sorted = ConvertTo-EntraOpsSortedObject -InputObject ([PSCustomObject]@{
                Items = @('Zulu', 'alpha', 'Bravo')
            }) -CollectionPathsToSort 'Items'

        @($Sorted.Items) | Should -Be @('alpha', 'Bravo', 'Zulu')
    }

    It 'keeps a nested collection distinguishable from its scalar equivalent' {
        $Sorted = ConvertTo-EntraOpsSortedObject -InputObject ([PSCustomObject]@{
                Items = @('alpha', @('alpha'))
            }) -CollectionPathsToSort 'Items'
        $Reverse = ConvertTo-EntraOpsSortedObject -InputObject ([PSCustomObject]@{
                Items = @(@('alpha'), 'alpha')
            }) -CollectionPathsToSort 'Items'

        $SortedJson = ConvertTo-Json -InputObject $Sorted -Depth 10 -Compress
        $SortedJson | Should -Be '{"Items":["alpha",["alpha"]]}'
        $SortedJson | Should -Be (ConvertTo-Json -InputObject $Reverse -Depth 10 -Compress)
    }

    It 'preserves positional collection order when the path is not explicitly selected' {
        $Sorted = ConvertTo-EntraOpsSortedObject -InputObject ([PSCustomObject]@{
                properties = [PSCustomObject]@{
                    stages = @(
                        [PSCustomObject]@{ displayName = 'Second approval stage' }
                        [PSCustomObject]@{ displayName = 'First approval stage' }
                    )
                }
            }) -CollectionPathsToSort 'properties.Members'

        @($Sorted.properties.stages.displayName) | Should -Be @(
            'Second approval stage'
            'First approval stage'
        )
    }
}

Describe 'Get-EntraOpsTenantGovernanceSnapshotReport last-attempt diagnostics' {
    It 'surfaces diagnostics of a rejected later attempt next to the published snapshot' {
        $SnapshotFolder = Join-Path $TestDrive 'report/TenantGovernance/Snapshots'
        $Type = 'microsoft.entra.conditionalaccesspolicy'
        New-Item -ItemType Directory -Path (Join-Path $SnapshotFolder "$Type/General") -Force | Out-Null
        [ordered]@{ resourceType = $Type; displayName = 'Policy'; properties = [ordered]@{ Id = 'policy-1' } } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $SnapshotFolder "$Type/General/Policy.json") -Encoding utf8
        [ordered]@{
            SnapshotId = 'job-published'; SnapshotJobStatus = 'succeeded'; CapturedDateTime = '2026-09-01T10:00:00Z'
            ResourcesToInclude = @($Type); CapturedResourceCount = 1
            PublishedResourceTypeCounts = [ordered]@{ ($Type) = 1 }; PublishedResourceTypes = @($Type); StaleResourceTypes = @()
            ResourceTypeStates = @([ordered]@{ ResourceType = $Type; Status = 'Published'; PublishedSnapshotId = 'job-published' })
            Diagnostics = @(); ErrorDetailsUnavailable = $false; IsComplete = $true
        } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $SnapshotFolder '.SnapshotManifest.json') -Encoding utf8
        [ordered]@{
            SnapshotId = 'job-duplicate'; SnapshotJobStatus = 'succeeded'; CapturedDateTime = '2026-09-04T10:00:00Z'
            ResourcesToInclude = @($Type); CapturedResourceCount = 2; PublishedResourceTypeCounts = [ordered]@{}
            PublishedResourceTypes = @(); StaleResourceTypes = @($Type); ResourceTypeStates = @()
            Diagnostics = @([ordered]@{ ResourceType = $Type; ErrorCategory = 'DuplicateResourceIdentity'; ErrorCode = 'DuplicateCanonicalIdentity'; Occurrences = 1; Message = 'duplicate identity'; RemediationHint = 'start a new job' })
            ErrorDetailsUnavailable = $false; IsComplete = $false
        } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $SnapshotFolder '.LastAttemptManifest.json') -Encoding utf8
        $ConfigPath = Join-Path $TestDrive 'report/EntraOpsConfig.json'
        @{ TenantGovernanceSnapshot = @{ ResourcesToInclude = @($Type) } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath -Encoding utf8
        Mock Show-EntraOpsWarningSummary {}

        $Report = Get-EntraOpsTenantGovernanceSnapshotReport -SnapshotFolder $SnapshotFolder -ConfigFilePath $ConfigPath -SkipGraphJobDetails -WarningAction SilentlyContinue

        @($Report.PersistedDiagnostics).Count | Should -Be 0
        @($Report.LastAttemptDiagnostics).Count | Should -Be 1
        $Report.LastAttemptDiagnostics[0].ErrorCategory | Should -Be 'DuplicateResourceIdentity'
        Should -Invoke Show-EntraOpsWarningSummary -Times 1 -Exactly -ParameterFilter {
            @($WarningMessages | Where-Object { $_.Message -like '*Last attempt job-duplicate*DuplicateCanonicalIdentity*' }).Count -eq 1
        }
    }

    It 'does not repeat diagnostics when the last attempt is the published snapshot itself' {
        $SnapshotFolder = Join-Path $TestDrive 'report-same/TenantGovernance/Snapshots'
        New-Item -ItemType Directory -Path $SnapshotFolder -Force | Out-Null
        $Manifest = [ordered]@{
            SnapshotId = 'job-partial'; SnapshotJobStatus = 'partiallySuccessful'; CapturedDateTime = '2026-09-01T10:00:00Z'
            ResourcesToInclude = @('microsoft.entra.namedlocation'); CapturedResourceCount = 0; PublishedResourceTypeCounts = [ordered]@{}
            PublishedResourceTypes = @(); StaleResourceTypes = @('microsoft.entra.namedlocation'); ResourceTypeStates = @()
            Diagnostics = @([ordered]@{ ResourceType = 'microsoft.entra.namedlocation'; ErrorCategory = 'ConnectionError'; ErrorCode = 'Timeout'; Occurrences = 2; Message = 'timeout'; RemediationHint = 'retry' })
            ErrorDetailsUnavailable = $false; IsComplete = $false
        }
        $Manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $SnapshotFolder '.SnapshotManifest.json') -Encoding utf8
        $Manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $SnapshotFolder '.LastAttemptManifest.json') -Encoding utf8
        $ConfigPath = Join-Path $TestDrive 'report-same/EntraOpsConfig.json'
        @{ TenantGovernanceSnapshot = @{ ResourcesToInclude = @('microsoft.entra.namedlocation') } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath -Encoding utf8
        Mock Show-EntraOpsWarningSummary {}

        $Report = Get-EntraOpsTenantGovernanceSnapshotReport -SnapshotFolder $SnapshotFolder -ConfigFilePath $ConfigPath -SkipGraphJobDetails -WarningAction SilentlyContinue

        @($Report.PersistedDiagnostics).Count | Should -Be 1
        @($Report.LastAttemptDiagnostics).Count | Should -Be 0
        Should -Invoke Show-EntraOpsWarningSummary -Times 1 -Exactly -ParameterFilter { @($WarningMessages).Count -eq 1 }
    }

    It 'does not double-prefix a diagnostic message that already starts with its bracketed error code' {
        $SnapshotFolder = Join-Path $TestDrive 'report-prefix/TenantGovernance/Snapshots'
        New-Item -ItemType Directory -Path $SnapshotFolder -Force | Out-Null
        $Manifest = [ordered]@{
            SnapshotId = 'job-prefix'; SnapshotJobStatus = 'partiallySuccessful'; CapturedDateTime = '2026-09-01T10:00:00Z'
            ResourcesToInclude = @('microsoft.entra.namedlocation'); CapturedResourceCount = 0; PublishedResourceTypeCounts = [ordered]@{}
            PublishedResourceTypes = @(); StaleResourceTypes = @('microsoft.entra.namedlocation'); ResourceTypeStates = @()
            Diagnostics = @(
                [ordered]@{ ResourceType = 'microsoft.entra.namedlocation'; ErrorCategory = 'ExportError'; ErrorCode = 'Request_ResourceNotFound'; Occurrences = 2; Message = "[Request_ResourceNotFound] : Resource '<id>' does not exist."; RemediationHint = 'retry' }
                [ordered]@{ ResourceType = 'microsoft.entra.namedlocation'; ErrorCategory = 'ConnectionError'; ErrorCode = 'Timeout'; Occurrences = 1; Message = 'timeout'; RemediationHint = 'retry' }
            )
            ErrorDetailsUnavailable = $false; IsComplete = $false
        }
        $Manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $SnapshotFolder '.SnapshotManifest.json') -Encoding utf8
        $Manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $SnapshotFolder '.LastAttemptManifest.json') -Encoding utf8
        $ConfigPath = Join-Path $TestDrive 'report-prefix/EntraOpsConfig.json'
        @{ TenantGovernanceSnapshot = @{ ResourcesToInclude = @('microsoft.entra.namedlocation') } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath -Encoding utf8
        Mock Show-EntraOpsWarningSummary {}

        Get-EntraOpsTenantGovernanceSnapshotReport -SnapshotFolder $SnapshotFolder -ConfigFilePath $ConfigPath -SkipGraphJobDetails -WarningAction SilentlyContinue | Out-Null

        Should -Invoke Show-EntraOpsWarningSummary -Times 1 -Exactly -ParameterFilter {
            $Messages = @($WarningMessages.Message)
            $Messages.Count -eq 2 -and
            @($Messages | Where-Object { $_.StartsWith("[Request_ResourceNotFound] : Resource") }).Count -eq 1 -and
            @($Messages | Where-Object { $_.Contains('[Request_ResourceNotFound] [Request_ResourceNotFound]') }).Count -eq 0 -and
            @($Messages | Where-Object { $_.StartsWith('[Timeout] timeout') }).Count -eq 1
        }
    }
}

