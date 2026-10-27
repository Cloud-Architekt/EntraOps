#Requires -Modules Pester

BeforeAll {
    $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepositoryRoot 'EntraOps') -Force

    function Save-HistoryTestCommit {
        param([string]$Date, [string]$Message)

        & git -C $Root add --all
        if ($LASTEXITCODE -ne 0) { throw 'Could not stage the snapshot fixture.' }
        $PreviousAuthorDate = $env:GIT_AUTHOR_DATE
        $PreviousCommitterDate = $env:GIT_COMMITTER_DATE
        try {
            $env:GIT_AUTHOR_DATE = $Date
            $env:GIT_COMMITTER_DATE = $Date
            & git -C $Root -c user.name=EntraOps -c user.email=fixture@example.com -c commit.gpgsign=false commit --quiet -m $Message
            if ($LASTEXITCODE -ne 0) { throw "Could not commit snapshot fixture '$Message'." }
        } finally {
            $env:GIT_AUTHOR_DATE = $PreviousAuthorDate
            $env:GIT_COMMITTER_DATE = $PreviousCommitterDate
        }
    }

    function Publish-HistoryTestSnapshot {
        param([string]$Date, [string]$Id, [string]$Value)

        @{
            resourceType = 'microsoft.entra.test'
            properties   = @{ Id = 'fixture-resource'; displayName = $Value }
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Snapshots 'microsoft.entra.test/resource.json')
        @{
            SnapshotId                  = $Id
            SnapshotJobStatus           = 'succeeded'
            IsComplete                  = $true
            CapturedDateTime            = $Date
            PublishedResourceTypes      = @('microsoft.entra.test')
            PublishedResourceTypeCounts = @{ 'microsoft.entra.test' = 1 }
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Snapshots '.SnapshotManifest.json')
        Remove-Item -LiteralPath (Join-Path $Snapshots '.PendingSnapshotJob.json') -Force -ErrorAction SilentlyContinue
        Save-HistoryTestCommit -Date $Date -Message "Complete $Id"
    }

    function Save-HistoryTestBookkeeping {
        param([string]$Date, [string]$Name, [string]$Id)

        @{ SnapshotJobId = $Id; LastCheckedDateTime = $Date } | ConvertTo-Json |
            Set-Content -LiteralPath (Join-Path $Snapshots $Name)
        Save-HistoryTestCommit -Date $Date -Message "Bookkeeping $Id $Name"
    }
}

Describe 'Configuration Analyzer snapshot history' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
    BeforeEach {
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:Snapshots = Join-Path $Root 'TenantGovernance/Snapshots'
        $script:AppRoot = Join-Path $Root 'Reports/ConfigurationAnalyzer'
        New-Item -ItemType Directory -Path (Join-Path $Snapshots 'microsoft.entra.test'), $AppRoot -Force | Out-Null
        & git -C $Root init --quiet
        if ($LASTEXITCODE -ne 0) { throw 'Could not initialize snapshot history fixture.' }
    }

    It 'keeps completed captures and excludes pending and failed attempts with interval <Interval>' -ForEach @(
        @{ Interval = 'P1W' }
        @{ Interval = 'None' }
    ) {
        Publish-HistoryTestSnapshot -Date '2026-10-02T07:00:00Z' -Id 'week1' -Value 'unchanged'
        Save-HistoryTestBookkeeping -Date '2026-10-09T06:00:00Z' -Name '.PendingSnapshotJob.json' -Id 'week2'
        Save-HistoryTestBookkeeping -Date '2026-10-09T06:30:00Z' -Name '.PendingSnapshotJob.json' -Id 'week2'
        # This successful capture changes only its manifest: the resources are unchanged.
        Publish-HistoryTestSnapshot -Date '2026-10-09T07:00:00Z' -Id 'week2' -Value 'unchanged'
        Save-HistoryTestBookkeeping -Date '2026-10-16T06:00:00Z' -Name '.PendingSnapshotJob.json' -Id 'week3'
        Publish-HistoryTestSnapshot -Date '2026-10-16T07:00:00Z' -Id 'week3' -Value 'updated'
        Save-HistoryTestBookkeeping -Date '2026-10-23T06:00:00Z' -Name '.PendingSnapshotJob.json' -Id 'week4'
        Save-HistoryTestBookkeeping -Date '2026-10-23T06:30:00Z' -Name '.LastAttemptManifest.json' -Id 'week4-failed'

        $Payload = New-EntraOpsTenantGovernanceConfigurationAnalyzerData -RepoRoot $Root -AppRoot $AppRoot `
            -SnapshotInterval $Interval -ResolveGroupMembersForPrivilegedAssets $false -AllowStaleSnapshot `
            -SkipWorkingTree -PassThru -WarningAction SilentlyContinue 6>$null

        @($Payload.snapshots.subject) | Should -Be @('Complete week1', 'Complete week2', 'Complete week3')
        @($Payload.snapshots | ForEach-Object { $Payload.blobs[$_.resources[0].h].properties.displayName }) |
            Should -Be @('unchanged', 'unchanged', 'updated')
    }
}
