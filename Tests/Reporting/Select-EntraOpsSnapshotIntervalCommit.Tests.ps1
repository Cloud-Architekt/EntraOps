#Requires -Modules Pester

BeforeAll {
    $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . (Join-Path $RepositoryRoot 'EntraOps/Private/Select-EntraOpsSnapshotIntervalCommit.ps1')

    function New-TestCommit {
        param ([string]$Sha, [string]$Date)
        [pscustomobject]@{ Sha = $Sha; Date = [datetimeoffset]::Parse($Date, [System.Globalization.CultureInfo]::InvariantCulture) }
    }
}

Describe 'Select-EntraOpsSnapshotIntervalCommit' {
    It 'keeps every weekly snapshot when a run finishes a few minutes earlier than the previous one' {
        $Commits = @(
            New-TestCommit -Sha 'w1' -Date '2026-10-02T07:15:00Z'
            New-TestCommit -Sha 'w2' -Date '2026-10-09T07:09:00Z'
            New-TestCommit -Sha 'w3' -Date '2026-10-16T07:20:00Z'
            New-TestCommit -Sha 'w4' -Date '2026-10-23T07:02:00Z'
        )

        $Kept = Select-EntraOpsSnapshotIntervalCommit -Commit $Commits -Days 7

        @($Kept.Sha) | Should -Be @('w1', 'w2', 'w3', 'w4')
    }

    It 'keeps one commit per week from daily commits' {
        $Commits = @(0..15 | ForEach-Object { New-TestCommit -Sha "d$_" -Date ([datetimeoffset]'2026-10-01T06:00:00Z').AddDays($_).ToString('o') })

        $Kept = Select-EntraOpsSnapshotIntervalCommit -Commit $Commits -Days 7

        @($Kept.Sha) | Should -Be @('d0', 'd7', 'd14', 'd15')
    }

    It 'still drops a second commit of the same snapshot day' {
        $Commits = @(
            New-TestCommit -Sha 'pending' -Date '2026-10-09T06:28:00Z'
            New-TestCommit -Sha 'complete' -Date '2026-10-09T07:09:00Z'
            New-TestCommit -Sha 'next-pending' -Date '2026-10-16T06:20:00Z'
            New-TestCommit -Sha 'next-complete' -Date '2026-10-16T07:05:00Z'
            New-TestCommit -Sha 'latest' -Date '2026-10-20T07:00:00Z'
        )

        $Kept = Select-EntraOpsSnapshotIntervalCommit -Commit $Commits -Days 7

        @($Kept.Sha) | Should -Be @('pending', 'next-pending', 'latest')
    }

    It 'limits the tolerance of a daily interval to a quarter of a day' {
        $Commits = @(
            New-TestCommit -Sha 'a' -Date '2026-10-01T06:00:00Z'
            New-TestCommit -Sha 'too-early' -Date '2026-10-01T23:00:00Z'
            New-TestCommit -Sha 'within-tolerance' -Date '2026-10-02T01:00:00Z'
            New-TestCommit -Sha 'last' -Date '2026-10-02T02:00:00Z'
        )

        $Kept = Select-EntraOpsSnapshotIntervalCommit -Commit $Commits -Days 1

        @($Kept.Sha) | Should -Be @('a', 'within-tolerance', 'last')
    }

    It 'returns the commits unchanged without an interval or with two commits at most' {
        $Commits = @(
            New-TestCommit -Sha 'a' -Date '2026-10-01T06:00:00Z'
            New-TestCommit -Sha 'b' -Date '2026-10-01T07:00:00Z'
            New-TestCommit -Sha 'c' -Date '2026-10-01T08:00:00Z'
        )

        @((Select-EntraOpsSnapshotIntervalCommit -Commit $Commits).Sha) | Should -Be @('a', 'b', 'c')
        @((Select-EntraOpsSnapshotIntervalCommit -Commit $Commits[0..1] -Days 7).Sha) | Should -Be @('a', 'b')
    }

    It 'is the only snapshot thinning of the history generators (<Generator>)' -ForEach @(
        @{ Generator = 'New-EntraOpsPrivilegedEamPrivilegeHistoryData' }
        @{ Generator = 'New-EntraOpsTenantGovernanceConfigurationAnalyzerData' }
    ) {
        $Path = Join-Path $PSScriptRoot "../../EntraOps/Public/Reportings/$Generator.ps1"
        $Ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        $Commands = @($Ast.FindAll({ param($Node) $Node -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
        $Commands | Should -Contain 'Select-EntraOpsSnapshotIntervalCommit'
        $Commands | Should -Not -Contain 'Add-SnapshotInterval'
    }
}
