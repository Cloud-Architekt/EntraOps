#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Assert-EntraOpsConditionalAccessGroupSyncSucceeded.ps1"
}

Describe "Assert-EntraOpsConditionalAccessGroupSyncSucceeded" {
    It "accepts successful and forced synchronization summaries" {
        $Summary = @(
            [pscustomobject]@{ Status = "SUCCESS"; Failed = 0 }
            [pscustomobject]@{ Status = "FORCED"; Failed = 0 }
        )

        { Assert-EntraOpsConditionalAccessGroupSyncSucceeded -SyncSummary $Summary } | Should -Not -Throw
    }

    It "rejects a safety abort" {
        { Assert-EntraOpsConditionalAccessGroupSyncSucceeded -SyncSummary @([pscustomobject]@{ Status = "ABORTED"; Failed = 0 }) } |
            Should -Throw "*aborted by the removal safety threshold*"
    }

    It "rejects failed membership operations" {
        { Assert-EntraOpsConditionalAccessGroupSyncSucceeded -SyncSummary @([pscustomobject]@{ Status = "FAILED"; Failed = 2 }) } |
            Should -Throw "*2 membership operation(s) failed*"
    }
}
