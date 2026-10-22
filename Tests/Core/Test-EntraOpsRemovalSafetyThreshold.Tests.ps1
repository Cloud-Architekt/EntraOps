#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsRemovalSafetyThreshold.ps1"
}

Describe "Test-EntraOpsRemovalSafetyThreshold" {
    It "protects small targets when removals exceed their calculated budget" {
        (Test-EntraOpsRemovalSafetyThreshold -CurrentCount 5 -RemovalCount 5).Exceeds | Should -BeTrue
        (Test-EntraOpsRemovalSafetyThreshold -CurrentCount 2 -RemovalCount 2).Exceeds | Should -BeTrue
        (Test-EntraOpsRemovalSafetyThreshold -CurrentCount 1 -RemovalCount 1).Exceeds | Should -BeFalse
    }

    It "engages when removals exceed the threshold fraction of current members" {
        $Result = Test-EntraOpsRemovalSafetyThreshold -CurrentCount 20 -RemovalCount 11
        $Result.Exceeds | Should -BeTrue
        $Result.RemovalThreshold | Should -Be 10
        $Result.ThresholdPercent | Should -Be 50
    }

    It "allows removals up to and including the threshold count" {
        (Test-EntraOpsRemovalSafetyThreshold -CurrentCount 20 -RemovalCount 10).Exceeds | Should -BeFalse
    }

    It "honors a custom threshold fraction" {
        (Test-EntraOpsRemovalSafetyThreshold -CurrentCount 100 -RemovalCount 26 -RemovalSafetyThreshold 0.25).Exceeds | Should -BeTrue
        (Test-EntraOpsRemovalSafetyThreshold -CurrentCount 100 -RemovalCount 25 -RemovalSafetyThreshold 0.25).Exceeds | Should -BeFalse
    }

    It "supports strict and fully permissive configured thresholds" {
        (Test-EntraOpsRemovalSafetyThreshold -CurrentCount 1 -RemovalCount 1 -RemovalSafetyThreshold 0).Exceeds | Should -BeTrue
        (Test-EntraOpsRemovalSafetyThreshold -CurrentCount 5 -RemovalCount 5 -RemovalSafetyThreshold 1).Exceeds | Should -BeFalse
        (Test-EntraOpsRemovalSafetyThreshold -CurrentCount 0 -RemovalCount 0).Exceeds | Should -BeFalse
    }

    It "matches the shared threshold semantics for every target size" {
        foreach ($Case in @(
                @{ Current = 10; Removal = 6; Expected = $true }
                @{ Current = 10; Removal = 5; Expected = $false }
                @{ Current = 6; Removal = 4; Expected = $true }
                @{ Current = 5; Removal = 5; Expected = $true }
            )) {
            (Test-EntraOpsRemovalSafetyThreshold -CurrentCount $Case.Current -RemovalCount $Case.Removal).Exceeds | Should -Be $Case.Expected
        }
    }
}

