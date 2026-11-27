#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
    # The tier table is module state: call the tier functions in the module scope.
    function Invoke-TierFunction([string]$Name, [hashtable]$Parameter = @{}) { & (Get-Module EntraOps) { param($Name, $Parameter) & $Name @Parameter } $Name $Parameter }
}

Describe 'ConvertTo-EntraOpsAdminTierLevel' {
    It 'maps <Value> to level <Level>' -ForEach @(
        @{ Value = 'ControlPlane'; Level = 0 }
        @{ Value = 'ManagementPlane'; Level = 1 }
        @{ Value = 'WorkloadPlane'; Level = 1 }
        @{ Value = 'UserAccess'; Level = 2 }
        @{ Value = 'controlplane'; Level = 0 }
        @{ Value = '0'; Level = 0 }
        @{ Value = ' 1 '; Level = 1 }
        @{ Value = '01'; Level = 1 }
        @{ Value = 2; Level = 2 }
    ) {
        Invoke-TierFunction ConvertTo-EntraOpsAdminTierLevel @{ Value = $Value } | Should -Be $Level
        Invoke-TierFunction Get-EntraOpsAdminTierLevel @{ Value = $Value } | Should -Be $Level
    }

    It 'returns the default for unclassified, empty and unknown values (<Value>)' -ForEach @(
        @{ Value = $null }
        @{ Value = '' }
        @{ Value = 'Unclassified' }
        @{ Value = '3' }
        @{ Value = '-1' }
        @{ Value = 'Tier0' }
    ) {
        Invoke-TierFunction ConvertTo-EntraOpsAdminTierLevel @{ Value = $Value } | Should -Be 2
        Invoke-TierFunction ConvertTo-EntraOpsAdminTierLevel @{ Value = $Value; Default = 9 } | Should -Be 9
        Invoke-TierFunction Get-EntraOpsAdminTierLevel @{ Value = $Value } | Should -Be 2
    }
}

Describe 'Tier table of the Findings rules' {
    It 'ranks <TierName> as <Rank> like the reports (case-sensitive)' -ForEach @(
        @{ TierName = 'ControlPlane'; Rank = 0 }
        @{ TierName = 'WorkloadPlane'; Rank = 2 }
        @{ TierName = 'Unclassified'; Rank = 4 }
        @{ TierName = 'controlplane'; Rank = 5 }
        @{ TierName = $null; Rank = 5 }
    ) {
        Invoke-TierFunction Get-EntraOpsReportTierRank @{ TierName = $TierName } | Should -Be $Rank
    }

    It 'treats only Control Plane and Management Plane as privileged' {
        Invoke-TierFunction Test-EntraOpsPrivilegedTier @{ TierName = 'ControlPlane' } | Should -BeTrue
        Invoke-TierFunction Test-EntraOpsPrivilegedTier @{ TierName = 'ManagementPlane' } | Should -BeTrue
        Invoke-TierFunction Test-EntraOpsPrivilegedTier @{ TierName = 'WorkloadPlane' } | Should -BeFalse
        Invoke-TierFunction Test-EntraOpsPrivilegedTier @{ TierName = 'controlplane' } | Should -BeFalse
        Invoke-TierFunction Test-EntraOpsPrivilegedTier @{ TierName = $null } | Should -BeFalse
    }

    It 'returns the most privileged tier' {
        Invoke-TierFunction Get-EntraOpsMostPrivilegedTier @{ TierName = @('UserAccess', 'ManagementPlane', 'Unknown') } | Should -Be 'ManagementPlane'
        Invoke-TierFunction Get-EntraOpsMostPrivilegedTier @{ TierName = @('Unclassified', 'Unknown') } | Should -BeNullOrEmpty
        Invoke-TierFunction Get-EntraOpsMostPrivilegedTier @{ TierName = @('Unclassified'); IncludeUnclassified = $true } | Should -Be 'Unclassified'
        Invoke-TierFunction Get-EntraOpsMostPrivilegedTier @{ TierName = @() } | Should -BeNullOrEmpty
    }
}
