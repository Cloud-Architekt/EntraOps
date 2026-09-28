#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps') -Force

    # Connect-EntraOps publishes these in the global scope; a disconnect must not leave any of them behind.
    $TenantContextVariables = @(
        'EntraOpsConfig'
        'TenantIdContext'
        'TenantNameContext'
        'ManagingTenantIdContext'
        'ManagingTenantNameContext'
        'EntraOpsIncludeObjectDetails'
        'XdrAvdHuntingAccess'
        'DefaultFolderClassification'
        'DefaultFolderClassifiedEam'
    )
    $Session = & (Get-Module EntraOps) { $__EntraOpsSession }
}

Describe 'Disconnect-EntraOps session cleanup' {
    BeforeEach {
        foreach ($Name in $TenantContextVariables) {
            New-Variable -Name $Name -Value 'TENANT-A-SENTINEL' -Scope Global -Force
        }
        $Session['AuthenticationType'] = 'ServicePrincipal'
        $Session['UseInvokeRestMethodOnly'] = $true
        $Session.MsGraphTokenCache['tenant-a'] = 'token-a'
        $Session.ArmTokenCache['tenant-a'] = 'token-a'
        $Session.NonPimGroupIds['group-a'] = $true
        $Session.RetryStatistics.TotalRetries = 42
    }

    It 'removes every tenant context variable' {
        Disconnect-EntraOps *> $null

        foreach ($Name in $TenantContextVariables) {
            Get-Variable -Name $Name -Scope Global -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }
    }

    It 'clears token caches and authentication state' {
        Disconnect-EntraOps *> $null

        $Session.MsGraphTokenCache.Count | Should -Be 0
        $Session.ArmTokenCache.Count | Should -Be 0
        $Session['AuthenticationType'] | Should -BeNullOrEmpty
        $Session.ContainsKey('UseInvokeRestMethodOnly') | Should -BeFalse
    }

    It 'resets per-session lookup caches and retry statistics' {
        Disconnect-EntraOps *> $null

        $Session.NonPimGroupIds.Count | Should -Be 0
        $Session.RetryStatistics.TotalRetries | Should -Be 0
        $Session.RetryStatistics.FailedRequestDetails.Count | Should -Be 0
    }

    It 'is idempotent' {
        Disconnect-EntraOps *> $null

        { Disconnect-EntraOps *> $null } | Should -Not -Throw
    }
}

