#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

Describe 'Update-EntraOpsClassificationControlPlaneScope empty scopes' {
    BeforeDiscovery {
        $ScopeVariables = @(
            'ScopeNamePrivilegedUsers'
            'ScopeNamePrivilegedDevices'
            'ScopeNamePrivilegedGroups'
            'ScopeNamePrivilegedServicePrincipals'
        )
    }

    BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $ScriptPath = Join-Path $script:TestRepositoryRoot 'EntraOps/Public/PrivilegedAccess/Update-EntraOpsClassificationControlPlaneScope.ps1'
        $ScriptContent = [System.IO.File]::ReadAllText($ScriptPath)
        $ScopeVariables = @(
            'ScopeNamePrivilegedUsers'
            'ScopeNamePrivilegedDevices'
            'ScopeNamePrivilegedGroups'
            'ScopeNamePrivilegedServicePrincipals'
        )
    }

    It 'serializes <ScopeVariable> only when it contains entries' -ForEach @($ScopeVariables | ForEach-Object { @{ ScopeVariable = $_ } }) {
        $ExpectedGuard = "if (@(`$$ScopeVariable).Count -gt 0)"
        $ScriptContent | Should -Match ([regex]::Escape($ExpectedGuard))
    }

    It 'does not use null checks to decide whether scope collections contain entries' {
        foreach ($ScopeVariable in $ScopeVariables) {
            $UnsafeGuard = "if (`$null -ne `$$ScopeVariable)"
            $ScriptContent | Should -Not -Match ([regex]::Escape($UnsafeGuard))
        }
    }

    It 'does not discard device owners when the home tenant ID is unavailable' {
        $ScriptContent | Should -Match ([regex]::Escape('Home tenant ID is unavailable; device owners will not be filtered by tenant.'))
    }

    It 'computes whether a home tenant ID is available once and reuses it, instead of two independent null checks' {
        $HasHomeTenantIdAssignment = [regex]::Matches($ScriptContent, [regex]::Escape('$HasHomeTenantId = -not [string]::IsNullOrWhiteSpace($HomeTenantId)'))
        $HasHomeTenantIdAssignment.Count | Should -Be 1

        $HasHomeTenantIdUsage = [regex]::Matches($ScriptContent, '\$HasHomeTenantId\b')
        # One assignment plus at least two reads (foreign-tenant detection and the owner filter).
        $HasHomeTenantIdUsage.Count | Should -BeGreaterOrEqual 3
    }
}
