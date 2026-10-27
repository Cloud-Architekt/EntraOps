#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps') -Force

    # Keep cleanup tests offline and isolated from the user's Azure/Graph sessions and disk cache.
    & (Get-Module EntraOps) {
        function script:Disconnect-AzAccount { [CmdletBinding()] param() }
        function script:Clear-AzContext { [CmdletBinding()] param($Scope, [switch]$Force) }
        function script:Get-AzContext { [CmdletBinding()] param() }
        function script:Get-MgContext { [CmdletBinding()] param() }
        function script:Disconnect-MgGraph { [CmdletBinding()] param() }
    }

    Add-Type -TypeDefinition @'
public static class EntraOpsDisconnectWarningTest {
    public static void Emit(System.Action<string> writer, string message) {
        System.Threading.Tasks.Task.Run(() => writer(message)).GetAwaiter().GetResult();
    }
}
'@

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
    $script:AuthorityWarning = "Failed to clear the persisted MSAL token cache during Disconnect-MgGraph: The authority (including the tenant ID) must be in a well-formed URI format.  (Parameter 'authority')"
}

AfterAll {
    & (Get-Module EntraOps) {
        Remove-Item Function:Disconnect-AzAccount, Function:Clear-AzContext, Function:Get-AzContext, Function:Get-MgContext, Function:Disconnect-MgGraph
    }
}

Describe 'Disconnect-EntraOps session cleanup' {
    BeforeEach {
        Mock Disconnect-AzAccount -ModuleName EntraOps {}
        Mock Clear-AzContext -ModuleName EntraOps {}
        Mock Get-AzContext -ModuleName EntraOps {}
        Mock Get-MgContext -ModuleName EntraOps {}
        Mock Disconnect-MgGraph -ModuleName EntraOps {}
        Mock Clear-EntraOpsCache -ModuleName EntraOps {}
        Mock Test-Path -ModuleName EntraOps { $false }
        Mock Get-EntraOpsGraphOutputWriter -ModuleName EntraOps { $null }
        foreach ($Name in $TenantContextVariables) {
            New-Variable -Name $Name -Value 'TENANT-A-SENTINEL' -Scope Global -Force
        }
        $Session['AuthenticationType'] = 'ServicePrincipal'
        $Session['UseInvokeRestMethodOnly'] = $true
        $Session['ConfigFilePath'] = 'previous-config.json'
        $Session.MsGraphTokenCache['tenant-a'] = 'token-a'
        $Session.ArmTokenCache['tenant-a'] = 'token-a'
        $Session.NonPimGroupIds['group-a'] = $true
        $Session.RetryStatistics.TotalRetries = 42
    }

    It 'removes every tenant context variable' {
        Disconnect-EntraOps *> $null

        $Session.ContainsKey('ConfigFilePath') | Should -BeFalse

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

Describe 'Disconnect-EntraOps Graph SDK warnings' {
    BeforeEach {
        Mock Disconnect-AzAccount -ModuleName EntraOps {}
        Mock Clear-AzContext -ModuleName EntraOps {}
        Mock Get-AzContext -ModuleName EntraOps {}
        Mock Clear-EntraOpsCache -ModuleName EntraOps {}
        Mock Test-Path -ModuleName EntraOps { $false }
        Mock Get-MgContext -ModuleName EntraOps { [pscustomobject]@{ AuthType = 'UserProvidedAccessToken' } }
        Mock Write-Host -ModuleName EntraOps {}

        $script:EscapedWarnings = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
        $script:OriginalWarningWriter = [Action[string]]$script:EscapedWarnings.Enqueue
        $script:GraphOutputWriter = [pscustomobject]@{ WriteWarning = $script:OriginalWarningWriter }
        Mock Get-EntraOpsGraphOutputWriter -ModuleName EntraOps { $script:GraphOutputWriter }
        Mock Disconnect-MgGraph -ModuleName EntraOps {
            [EntraOpsDisconnectWarningTest]::Emit($script:GraphOutputWriter.WriteWarning, $script:AuthorityWarning)
        }
    }

    It 'captures authority warnings from the SDK callback on a worker thread' {
        $Output = @(Disconnect-EntraOps 3>&1)

        @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }) | Should -BeNullOrEmpty
        $script:EscapedWarnings.Count | Should -Be 0
        $script:GraphOutputWriter.WriteWarning | Should -Be $script:OriginalWarningWriter
        Should -Invoke Disconnect-MgGraph -ModuleName EntraOps -Times 1 -Exactly
    }

    It 'keeps the authority diagnostic available through verbose output' {
        $Output = @(& (Get-Module EntraOps) { $VerbosePreference = 'Continue'; Disconnect-EntraOps 4>&1 })

        @($Output | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } | ForEach-Object Message) | Should -Contain $script:AuthorityWarning
    }

    It 'also filters the authority warning on the normal warning stream without an SDK writer' {
        Mock Get-EntraOpsGraphOutputWriter -ModuleName EntraOps { $null }
        Mock Disconnect-MgGraph -ModuleName EntraOps { Write-Warning $script:AuthorityWarning }

        $Output = @(Disconnect-EntraOps 3>&1)

        @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }) | Should -BeNullOrEmpty
    }

    It 'preserves other persisted-cache failures and unrelated warnings from both paths' {
        Mock Disconnect-MgGraph -ModuleName EntraOps {
            [EntraOpsDisconnectWarningTest]::Emit($script:GraphOutputWriter.WriteWarning, 'Failed to clear the persisted MSAL token cache during Disconnect-MgGraph: Access denied')
            Write-Warning 'Other SDK warning'
        }

        $Output = @(Disconnect-EntraOps 3>&1)
        $Warnings = @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object Message)

        $Warnings.Count | Should -Be 2
        $Warnings | Should -Contain 'Failed to clear the persisted MSAL token cache during Disconnect-MgGraph: Access denied'
        $Warnings | Should -Contain 'Other SDK warning'
        $script:EscapedWarnings.Count | Should -Be 0
    }

    It 'restores the SDK writer and preserves pending warnings when disconnect throws' {
        Mock Disconnect-MgGraph -ModuleName EntraOps {
            [EntraOpsDisconnectWarningTest]::Emit($script:GraphOutputWriter.WriteWarning, 'Cache warning before failure')
            throw 'Disconnect failed'
        }

        $Output = @(Disconnect-EntraOps 3>&1)
        $Warnings = @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object Message)

        $Warnings | Should -Contain 'Cache warning before failure'
        $Warnings | Should -Contain 'Failed to disconnect from Microsoft Graph: Disconnect failed'
        $script:GraphOutputWriter.WriteWarning | Should -Be $script:OriginalWarningWriter
    }

    It 'skips Graph disconnect when the SDK commands are unavailable' {
        Mock Get-Command -ModuleName EntraOps { $null } -ParameterFilter { $Name -eq 'Get-MgContext' }

        { Disconnect-EntraOps } | Should -Not -Throw

        Should -Invoke Disconnect-MgGraph -ModuleName EntraOps -Times 0 -Exactly
        Should -Invoke Get-EntraOpsGraphOutputWriter -ModuleName EntraOps -Times 0 -Exactly
    }
}

