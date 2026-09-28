BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:RepositoryRoot = $script:TestRepositoryRoot
    Import-Module (Join-Path $script:RepositoryRoot 'EntraOps/EntraOps.psd1') -Force
}

Describe 'Portable automation entry points' {
    It 'exports <_>' -ForEach @(
        'Get-EntraOpsUpdateCandidate'
        'Get-EntraOpsUpdatePlan'
        'Install-EntraOpsUpdateCandidate'
        'Invoke-EntraOpsReportingGeneration'
        'Invoke-EntraOpsTenantGovernanceSnapshot'
        'Resolve-EntraOpsUpdateSource'
        'Test-EntraOpsGeneratedArtifacts'
        'Test-EntraOpsUpdateContract'
    ) {
        Get-Command $_ -Module EntraOps -ErrorAction Stop | Should -Not -BeNullOrEmpty
    }

    It 'honors the configuration switches before opening an automation connection' {
        $ConfigPath = Join-Path $TestDrive 'disabled.json'
        @{
            TenantName                   = 'contoso.onmicrosoft.com'
            AutomatedReportingGeneration = @{ ApplyAutomatedReportingGeneration = $false }
            TenantGovernanceSnapshot     = @{ EnableTenantGovernanceSnapshot = $false }
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath

        (Invoke-EntraOpsReportingGeneration -ConfigFilePath $ConfigPath).Status | Should -Be 'Disabled'
        (Invoke-EntraOpsTenantGovernanceSnapshot -ConfigFilePath $ConfigPath).Status | Should -Be 'Disabled'
    }

    It 'translates a separately validated candidate into a trusted Update-EntraOps apply' {
        Mock Update-EntraOps -ModuleName EntraOps {}
        Mock Disconnect-EntraOps -ModuleName EntraOps {}

        Install-EntraOpsUpdateCandidate -ConfigFile './test-config.json' -CandidatePath './missing-candidate' `
            -SourceCommit ('a' * 40) -ValidationRequired:$true -BrowserTestsValidated:$true

        Should -Invoke Update-EntraOps -ModuleName EntraOps -Times 1 -ParameterFilter {
            $ConfigFile -eq './test-config.json' -and
            $PreparedCandidatePath -eq './missing-candidate' -and
            $ValidatedSourceCommit -eq ('a' * 40) -and
            $BrowserTestsValidated -and
            -not $SkipCandidateValidation
        }
        Should -Invoke Disconnect-EntraOps -ModuleName EntraOps -Times 1
    }

    It 'can explicitly apply an unvalidated candidate without claiming validation' {
        Mock Update-EntraOps -ModuleName EntraOps {}
        Mock Disconnect-EntraOps -ModuleName EntraOps {}

        Install-EntraOpsUpdateCandidate -CandidatePath './missing-candidate' -SourceCommit ('b' * 40) -ValidationRequired:$false

        Should -Invoke Update-EntraOps -ModuleName EntraOps -Times 1 -ParameterFilter {
            $PreparedCandidatePath -eq './missing-candidate' -and
            $SkipCandidateValidation -and
            -not $ValidatedSourceCommit
        }
    }

    It 'skips Configuration Analyzer without connecting when no snapshot manifest exists' {
        $ConfigPath = Join-Path $TestDrive 'reporting.json'
        @{
            TenantName                   = 'contoso.onmicrosoft.com'
            AutomatedReportingGeneration = @{
                ApplyAutomatedReportingGeneration = $true
                GenerateClassificationExplorer    = $false
                GenerateTierBreachAnalyzer        = $false
                GenerateEamDashboard              = $false
                GenerateAccessPathMap             = $false
                GeneratePrivilegeHistory          = $false
                GenerateConfigurationAnalyzer     = $true
                GenerateAccessPackageFlow         = $false
            }
            PrivilegeHistory             = @{ EnablePrivilegeHistory = $false }
            ConfigurationAnalyzer        = @{ AllowPartialTenantGovernanceSnapshot = $true }
            EamDashboard                 = @{ ResolveLinkedIdentityObjectIds = $false }
            AccessPathMap                = @{ ResolveObjectIdsOutsidePrivilegedEAM = $false }
            ClassificationExplorer       = @{ GenerateChangeHistory = $false }
        } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ConfigPath

        Mock Connect-EntraOps -ModuleName EntraOps { throw 'Connection should not be opened.' }
        Mock New-EntraOpsReportingData -ModuleName EntraOps { @() }

        # A configured deployment repository commits a real snapshot manifest under the module base
        # folder, which EntraOps.psm1 also defines module-scoped, shadowing the global for the
        # cmdlet's unqualified read. Point it at an empty folder to exercise the missing-manifest path.
        $SnapshotRoot = Join-Path $TestDrive 'no-snapshot'
        New-Item -Path $SnapshotRoot -ItemType Directory -Force | Out-Null
        $PreviousBaseFolder = InModuleScope EntraOps { $EntraOpsBaseFolder }
        try {
            InModuleScope EntraOps -Parameters @{ Path = $SnapshotRoot } { param($Path) Set-Variable -Name EntraOpsBaseFolder -Value $Path -Scope Script -Force }
            $Result = Invoke-EntraOpsReportingGeneration -ConfigFilePath $ConfigPath
        } finally {
            InModuleScope EntraOps -Parameters @{ Path = $PreviousBaseFolder } { param($Path) Set-Variable -Name EntraOpsBaseFolder -Value $Path -Scope Script -Force }
        }

        $Result.Status | Should -Be 'Generated'
        Should -Invoke Connect-EntraOps -ModuleName EntraOps -Times 0
        Should -Invoke New-EntraOpsReportingData -ModuleName EntraOps -Times 1 -ParameterFilter {
            $SkipConfigurationAnalyzer -and $ConfigFilePath -eq $ConfigPath -and $FailureAction -eq 'Stop' -and
            -not $PSBoundParameters.ContainsKey('AccessPathMapTenantId')
        }
    }

    # The former workflow step always passed the configured TenantId to New-EntraOpsAccessPathMapData;
    # the orchestrator must not fall back to inferring it from exported objects when it is configured.
    It 'forwards the configured TenantId to the Access Path Map generator' {
        $ConfigPath = Join-Path $TestDrive 'reporting-tenant.json'
        @{
            TenantName                   = 'contoso.onmicrosoft.com'
            TenantId                     = '11111111-2222-3333-4444-555555555555'
            AutomatedReportingGeneration = @{
                ApplyAutomatedReportingGeneration = $true
                GenerateClassificationExplorer    = $false
                GenerateTierBreachAnalyzer        = $false
                GenerateEamDashboard              = $false
                GenerateAccessPathMap             = $true
                GeneratePrivilegeHistory          = $false
                GenerateConfigurationAnalyzer     = $false
                GenerateAccessPackageFlow         = $false
            }
            AccessPathMap                = @{ ResolveObjectIdsOutsidePrivilegedEAM = $false }
        } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ConfigPath

        Mock Connect-EntraOps -ModuleName EntraOps { throw 'Connection should not be opened.' }
        Mock New-EntraOpsReportingData -ModuleName EntraOps { @() }

        Invoke-EntraOpsReportingGeneration -ConfigFilePath $ConfigPath | Out-Null

        Should -Invoke New-EntraOpsReportingData -ModuleName EntraOps -Times 1 -ParameterFilter {
            $AccessPathMapTenantId -eq '11111111-2222-3333-4444-555555555555' -and -not $SkipAccessPathMap
        }
    }
}
