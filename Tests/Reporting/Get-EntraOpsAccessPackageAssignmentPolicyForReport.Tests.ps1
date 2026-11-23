#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
}

Describe 'Access package assignment policy lookups of a reporting run' {
    BeforeEach {
        InModuleScope EntraOps { $Script:EntraOpsReportingRunCache = $null }
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery {
            # Same shape as the error Invoke-EntraOpsMsGraphQuery -ThrowOnFailure throws for a non-retryable answer
            $Status = switch -Wildcard ($Uri) { '*/deleted-*' { 404 } '*/broken-*' { 500 } default { 0 } }
            if ($Status) {
                $Exception = [System.InvalidOperationException]::new("Microsoft Graph query '$Uri' failed: HTTP $Status")
                $Exception.Data['StatusCode'] = $Status
                throw $Exception
            }
            [pscustomobject]@{ id = ($Uri -split '/')[-1] }
        }
    }

    It 'requests a deleted policy once per run and reports all deleted policies in one warning' {
        $Warnings = InModuleScope EntraOps {
            $null = Start-EntraOpsReportingRunCache -Force
            # Both report generators look up the same policies
            foreach ($Generator in 1..2) {
                foreach ($PolicyId in 'policy-1', 'deleted-2', 'deleted-1') {
                    $Policy = Get-EntraOpsAccessPackageAssignmentPolicyForReport -PolicyId $PolicyId
                    if ($PolicyId -like 'deleted-*') { $Policy | Should -BeNullOrEmpty } else { $Policy.id | Should -Be $PolicyId }
                }
            }
            Complete-EntraOpsReportingRunCache -WarningVariable Warnings -WarningAction SilentlyContinue
            $Warnings
            $Script:EntraOpsReportingRunCache | Should -BeNullOrEmpty
        }

        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -like '*/deleted-1' }
        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -like '*/deleted-2' }
        @($Warnings).Count | Should -Be 1
        "$($Warnings[0])" | Should -Match 'NotFound'
        "$($Warnings[0])" | Should -Match '\(2\): deleted-1, deleted-2\.'
    }

    It 'throws other errors to the caller and does not remember them' {
        InModuleScope EntraOps {
            $null = Start-EntraOpsReportingRunCache -Force
            { Get-EntraOpsAccessPackageAssignmentPolicyForReport -PolicyId 'broken-1' } | Should -Throw '*HTTP 500*'
            { Get-EntraOpsAccessPackageAssignmentPolicyForReport -PolicyId 'broken-1' } | Should -Throw '*HTTP 500*'
            Complete-EntraOpsReportingRunCache -WarningVariable Warnings -WarningAction SilentlyContinue
            @($Warnings).Count | Should -Be 0
        }
        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery -Times 2 -Exactly
    }

    It 'throws a 404 to the caller when no run cache is active, so the caller still reports it' {
        InModuleScope EntraOps {
            { Get-EntraOpsAccessPackageAssignmentPolicyForReport -PolicyId 'deleted-1' } | Should -Throw '*HTTP 404*'
        }
    }

    It 'keeps the cache of a running owner and replaces one whose owner is no longer running' {
        InModuleScope EntraOps {
            function New-EntraOpsReportingData { Start-EntraOpsReportingRunCache }
            # Owner on the call stack: a generator inside the run uses the run's cache
            $null = Start-EntraOpsReportingRunCache -Force -Owner 'New-EntraOpsReportingData'
            [void]$Script:EntraOpsReportingRunCache.NotFoundAssignmentPolicyIds.Add('deleted-1')
            New-EntraOpsReportingData | Should -BeFalse
            $Script:EntraOpsReportingRunCache.NotFoundAssignmentPolicyIds.Count | Should -Be 1
            # Owner not on the call stack (a run that ended with an error): replaced by a new, empty cache
            Start-EntraOpsReportingRunCache | Should -BeTrue
            $Script:EntraOpsReportingRunCache.NotFoundAssignmentPolicyIds.Count | Should -Be 0
            Complete-EntraOpsReportingRunCache
        }
    }
}

Describe 'New-EntraOpsReportingData access package assignment policy lookups' {
    BeforeAll {
        $script:OriginalBaseFolder = $Global:EntraOpsBaseFolder
    }

    AfterAll {
        $Global:EntraOpsBaseFolder = $script:OriginalBaseFolder
    }

    BeforeEach {
        $script:Workspace = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $Global:EntraOpsBaseFolder = $script:Workspace
        New-Item -ItemType Directory -Path "$script:Workspace/TenantGovernance/Snapshots" -Force | Out-Null
        foreach ($App in 'TierBreachAnalyzer', 'EamDashboard', 'AccessPathMap', 'PrivilegedAssets', 'ConfigurationAnalyzer', 'AccessPackageFlow') {
            New-Item -ItemType Directory -Path "$script:Workspace/Reports/$App" -Force | Out-Null
            Set-Content -LiteralPath "$script:Workspace/Reports/$App/index.html" -Value 'app'
        }
        Set-Content -LiteralPath "$script:Workspace/Reports/index.html" -Value 'portal'
        foreach ($Generator in 'New-EntraOpsTierBreachAnalyzerData', 'New-EntraOpsPrivilegedEamDashboardData', 'New-EntraOpsPrivilegedAssetsData', 'New-EntraOpsAccessPathMapData', 'New-EntraOpsReportFindingData', 'Write-Host') {
            Mock -ModuleName EntraOps $Generator {}
        }
        # Both generators look up the same policies, as the real ones do (in the module, where the lookup is defined)
        $LookUpPolicies = {
            & (Get-Module EntraOps) {
                foreach ($PolicyId in 'policy-1', 'deleted-1') {
                    try { $null = Get-EntraOpsAccessPackageAssignmentPolicyForReport -PolicyId $PolicyId } catch { Write-Warning "Could not resolve access package assignment policy ${PolicyId}: $($_.Exception.Message)" }
                }
            }
        }
        Mock -ModuleName EntraOps New-EntraOpsTenantGovernanceConfigurationAnalyzerData $LookUpPolicies
        Mock -ModuleName EntraOps New-EntraOpsAccessPackageFlowData $LookUpPolicies
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like '*/deleted-*') {
                $Exception = [System.InvalidOperationException]::new("Microsoft Graph query '$Uri' failed: NotFound")
                $Exception.Data['StatusCode'] = 404
                throw $Exception
            }
            [pscustomobject]@{ id = ($Uri -split '/')[-1] }
        }
        $script:Parameters = @{ SkipClassificationExplorer = $true; SkipPrivilegeHistory = $true; SkipFindings = $true }
    }

    It 'warns once per run about a deleted policy both generators look up' {
        New-EntraOpsReportingData @script:Parameters -WarningVariable Warnings -WarningAction SilentlyContinue

        Should -Invoke -ModuleName EntraOps New-EntraOpsTenantGovernanceConfigurationAnalyzerData -Times 1 -Exactly
        Should -Invoke -ModuleName EntraOps New-EntraOpsAccessPackageFlowData -Times 1 -Exactly
        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -like '*/deleted-1' }
        $PolicyWarnings = @($Warnings | Where-Object { "$_" -match 'deleted-1' })
        $PolicyWarnings.Count | Should -Be 1
        "$($PolicyWarnings[0])" | Should -Match 'NotFound'
    }

    It 'does not reuse the deleted policies of an earlier run' {
        New-EntraOpsReportingData @script:Parameters -WarningAction SilentlyContinue
        New-EntraOpsReportingData @script:Parameters -WarningVariable Warnings -WarningAction SilentlyContinue

        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery -Times 2 -Exactly -ParameterFilter { $Uri -like '*/deleted-1' }
        @($Warnings | Where-Object { "$_" -match 'deleted-1' }).Count | Should -Be 1
    }
}
