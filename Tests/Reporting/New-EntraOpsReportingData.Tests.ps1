#Requires -Modules Pester

Describe 'New-EntraOpsReportingData content preflight' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
        $script:OriginalBaseFolder = $Global:EntraOpsBaseFolder
    }

    AfterAll {
        $Global:EntraOpsBaseFolder = $script:OriginalBaseFolder
    }

    BeforeEach {
        $script:Workspace = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $Global:EntraOpsBaseFolder = $script:Workspace
        New-Item -ItemType Directory -Path "$script:Workspace/Reports" -Force | Out-Null
        Set-Content -LiteralPath "$script:Workspace/Reports/index.html" -Value 'portal'
        foreach ($App in 'TierBreachAnalyzer', 'EamDashboard', 'AccessPathMap') {
            New-Item -ItemType Directory -Path "$script:Workspace/Reports/$App" -Force | Out-Null
            Set-Content -LiteralPath "$script:Workspace/Reports/$App/index.html" -Value 'app'
        }
        $script:Parameters = @{
            SkipClassificationExplorer = $true
            SkipPrivilegeHistory       = $true
            SkipConfigurationAnalyzer  = $true
            SkipAccessPackageFlow      = $true
        }
        Mock -ModuleName EntraOps New-EntraOpsTierBreachAnalyzerData {}
        Mock -ModuleName EntraOps New-EntraOpsPrivilegedEamDashboardData {}
        Mock -ModuleName EntraOps New-EntraOpsPrivilegedAssetsData {}
        Mock -ModuleName EntraOps New-EntraOpsAccessPathMapData {}
        Mock -ModuleName EntraOps Install-EntraOpsReportingFolder {
            New-Item -ItemType Directory -Path "$DestinationPath/PrivilegedAssets" -Force | Out-Null
            Set-Content -LiteralPath "$DestinationPath/PrivilegedAssets/index.html" -Value 'app'
        }
        Mock -ModuleName EntraOps Write-Host {}
    }

    It 'detects a missing app before any generator runs even when the portal exists' {
        { New-EntraOpsReportingData @script:Parameters } | Should -Throw '*PrivilegedAssets*Install-EntraOpsReportingFolder -Force*'

        Should -Invoke -ModuleName EntraOps New-EntraOpsTierBreachAnalyzerData -Times 0
        Should -Invoke -ModuleName EntraOps New-EntraOpsPrivilegedEamDashboardData -Times 0
        Should -Invoke -ModuleName EntraOps Install-EntraOpsReportingFolder -Times 0
    }

    It 'repairs an incomplete Reports folder with the install switch' {
        New-EntraOpsReportingData @script:Parameters -InstallMissingReportingFolder

        Test-Path -LiteralPath "$script:Workspace/Reports/PrivilegedAssets/index.html" | Should -BeTrue
        Should -Invoke -ModuleName EntraOps Install-EntraOpsReportingFolder -Times 1 -Exactly -ParameterFilter { $Force -and [System.IO.Path]::GetFullPath($DestinationPath) -eq [System.IO.Path]::GetFullPath((Join-Path $script:Workspace 'Reports')) }
        Should -Invoke -ModuleName EntraOps New-EntraOpsPrivilegedAssetsData -Times 1 -Exactly
    }

    It 'saves the finding results with the report data, so the reporting pipelines publish them' {
        New-EntraOpsReportingData @script:Parameters -InstallMissingReportingFolder

        $FindingsFile = "$script:Workspace/Reports/Findings/data/findings.json"
        $FindingsFile | Should -Exist
        $Findings = Get-Content -LiteralPath $FindingsFile -Raw | ConvertFrom-Json
        $Findings.SchemaVersion | Should -Be '1.0'
        @($Findings.Rules).Count | Should -Be 59
        # Without Privileged EAM export and report data, every rule is skipped with the reason.
        @($Findings.Rules.Status | Select-Object -Unique) | Should -Be @('Skipped')
        ($Findings.Rules | Where-Object Area -eq 'TierBreach')[0].Reason | Should -Match 'Save-EntraOpsPrivilegedEAMJson'
        ($Findings.Rules | Where-Object Area -eq 'PimRequestFlow')[0].Reason | Should -Match 'New-EntraOpsReportingData'
        # The same results as script for Privileged Assets, which loads ../Findings/data/findings.js.
        "$script:Workspace/Reports/Findings/data/findings.js" | Should -Exist
        Test-Path -LiteralPath "$script:Workspace/Reports/PrivilegedAssets/../Findings/data/findings.js" -PathType Leaf | Should -BeTrue
    }

    It 'does not evaluate the Tenant Governance data of an earlier run when the Configuration Analyzer data fails' {
        New-Item -ItemType Directory -Path "$script:Workspace/TenantGovernance/Snapshots", "$script:Workspace/Reports/ConfigurationAnalyzer/data" -Force | Out-Null
        Set-Content -LiteralPath "$script:Workspace/Reports/ConfigurationAnalyzer/index.html" -Value 'app'
        Set-Content -LiteralPath "$script:Workspace/Reports/ConfigurationAnalyzer/data/configuration-analyzer-data.js" -Value 'window.ENTRAOPS_CONFIGANALYZER_DATA = {"snapshots":[]};'
        Mock -ModuleName EntraOps New-EntraOpsTenantGovernanceConfigurationAnalyzerData { throw 'The newest snapshot is 31 hours old.' }
        Mock -ModuleName EntraOps New-EntraOpsReportFindingData {}
        $Parameters = $script:Parameters.Clone()
        $Parameters.Remove('SkipConfigurationAnalyzer')

        New-EntraOpsReportingData @Parameters -InstallMissingReportingFolder -WarningVariable Warnings -WarningAction SilentlyContinue

        Should -Invoke -ModuleName EntraOps New-EntraOpsReportFindingData -Times 0
        @($Warnings | Where-Object { "$_" -like 'Skipped PIM Request Flow and Access Package Flow findings*' }).Count | Should -Be 1
        $Findings = Get-Content -LiteralPath "$script:Workspace/Reports/Findings/data/findings.json" -Raw | ConvertFrom-Json
        foreach ($Area in 'TenantGovernance', 'PimRequestFlow', 'AccessPackageFlow') {
            ($Findings.Rules | Where-Object Area -eq $Area)[0].Reason | Should -BeLike '*could not be generated in this run*31 hours old*'
        }
    }

    It 'does not save the finding results with SkipFindings' {
        New-EntraOpsReportingData @script:Parameters -InstallMissingReportingFolder -SkipFindings

        "$script:Workspace/Reports/Findings/data/findings.json" | Should -Not -Exist
        "$script:Workspace/Reports/Findings/data/findings.js" | Should -Not -Exist
    }

    It 'checks and installs the reporting apps below an explicit EntraOpsRoot' {
        $OtherRoot = Join-Path $TestDrive "other-$([guid]::NewGuid().ToString('N'))"
        Copy-Item -LiteralPath $script:Workspace -Destination $OtherRoot -Recurse
        # The base folder lacks every app; only the explicit root is relevant.
        Remove-Item -LiteralPath "$script:Workspace/Reports" -Recurse -Force

        New-EntraOpsReportingData @script:Parameters -EntraOpsRoot $OtherRoot -InstallMissingReportingFolder

        Should -Invoke -ModuleName EntraOps Install-EntraOpsReportingFolder -Times 1 -Exactly -ParameterFilter { [System.IO.Path]::GetFullPath($DestinationPath) -eq [System.IO.Path]::GetFullPath((Join-Path $OtherRoot 'Reports')) }
        Test-Path -LiteralPath "$OtherRoot/Reports/PrivilegedAssets/index.html" | Should -BeTrue
    }

    It 'takes the working folder as -Path, like Invoke-EntraOpsAssessment and Initialize-EntraOpsWorkspace' {
        (Get-Command New-EntraOpsReportingData).Parameters['EntraOpsRoot'].Aliases | Should -Contain 'Path'
        (Get-Command New-EntraOpsPrivilegedEamPrivilegeHistoryData).Parameters['RepoRoot'].Aliases | Should -Contain 'Path'
    }

    It 'resolves the default app folder of <Generator> below the given RepoRoot' -ForEach @(
        @{ Generator = 'New-EntraOpsTierBreachAnalyzerData'; App = 'TierBreachAnalyzer' }
        @{ Generator = 'New-EntraOpsPrivilegedEamDashboardData'; App = 'EamDashboard' }
        @{ Generator = 'New-EntraOpsPrivilegedAssetsData'; App = 'PrivilegedAssets' }
        @{ Generator = 'New-EntraOpsAccessPathMapData'; App = 'AccessPathMap' }
        @{ Generator = 'New-EntraOpsPrivilegedEamPrivilegeHistoryData'; App = 'PrivilegeHistory' }
        @{ Generator = 'New-EntraOpsTenantGovernanceConfigurationAnalyzerData'; App = 'ConfigurationAnalyzer' }
    ) {
        # The base folder has no reporting apps; only the explicit root has them. Other input may be missing,
        # but no error may refer to the base folder.
        $OtherRoot = Join-Path $TestDrive "root-$([guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path "$OtherRoot/Reports/$App/data" -Force | Out-Null
        Remove-Item -LiteralPath "$script:Workspace/Reports" -Recurse -Force

        $ErrorMessage = $null
        try {
            & (Get-Command $Generator -Module EntraOps) -RepoRoot $OtherRoot -WarningAction SilentlyContinue -ErrorAction Stop *> $null
        } catch {
            $ErrorMessage = $_.Exception.Message
        }

        "$ErrorMessage" | Should -Not -Match ([regex]::Escape($script:Workspace))
    }

    It 'does not require a skipped app' {
        New-EntraOpsReportingData @script:Parameters -SkipPrivilegedAssets

        Should -Invoke -ModuleName EntraOps New-EntraOpsTierBreachAnalyzerData -Times 1 -Exactly
        Should -Invoke -ModuleName EntraOps New-EntraOpsPrivilegedAssetsData -Times 0
        Should -Invoke -ModuleName EntraOps Install-EntraOpsReportingFolder -Times 0
    }

    It 'still checks other selected apps when one app uses a custom root' {
        { New-EntraOpsReportingData @script:Parameters -EamDashboardAppRoot "$script:Workspace/Reports/EamDashboard" } | Should -Throw '*PrivilegedAssets*'

        Should -Invoke -ModuleName EntraOps New-EntraOpsTierBreachAnalyzerData -Times 0
    }

    It 'warns and generates nothing under WhatIf when content is missing' {
        New-EntraOpsReportingData @script:Parameters -WhatIf -WarningVariable Warnings -WarningAction SilentlyContinue

        "$Warnings" | Should -Match 'PrivilegedAssets'
        Should -Invoke -ModuleName EntraOps Install-EntraOpsReportingFolder -Times 0
        Should -Invoke -ModuleName EntraOps New-EntraOpsTierBreachAnalyzerData -Times 0
    }

    It 'reports when the installed source still lacks the required app' {
        Mock -ModuleName EntraOps Install-EntraOpsReportingFolder {}

        { New-EntraOpsReportingData @script:Parameters -InstallMissingReportingFolder } | Should -Throw '*still missing after installation*PrivilegedAssets*'
        Should -Invoke -ModuleName EntraOps New-EntraOpsTierBreachAnalyzerData -Times 0
    }

    It 'preserves the existing controls for generation without Graph enrichment' {
        New-EntraOpsReportingData @script:Parameters -InstallMissingReportingFolder `
            -EamDashboardResolveLinkedIdentityObjectIds $false `
            -PrivilegedAssetsResolveRelatedObjectIds $false `
            -AccessPathMapResolveObjectIdsOutsidePrivilegedEAM $false

        Should -Invoke -ModuleName EntraOps New-EntraOpsPrivilegedEamDashboardData -Times 1 -Exactly -ParameterFilter { $ResolveLinkedIdentityObjectIds -eq $false }
        Should -Invoke -ModuleName EntraOps New-EntraOpsPrivilegedAssetsData -Times 1 -Exactly -ParameterFilter { $ResolveRelatedObjectIds -eq $false }
        Should -Invoke -ModuleName EntraOps New-EntraOpsAccessPathMapData -Times 1 -Exactly -ParameterFilter { $ResolveObjectIdsOutsidePrivilegedEAM -eq $false }
    }
}
