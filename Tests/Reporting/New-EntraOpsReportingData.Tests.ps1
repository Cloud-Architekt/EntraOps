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
