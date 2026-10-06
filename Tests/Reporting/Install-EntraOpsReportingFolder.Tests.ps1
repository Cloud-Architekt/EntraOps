#Requires -Modules Pester

Describe 'Install-EntraOpsReportingFolder' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue

        # GitHub source archive layout: one top-level <owner>-<repo>-<sha> folder.
        $script:ArchiveSource = Join-Path $TestDrive 'archive'
        $ArchiveRoot = Join-Path $script:ArchiveSource 'Cloud-Architekt-EntraOps-abc1234'
        New-Item -ItemType Directory -Path "$ArchiveRoot/Reports/PrivilegedAssets/data", "$ArchiveRoot/Reports/shared", "$ArchiveRoot/EntraOps" -Force | Out-Null
        Set-Content -LiteralPath "$ArchiveRoot/Reports/index.html" -Value 'portal'
        Set-Content -LiteralPath "$ArchiveRoot/Reports/reports.smoke.spec.mjs" -Value 'spec'
        Set-Content -LiteralPath "$ArchiveRoot/Reports/PrivilegedAssets/index.html" -Value 'app v2'
        Set-Content -LiteralPath "$ArchiveRoot/Reports/PrivilegedAssets/data/privileged-assets-data.js" -Value 'upstream data'
        Set-Content -LiteralPath "$ArchiveRoot/Reports/shared/theme.css" -Value 'css'
        Set-Content -LiteralPath "$ArchiveRoot/EntraOps/EntraOps.psd1" -Value 'module'
        $script:ArchivePath = Join-Path $TestDrive 'source.zip'
        Compress-Archive -Path $ArchiveRoot -DestinationPath $script:ArchivePath -Force
    }

    BeforeEach {
        $script:Destination = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Mock -ModuleName EntraOps Invoke-WebRequest { Copy-Item -LiteralPath (Join-Path $TestDrive 'source.zip') -Destination $OutFile } -ParameterFilter { $OutFile }
        Mock -ModuleName EntraOps Write-Host {}
    }

    It 'installs only the Reports folder without browser test specs' {
        $Result = Install-EntraOpsReportingFolder -DestinationPath $script:Destination

        Get-Content -LiteralPath "$script:Destination/index.html" | Should -Be 'portal'
        Get-Content -LiteralPath "$script:Destination/PrivilegedAssets/index.html" | Should -Be 'app v2'
        Test-Path -LiteralPath "$script:Destination/reports.smoke.spec.mjs" | Should -BeFalse
        Test-Path -LiteralPath "$script:Destination/EntraOps" | Should -BeFalse
        $Result.InstalledFile | Should -Be 4
        Should -Invoke -ModuleName EntraOps Invoke-WebRequest -Times 1 -ParameterFilter { $Uri -eq 'https://api.github.com/repos/Cloud-Architekt/EntraOps/zipball/main' -and -not $Headers.ContainsKey('Authorization') }
    }

    It 'refuses to change an existing Reports folder without -Force' {
        New-Item -ItemType Directory -Path $script:Destination | Out-Null

        { Install-EntraOpsReportingFolder -DestinationPath $script:Destination } | Should -Throw '*already exists*'
        Should -Invoke -ModuleName EntraOps Invoke-WebRequest -Times 0
    }

    It 'updates app files with -Force and keeps generated report data' {
        New-Item -ItemType Directory -Path "$script:Destination/PrivilegedAssets/data" -Force | Out-Null
        Set-Content -LiteralPath "$script:Destination/PrivilegedAssets/index.html" -Value 'app v1'
        Set-Content -LiteralPath "$script:Destination/PrivilegedAssets/data/privileged-assets-data.js" -Value 'tenant data'

        $Result = Install-EntraOpsReportingFolder -DestinationPath $script:Destination -Ref 'v1.2.0' -Force

        Get-Content -LiteralPath "$script:Destination/PrivilegedAssets/index.html" | Should -Be 'app v2'
        Get-Content -LiteralPath "$script:Destination/PrivilegedAssets/data/privileged-assets-data.js" | Should -Be 'tenant data'
        $Result.KeptDataFile | Should -Be 1
        Should -Invoke -ModuleName EntraOps Invoke-WebRequest -Times 1 -ParameterFilter { $Uri -like '*/zipball/v1.2.0' }
    }

    It 'changes nothing with -WhatIf' {
        Install-EntraOpsReportingFolder -DestinationPath $script:Destination -WhatIf

        Test-Path -LiteralPath $script:Destination | Should -BeFalse
    }

    It 'requires a token for the private Insiders repository before downloading' {
        $PreviousPat = $env:ENTRAOPS_PAT
        try {
            $env:ENTRAOPS_PAT = $null
            { Install-EntraOpsReportingFolder -Repository 'EntraOps-Insiders' -DestinationPath $script:Destination } | Should -Throw '*requires -PersonalAccessToken*'
            Should -Invoke -ModuleName EntraOps Invoke-WebRequest -Times 0
        } finally {
            $env:ENTRAOPS_PAT = $PreviousPat
        }
    }

    It 'sends the token only to the Insiders repository' {
        Install-EntraOpsReportingFolder -Repository 'EntraOps-Insiders' -PersonalAccessToken 'test-token' -DestinationPath $script:Destination | Out-Null

        Should -Invoke -ModuleName EntraOps Invoke-WebRequest -Times 1 -ParameterFilter { $Uri -like '*/EntraOps-Insiders/zipball/main' -and $Headers['Authorization'] -eq 'Bearer test-token' }
    }

    It 'rejects refs that could leave the archive endpoint' {
        { Install-EntraOpsReportingFolder -Ref 'main/../../user' -DestinationPath $script:Destination } | Should -Throw '*Unsupported ref*'
        { Install-EntraOpsReportingFolder -Ref '-main' -DestinationPath $script:Destination } | Should -Throw
        Should -Invoke -ModuleName EntraOps Invoke-WebRequest -Times 0
    }
}
