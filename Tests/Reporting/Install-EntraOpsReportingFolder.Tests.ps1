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
        # The content version: the module version, as on the branch that matches the module.
        $script:ModuleVersion = [version](Import-PowerShellDataFile (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1')).ModuleVersion
        Set-Content -LiteralPath "$ArchiveRoot/EntraOps/EntraOps.psd1" -Value "@{ ModuleVersion = '$script:ModuleVersion' }"
        $script:ArchivePath = Join-Path $TestDrive 'source.zip'
        Compress-Archive -Path $ArchiveRoot -DestinationPath $script:ArchivePath -Force
    }

    BeforeEach {
        $script:Destination = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        # GITHUB_TOKEN or GH_TOKEN of the environment would authenticate the download of the public repository.
        $script:SavedTokens = @{ GITHUB_TOKEN = $env:GITHUB_TOKEN; GH_TOKEN = $env:GH_TOKEN }
        $env:GITHUB_TOKEN = $null; $env:GH_TOKEN = $null
        Mock -ModuleName EntraOps Invoke-RestMethod { Copy-Item -LiteralPath (Join-Path $TestDrive 'source.zip') -Destination $OutFile } -ParameterFilter { $OutFile }
        Mock -ModuleName EntraOps Write-Host {}
        Mock -ModuleName EntraOps Resolve-EntraOpsContentRef {
            [pscustomobject]@{ Repository = $Repository; Branch = 'main'; Ref = 'main'; ModuleVersion = $ModuleVersion; BranchVersion = $ModuleVersion; ContentVersion = $ModuleVersion; Matched = $true; Resolution = 'BranchHead' }
        }
        # The module is imported from this repository checkout: download as for a module-only installation.
        Mock -ModuleName EntraOps Test-EntraOpsRepositoryCheckout { $false }
    }

    AfterEach {
        foreach ($Name in $script:SavedTokens.Keys) { Set-Item -Path "Env:$Name" -Value $script:SavedTokens[$Name] -ErrorAction SilentlyContinue }
    }

    It 'installs only the Reports folder without browser test specs' {
        $Result = Install-EntraOpsReportingFolder -DestinationPath $script:Destination

        Get-Content -LiteralPath "$script:Destination/index.html" | Should -Be 'portal'
        Get-Content -LiteralPath "$script:Destination/PrivilegedAssets/index.html" | Should -Be 'app v2'
        Test-Path -LiteralPath "$script:Destination/reports.smoke.spec.mjs" | Should -BeFalse
        Test-Path -LiteralPath "$script:Destination/EntraOps" | Should -BeFalse
        $Result.InstalledFile | Should -Be 4
        Should -Invoke -ModuleName EntraOps Invoke-RestMethod -Times 1 -ParameterFilter { $Uri -eq 'https://github.com/Cloud-Architekt/EntraOps/archive/main.zip' -and -not $Headers.ContainsKey('Authorization') }
    }

    It 'records the source and version of the apps that match the module' {
        $Result = Install-EntraOpsReportingFolder -DestinationPath $script:Destination

        $Result.Matched | Should -BeTrue
        $Marker = Get-Content -LiteralPath "$script:Destination/.EntraOpsContent.json" -Raw | ConvertFrom-Json
        $Marker.ContentVersion | Should -Be "$script:ModuleVersion"
        $Marker.Resolution | Should -Be 'BranchHead'
        $Marker.Ref | Should -Be 'main'
    }

    It 'keeps existing apps when no apps of the module version are available' {
        Mock -ModuleName EntraOps Get-EntraOpsModuleVersion { [version]'9.9.0' }
        New-Item -ItemType Directory -Path "$script:Destination/PrivilegedAssets" -Force | Out-Null
        Set-Content -LiteralPath "$script:Destination/index.html" -Value 'portal v1'

        $Kept = Install-EntraOpsReportingFolder -DestinationPath $script:Destination -Force -KeepExistingWithoutMatch -WarningVariable Warnings -WarningAction SilentlyContinue

        $Kept.InstalledFile | Should -Be 0
        $Kept.Matched | Should -BeFalse
        Get-Content -LiteralPath "$script:Destination/index.html" | Should -Be 'portal v1'
        ($Warnings -join ' ') | Should -Match 'No reporting apps of the EntraOps module version 9\.9\.0.*kept'

        $Installed = Install-EntraOpsReportingFolder -DestinationPath $script:Destination -Force -WarningVariable Warnings -WarningAction SilentlyContinue
        $Installed.InstalledFile | Should -BeGreaterThan 0
        ($Warnings -join ' ') | Should -Match "are version $([regex]::Escape("$script:ModuleVersion")), the EntraOps module is 9\.9\.0"
    }

    It 'keeps existing apps without a download when the branch already shows that it has no apps of the module version' {
        Mock -ModuleName EntraOps Resolve-EntraOpsContentRef {
            [pscustomobject]@{ Repository = $Repository; Branch = 'main'; Ref = 'main'; ModuleVersion = $ModuleVersion; BranchVersion = [version]'1.1.0'; ContentVersion = [version]'1.1.0'; Matched = $false; Resolution = 'NoMatch' }
        }
        New-Item -ItemType Directory -Path $script:Destination -Force | Out-Null
        Set-Content -LiteralPath "$script:Destination/index.html" -Value 'portal v1'

        $Kept = Install-EntraOpsReportingFolder -DestinationPath $script:Destination -Force -KeepExistingWithoutMatch -WarningVariable Warnings -WarningAction SilentlyContinue

        $Kept.InstalledFile | Should -Be 0
        $Kept.ContentVersion | Should -Be ([version]'1.1.0')
        Get-Content -LiteralPath "$script:Destination/index.html" | Should -Be 'portal v1'
        ($Warnings -join ' ') | Should -Match "No reporting apps of the EntraOps module version .* from Cloud-Architekt/EntraOps at 'main' \(version 1\.1\.0\)"
        Should -Invoke -ModuleName EntraOps Invoke-RestMethod -Times 0
    }

    It 'takes the repository from AutomatedEntraOpsUpdate.Repository of the folder that holds the Reports folder' {
        $Deployment = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $Deployment | Out-Null
        @{ AutomatedEntraOpsUpdate = @{ Repository = 'Cloud-Architekt/EntraOps-Insiders' } } | ConvertTo-Json | Set-Content -LiteralPath "$Deployment/EntraOpsConfig.json"

        $Result = Install-EntraOpsReportingFolder -DestinationPath (Join-Path $Deployment 'Reports') -PersonalAccessToken 'test-token'

        $Result.Repository | Should -Be 'Cloud-Architekt/EntraOps-Insiders'
        Should -Invoke -ModuleName EntraOps Invoke-RestMethod -Times 1 -Exactly -ParameterFilter { $Uri -like '*/EntraOps-Insiders/zipball/main' -and $Headers['Authorization'] -eq 'Bearer test-token' }
        Should -Invoke -ModuleName EntraOps Write-Host -ParameterFilter { "$Object" -eq "Content repository: EntraOps-Insiders (AutomatedEntraOpsUpdate.Repository in $(Join-Path $Deployment 'EntraOpsConfig.json'))" }
    }

    It 'fails for the configured Insiders repository without a token instead of installing the public apps' {
        $Deployment = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $Deployment | Out-Null
        @{ AutomatedEntraOpsUpdate = @{ Repository = 'EntraOps-Insiders' } } | ConvertTo-Json | Set-Content -LiteralPath "$Deployment/EntraOpsConfig.json"
        $PreviousPat = $env:ENTRAOPS_PAT
        try {
            $env:ENTRAOPS_PAT = $null
            { Install-EntraOpsReportingFolder -DestinationPath (Join-Path $Deployment 'Reports') } | Should -Throw '*requires -PersonalAccessToken*'
            Should -Invoke -ModuleName EntraOps Invoke-RestMethod -Times 0
        } finally {
            $env:ENTRAOPS_PAT = $PreviousPat
        }
    }

    It 'refuses to change an existing Reports folder without -Force' {
        New-Item -ItemType Directory -Path $script:Destination | Out-Null

        { Install-EntraOpsReportingFolder -DestinationPath $script:Destination } | Should -Throw '*already exists*'
        Should -Invoke -ModuleName EntraOps Invoke-RestMethod -Times 0
    }

    It 'updates app files with -Force and keeps generated report data' {
        New-Item -ItemType Directory -Path "$script:Destination/PrivilegedAssets/data" -Force | Out-Null
        Set-Content -LiteralPath "$script:Destination/PrivilegedAssets/index.html" -Value 'app v1'
        Set-Content -LiteralPath "$script:Destination/PrivilegedAssets/data/privileged-assets-data.js" -Value 'tenant data'

        $Result = Install-EntraOpsReportingFolder -DestinationPath $script:Destination -Ref 'v1.2.0' -Force

        Get-Content -LiteralPath "$script:Destination/PrivilegedAssets/index.html" | Should -Be 'app v2'
        Get-Content -LiteralPath "$script:Destination/PrivilegedAssets/data/privileged-assets-data.js" | Should -Be 'tenant data'
        $Result.KeptDataFile | Should -Be 1
        Should -Invoke -ModuleName EntraOps Invoke-RestMethod -Times 1 -ParameterFilter { $Uri -eq 'https://github.com/Cloud-Architekt/EntraOps/archive/v1.2.0.zip' }
        Should -Invoke -ModuleName EntraOps Resolve-EntraOpsContentRef -Times 0
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
            Should -Invoke -ModuleName EntraOps Invoke-RestMethod -Times 0
        } finally {
            $env:ENTRAOPS_PAT = $PreviousPat
        }
    }

    It 'sends the token only to the Insiders repository' {
        Install-EntraOpsReportingFolder -Repository 'EntraOps-Insiders' -PersonalAccessToken 'test-token' -DestinationPath $script:Destination | Out-Null

        Should -Invoke -ModuleName EntraOps Invoke-RestMethod -Times 1 -ParameterFilter { $Uri -like '*/EntraOps-Insiders/zipball/main' -and $Headers['Authorization'] -eq 'Bearer test-token' }
    }

    It 'rejects refs that could leave the archive endpoint' {
        { Install-EntraOpsReportingFolder -Ref 'main/../../user' -DestinationPath $script:Destination } | Should -Throw '*Unsupported ref*'
        { Install-EntraOpsReportingFolder -Ref '-main' -DestinationPath $script:Destination } | Should -Throw
        Should -Invoke -ModuleName EntraOps Invoke-RestMethod -Times 0
    }
}
