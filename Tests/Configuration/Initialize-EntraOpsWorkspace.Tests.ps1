#Requires -Modules Pester

Describe 'Initialize-EntraOpsWorkspace' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue

        # GitHub source archive layout: one top-level <owner>-<repo>-<sha> folder.
        $ArchiveRoot = Join-Path $TestDrive 'archive/Cloud-Architekt-EntraOps-abc1234'
        New-Item -ItemType Directory -Path "$ArchiveRoot/Classification/Templates", "$ArchiveRoot/Classification/contoso.onmicrosoft.com", "$ArchiveRoot/Samples", "$ArchiveRoot/Reports/EamDashboard/data", "$ArchiveRoot/EntraOps" -Force | Out-Null
        Set-Content -LiteralPath "$ArchiveRoot/Classification/Global.json" -Value 'upstream global'
        Set-Content -LiteralPath "$ArchiveRoot/Classification/Templates/Classification_AadResources.json" -Value 'template v2'
        Set-Content -LiteralPath "$ArchiveRoot/Classification/contoso.onmicrosoft.com/Classification_AadResources.json" -Value 'upstream tenant classification'
        Set-Content -LiteralPath "$ArchiveRoot/Samples/AadRoleManagementAssignments.json" -Value 'sample'
        Set-Content -LiteralPath "$ArchiveRoot/Reports/index.html" -Value 'portal'
        Set-Content -LiteralPath "$ArchiveRoot/Reports/EamDashboard/data/eam-dashboard-data.js" -Value 'upstream data'
        # The content version: the module version, as on the branch that matches the module.
        $script:ModuleVersion = [version](Import-PowerShellDataFile (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1')).ModuleVersion
        Set-Content -LiteralPath "$ArchiveRoot/EntraOps/EntraOps.psd1" -Value "@{ ModuleVersion = '$script:ModuleVersion' }"
        Compress-Archive -Path $ArchiveRoot -DestinationPath (Join-Path $TestDrive 'source.zip') -Force
    }

    BeforeEach {
        $script:Workspace = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:OriginalBaseFolder = $Global:EntraOpsBaseFolder
        $script:OriginalEntraOpsRoot = $env:ENTRAOPS_ROOT
        Mock -ModuleName EntraOps Invoke-RestMethod { Copy-Item -LiteralPath (Join-Path $TestDrive 'source.zip') -Destination $OutFile } -ParameterFilter { $OutFile }
        Mock -ModuleName EntraOps Write-Host {}
        Mock -ModuleName EntraOps Resolve-EntraOpsContentRef {
            [pscustomobject]@{ Repository = $Repository; Branch = 'main'; Ref = 'main'; ModuleVersion = $ModuleVersion; BranchVersion = $ModuleVersion; ContentVersion = $ModuleVersion; Matched = $true; Resolution = 'BranchHead' }
        }
        # The module is imported from this repository checkout: download as for a module-only installation.
        Mock -ModuleName EntraOps Test-EntraOpsRepositoryCheckout { $false }
        Mock -ModuleName EntraOps Test-EntraOpsRepositoryCheckout { $true } -ParameterFilter { $Path -eq $script:TestRepositoryRoot -and $script:CheckoutGuard }
        $script:CheckoutGuard = $false
    }

    AfterEach {
        $Global:EntraOpsBaseFolder = $script:OriginalBaseFolder
        $env:ENTRAOPS_ROOT = $script:OriginalEntraOpsRoot
    }

    It 'uses -Path as working folder for the current session' {
        Initialize-EntraOpsWorkspace -Path $script:Workspace -Content Reports | Out-Null

        $Global:EntraOpsBaseFolder | Should -Be $script:Workspace
        $env:ENTRAOPS_ROOT | Should -Be $script:Workspace
    }

    It 'keeps the working folder with -KeepWorkingFolder or -WhatIf' {
        Initialize-EntraOpsWorkspace -Path $script:Workspace -Content Reports -KeepWorkingFolder | Out-Null
        $Global:EntraOpsBaseFolder | Should -Be $script:OriginalBaseFolder
        $env:ENTRAOPS_ROOT | Should -Be $script:OriginalEntraOpsRoot

        Initialize-EntraOpsWorkspace -Path $script:Workspace -Content Reports -WhatIf
        $Global:EntraOpsBaseFolder | Should -Be $script:OriginalBaseFolder
    }

    It 'installs classification templates, samples and reports but not the module' {
        $Result = Initialize-EntraOpsWorkspace -Path $script:Workspace

        @($Result.Content) | Should -Be @('Classification', 'Samples', 'Reports')
        Get-Content -LiteralPath "$script:Workspace/Classification/Templates/Classification_AadResources.json" | Should -Be 'template v2'
        Test-Path -LiteralPath "$script:Workspace/Samples/AadRoleManagementAssignments.json" | Should -BeTrue
        Test-Path -LiteralPath "$script:Workspace/Reports/index.html" | Should -BeTrue
        Test-Path -LiteralPath "$script:Workspace/EntraOps" | Should -BeFalse
        Test-Path -LiteralPath "$script:Workspace/Classification/contoso.onmicrosoft.com" | Should -BeFalse
        Should -Invoke -ModuleName EntraOps Invoke-RestMethod -Times 1 -ParameterFilter { $Uri -eq 'https://github.com/Cloud-Architekt/EntraOps/archive/main.zip' }
        (Get-Content -LiteralPath "$script:Workspace/Reports/.EntraOpsContent.json" -Raw | ConvertFrom-Json).ContentVersion | Should -Be "$script:ModuleVersion"
    }

    It 'keeps existing files without -Force' {
        New-Item -ItemType Directory -Path "$script:Workspace/Classification/Templates" -Force | Out-Null
        Set-Content -LiteralPath "$script:Workspace/Classification/Templates/Classification_AadResources.json" -Value 'template v1'

        $Result = Initialize-EntraOpsWorkspace -Path $script:Workspace -Content Classification

        Get-Content -LiteralPath "$script:Workspace/Classification/Templates/Classification_AadResources.json" | Should -Be 'template v1'
        $Result.SkippedFile | Should -Be 1
        $Result.InstalledFile | Should -Be 1
    }

    It 'refreshes templates with -Force but never replaces Global.json, tenant folders or report data' {
        New-Item -ItemType Directory -Path "$script:Workspace/Classification/Templates", "$script:Workspace/Classification/contoso.onmicrosoft.com", "$script:Workspace/Reports/EamDashboard/data" -Force | Out-Null
        Set-Content -LiteralPath "$script:Workspace/Classification/Templates/Classification_AadResources.json" -Value 'template v1'
        Set-Content -LiteralPath "$script:Workspace/Classification/Global.json" -Value 'tenant global'
        Set-Content -LiteralPath "$script:Workspace/Classification/contoso.onmicrosoft.com/Classification_AadResources.json" -Value 'tenant classification'
        Set-Content -LiteralPath "$script:Workspace/Reports/EamDashboard/data/eam-dashboard-data.js" -Value 'tenant data'

        Initialize-EntraOpsWorkspace -Path $script:Workspace -Force | Out-Null

        Get-Content -LiteralPath "$script:Workspace/Classification/Templates/Classification_AadResources.json" | Should -Be 'template v2'
        Get-Content -LiteralPath "$script:Workspace/Classification/Global.json" | Should -Be 'tenant global'
        Get-Content -LiteralPath "$script:Workspace/Classification/contoso.onmicrosoft.com/Classification_AadResources.json" | Should -Be 'tenant classification'
        Get-Content -LiteralPath "$script:Workspace/Reports/EamDashboard/data/eam-dashboard-data.js" | Should -Be 'tenant data'
    }

    It 'records the version of the reporting apps only when all app files were installed' {
        # Reporting apps of an earlier version, without a marker.
        New-Item -ItemType Directory -Path "$script:Workspace/Reports" -Force | Out-Null
        Set-Content -LiteralPath "$script:Workspace/Reports/index.html" -Value 'portal v1'

        $Result = Initialize-EntraOpsWorkspace -Path $script:Workspace -Content Reports -WarningVariable Warnings -WarningAction SilentlyContinue

        $Result.SkippedFile | Should -Be 1
        Get-Content -LiteralPath "$script:Workspace/Reports/index.html" | Should -Be 'portal v1'
        # Invoke-EntraOpsAssessment would take the kept apps for apps of the module version and never update them.
        Test-Path -LiteralPath "$script:Workspace/Reports/.EntraOpsContent.json" | Should -BeFalse
        ($Warnings -join ' ') | Should -Match 'Kept 1 existing reporting app file\(s\).*-Force'

        Initialize-EntraOpsWorkspace -Path $script:Workspace -Content Reports -Force | Out-Null

        Get-Content -LiteralPath "$script:Workspace/Reports/index.html" | Should -Be 'portal'
        (Get-Content -LiteralPath "$script:Workspace/Reports/.EntraOpsContent.json" -Raw | ConvertFrom-Json).ContentVersion | Should -Be "$script:ModuleVersion"
    }

    It 'keeps the marker of an earlier version when app files were kept' {
        New-Item -ItemType Directory -Path "$script:Workspace/Reports" -Force | Out-Null
        Set-Content -LiteralPath "$script:Workspace/Reports/index.html" -Value 'portal v1'
        @{ ContentVersion = '1.0.0' } | ConvertTo-Json | Set-Content -LiteralPath "$script:Workspace/Reports/.EntraOpsContent.json"

        Initialize-EntraOpsWorkspace -Path $script:Workspace -Content Reports -WarningAction SilentlyContinue | Out-Null

        (Get-Content -LiteralPath "$script:Workspace/Reports/.EntraOpsContent.json" -Raw | ConvertFrom-Json).ContentVersion | Should -Be '1.0.0'
    }

    It 'takes the content repository from AutomatedEntraOpsUpdate.Repository of the working folder' {
        New-Item -ItemType Directory -Path $script:Workspace -Force | Out-Null
        @{ AutomatedEntraOpsUpdate = @{ Repository = 'EntraOps-Insiders' } } | ConvertTo-Json | Set-Content -LiteralPath "$script:Workspace/EntraOpsConfig.json"

        Initialize-EntraOpsWorkspace -Path $script:Workspace -Content Reports -PersonalAccessToken 'test-token' | Out-Null

        Should -Invoke -ModuleName EntraOps Resolve-EntraOpsContentRef -Times 1 -Exactly -ParameterFilter { $Repository -eq 'EntraOps-Insiders' }
        Should -Invoke -ModuleName EntraOps Invoke-RestMethod -Times 1 -Exactly -ParameterFilter { $Uri -like '*/EntraOps-Insiders/zipball/main' -and $Headers['Authorization'] -eq 'Bearer test-token' }
        Should -Invoke -ModuleName EntraOps Write-Host -ParameterFilter { "$Object" -eq "Content repository: EntraOps-Insiders (AutomatedEntraOpsUpdate.Repository in $(Join-Path $script:Workspace 'EntraOpsConfig.json'))" }
    }

    It 'prefers -Repository over the configuration' {
        New-Item -ItemType Directory -Path $script:Workspace -Force | Out-Null
        @{ AutomatedEntraOpsUpdate = @{ Repository = 'EntraOps-Insiders' } } | ConvertTo-Json | Set-Content -LiteralPath "$script:Workspace/EntraOpsConfig.json"

        Initialize-EntraOpsWorkspace -Path $script:Workspace -Content Reports -Repository EntraOps | Out-Null

        Should -Invoke -ModuleName EntraOps Invoke-RestMethod -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://github.com/Cloud-Architekt/EntraOps/archive/main.zip' }
        Should -Invoke -ModuleName EntraOps Write-Host -ParameterFilter { "$Object" -eq 'Content repository: EntraOps (-Repository)' }
    }

    It 'fails for the configured Insiders repository without a token instead of installing the public content' {
        New-Item -ItemType Directory -Path $script:Workspace -Force | Out-Null
        @{ AutomatedEntraOpsUpdate = @{ Repository = 'EntraOps-Insiders' } } | ConvertTo-Json | Set-Content -LiteralPath "$script:Workspace/EntraOpsConfig.json"
        $PreviousPat = $env:ENTRAOPS_PAT
        try {
            $env:ENTRAOPS_PAT = $null
            { Initialize-EntraOpsWorkspace -Path $script:Workspace -Content Reports } | Should -Throw "*'EntraOps-Insiders' is private and requires -PersonalAccessToken or ENTRAOPS_PAT*"
            Should -Invoke -ModuleName EntraOps Invoke-RestMethod -Times 0
            Test-Path -LiteralPath "$script:Workspace/Reports" | Should -BeFalse
        } finally {
            $env:ENTRAOPS_PAT = $PreviousPat
        }
    }

    It 'changes nothing with -WhatIf' {
        Initialize-EntraOpsWorkspace -Path $script:Workspace -WhatIf

        Test-Path -LiteralPath $script:Workspace | Should -BeFalse
    }

    It 'refuses the repository checkout that contains the module' {
        $script:CheckoutGuard = $true
        { Initialize-EntraOpsWorkspace -Path $script:TestRepositoryRoot } | Should -Throw '*Use Update-EntraOps*'
        { Initialize-EntraOpsWorkspace -Path (Join-Path $script:TestRepositoryRoot 'EntraOps/Private') } | Should -Throw '*inside the EntraOps module folder*'
        Should -Invoke -ModuleName EntraOps Invoke-RestMethod -Times 0
    }
}
