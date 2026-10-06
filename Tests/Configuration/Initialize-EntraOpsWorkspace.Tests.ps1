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
        Set-Content -LiteralPath "$ArchiveRoot/EntraOps/EntraOps.psd1" -Value 'module'
        Compress-Archive -Path $ArchiveRoot -DestinationPath (Join-Path $TestDrive 'source.zip') -Force
    }

    BeforeEach {
        $script:Workspace = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Mock -ModuleName EntraOps Invoke-WebRequest { Copy-Item -LiteralPath (Join-Path $TestDrive 'source.zip') -Destination $OutFile } -ParameterFilter { $OutFile }
        Mock -ModuleName EntraOps Write-Host {}
    }

    It 'installs classification templates, samples and reports but not the module' {
        $Result = Initialize-EntraOpsWorkspace -Path $script:Workspace

        @($Result.Content) | Should -Be @('Classification', 'Samples', 'Reports')
        Get-Content -LiteralPath "$script:Workspace/Classification/Templates/Classification_AadResources.json" | Should -Be 'template v2'
        Test-Path -LiteralPath "$script:Workspace/Samples/AadRoleManagementAssignments.json" | Should -BeTrue
        Test-Path -LiteralPath "$script:Workspace/Reports/index.html" | Should -BeTrue
        Test-Path -LiteralPath "$script:Workspace/EntraOps" | Should -BeFalse
        Test-Path -LiteralPath "$script:Workspace/Classification/contoso.onmicrosoft.com" | Should -BeFalse
        Should -Invoke -ModuleName EntraOps Invoke-WebRequest -Times 1 -ParameterFilter { $Uri -eq 'https://api.github.com/repos/Cloud-Architekt/EntraOps/zipball/main' }
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

    It 'changes nothing with -WhatIf' {
        Initialize-EntraOpsWorkspace -Path $script:Workspace -WhatIf

        Test-Path -LiteralPath $script:Workspace | Should -BeFalse
    }

    It 'refuses the repository checkout that contains the module' {
        { Initialize-EntraOpsWorkspace -Path $script:TestRepositoryRoot } | Should -Throw '*Use Update-EntraOps*'
        { Initialize-EntraOpsWorkspace -Path (Join-Path $script:TestRepositoryRoot 'EntraOps/Private') } | Should -Throw '*inside the EntraOps module folder*'
        Should -Invoke -ModuleName EntraOps Invoke-WebRequest -Times 0
    }
}
