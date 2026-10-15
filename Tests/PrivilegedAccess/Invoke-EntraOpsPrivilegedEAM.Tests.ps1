#Requires -Modules Pester

Describe 'Invoke-EntraOpsPrivilegedEAM session working folder' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $script:OriginalEntraOpsRoot = $env:ENTRAOPS_ROOT
        $script:SessionVariableNames = @(
            'EntraOpsBaseFolder', 'TenantIdContext', 'TenantNameContext',
            'DefaultFolderClassification', 'DefaultFolderClassifiedEam', 'XdrAvdHuntingAccess',
            'ManagingTenantIdContext', 'ManagingTenantNameContext', 'EntraOpsConfig'
        )
        $script:OriginalVariables = @{}
        foreach ($Name in $script:SessionVariableNames) {
            $Variable = Get-Variable -Name $Name -Scope Global -ErrorAction SilentlyContinue
            if ($Variable) { $script:OriginalVariables[$Name] = $Variable.Value }
        }

        $script:ImportFolder = Join-Path $TestDrive 'import-folder'
        $env:ENTRAOPS_ROOT = $script:ImportFolder
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
    }

    AfterAll {
        $env:ENTRAOPS_ROOT = $script:OriginalEntraOpsRoot
        foreach ($Name in $script:SessionVariableNames) {
            if ($script:OriginalVariables.ContainsKey($Name)) {
                Set-Variable -Name $Name -Value $script:OriginalVariables[$Name] -Scope Global
            } else {
                Remove-Variable -Name $Name -Scope Global -ErrorAction SilentlyContinue
            }
        }
        Remove-Module EntraOps -Force
    }

    BeforeEach {
        $script:Workspace = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $Global:EntraOpsBaseFolder = $script:ImportFolder
        $script:ArchiveFolder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path "$script:ArchiveFolder/source/Reports" -Force | Out-Null
        Set-Content -LiteralPath "$script:ArchiveFolder/source/Reports/index.html" -Value 'report'

        Mock -ModuleName EntraOps Get-EntraOpsSourceArchive {
            [pscustomobject]@{ SourceRoot = "$script:ArchiveFolder/source"; TemporaryFolder = $script:ArchiveFolder; Repository = 'EntraOps' }
        }
        Mock -ModuleName EntraOps Get-AzContext {
            [pscustomobject]@{ Account = @{ Id = 'test@example.com' }; Tenant = @{ Id = '00000000-0000-0000-0000-000000000001' } }
        }
        Mock -ModuleName EntraOps Get-MgContext {
            [pscustomobject]@{ Account = 'test@example.com'; TenantId = '00000000-0000-0000-0000-000000000001'; Scopes = @() }
        }
        Mock -ModuleName EntraOps Get-AzTenant { [pscustomobject]@{ Domains = @('contoso.onmicrosoft.com') } }
        Mock -ModuleName EntraOps Update-EntraOpsClassificationFiles {
            Set-Content -LiteralPath (Join-Path $FolderClassification 'Classification_AadResources.json') -Value '{}'
        }
        Mock -ModuleName EntraOps Update-EntraOpsClassificationControlPlaneScope {
            Set-Content -LiteralPath (Join-Path $Global:DefaultFolderClassification 'contoso.onmicrosoft.com/Classification_AadResources.json') -Value '{}'
        }
        Mock -ModuleName EntraOps Save-EntraOpsPrivilegedEAMJson {
            New-Item -ItemType Directory -Path (Join-Path $ExportFolder 'EntraID') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $ExportFolder 'EntraID/EntraID.json') -Value '[]'
        }
        Mock -ModuleName EntraOps Disconnect-EntraOps {}
        Mock -ModuleName EntraOps Start-Sleep {}
        Mock -ModuleName EntraOps Write-Host {}

        Initialize-EntraOpsWorkspace -Path $script:Workspace -Content Reports | Out-Null
    }

    It 'keeps exports and classification files in the workspace selected after module import' {
        Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles -RbacSystems 'EntraID'

        Test-Path -LiteralPath "$script:Workspace/PrivilegedEAM/EntraID/EntraID.json" | Should -BeTrue
        Test-Path -LiteralPath "$script:Workspace/Classification/Templates/Classification_AadResources.json" | Should -BeTrue
        Test-Path -LiteralPath "$script:Workspace/Classification/contoso.onmicrosoft.com/Classification_AadResources.json" | Should -BeTrue
        Test-Path -LiteralPath $script:ImportFolder | Should -BeFalse
        $Global:DefaultFolderClassifiedEam.TrimEnd('/') | Should -Be "$script:Workspace/PrivilegedEAM"
        $Global:DefaultFolderClassification.TrimEnd('/') | Should -Be "$script:Workspace/Classification"
    }

    It 'honors an explicit export folder while keeping classification in the selected workspace' {
        $ExportPath = Join-Path $TestDrive 'custom-export'
        Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles -RbacSystems 'EntraID' -ExportFolder $ExportPath

        Test-Path -LiteralPath "$ExportPath/EntraID/EntraID.json" | Should -BeTrue
        Test-Path -LiteralPath "$script:Workspace/Classification/Templates/Classification_AadResources.json" | Should -BeTrue
        Test-Path -LiteralPath "$script:Workspace/Classification/contoso.onmicrosoft.com/Classification_AadResources.json" | Should -BeTrue
        Test-Path -LiteralPath "$script:Workspace/PrivilegedEAM" | Should -BeFalse
        Test-Path -LiteralPath $script:ImportFolder | Should -BeFalse
        $Global:DefaultFolderClassifiedEam | Should -Be $ExportPath
    }
}
