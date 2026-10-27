#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps') -Force
}

Describe 'Remove-EntraOpsData' {
    BeforeEach {
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:Tenant = Join-Path $script:Root 'Classification/contoso.onmicrosoft.com'
        foreach ($Folder in 'PrivilegedEAM/EntraID', 'TenantGovernance/Snapshots', 'Classification/Templates', 'Classification/contoso.onmicrosoft.com', 'Classification/fabrikam.onmicrosoft.com', 'Reports/EamDashboard/data') {
            New-Item -ItemType Directory -Path (Join-Path $script:Root $Folder) -Force | Out-Null
        }
        foreach ($File in 'PrivilegedEAM/EntraID/EntraID.json', 'TenantGovernance/Snapshots/.SnapshotManifest.json', 'Classification/Templates/Classification_AadResources.json',
            'Classification/Global.json', 'Classification/ObjectClassification.json', 'Classification/contoso.onmicrosoft.com/Classification_AadResources.json',
            'Classification/contoso.onmicrosoft.com/Classification_RoleActionOverwrites.json', 'Classification/contoso.onmicrosoft.com/Classification_RoleDefinitionOverwrites_PAW.json', 'Classification/contoso.onmicrosoft.com/Classification_ApiPermissionOverwrites.json', 'Classification/fabrikam.onmicrosoft.com/Classification_AadResources.json',
            'Reports/EamDashboard/data/eam-dashboard-data.js', 'EntraOpsConfig.json') {
            Set-Content -LiteralPath (Join-Path $script:Root $File) -Value '{}'
        }
        Mock Clear-EntraOpsCache -ModuleName EntraOps {}
    }

    It 'removes exports, report data, tenant classification and snapshots but keeps overwrites and shipped content' {
        Remove-EntraOpsData -Path $script:Root -Confirm:$false 6>$null

        Test-Path (Join-Path $script:Root 'PrivilegedEAM') | Should -BeFalse
        Test-Path (Join-Path $script:Root 'TenantGovernance/Snapshots') | Should -BeFalse
        Test-Path (Join-Path $script:Root 'Reports/EamDashboard/data/eam-dashboard-data.js') | Should -BeFalse
        Test-Path (Join-Path $script:Tenant 'Classification_AadResources.json') | Should -BeFalse
        Test-Path (Join-Path $script:Root 'Classification/fabrikam.onmicrosoft.com') | Should -BeFalse
        Test-Path (Join-Path $script:Tenant 'Classification_RoleActionOverwrites.json') | Should -BeTrue
        Test-Path (Join-Path $script:Tenant 'Classification_RoleDefinitionOverwrites_PAW.json') | Should -BeTrue
        Test-Path (Join-Path $script:Tenant 'Classification_ApiPermissionOverwrites.json') | Should -BeTrue
        Test-Path (Join-Path $script:Root 'Classification/Templates/Classification_AadResources.json') | Should -BeTrue
        Test-Path (Join-Path $script:Root 'Classification/Global.json') | Should -BeTrue
        Test-Path (Join-Path $script:Root 'Classification/ObjectClassification.json') | Should -BeTrue
        Test-Path (Join-Path $script:Root 'Reports/EamDashboard') | Should -BeTrue
        Test-Path (Join-Path $script:Root 'EntraOpsConfig.json') | Should -BeTrue
        Should -Invoke Clear-EntraOpsCache -ModuleName EntraOps -Times 1 -Exactly -ParameterFilter { $CacheType -eq 'All' }
    }

    It 'removes nothing with WhatIf' {
        Remove-EntraOpsData -Path $script:Root -WhatIf 6>$null

        Test-Path (Join-Path $script:Root 'PrivilegedEAM/EntraID/EntraID.json') | Should -BeTrue
        Test-Path (Join-Path $script:Root 'Reports/EamDashboard/data/eam-dashboard-data.js') | Should -BeTrue
        Test-Path (Join-Path $script:Tenant 'Classification_AadResources.json') | Should -BeTrue
        Should -Invoke Clear-EntraOpsCache -ModuleName EntraOps -Times 0 -Exactly
    }

    It 'only removes the selected content and tenants' {
        $Result = Remove-EntraOpsData -Path $script:Root -Content Classification -TenantName 'fabrikam.onmicrosoft.com' -Confirm:$false -PassThru 6>$null

        Test-Path (Join-Path $script:Root 'Classification/fabrikam.onmicrosoft.com') | Should -BeFalse
        Test-Path (Join-Path $script:Tenant 'Classification_AadResources.json') | Should -BeTrue
        Test-Path (Join-Path $script:Root 'PrivilegedEAM/EntraID/EntraID.json') | Should -BeTrue
        @($Result | Where-Object Removed).Content | Should -Be @('Classification')
        Should -Invoke Clear-EntraOpsCache -ModuleName EntraOps -Times 0 -Exactly
    }

    It 'stops in a git repository unless Force is used' {
        New-Item -ItemType Directory -Path (Join-Path $script:Root '.git') | Out-Null

        { Remove-EntraOpsData -Path $script:Root -Content PrivilegedEAM -Confirm:$false 6>$null } | Should -Throw '*is a git repository*'
        Test-Path (Join-Path $script:Root 'PrivilegedEAM') | Should -BeTrue

        Remove-EntraOpsData -Path $script:Root -Content PrivilegedEAM -Force -Confirm:$false 6>$null
        Test-Path (Join-Path $script:Root 'PrivilegedEAM') | Should -BeFalse
    }

    It 'clears only the cache in a git repository without Force' {
        New-Item -ItemType Directory -Path (Join-Path $script:Root '.git') | Out-Null

        Remove-EntraOpsData -Path $script:Root -Content Cache -Confirm:$false 6>$null

        Should -Invoke Clear-EntraOpsCache -ModuleName EntraOps -Times 1 -Exactly
        Test-Path (Join-Path $script:Root 'PrivilegedEAM') | Should -BeTrue
    }

    It 'does not follow a linked export folder' -Skip:($IsWindows) {
        $Outside = Join-Path $TestDrive "outside-$([guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $Outside | Out-Null
        Set-Content -LiteralPath (Join-Path $Outside 'keep.json') -Value '{}'
        Remove-Item -LiteralPath (Join-Path $script:Root 'PrivilegedEAM') -Recurse -Force
        New-Item -ItemType SymbolicLink -Path (Join-Path $script:Root 'PrivilegedEAM') -Target $Outside | Out-Null

        Remove-EntraOpsData -Path $script:Root -Content PrivilegedEAM -Confirm:$false -WarningAction SilentlyContinue 6>$null

        Test-Path (Join-Path $Outside 'keep.json') | Should -BeTrue
    }
}
