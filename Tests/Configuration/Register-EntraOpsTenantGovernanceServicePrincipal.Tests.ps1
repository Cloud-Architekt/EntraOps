#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    function Install-EntraOpsRequiredModule { param($ModuleName) }
    function Get-MgContext { [pscustomobject]@{ Scopes = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All') } }
    function Connect-MgGraph { throw 'Connect-MgGraph must not be called' }
    function Invoke-EntraOpsMsGraphQuery {
        param($Method, $Uri, $Body, $OutputType, [switch]$DisableCache, [switch]$ThrowOnFailure)
        throw 'Invoke-EntraOpsMsGraphQuery must be mocked'
    }
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsTenantGovernanceResourceDefinition.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/Configuration/Register-EntraOpsTenantGovernanceServicePrincipal.ps1"

    $script:GraphSp = [pscustomobject]@{
        id       = 'graph-sp'
        appRoles = @(
            [pscustomobject]@{ id = 'role-au'; value = 'AdministrativeUnit.Read.All' }
            [pscustomobject]@{ id = 'role-rm'; value = 'RoleManagement.Read.Directory' }
        )
    }
}

Describe 'Register-EntraOpsTenantGovernanceServicePrincipal' {
    BeforeEach {
        $script:UtcmSpFixture = $null
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'GET' -and $Uri -like "*appId eq '00000003-0000-0000-c000-000000000000'*" } { $script:GraphSp }
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'GET' -and $Uri -like "*appId eq '00000002-0000-0ff1-ce00-000000000000'*" } { $null }
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'GET' -and $Uri -like "*appId eq '03b07b79-c5bc-4b5e-9bfa-13acf4a99998'*" } { $script:UtcmSpFixture }
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'GET' -and $Uri -like '*/appRoleAssignments' } { @() }
        # Like the real helper: a failed request only throws with -ThrowOnFailure, otherwise it returns nothing.
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'POST' } { if ($ThrowOnFailure) { throw 'simulated grant failure' } }
    }

    It 'creates and assigns nothing under WhatIf' {
        $Result = Register-EntraOpsTenantGovernanceServicePrincipal -ResourcesToInclude 'microsoft.entra.administrativeUnit' -ConfigFile (Join-Path $TestDrive 'missing.json') -WhatIf 6>$null

        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly -ParameterFilter { $Method -eq 'POST' }
        $Result.NewlyAssignedCount | Should -Be 0
    }

    It 'reports a failed grant instead of counting it as assigned' {
        $script:UtcmSpFixture = [pscustomobject]@{ id = 'utcm-sp' }

        $Result = Register-EntraOpsTenantGovernanceServicePrincipal -ResourcesToInclude 'microsoft.entra.administrativeUnit' -ConfigFile (Join-Path $TestDrive 'missing.json') -WarningAction SilentlyContinue 6>$null |
            Where-Object { $_ -isnot [string] }

        $Result.NewlyAssignedCount | Should -Be 0
        @($Result.FailedPermissions) | Should -Be @('AdministrativeUnit.Read.All', 'RoleManagement.Read.Directory')
    }
}
