#Requires -Modules Pester

Describe 'Test-EntraOpsDirectoryRoleRestrictsManagement' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
    }

    It 'does not count <Name>, whose holders lower administrators can still manage' -ForEach @(
        @{ Name = 'Directory Readers'; Id = '88d8e3e3-8f55-4a1e-953a-9b9898b8876b' }
        @{ Name = 'Guest Inviter'; Id = '95e79109-95c0-4d8e-aee3-d01accf2d47b' }
        @{ Name = 'Password Administrator'; Id = '966707d0-3269-4727-9be2-8c3a10f19b9d' }
        @{ Name = 'Helpdesk Administrator'; Id = '729827e3-9c14-49f7-bb1b-9608f156bbb8' }
        @{ Name = 'Message Center Reader'; Id = '790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b' }
        @{ Name = 'Reports Reader'; Id = '4a5d8f65-41da-4de4-8968-e035b65339cf' }
        @{ Name = 'User Experience Success Manager'; Id = '27460883-1df1-4691-b032-3b79643e5e63' }
        @{ Name = 'Usage Summary Reports Reader'; Id = '75934031-6c7e-415a-99d7-48dbd49e875e' }
        @{ Name = 'Authentication Administrator'; Id = 'c4e39bd9-1100-46d3-8c65-fb160da0071f' }
        @{ Name = 'Groups Administrator'; Id = 'fdd7a751-b60b-444a-984c-02652fe8fa1c' }
        @{ Name = 'User Administrator'; Id = 'FE930BE7-5E62-47DB-91AF-98C3A49A38B1' }
    ) {
        InModuleScope EntraOps -Parameters @{ Id = $Id } { Test-EntraOpsDirectoryRoleRestrictsManagement -RoleDefinitionId $Id } | Should -BeFalse
    }

    It 'counts <Name> as restricted management' -ForEach @(
        @{ Name = 'Global Administrator'; Id = '62e90394-69f5-4237-9190-012177145e10' }
        @{ Name = 'Global Reader'; Id = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451' }
        @{ Name = 'a custom role'; Id = '11111111-2222-3333-4444-555555555555' }
        @{ Name = 'an empty role ID'; Id = '' }
    ) {
        InModuleScope EntraOps -Parameters @{ Id = $Id } { Test-EntraOpsDirectoryRoleRestrictsManagement -RoleDefinitionId $Id } | Should -BeTrue
    }
}
