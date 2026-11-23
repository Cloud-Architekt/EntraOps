#Requires -Modules Pester

# Origin of privileged objects in the Privileged EAM export: OriginType, OriginTenantId and OriginId.
Describe 'Resolve-EntraOpsObjectOrigin' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
        $script:HomeTenant = '11111111-1111-1111-1111-111111111111'
        $script:Other = '22222222-2222-2222-2222-222222222222'
        $script:Microsoft = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
        $script:Resolve = { param([hashtable]$Parameters) & (Get-Module EntraOps) { param($p) Resolve-EntraOpsObjectOrigin @p } $Parameters }
    }

    It 'reads <Case> of a user or group' -ForEach @(
        @{ Case = 'cross-tenant synchronization'; ObjectType = 'user'; Info = @{ originTenantId = '22222222-2222-2222-2222-222222222222'; originId = '00000001-0000-0000-0000-000000000001'; synchronizationInfo = @{ creationType = 'tenantToTenantSync' } }; Type = 'CrossTenantSync'; Tenant = '22222222-2222-2222-2222-222222222222'; Id = '00000001-0000-0000-0000-000000000001' }
        @{ Case = 'a synchronized group'; ObjectType = 'group'; Info = @{ originTenantId = '22222222-2222-2222-2222-222222222222'; originId = '00000002-0000-0000-0000-000000000002'; synchronizationInfo = @{ creationType = 'tenantToTenantSync' } }; Type = 'CrossTenantSync'; Tenant = '22222222-2222-2222-2222-222222222222'; Id = '00000002-0000-0000-0000-000000000002' }
        @{ Case = 'an invited guest'; ObjectType = 'user'; Info = @{ originTenantId = '22222222-2222-2222-2222-222222222222'; originId = '00000003-0000-0000-0000-000000000003'; synchronizationInfo = $null }; Type = 'B2BInvitation'; Tenant = '22222222-2222-2222-2222-222222222222'; Id = '00000003-0000-0000-0000-000000000003' }
        @{ Case = 'another creation type'; ObjectType = 'user'; Info = @{ originTenantId = '22222222-2222-2222-2222-222222222222'; originId = '00000004-0000-0000-0000-000000000004'; synchronizationInfo = @{ creationType = 'somethingNew' } }; Type = 'somethingNew'; Tenant = '22222222-2222-2222-2222-222222222222'; Id = '00000004-0000-0000-0000-000000000004' }
    ) {
        $Origin = & $script:Resolve @{ ObjectType = $ObjectType; ObjectId = '00000009-0000-0000-0000-000000000009'; TenantId = $script:HomeTenant; OriginTenantInfo = [pscustomobject]$Info; OriginTenantInfoAvailable = $true; UserType = 'Member' }
        $Origin.OriginType | Should -Be $Type
        $Origin.OriginTenantId | Should -Be $Tenant
        $Origin.OriginId | Should -Be $Id
    }

    It 'names a guest without originTenantInfo (one-time passcode, Microsoft account) a B2B invitation without tenant' {
        foreach ($User in @(@{ UserType = 'Guest'; UserPrincipalName = 'a_b.com#EXT#@contoso.onmicrosoft.com' }, @{ UserType = 'Member'; UserPrincipalName = 'a_b.com#EXT#@contoso.onmicrosoft.com' })) {
            $Origin = & $script:Resolve (@{ ObjectType = 'user'; ObjectId = 'u'; TenantId = $script:HomeTenant; OriginTenantInfoAvailable = $true } + $User)
            $Origin.OriginType | Should -Be 'B2BInvitation'
            $Origin.OriginTenantId | Should -BeNullOrEmpty
            $Origin.OriginId | Should -BeNullOrEmpty
        }
    }

    It 'names an object synchronized from Active Directory by its SID, and an object managed in the cloud by its ID' {
        $OnPremises = & $script:Resolve @{ ObjectType = 'group'; ObjectId = 'g'; TenantId = $script:HomeTenant; OnPremisesSyncEnabled = $true; OnPremisesSecurityIdentifier = 'S-1-5-21-1-2-3-1104'; OriginTenantInfoAvailable = $true }
        $OnPremises.OriginType | Should -Be 'OnPremises'
        $OnPremises.OriginTenantId | Should -Be $script:HomeTenant
        $OnPremises.OriginId | Should -Be 'S-1-5-21-1-2-3-1104'
        # Management moved to the cloud (onPremisesSyncEnabled false), or a group written back to Active Directory: the SID stays, the origin is the cloud.
        $Moved = & $script:Resolve @{ ObjectType = 'group'; ObjectId = 'g'; TenantId = $script:HomeTenant; OnPremisesSyncEnabled = $false; OnPremisesSecurityIdentifier = 'S-1-5-21-1-2-3-1104'; OriginTenantInfoAvailable = $true }
        $Moved.OriginType | Should -Be 'Cloud'
        $Moved.OriginId | Should -Be 'g'
    }

    It 'leaves a member unknown without originTenantInfo, as it can be synchronized from another tenant' {
        $Origin = & $script:Resolve @{ ObjectType = 'group'; ObjectId = 'g'; TenantId = $script:HomeTenant; OriginTenantInfoAvailable = $false }
        $Origin.OriginType | Should -BeNullOrEmpty
        $Origin.OriginTenantId | Should -BeNullOrEmpty
        # An object synchronized from Active Directory is known without it.
        (& $script:Resolve @{ ObjectType = 'user'; ObjectId = 'u'; TenantId = $script:HomeTenant; OnPremisesSyncEnabled = $true; OnPremisesSecurityIdentifier = 'S-1-5-21-1'; OriginTenantInfoAvailable = $false }).OriginType | Should -Be 'OnPremises'
    }

    It 'names an object with access through Tenant Governance by its tenant and ID' {
        $Origin = & $script:Resolve @{ ObjectType = 'user'; ObjectId = 'u'; TenantId = $script:Other; TenantGovernance = $true; OriginTenantInfoAvailable = $false }
        $Origin.OriginType | Should -Be 'TenantGovernance'
        $Origin.OriginTenantId | Should -Be $script:Other
        $Origin.OriginId | Should -Be 'u'
    }

    It 'names the application of a service principal: <Case>' -ForEach @(
        @{ Case = 'of this tenant'; SubType = 'Application'; Owner = '11111111-1111-1111-1111-111111111111'; AppId = 'app-1'; Type = 'InternalApplication'; Tenant = '11111111-1111-1111-1111-111111111111' }
        @{ Case = 'a managed identity'; SubType = 'ManagedIdentity'; Owner = ''; AppId = 'mi-1'; Type = 'InternalApplication'; Tenant = '11111111-1111-1111-1111-111111111111' }
        @{ Case = 'of another organization'; SubType = 'Application'; Owner = '22222222-2222-2222-2222-222222222222'; AppId = 'app-2'; Type = 'ExternalApplication'; Tenant = '22222222-2222-2222-2222-222222222222' }
        @{ Case = 'of Microsoft'; SubType = 'Application'; Owner = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'; AppId = 'app-3'; Type = 'FirstPartyApplication'; Tenant = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' }
        @{ Case = 'an agent identity of a blueprint of this tenant'; SubType = 'AgentIdentity'; Owner = '11111111-1111-1111-1111-111111111111'; AppId = 'agent-1'; Type = 'InternalApplication'; Tenant = '11111111-1111-1111-1111-111111111111' }
    ) {
        $Origin = & $script:Resolve @{ ObjectType = 'serviceprincipal'; ObjectSubType = $SubType; ObjectId = 'sp'; TenantId = $script:HomeTenant; AppId = $AppId; AppOwnerOrganizationId = $Owner }
        $Origin.OriginType | Should -Be $Type
        $Origin.OriginTenantId | Should -Be $Tenant
        $Origin.OriginId | Should -Be $AppId
    }

    It 'leaves a service principal without application tenant unknown (an agent identity whose blueprint was not read)' {
        (& $script:Resolve @{ ObjectType = 'serviceprincipal'; ObjectSubType = 'AgentIdentity'; ObjectId = 'sp'; TenantId = $script:HomeTenant; AppId = 'a' }).OriginType | Should -BeNullOrEmpty
    }
}

Describe 'Get-EntraOpsObjectOriginTenantInfo' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
    }

    BeforeEach {
        InModuleScope EntraOps {
            $__EntraOpsSession.Remove('OriginTenantInfoDenied')
            $__EntraOpsSession.Remove('GroupOriginTenantInfoAccess')
        }
    }

    AfterAll {
        InModuleScope EntraOps {
            $__EntraOpsSession.Remove('OriginTenantInfoDenied')
            $__EntraOpsSession.Remove('GroupOriginTenantInfoAccess')
        }
    }

    It 'reads originTenantInfo and the SID of a group' {
        InModuleScope EntraOps {
            Mock Invoke-EntraOpsMsGraphQuery { [pscustomobject]@{ id = 'g'; onPremisesSecurityIdentifier = 'S-1-5-21-1'; originTenantInfo = [pscustomobject]@{ originTenantId = 't'; originId = 'o' } } } -ParameterFilter { $Uri -like '/beta/groups/g?$select=id,originTenantInfo,onPremisesSecurityIdentifier' }
            $Result = Get-EntraOpsObjectOriginTenantInfo -ObjectType group -ObjectId g
            $Result.Available | Should -BeTrue
            $Result.OriginTenantInfo.originId | Should -Be 'o'
            $Result.OnPremisesSecurityIdentifier | Should -Be 'S-1-5-21-1'
        }
    }

    It 'stops reading originTenantInfo of groups after Microsoft Graph refused it, warns once and still reads the SID' {
        InModuleScope EntraOps {
            Mock Invoke-EntraOpsMsGraphQuery {
                $Exception = [System.Exception]::new('Forbidden'); $Exception.Data['StatusCode'] = 403; throw $Exception
            } -ParameterFilter { $Uri -like '*originTenantInfo*' }
            Mock Invoke-EntraOpsMsGraphQuery { [pscustomobject]@{ id = 'g'; onPremisesSecurityIdentifier = 'S-1-5-21-2' } } -ParameterFilter { $Uri -like '/beta/groups/*?$select=id,onPremisesSecurityIdentifier' }

            $First = Get-EntraOpsObjectOriginTenantInfo -ObjectType group -ObjectId g -WarningVariable Warnings -WarningAction SilentlyContinue
            $Second = Get-EntraOpsObjectOriginTenantInfo -ObjectType group -ObjectId h -WarningVariable MoreWarnings -WarningAction SilentlyContinue
            $First.Available | Should -BeFalse
            $First.OnPremisesSecurityIdentifier | Should -Be 'S-1-5-21-2'
            $Second.Available | Should -BeFalse
            @($Warnings).Count | Should -Be 1
            "$Warnings" | Should -BeLike '*Group-XTenantIdentitySync.Read.All*'
            @($MoreWarnings).Count | Should -Be 0
            Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -like '*originTenantInfo*' }
            # Users are read on.
            Mock Invoke-EntraOpsMsGraphQuery { [pscustomobject]@{ id = 'u'; originTenantInfo = $null } } -ParameterFilter { $Uri -like '/beta/users/*' }
            (Get-EntraOpsObjectOriginTenantInfo -ObjectType user -ObjectId u).Available | Should -BeTrue
        }
    }

    It 'does not read originTenantInfo of groups when the session knows that the permission is not granted' {
        InModuleScope EntraOps {
            $__EntraOpsSession['GroupOriginTenantInfoAccess'] = $false
            Mock Invoke-EntraOpsMsGraphQuery { [pscustomobject]@{ id = 'g'; onPremisesSecurityIdentifier = '' } }
            $Result = Get-EntraOpsObjectOriginTenantInfo -ObjectType group -ObjectId g -WarningAction SilentlyContinue
            $Result.Available | Should -BeFalse
            Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly -ParameterFilter { $Uri -like '*originTenantInfo*' }
        }
    }

    It 'leaves the origin of one object unknown on another error, without stopping the session' {
        InModuleScope EntraOps {
            Mock Invoke-EntraOpsMsGraphQuery { $Exception = [System.Exception]::new('Not found'); $Exception.Data['StatusCode'] = 404; throw $Exception }
            (Get-EntraOpsObjectOriginTenantInfo -ObjectType user -ObjectId u).Available | Should -BeFalse
            $__EntraOpsSession['OriginTenantInfoDenied'].ContainsKey('user') | Should -BeFalse
        }
    }
}
