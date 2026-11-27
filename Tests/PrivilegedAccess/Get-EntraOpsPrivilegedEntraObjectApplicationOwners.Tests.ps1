#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    function Invoke-EntraOpsMsGraphQuery {
        param($Method, $Uri, $OutputType, $Body, [switch]$SuppressNotFoundWarning, [switch]$SuppressForbiddenWarning, [switch]$SuppressBadRequestWarning, [switch]$ThrowOnFailure, [switch]$DisableCache, $WarningAction, $ConsistencyLevel)
        throw 'Invoke-EntraOpsMsGraphQuery must be mocked'
    }

    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsCustomSecurityAttributeClassificationEnabled.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsAlternateObjectTierLevelEnabled.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Get-EntraOpsPrivilegedEntraObject.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsObjectOrigin.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsObjectOriginTenantInfo.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Findings/Test-EntraOpsMicrosoftFirstParty.ps1"
}

Describe 'Get-EntraOpsPrivilegedEntraObject owners of the app registration' {
    BeforeEach {
        $global:TenantIdContext = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        $global:EntraOpsConfig = [pscustomobject]@{
            CustomSecurityAttributes           = [pscustomobject]@{}
            AlternateObjectTierLevelAttributes = $null
        }
        $script:ServicePrincipalId = '11111111-1111-1111-1111-111111111111'
        $script:AppId = '22222222-2222-2222-2222-222222222222'
        $script:Sp = @{ Type = 'Application'; AppOwnerOrganizationId = $global:TenantIdContext }

        Mock Invoke-EntraOpsMsGraphQuery {
            switch -Wildcard ($Uri) {
                "/beta/directoryObjects/$($script:ServicePrincipalId)*" { return [pscustomobject]@{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = $script:ServicePrincipalId; displayName = 'Deployment app' } }
                "/beta/serviceprincipals/$($script:ServicePrincipalId)[?]*" { return [pscustomobject]@{ id = $script:ServicePrincipalId; appId = $script:AppId; servicePrincipalType = $script:Sp.Type; appOwnerOrganizationId = $script:Sp.AppOwnerOrganizationId } }
                "/beta/servicePrincipals/$($script:ServicePrincipalId)/owners*" { return @([pscustomobject]@{ id = 'owner-of-sp' }, [pscustomobject]@{ id = 'owner-of-both' }) }
                "/beta/applications(appId='$($script:AppId)')/owners*" { return @([pscustomobject]@{ id = 'owner-of-app' }, [pscustomobject]@{ id = 'owner-of-both' }) }
                default { return @() }
            }
        }
    }

    It 'adds the owners of an app registration of the tenant to the owners of the service principal, once each' {
        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:ServicePrincipalId -TenantId $global:TenantIdContext

        @($Result.Owners) | Should -Be @('owner-of-app', 'owner-of-both', 'owner-of-sp')
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -like "/beta/applications(appId='*')/owners*" -and $SuppressNotFoundWarning }
    }

    It 'does not look up an app registration for <Case>' -ForEach @(
        @{ Case = 'a Microsoft first-party or multi-tenant application of another tenant'; Type = 'Application'; Tenant = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' }
        @{ Case = 'a managed identity'; Type = 'ManagedIdentity'; Tenant = $null }
    ) {
        $script:Sp = @{ Type = $Type; AppOwnerOrganizationId = $Tenant }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:ServicePrincipalId -TenantId $global:TenantIdContext

        @($Result.Owners) | Should -Be @('owner-of-both', 'owner-of-sp')
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly -ParameterFilter { $Uri -like '/beta/applications(*' }
    }

    It 'names the origin of the service principal: <Type>' -ForEach @(
        @{ SpType = 'Application'; Tenant = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; Type = 'InternalApplication'; OriginTenant = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' }
        @{ SpType = 'ManagedIdentity'; Tenant = $null; Type = 'InternalApplication'; OriginTenant = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' }
        @{ SpType = 'Application'; Tenant = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'; Type = 'ExternalApplication'; OriginTenant = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' }
        @{ SpType = 'Application'; Tenant = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'; Type = 'FirstPartyApplication'; OriginTenant = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' }
    ) {
        $script:Sp = @{ Type = $SpType; AppOwnerOrganizationId = $Tenant }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:ServicePrincipalId -TenantId $global:TenantIdContext

        $Result.OriginType | Should -Be $Type
        $Result.OriginTenantId | Should -Be $OriginTenant
        $Result.OriginId | Should -Be $script:AppId
        # Only an application of another tenant is outside the home tenant: a managed identity has no owner organization
        # in Microsoft Graph and belongs to this tenant.
        $Result.OutsideOfHomeTenant | Should -Be ($Type -ne 'InternalApplication')
    }
}

Describe 'Get-EntraOpsPrivilegedEntraObject origin of users and groups' {
    BeforeEach {
        $global:TenantIdContext = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        $global:EntraOpsConfig = [pscustomobject]@{
            CustomSecurityAttributes           = [pscustomobject]@{}
            AlternateObjectTierLevelAttributes = $null
        }
        $script:ObjectId = '33333333-3333-3333-3333-333333333333'
        $script:Object = @{ Type = '#microsoft.graph.user'; UserType = 'Member'; Upn = 'AdeleV@contoso.com'; OnPremises = $false; Sid = $null; Origin = $null }

        Mock Invoke-EntraOpsMsGraphQuery {
            switch -Wildcard ($Uri) {
                "/beta/directoryObjects/$($script:ObjectId)?*" { return [pscustomobject]@{ '@odata.type' = $script:Object.Type; id = $script:ObjectId; displayName = 'Object'; userPrincipalName = $script:Object.Upn; userType = $script:Object.UserType; onPremisesSyncEnabled = $script:Object.OnPremises; isAssignableToRole = $true } }
                "/beta/users/$($script:ObjectId)?`$select=id,originTenantInfo" { return [pscustomobject]@{ id = $script:ObjectId; originTenantInfo = $script:Object.Origin } }
                "/beta/groups/$($script:ObjectId)?`$select=id,originTenantInfo,onPremisesSecurityIdentifier" { return [pscustomobject]@{ id = $script:ObjectId; originTenantInfo = $script:Object.Origin; onPremisesSecurityIdentifier = $script:Object.Sid } }
                "/beta/users/$($script:ObjectId)?*" { return [pscustomobject]@{ id = $script:ObjectId; userPrincipalName = $script:Object.Upn; userType = $script:Object.UserType; onPremisesSecurityIdentifier = $script:Object.Sid } }
                default { return @() }
            }
        }
    }

    It 'names a member synchronized from another tenant, also without #EXT#, and flags it outside the home tenant' {
        $script:Object.Origin = [pscustomobject]@{ originTenantId = 'BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB'; originId = '44444444-4444-4444-4444-444444444444'; synchronizationInfo = [pscustomobject]@{ creationType = 'tenantToTenantSync' } }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:ObjectId -TenantId $global:TenantIdContext

        $Result.OriginType | Should -Be 'CrossTenantSync'
        $Result.OriginTenantId | Should -Be 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        $Result.OriginId | Should -Be '44444444-4444-4444-4444-444444444444'
        $Result.OutsideOfHomeTenant | Should -BeTrue
    }

    It 'names a group synchronized from Active Directory by its SID, and a cloud user by its ID' {
        $script:Object = @{ Type = '#microsoft.graph.group'; OnPremises = $true; Sid = 'S-1-5-21-1-2-3-1104'; Origin = $null }
        $Group = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:ObjectId -TenantId $global:TenantIdContext
        $Group.OriginType | Should -Be 'OnPremises'
        $Group.OriginId | Should -Be 'S-1-5-21-1-2-3-1104'

        $script:Object = @{ Type = '#microsoft.graph.user'; UserType = 'Member'; Upn = 'AdeleV@contoso.com'; OnPremises = $false; Sid = $null; Origin = $null }
        $User = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:ObjectId -TenantId $global:TenantIdContext
        $User.OriginType | Should -Be 'Cloud'
        $User.OriginTenantId | Should -Be 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        $User.OriginId | Should -Be $script:ObjectId
        $User.OutsideOfHomeTenant | Should -BeFalse
    }
}
