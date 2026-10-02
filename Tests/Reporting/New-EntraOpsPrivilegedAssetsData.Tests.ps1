#Requires -Modules Pester

Describe 'New-EntraOpsPrivilegedAssetsData' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
    }

    BeforeEach {
        $script:UserId = '11111111-1111-1111-1111-111111111111'
        $script:AppId = '22222222-2222-2222-2222-222222222222'
        $script:OwnerId = '33333333-3333-3333-3333-333333333333'
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid())
        New-Item -ItemType Directory -Path "$script:Root/PrivilegedEAM/EntraID", "$script:Root/PrivilegedEAM/Azure", "$script:Root/Classification", "$script:Root/App" -Force | Out-Null

        @(
            [ordered]@{
                ObjectId = $script:UserId; ObjectTenantId = 't1'; ObjectType = 'user'; ObjectSubType = 'Member'; ObjectDisplayName = 'Admin A'
                ObjectAdminTierLevel = 'Unclassified'; ObjectAdminTierLevelName = 'Unclassified'; OnPremSynchronized = $true
                AssignedAdministrativeUnits = @(@{ id = 'AU1'; displayName = 'Tier0-AU' }); RestrictedManagementByAadRole = $true
                OwnedObjects = @($script:AppId); OwnedDevices = @('44444444-4444-4444-4444-444444444444')
                RoleAssignments = @(@{ RoleAssignmentId = 'ra1'; RoleDefinitionName = 'Global Administrator'; RoleAssignmentScopeId = '/'; PIMAssignmentType = 'Eligible'; Classification = @(@{ AdminTierLevelName = 'ControlPlane'; Service = 'Identity' }) })
            }
            [ordered]@{
                ObjectId = $script:AppId; ObjectTenantId = 't1'; ObjectType = 'serviceprincipal'; ObjectSubType = 'Application'; ObjectDisplayName = 'App B'
                ObjectUserPrincipalName = 'aaaaaaaa-0000-0000-0000-000000000000'; ObjectAdminTierLevel = '1'; ObjectAdminTierLevelName = 'ManagementPlane'
                Owners = @($script:OwnerId, $script:UserId); RoleAssignments = @()
            }
            [ordered]@{
                ObjectId = '66666666-6666-6666-6666-666666666666'; ObjectTenantId = 't1'; ObjectType = 'serviceprincipal'; ObjectSubType = 'AgentIdentity'
                ObjectDisplayName = 'Agent C'; ObjectAdminTierLevelName = 'UserAccess'; IdentityParent = 'aaaaaaaa-0000-0000-0000-000000000000'; RoleAssignments = @()
            }
        ) | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$script:Root/PrivilegedEAM/EntraID/EntraID.json"
        @([ordered]@{
                ObjectId = $script:UserId.ToUpperInvariant(); ObjectType = 'user'; ObjectDisplayName = 'Admin A'
                RoleAssignments = @(@{ RoleAssignmentId = 'az1'; RoleDefinitionName = 'Owner'; RoleAssignmentScopeId = '/subscriptions/x'; PIMAssignmentType = 'Permanent'; Classification = @(@{ AdminTierLevelName = 'ManagementPlane'; Service = 'Azure' }) })
            }) | ConvertTo-Json -Depth 10 -AsArray | Set-Content -LiteralPath "$script:Root/PrivilegedEAM/Azure/Azure.json"
        @{
            TenantName               = 'contoso.onmicrosoft.com'
            CustomSecurityAttributes = @{ PrivilegedUserAttribute = 'tierUser'; PrivilegedUserAdminTierLevelAttribute = 'level' }
            ObjectClassificationFile = @{ Enabled = $true; FilePath = './Classification/ObjectClassification.json' }
            AlternateObjectTierLevelAttributes = @{ Enabled = $true; ServicePrincipal = @{ Enabled = $false }; Group = @{ ControlPlane = '$true' } }
            PrivilegedAssets         = @{ ResolveRelatedObjectIds = $true }
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$script:Root/EntraOpsConfig.json"
        @(@{ ObjectId = $script:UserId; ObjectType = 'user'; AdminTierLevelName = 'ControlPlane'; Justification = 'GA' }) | ConvertTo-Json -AsArray |
            Set-Content -LiteralPath "$script:Root/Classification/ObjectClassification.json"

        Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps {
            @(
                [pscustomobject]@{ id = '33333333-3333-3333-3333-333333333333'; '@odata.type' = '#microsoft.graph.user'; displayName = 'Helpdesk Owner' }
                [pscustomobject]@{ id = '44444444-4444-4444-4444-444444444444'; '@odata.type' = '#microsoft.graph.device'; displayName = 'LAPTOP-1'; isCompliant = $false }
            )
        }
    }

    It 'merges objects across RBAC systems and summarizes assignment tiers' {
        $Payload = New-EntraOpsPrivilegedAssetsData -RepoRoot $script:Root -AppRoot "$script:Root/App" -PassThru 6>$null
        $User = @($Payload.objects | Where-Object { $_.objectId -eq $script:UserId })

        $Payload.objects.Count | Should -Be 3
        $User.Count | Should -Be 1
        @($User[0].roleSystems) | Should -Be @('Azure', 'EntraID')
        $User[0].assignmentSummary.total | Should -Be 2
        $User[0].assignmentSummary.highestTierName | Should -Be 'ControlPlane'
        $User[0].assignmentSummary.eligible | Should -Be 1
        $User[0].onPremSynchronized | Should -BeTrue
        $User[0].restrictedManagement | Should -Be 'Applied'
        Test-Path -LiteralPath "$script:Root/App/data/privileged-assets-data.js" | Should -BeTrue
    }

    It 'resolves related objects from the export, by app id and through Microsoft Graph' {
        $Payload = New-EntraOpsPrivilegedAssetsData -RepoRoot $script:Root -AppRoot "$script:Root/App" -PassThru 6>$null

        $Payload.relatedObjects[$script:OwnerId].displayName | Should -Be 'Helpdesk Owner'
        $Payload.relatedObjects[$script:OwnerId].source | Should -Be 'Microsoft Graph'
        $Payload.relatedObjects[$script:AppId].source | Should -Be 'PrivilegedEAM'
        $Payload.relatedObjects['aaaaaaaa-0000-0000-0000-000000000000'].objectId | Should -Be $script:AppId
        Should -Invoke Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -Times 1 -Exactly -ParameterFilter { $Uri -eq '/v1.0/directoryObjects/getByIds' }
    }

    It 'skips Microsoft Graph when related object resolution is disabled' {
        $Payload = New-EntraOpsPrivilegedAssetsData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRelatedObjectIds $false -PassThru 6>$null

        $Payload.relatedObjects.Contains($script:OwnerId) | Should -BeFalse
        Should -Invoke Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -Times 0
    }

    It 'embeds custom security attribute names and the Object Classification File entries' {
        $Payload = New-EntraOpsPrivilegedAssetsData -RepoRoot $script:Root -AppRoot "$script:Root/App" -PassThru 6>$null
        $Settings = $Payload.classificationSettings

        $Settings.customSecurityAttributes.userAttributeSet | Should -Be 'tierUser'
        $Settings.customSecurityAttributes.userTierLevelAttribute | Should -Be 'level'
        $Settings.customSecurityAttributes.userTierNameAttribute | Should -Be 'adminTierLevelName'
        $Settings.customSecurityAttributes.enabledFor.user | Should -BeFalse
        $Settings.customSecurityAttributes.enabledFor.application | Should -BeFalse
        $Settings.objectClassificationFile.enabled | Should -BeTrue
        $Settings.objectClassificationFile.entries[0].objectId | Should -Be $script:UserId
        $Settings.objectClassificationFile.entries[0].adminTierLevelName | Should -Be 'ControlPlane'
        $Settings.alternateObjectTierLevelAttributes.user | Should -BeTrue
        $Settings.alternateObjectTierLevelAttributes.servicePrincipal | Should -BeFalse
        $Settings.alternateObjectTierLevelAttributes.group | Should -BeTrue
    }
}
