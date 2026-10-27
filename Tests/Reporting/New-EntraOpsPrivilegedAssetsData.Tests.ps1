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

    Context 'Maester test results' {
        BeforeEach {
            $script:User2Id = '77777777-7777-7777-7777-777777777777'
            $script:AppRegId = '88888888-8888-8888-8888-888888888888'
            $script:AppRegAppId = 'bbbbbbbb-0000-0000-0000-000000000000'
            New-Item -ItemType Directory -Path "$script:Root/PrivilegedEAM/IdentityGovernance" -Force | Out-Null
            @(
                [ordered]@{ ObjectId = $script:User2Id; ObjectTenantId = 't1'; ObjectType = 'user'; ObjectDisplayName = 'Admin D'; ObjectUserPrincipalName = 'admin.d@contoso.com'; ObjectAdminTierLevelName = 'ControlPlane'; RoleAssignments = @() }
                [ordered]@{ ObjectId = $script:AppRegId; ObjectTenantId = 't1'; ObjectType = 'application'; ObjectDisplayName = 'App Reg E'; ObjectUserPrincipalName = $script:AppRegAppId; ObjectAdminTierLevelName = 'ManagementPlane'; RoleAssignments = @() }
            ) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$script:Root/PrivilegedEAM/IdentityGovernance/IdentityGovernance.json"

            $script:NewMaesterResult = {
                param([string]$TenantId = 't1', [string]$AssetProperty = 'AffectedObjects')
                $test = {
                    param($Id, $Result)
                    [ordered]@{
                        Id = $Id; Result = $Result; Title = "Title of $Id"; Name = "$($Id): Title of $Id"; Severity = 'High'; Tag = @('Maester', $Id)
                        HelpUrl = "https://maester.dev/docs/tests/$Id"; Block = 'Maester/Entra'
                        ResultDetail = [ordered]@{ TestDescription = "Description of $Id"; TestResult = "Result of $Id"; Service = 'EntraID' }
                    }
                }
                [ordered]@{
                    TenantId = $TenantId; TenantName = 'contoso'; ExecutedAt = '2026-10-04T08:35:43Z'
                    TotalCount = 4; FailedCount = 3; PassedCount = 1; SkippedCount = 0
                    Tests = @((& $test 'MT.1001' 'Failed'), (& $test 'MT.1002' 'Passed'), (& $test 'MT.1003' 'Failed'), (& $test 'MT.1004' 'Failed'))
                    $AssetProperty = @(
                        [ordered]@{ Id = $script:UserId; Type = 'User'; DisplayName = 'Admin A'; Tests = @('MT.1001', 'MT.1002') }
                        [ordered]@{ Id = $script:AppRegAppId; Type = 'AppRegistration'; DisplayName = 'App Reg E'; Tests = @('MT.1003') }
                        [ordered]@{ Id = 'cccccccc-0000-0000-0000-000000000000'; Type = 'User'; UserPrincipalName = 'Admin.D@contoso.com'; Tests = @('MT.1003') }
                        [ordered]@{ Id = '99999999-9999-9999-9999-999999999999'; Type = 'User'; DisplayName = 'Not privileged'; Tests = @('MT.1004') }
                    )
                } | ConvertTo-Json -Depth 6
            }
            $script:MaesterRoot = Join-Path $script:Root 'maester'
            New-Item -ItemType Directory -Path $script:MaesterRoot -Force | Out-Null
            $script:GetObject = { param($Payload, $Id) @($Payload.objects | Where-Object { $_.objectId -eq $Id })[0] }
        }

        It 'matches failed tests by object id, app id of app registrations and user principal name' {
            & $script:NewMaesterResult | Set-Content -LiteralPath "$script:MaesterRoot/TestResults-2026-10-04-103542.json"

            $Payload = New-EntraOpsPrivilegedAssetsData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRelatedObjectIds $false -MaesterTestResultPath "$script:MaesterRoot/TestResults-2026-10-04-103542.json" -PassThru 6>$null

            $Payload.maester.sourceFile | Should -Be 'TestResults-2026-10-04-103542.json'
            $Payload.maester.matchedObjectCount | Should -Be 3
            $Payload.maester.affectedObjectCount | Should -Be 4
            $Payload.maester.totals.failed | Should -Be 3
            @($Payload.maester.tests.Keys) | Should -Be @('MT.1001', 'MT.1003')
            $Payload.maester.tests['MT.1001'].description | Should -Be 'Description of MT.1001'
            $Payload.maester.tests['MT.1001'].service | Should -Be 'EntraID'
            @((& $script:GetObject $Payload $script:UserId).maesterAssets.tests) | Should -Be @('MT.1001')
            @((& $script:GetObject $Payload $script:AppRegId).maesterAssets.tests) | Should -Be @('MT.1003')
            @((& $script:GetObject $Payload $script:User2Id).maesterAssets.tests) | Should -Be @('MT.1003')
            (& $script:GetObject $Payload $script:AppId).Contains('maesterAssets') | Should -BeFalse
        }

        It 'uses the latest TestResults file of a folder' {
            & $script:NewMaesterResult | Set-Content -LiteralPath "$script:MaesterRoot/TestResults-2026-10-01-080000.json"
            & $script:NewMaesterResult | Set-Content -LiteralPath "$script:MaesterRoot/TestResults-2026-10-04-103542.json"
            'not json' | Set-Content -LiteralPath "$script:MaesterRoot/TestResults-latest.json"

            $Payload = New-EntraOpsPrivilegedAssetsData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRelatedObjectIds $false -MaesterTestResultPath $script:MaesterRoot -PassThru 6>$null

            $Payload.maester.sourceFile | Should -Be 'TestResults-2026-10-04-103542.json'
        }

        It 'accepts the result path without the .json extension' {
            & $script:NewMaesterResult | Set-Content -LiteralPath "$script:MaesterRoot/TestResults-2026-10-04-103542.json"

            $Payload = New-EntraOpsPrivilegedAssetsData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRelatedObjectIds $false -MaesterTestResultPath "$script:MaesterRoot/TestResults-2026-10-04-103542" -PassThru 6>$null

            $Payload.maester.sourceFile | Should -Be 'TestResults-2026-10-04-103542.json'
        }

        It 'reads AssetInventory of older Maester versions' {
            & $script:NewMaesterResult -AssetProperty 'AssetInventory' | Set-Content -LiteralPath "$script:MaesterRoot/TestResults-2026-10-04-103542.json"

            $Payload = New-EntraOpsPrivilegedAssetsData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRelatedObjectIds $false -MaesterTestResultPath $script:MaesterRoot -PassThru 6>$null

            $Payload.maester.matchedObjectCount | Should -Be 3
        }

        It 'warns when the Maester result belongs to another tenant' {
            & $script:NewMaesterResult -TenantId 't2' | Set-Content -LiteralPath "$script:MaesterRoot/TestResults-2026-10-04-103542.json"

            $Payload = New-EntraOpsPrivilegedAssetsData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRelatedObjectIds $false -MaesterTestResultPath $script:MaesterRoot -PassThru -WarningVariable warnings -WarningAction SilentlyContinue 6>$null

            @($warnings | Where-Object { "$_" -like '*belongs to tenant t2*' }).Count | Should -Be 1
            $Payload.maester.tenantId | Should -Be 't2'
        }

        It 'skips the integration with a warning when an explicit path has no result' {
            $Payload = New-EntraOpsPrivilegedAssetsData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRelatedObjectIds $false -MaesterTestResultPath "$script:MaesterRoot/missing" -PassThru -WarningVariable warnings -WarningAction SilentlyContinue 6>$null

            $Payload.maester | Should -BeNullOrEmpty
            @($warnings | Where-Object { "$_" -like '*No Maester test result found*' }).Count | Should -Be 1
        }

        It 'stops with a clear error for an unreadable result file' {
            'not json' | Set-Content -LiteralPath "$script:MaesterRoot/TestResults-2026-10-04-103542.json"

            { New-EntraOpsPrivilegedAssetsData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRelatedObjectIds $false -MaesterTestResultPath $script:MaesterRoot 6>$null } |
            Should -Throw '*Failed to read or parse Maester test result*'
        }
    }
}
