#Requires -Modules Pester

Describe 'New-EntraOpsAccessPackageFlowData' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
    }

    BeforeEach {
        $script:ControlPlaneUserId = '11111111-1111-1111-1111-111111111111'
        $script:ManagementPlaneUserId = '22222222-2222-2222-2222-222222222222'
        $script:UnprivilegedUserId = '33333333-3333-3333-3333-333333333333'
        $script:GroupId = '44444444-4444-4444-4444-444444444444'
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid())
        New-Item -ItemType Directory -Path "$script:Root/PrivilegedEAM/EntraID", "$script:Root/TenantGovernance/Snapshots", "$script:Root/App" -Force | Out-Null

        # At least two privileged objects are required: with a single object the nested-list bug
        # was masked because member enumeration still yields one valid object ID.
        @(
            [ordered]@{
                ObjectId = $script:ControlPlaneUserId; ObjectType = 'user'; ObjectSubType = 'Member'; ObjectDisplayName = 'CP Admin'
                ObjectAdminTierLevel = 'Unclassified'; ObjectAdminTierLevelName = 'Unclassified'
                RoleAssignments = @(@{ RoleAssignmentId = 'ra1'; RoleDefinitionName = 'Global Administrator'; RoleAssignmentScopeId = '/'; Classification = @(@{ AdminTierLevelName = 'ControlPlane'; Service = 'Global' }) })
            }
            [ordered]@{
                ObjectId = $script:ManagementPlaneUserId; ObjectType = 'user'; ObjectSubType = 'Member'; ObjectDisplayName = 'MP Admin'
                ObjectAdminTierLevel = 'Unclassified'; ObjectAdminTierLevelName = 'Unclassified'
                RoleAssignments = @(@{ RoleAssignmentId = 'ra2'; RoleDefinitionName = 'Groups Administrator'; RoleAssignmentScopeId = '/'; Classification = @(@{ AdminTierLevelName = 'ManagementPlane'; Service = 'Groups' }) })
            }
        ) | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$script:Root/PrivilegedEAM/EntraID/EntraID.json"

        @{
            resourceType = 'microsoft.entra.entitlementManagementAccessPackageAssignmentPolicy'
            properties   = @{ Id = 'policy1' }
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$script:Root/TenantGovernance/Snapshots/policy1.json"

        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery {
            switch -Wildcard ($Uri) {
                '*/accessPackageAssignmentPolicies/policy1' {
                    return [pscustomobject]@{
                        accessPackageId         = 'package1'
                        requestorSettings       = [pscustomobject]@{
                            scopeType         = 'SpecificDirectorySubjects'
                            allowedRequestors = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupMembers'; id = '44444444-4444-4444-4444-444444444444' })
                        }
                        requestApprovalSettings = [pscustomobject]@{ approvalStages = @() }
                    }
                }
                '*/accessPackages/package1' { return [pscustomobject]@{ displayName = 'Package 1'; catalogId = '' } }
                '*/accessPackages/package1?*' { return [pscustomobject]@{ accessPackageResourceRoleScopes = @() } }
                '*/accessPackageAssignments?*' { return @() }
                '*/groups/44444444-4444-4444-4444-444444444444*' { return [pscustomobject]@{ id = '44444444-4444-4444-4444-444444444444'; displayName = 'Requestor Group' } }
                default { throw "Unexpected Graph request in test: $Uri" }
            }
        }
        Mock -ModuleName EntraOps Get-EntraOpsIdGovScopeClassification { @() }
        Mock -ModuleName EntraOps Get-EntraOpsPrivilegedTransitiveGroupMember {
            @(
                [pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111'; DisplayName = 'CP Admin' }
                [pscustomobject]@{ Id = '22222222-2222-2222-2222-222222222222'; DisplayName = 'MP Admin' }
                [pscustomobject]@{ Id = '33333333-3333-3333-3333-333333333333'; DisplayName = 'Regular User' }
            )
        }
        Mock -ModuleName EntraOps Save-EntraOpsReportDataFile {}
    }

    It 'resolves requestor group member tiers from multiple Privileged EAM objects' {
        $Result = New-EntraOpsAccessPackageFlowData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRequestorApproverTiers $true -PassThru -WarningAction SilentlyContinue

        $Group = $Result.resolvedGroupTiers[$script:GroupId]
        $Group | Should -Not -BeNullOrEmpty
        $Group.tierName | Should -Be 'ControlPlane'
        $Group.totalMembers | Should -Be 3
        $Group.privilegedMemberCount | Should -Be 2

        $MemberTiers = @{}
        foreach ($Member in $Group.members) { $MemberTiers[$Member.id] = $Member.tierName }
        $MemberTiers[$script:ControlPlaneUserId] | Should -Be 'ControlPlane'
        $MemberTiers[$script:ManagementPlaneUserId] | Should -Be 'ManagementPlane'
        $MemberTiers[$script:UnprivilegedUserId] | Should -Be 'UserAccess'
    }
}
