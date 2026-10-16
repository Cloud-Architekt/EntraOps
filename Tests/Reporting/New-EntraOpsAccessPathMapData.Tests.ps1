#Requires -Modules Pester

Describe 'New-EntraOpsAccessPathMapData' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
    }

    BeforeEach {
        $script:UserId = '11111111-1111-1111-1111-111111111111'
        $script:OwnerRoleId = '8E3AF657-A8FF-443C-A75C-2FE8C4BCB635'
        $script:ReaderRoleId = 'ACDD72A7-3385-48EF-BD42-F606FBA81AE7'
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid())
        New-Item -ItemType Directory -Path "$script:Root/PrivilegedEAM/Azure", "$script:Root/App" -Force | Out-Null

        # One unclassified (Tier 2) user with the same Owner role at two Tier 0 scopes and a
        # Tier 2 Reader assignment: two Owner role assignment edges, one (shared) Owner role edge.
        @([ordered]@{
                ObjectId = $script:UserId; ObjectTenantId = 't1'; ObjectType = 'user'; ObjectDisplayName = 'Admin A'
                ObjectAdminTierLevel = ''; ObjectAdminTierLevelName = 'Unclassified'
                RoleAssignments = @(
                    @{ RoleAssignmentInstanceId = 'ra-owner-1'; RoleDefinitionId = $script:OwnerRoleId; RoleDefinitionName = 'Owner'; RoleAssignmentScopeId = '/subscriptions/a'; PIMAssignmentType = 'Permanent'; Classification = @(@{ AdminTierLevel = '0'; AdminTierLevelName = 'ControlPlane'; Service = 'Azure' }) }
                    @{ RoleAssignmentInstanceId = 'ra-owner-2'; RoleDefinitionId = $script:OwnerRoleId; RoleDefinitionName = 'Owner'; RoleAssignmentScopeId = '/subscriptions/b'; PIMAssignmentType = 'Permanent'; Classification = @(@{ AdminTierLevel = '0'; AdminTierLevelName = 'ControlPlane'; Service = 'Azure' }) }
                    @{ RoleAssignmentInstanceId = 'ra-reader'; RoleDefinitionId = $script:ReaderRoleId; RoleDefinitionName = 'Reader'; RoleAssignmentScopeId = '/subscriptions/c'; PIMAssignmentType = 'Permanent'; Classification = @(@{ AdminTierLevel = '2'; AdminTierLevelName = 'UserAccess'; Service = 'Azure' }) }
                )
            }) | ConvertTo-Json -Depth 10 -AsArray | Set-Content -LiteralPath "$script:Root/PrivilegedEAM/Azure/Azure.json"

        Mock Get-EntraOpsClassificationSourceCache -ModuleName EntraOps { $null }
    }

    It 'marks exactly one distinct tier breach path per principal role assignment' {
        $Payload = New-EntraOpsAccessPathMapData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveObjectIdsOutsidePrivilegedEAM $false -PassThru -WarningAction SilentlyContinue 6>$null
        $BreachableEdges = @($Payload.edges | Where-Object { $_.kind -match '^EO_(Has|EligibleFor)\w*Role(Assignment)?$' })
        $AssignmentEdges = @($BreachableEdges | Where-Object { $_.kind -eq 'EO_HasAzureRoleAssignment' })
        $OwnerRoleEdges = @($BreachableEdges | Where-Object { $_.kind -eq 'EO_HasAzureRole' -and $_.target -like "$script:OwnerRoleId@*" })

        $AssignmentEdges.Count | Should -Be 3
        $OwnerRoleEdges.Count | Should -Be 1

        # Graph rendering keeps the breach flags on both representations of the privilege...
        @($AssignmentEdges | Where-Object { $_.properties.tier0breach }).Count | Should -Be 2
        $OwnerRoleEdges[0].properties.tier0breach | Should -BeTrue
        $OwnerRoleEdges[0].properties.tierbreach | Should -BeTrue

        # ...but only the role assignment edges represent the distinct paths.
        @($AssignmentEdges | Where-Object { $_.properties.distinctpath -ne $true }).Count | Should -Be 0
        @($BreachableEdges | Where-Object { $_.kind -like '*Role' } | Where-Object { $_.properties.distinctpath -ne $false }).Count | Should -Be 0
        @($BreachableEdges | Where-Object { $_.properties.distinctpath -and $_.properties.tier0breach }).Count | Should -Be 2
        @($BreachableEdges | Where-Object { $_.properties.distinctpath -and $_.properties.tierbreach }).Count | Should -Be 2
    }

    It 'reports de-duplicated tier breach counts' {
        $Output = New-EntraOpsAccessPathMapData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveObjectIdsOutsidePrivilegedEAM $false -WarningAction SilentlyContinue 6>&1 | ForEach-Object { "$_" }

        $Output | Should -Contain 'Tier breach paths: 2'
        $Output | Should -Contain 'Tier 0 breaches:   2'
        Test-Path -LiteralPath "$script:Root/App/data/access-path-map-data.js" | Should -BeTrue
    }
}
