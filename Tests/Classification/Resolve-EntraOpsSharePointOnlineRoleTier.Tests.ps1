#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsSharePointOnlineRoleTier.ps1"
}

Describe "Resolve-EntraOpsSharePointOnlineRoleTier" {
    It "maps English role name <RoleDisplayName> to <ExpectedTier>" -TestCases @(
        @{ RoleDisplayName = "Give @ CloudLab Visitors"; ExpectedTier = "UserAccess" }
        @{ RoleDisplayName = "Site Members"; ExpectedTier = "UserAccess" }
        @{ RoleDisplayName = "Contributors"; ExpectedTier = "UserAccess" }
        @{ RoleDisplayName = "Site Owners"; ExpectedTier = "ManagementPlane" }
        @{ RoleDisplayName = "Full Control"; ExpectedTier = "ManagementPlane" }
        @{ RoleDisplayName = "Site Collection Admin"; ExpectedTier = "ManagementPlane" }
    ) {
        $Result = Resolve-EntraOpsSharePointOnlineRoleTier -RoleDisplayName $RoleDisplayName -RoleOriginId ""
        $Result.AdminTierLevelName | Should -Be $ExpectedTier
        $Result.IsFallback | Should -BeFalse
        $Result.IsCatalogLevel | Should -BeFalse
    }

    It "resolves localized role name <RoleDisplayName> via default site group originId <RoleOriginId>" -TestCases @(
        @{ RoleDisplayName = "Besitzer von Give"; RoleOriginId = "3"; ExpectedTier = "ManagementPlane" }
        @{ RoleDisplayName = "Besucher von Give"; RoleOriginId = "4"; ExpectedTier = "UserAccess" }
        @{ RoleDisplayName = "Mitglieder von Give"; RoleOriginId = "5"; ExpectedTier = "UserAccess" }
    ) {
        $Result = Resolve-EntraOpsSharePointOnlineRoleTier -RoleDisplayName $RoleDisplayName -RoleOriginId $RoleOriginId
        $Result.AdminTierLevelName | Should -Be $ExpectedTier
        $Result.IsFallback | Should -BeFalse
    }

    It "prefers the unambiguous English name over a conflicting originId" {
        # A custom role named like an owner role must not be downgraded by a reused group ID.
        $Result = Resolve-EntraOpsSharePointOnlineRoleTier -RoleDisplayName "Site Owners" -RoleOriginId "4"
        $Result.AdminTierLevelName | Should -Be "ManagementPlane"
        $Result.IsFallback | Should -BeFalse
    }

    It "falls back to ManagementPlane for an unknown role and flags the fallback" {
        $Result = Resolve-EntraOpsSharePointOnlineRoleTier -RoleDisplayName "Rolle personnalisée" -RoleOriginId "17"
        $Result.AdminTierLevelName | Should -Be "ManagementPlane"
        $Result.IsFallback | Should -BeTrue
        $Result.IsCatalogLevel | Should -BeFalse
    }

    It "treats an empty role as a catalog-level entry without the unknown-role fallback" {
        $Result = Resolve-EntraOpsSharePointOnlineRoleTier -RoleDisplayName "" -RoleOriginId ""
        $Result.AdminTierLevelName | Should -Be "ManagementPlane"
        $Result.IsFallback | Should -BeFalse
        $Result.IsCatalogLevel | Should -BeTrue
    }
}

