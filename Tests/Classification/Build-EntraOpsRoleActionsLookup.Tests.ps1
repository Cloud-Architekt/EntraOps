#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Build-EntraOpsRoleActionsLookup.ps1"
}

Describe "Build-EntraOpsRoleActionsLookup" {
    BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        # Built-in role: id equals templateId (Graph behavior for built-in unified role definitions)
        $BuiltInRole = [pscustomobject]@{
            Id              = "62e90394-69f5-4237-9190-012177145e10"
            TemplateId      = "62e90394-69f5-4237-9190-012177145e10"
            DisplayName     = "Global Administrator"
            RolePermissions = @(@{ allowedResourceActions = @("microsoft.directory/allEntities/allTasks") })
        }
        # Ordinary custom role: templateId equals id
        $CustomRole = [pscustomobject]@{
            Id              = "11111111-1111-1111-1111-111111111111"
            TemplateId      = "11111111-1111-1111-1111-111111111111"
            DisplayName     = "Custom Helpdesk Role"
            RolePermissions = @(@{ allowedResourceActions = @("microsoft.directory/users/password/update") })
        }
        # Custom role created with an explicit templateId that differs from id
        $DistinctTemplateRole = [pscustomobject]@{
            Id              = "22222222-2222-2222-2222-222222222222"
            TemplateId      = "33333333-3333-3333-3333-333333333333"
            DisplayName     = "Cross-Tenant Custom Role"
            RolePermissions = @(@{ allowedResourceActions = @("microsoft.directory/groups/members/update") })
        }
        # Cached/sample data written before templateId was selected from Graph
        $LegacyCachedRole = [pscustomobject]@{
            Id              = "44444444-4444-4444-4444-444444444444"
            DisplayName     = "Legacy Cached Role"
            RolePermissions = @(@{ allowedResourceActions = @("microsoft.directory/devices/standard/read") })
        }

        $Lookup = Build-EntraOpsRoleActionsLookup -RoleDefinitions @(
            $BuiltInRole, $CustomRole, $DistinctTemplateRole, $LegacyCachedRole
        )
    }

    It "resolves a built-in role by its id (== templateId)" {
        $Lookup["62e90394-69f5-4237-9190-012177145e10"] | Should -Be $BuiltInRole
    }

    It "resolves an ordinary custom role by its id" {
        $Lookup["11111111-1111-1111-1111-111111111111"] | Should -Be $CustomRole
    }

    It "resolves a custom role by templateId when it differs from id (assignment normalization)" {
        $Lookup["33333333-3333-3333-3333-333333333333"] | Should -Be $DistinctTemplateRole
    }

    It "still resolves a distinct-template custom role by its instance id" {
        $Lookup["22222222-2222-2222-2222-222222222222"] | Should -Be $DistinctTemplateRole
    }

    It "resolves by displayName even when id is present (fallback must not be shadowed by id indexing)" {
        $Lookup["Global Administrator"] | Should -Be $BuiltInRole
        $Lookup["Legacy Cached Role"] | Should -Be $LegacyCachedRole
    }

    It "handles roles without templateId (legacy cache) without error" {
        $Lookup["44444444-4444-4444-4444-444444444444"] | Should -Be $LegacyCachedRole
    }

    It "does not resolve an ambiguous displayName fallback" {
        $FirstRole = [pscustomobject]@{
            Id          = "55555555-5555-5555-5555-555555555555"
            DisplayName = "Duplicate Role"
        }
        $SecondRole = [pscustomobject]@{
            Id          = "66666666-6666-6666-6666-666666666666"
            DisplayName = "duplicate role"
        }

        $DuplicateLookup = Build-EntraOpsRoleActionsLookup -RoleDefinitions @($FirstRole, $SecondRole)

        $DuplicateLookup.ContainsKey("Duplicate Role") | Should -BeFalse
        $DuplicateLookup[$FirstRole.Id] | Should -Be $FirstRole
        $DuplicateLookup[$SecondRole.Id] | Should -Be $SecondRole
    }

    It "does not let a displayName overwrite an identifier key" {
        $IdentifierOwner = [pscustomobject]@{
            Id          = "77777777-7777-7777-7777-777777777777"
            DisplayName = "Identifier Owner"
        }
        $NameOwner = [pscustomobject]@{
            Id          = "88888888-8888-8888-8888-888888888888"
            DisplayName = "77777777-7777-7777-7777-777777777777"
        }

        $CollisionLookup = Build-EntraOpsRoleActionsLookup -RoleDefinitions @($IdentifierOwner, $NameOwner)

        $CollisionLookup[$IdentifierOwner.Id] | Should -Be $IdentifierOwner
        $CollisionLookup[$NameOwner.Id] | Should -Be $NameOwner
    }

    It "returns an empty lookup for null or empty input" {
        (Build-EntraOpsRoleActionsLookup -RoleDefinitions $null).Count | Should -Be 0
        (Build-EntraOpsRoleActionsLookup -RoleDefinitions @()).Count | Should -Be 0
    }
}

