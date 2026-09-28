#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsClassifiableRoleActions.ps1"
}

Describe "Get-EntraOpsClassifiableRoleActions" {
    It "excludes the owner-scoped Application Developer actions" {
        $RolePermissions = @(
            [pscustomobject]@{
                condition              = '$SubjectIsOwner'
                allowedResourceActions = @(
                    'microsoft.directory/applications/appRoles/update'
                    'microsoft.directory/applications/credentials/update'
                    'microsoft.directory/applications/delete'
                )
            }
            [pscustomobject]@{
                condition              = $null
                allowedResourceActions = @(
                    'microsoft.directory/applications/createAsOwner'
                    'microsoft.directory/oAuth2PermissionGrants/createAsOwner'
                    'microsoft.directory/servicePrincipals/createAsOwner'
                )
            }
        )

        $Actions = @(Get-EntraOpsClassifiableRoleActions -RolePermissions $RolePermissions)

        $Actions | Should -Be @(
            'microsoft.directory/applications/createAsOwner'
            'microsoft.directory/oAuth2PermissionGrants/createAsOwner'
            'microsoft.directory/servicePrincipals/createAsOwner'
        )
    }

    It "matches the owner condition case-insensitively and ignores surrounding whitespace" {
        $RolePermissions = [pscustomobject]@{
            condition              = '  $subjectisowner  '
            allowedResourceActions = @('owner-scoped/action')
        }

        @(Get-EntraOpsClassifiableRoleActions -RolePermissions $RolePermissions) | Should -BeNullOrEmpty
    }

    It "retains actions with no condition or a different condition" {
        $RolePermissions = @(
            [pscustomobject]@{ condition = $null; allowedResourceActions = @('unconditional/action') }
            [pscustomobject]@{ condition = '$ResourceIsSelf'; allowedResourceActions = @('self/action') }
        )

        @(Get-EntraOpsClassifiableRoleActions -RolePermissions $RolePermissions) | Should -Be @(
            'unconditional/action'
            'self/action'
        )
    }

    It "handles null, empty and malformed permission entries safely" {
        @(Get-EntraOpsClassifiableRoleActions -RolePermissions $null) | Should -BeNullOrEmpty
        @(Get-EntraOpsClassifiableRoleActions -RolePermissions @()) | Should -BeNullOrEmpty
        @(Get-EntraOpsClassifiableRoleActions -RolePermissions @($null, [pscustomobject]@{})) | Should -BeNullOrEmpty
    }
}

