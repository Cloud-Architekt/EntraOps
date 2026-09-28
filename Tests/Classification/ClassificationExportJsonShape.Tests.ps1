#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:ExportRoot = "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess"

    function Invoke-EntraOpsMsGraphQuery {
        param($Method, $Uri, $OutputType, $Body, [switch]$SuppressBadRequestWarning, [switch]$ThrowOnFailure, [switch]$DisableCache)
        throw "Invoke-EntraOpsMsGraphQuery must be mocked"
    }

    function ConvertTo-EntraOpsODataStringLiteral {
        param($Value)
        return $Value
    }

    . "$script:ExportRoot/Export-EntraOpsClassificationDeviceManagementRoles.ps1"
    . "$script:ExportRoot/Export-EntraOpsClassificationIdentityGovernanceRoles.ps1"
    . "$script:ExportRoot/Export-EntraOpsClassificationDirectoryRoles.ps1"
    . "$script:ExportRoot/Export-EntraOpsClassificationDirectoryRolesFromMsftDocs.ps1"
    . "$script:ExportRoot/Export-EntraOpsClassificationAppRoles.ps1"
    . "$script:ExportRoot/Export-EntraOpsClassificationScopes.ps1"

    function New-ExportFixtureRoot {
        param(
            [Parameter(Mandatory = $true)][string]$ClassificationFileName,
            [Parameter(Mandatory = $true)]$Classification
        )

        $Root = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -Path (Join-Path $Root 'EntraOps_Classification') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $Root 'Classification') -ItemType Directory -Force | Out-Null
        $Classification | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $Root "EntraOps_Classification/$ClassificationFileName") -Encoding UTF8
        return $Root
    }

    function New-TierFixture {
        param(
            [Parameter(Mandatory = $true)][string]$Service,
            [Parameter(Mandatory = $true)][string[]]$Actions,
            [Parameter(Mandatory = $true)][string]$Scope
        )

        return @(
            [ordered]@{
                EAMTierLevelName    = 'ControlPlane'
                EAMTierLevelTagValue = '0'
                TierLevelDefinition = @(
                    [ordered]@{
                        Category                        = 'Test'
                        Service                         = $Service
                        RoleAssignmentScopeName         = @($Scope)
                        ExcludedRoleAssignmentScopeName = @()
                        RoleDefinitionActions           = @($Actions)
                    }
                )
            }
        )
    }

    # Each exporter resolves its classification input and (some of) its output path relative to the
    # current directory, so every export has to run inside its own fixture root.
    function Invoke-InFixtureRoot {
        param(
            [Parameter(Mandatory = $true)][string]$Root,
            [Parameter(Mandatory = $true)][scriptblock]$Body
        )

        Push-Location $Root
        try { & $Body } finally { Pop-Location }
    }

    function Get-ExportedRoles {
        param([Parameter(Mandatory = $true)][string]$Path)
        return @(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
    }
}

Describe 'Classification export JSON shapes' {
    It 'keeps RolePermissions an array when a Device Management role has a single action' {
        $Root = New-ExportFixtureRoot -ClassificationFileName 'Classification_DeviceManagement.json' -Classification (New-TierFixture -Service 'Privileged IAM' -Actions 'Microsoft.Intune/Roles/Assign' -Scope '/')
        $ExportFile = Join-Path $Root 'Classification/Classification_DeviceManagementRoles.json'

        Mock Invoke-EntraOpsMsGraphQuery {
            return @([pscustomobject]@{
                    displayName             = 'Single action role'
                    templateId              = '11111111-1111-1111-1111-111111111111'
                    isBuiltin               = $true
                    isPrivileged            = $true
                    rolePermissions         = @([pscustomobject]@{ allowedResourceActions = @('Microsoft.Intune/Roles/Assign') })
                    inheritsPermissionsFrom = @()
                    assignmentMode          = 'Direct'
                })
        }

        Invoke-InFixtureRoot -Root $Root -Body { Export-EntraOpsClassificationDeviceManagementRoles -Exportfile $ExportFile | Out-Null }

        $Role = (Get-ExportedRoles -Path $ExportFile)[0]
        # Piping the value into Should would unroll it, so assert the type directly.
        $Role.RolePermissions.GetType().IsArray | Should -BeTrue
        @($Role.RolePermissions).Count | Should -Be 1
    }

    It 'keeps RolePermissions an array when an Identity Governance role has a single action' {
        $Root = New-ExportFixtureRoot -ClassificationFileName 'Classification_IdentityGovernance.json' -Classification (New-TierFixture -Service 'Catalog Management' -Actions 'microsoft.entitlementManagement/AccessPackageCatalog/Create' -Scope '/AccessPackageCatalog/*')
        $ExportFile = Join-Path $Root 'Classification/Classification_IdentityGovernance.json'

        Mock Invoke-EntraOpsMsGraphQuery {
            return @([pscustomobject]@{
                    displayName             = 'Single action role'
                    templateId              = '22222222-2222-2222-2222-222222222222'
                    isBuiltin               = $true
                    isPrivileged            = $true
                    description             = 'Test role'
                    rolePermissions         = @([pscustomobject]@{ allowedResourceActions = @('microsoft.entitlementManagement/AccessPackageCatalog/Create') })
                    inheritsPermissionsFrom = @()
                    assignmentMode          = 'Direct'
                })
        }

        Invoke-InFixtureRoot -Root $Root -Body { Export-EntraOpsClassificationIdentityGovernanceRoles -Exportfile $ExportFile | Out-Null }

        $Role = (Get-ExportedRoles -Path $ExportFile)[0]
        $Role.RolePermissions.GetType().IsArray | Should -BeTrue
        @($Role.RolePermissions).Count | Should -Be 1
    }

    It 'preserves the scalar Categories value exposed by Microsoft Graph' {
        $Root = New-ExportFixtureRoot -ClassificationFileName 'Classification_AadResources.json' -Classification (New-TierFixture -Service 'Privileged IAM' -Actions 'microsoft.directory/roleAssignments/allProperties/allTasks' -Scope '/')

        Mock Invoke-EntraOpsMsGraphQuery {
            return @(
                [pscustomobject]@{
                    displayName             = 'Single category role'
                    templateId              = '33333333-3333-3333-3333-333333333333'
                    isBuiltin               = $true
                    isPrivileged            = $true
                    rolePermissions         = @([pscustomobject]@{ allowedResourceActions = @('microsoft.directory/roleAssignments/allProperties/allTasks'); condition = $null })
                    categories              = 'Identity'
                    richDescription         = 'Test role'
                    inheritsPermissionsFrom = @()
                    assignmentMode          = 'Direct'
                },
                [pscustomobject]@{
                    displayName             = 'Multiple category role'
                    templateId              = '44444444-4444-4444-4444-444444444444'
                    isBuiltin               = $true
                    isPrivileged            = $true
                    rolePermissions         = @([pscustomobject]@{ allowedResourceActions = @('microsoft.directory/roleAssignments/allProperties/allTasks'); condition = $null })
                    categories              = 'Collaboration,Identity'
                    richDescription         = 'Test role'
                    inheritsPermissionsFrom = @()
                    assignmentMode          = 'Direct'
                },
                [pscustomobject]@{
                    displayName             = 'No category role'
                    templateId              = '55555555-5555-5555-5555-555555555555'
                    isBuiltin               = $true
                    isPrivileged            = $false
                    rolePermissions         = @([pscustomobject]@{ allowedResourceActions = @('microsoft.directory/roleAssignments/allProperties/allTasks'); condition = $null })
                    categories              = $null
                    richDescription         = 'Test role'
                    inheritsPermissionsFrom = @()
                    assignmentMode          = 'Direct'
                })
        }

        Invoke-InFixtureRoot -Root $Root -Body { Export-EntraOpsClassificationDirectoryRoles | Out-Null }

        $Roles = Get-ExportedRoles -Path (Join-Path $Root 'Classification/Classification_EntraIdDirectoryRoles.json')
        $WithCategory = $Roles | Where-Object { $_.RoleName -eq 'Single category role' }
        $WithMultipleCategories = $Roles | Where-Object { $_.RoleName -eq 'Multiple category role' }
        $WithoutCategory = $Roles | Where-Object { $_.RoleName -eq 'No category role' }

        $WithCategory.Categories | Should -BeExactly 'Identity'
        $WithMultipleCategories.Categories | Should -BeExactly 'Collaboration,Identity'
        $WithoutCategory.Categories | Should -BeNullOrEmpty
    }

    It 'keeps AuthorizedApiCalls an array and does not carry Graph calls over to other resources' {
        $Classification = @(
            [ordered]@{
                EAMTierLevelName    = 'ControlPlane'
                EAMTierLevelTagValue = '0'
                TierLevelDefinition = @(
                    [ordered]@{
                        Service               = 'Directory Write'
                        ResourceScope         = 'Application'
                        ResourceAppId         = '00000003-0000-0000-c000-000000000000'
                        RoleDefinitionActions = @('Directory.ReadWrite.All')
                    },
                    [ordered]@{
                        Service               = 'Directory Read'
                        ResourceScope         = 'Application'
                        ResourceAppId         = '00000002-0000-0000-c000-000000000000'
                        RoleDefinitionActions = @('Directory.Read.All')
                    }
                )
            }
        )
        $Root = New-ExportFixtureRoot -ClassificationFileName 'Classification_ApiPermissions.json' -Classification $Classification

        # Two identical rows so the deduplicated result is a single API call.
        Mock Invoke-WebRequest {
            return @('PermissionName,API', 'Directory.ReadWrite.All,GET /users', 'Directory.ReadWrite.All,GET /users')
        }

        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like "*00000003-0000-0000-c000-000000000000*") {
                return @([pscustomobject]@{
                        appId                     = '00000003-0000-0000-c000-000000000000'
                        appRoles                  = @([pscustomobject]@{ id = 'aaaaaaaa-0000-0000-0000-000000000001'; value = 'Directory.ReadWrite.All' })
                        publishedPermissionScopes = @()
                    })
            }
            if ($Uri -like "*00000002-0000-0000-c000-000000000000*") {
                return @([pscustomobject]@{
                        appId                     = '00000002-0000-0000-c000-000000000000'
                        appRoles                  = @([pscustomobject]@{ id = 'aaaaaaaa-0000-0000-0000-000000000002'; value = 'Directory.Read.All' })
                        publishedPermissionScopes = @()
                    })
            }
            return @()
        }

        Invoke-InFixtureRoot -Root $Root -Body { Export-EntraOpsClassificationAppRoles -IncludeAuthorizedApiCalls $true | Out-Null }

        $AppRoles = Get-ExportedRoles -Path (Join-Path $Root 'Classification/Classification_AppRoles.json')
        $GraphRole = $AppRoles | Where-Object { $_.AppRoleDisplayName -eq 'Directory.ReadWrite.All' }
        $OtherRole = $AppRoles | Where-Object { $_.AppRoleDisplayName -eq 'Directory.Read.All' }

        $GraphRole.AuthorizedApiCalls.GetType().IsArray | Should -BeTrue
        @($GraphRole.AuthorizedApiCalls).Count | Should -Be 1
        @($OtherRole.AuthorizedApiCalls).Count | Should -Be 0
    }

    It 'keeps delegated AuthorizedApiCalls an array and does not carry Graph calls over to other resources' {
        $Classification = @(
            [ordered]@{
                EAMTierLevelName    = 'ControlPlane'
                EAMTierLevelTagValue = '0'
                TierLevelDefinition = @(
                    [ordered]@{
                        Service               = 'Directory Write'
                        ResourceScope         = 'Delegation'
                        ResourceAppId         = '00000003-0000-0000-c000-000000000000'
                        RoleDefinitionActions = @('Directory.ReadWrite.All')
                    },
                    [ordered]@{
                        Service               = 'Directory Read'
                        ResourceScope         = 'Delegation'
                        ResourceAppId         = '00000002-0000-0000-c000-000000000000'
                        RoleDefinitionActions = @('Directory.Read.All')
                    }
                )
            }
        )
        $Root = New-ExportFixtureRoot -ClassificationFileName 'Classification_ApiPermissions.json' -Classification $Classification

        Mock Invoke-WebRequest {
            return @('PermissionName,API', 'Directory.ReadWrite.All,GET /users', 'Directory.ReadWrite.All,GET /users')
        }

        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like "*00000003-0000-0000-c000-000000000000*") {
                return @([pscustomobject]@{
                        appId                     = '00000003-0000-0000-c000-000000000000'
                        appRoles                  = @()
                        publishedPermissionScopes = @([pscustomobject]@{ id = 'bbbbbbbb-0000-0000-0000-000000000001'; value = 'Directory.ReadWrite.All' })
                    })
            }
            if ($Uri -like "*00000002-0000-0000-c000-000000000000*") {
                return @([pscustomobject]@{
                        appId                     = '00000002-0000-0000-c000-000000000000'
                        appRoles                  = @()
                        publishedPermissionScopes = @([pscustomobject]@{ id = 'bbbbbbbb-0000-0000-0000-000000000002'; value = 'Directory.Read.All' })
                    })
            }
            return @()
        }

        Invoke-InFixtureRoot -Root $Root -Body { Export-EntraOpsClassificationScopes -IncludeAuthorizedApiCalls $true | Out-Null }

        $Scopes = Get-ExportedRoles -Path (Join-Path $Root 'Classification/Classification_Scopes.json')
        $GraphScope = $Scopes | Where-Object { $_.ScopeDisplayName -eq 'Directory.ReadWrite.All' }
        $OtherScope = $Scopes | Where-Object { $_.ScopeDisplayName -eq 'Directory.Read.All' }

        $GraphScope.AuthorizedApiCalls.GetType().IsArray | Should -BeTrue
        @($GraphScope.AuthorizedApiCalls).Count | Should -Be 1
        @($OtherScope.AuthorizedApiCalls).Count | Should -Be 0
    }

    It 'emits Microsoft Docs directory role Categories in the Graph-compatible scalar form' {
        $FirstAction = 'microsoft.directory/roleAssignments/allProperties/allTasks'
        $SecondAction = 'microsoft.directory/users/allProperties/read'
        # PowerShell unwraps a single pipeline result unless the call is explicitly array-wrapped.
        $Classification = @(New-TierFixture -Service 'Privileged IAM' -Actions $FirstAction -Scope '/')
        $Classification[0].TierLevelDefinition += [ordered]@{
            Category                        = 'Test'
            Service                         = 'User Management'
            RoleAssignmentScopeName         = @('/')
            ExcludedRoleAssignmentScopeName = @()
            RoleDefinitionActions           = @($SecondAction)
        }
        $Root = New-ExportFixtureRoot -ClassificationFileName 'Classification_AadResources.json' -Classification $Classification
        $ExportFile = Join-Path $Root 'Classification/Classification_EntraIdDirectoryRolesFromMsftDocs.json'
        $ReferenceUri = 'https://example.test/permissions-reference.md'
        $ReferenceMarkdown = @'
| [Single category role](#single-category-role) | Privileged label | 55555555-5555-5555-5555-555555555555 |
[!INCLUDE [single-category-role](includes/single-category-role.md)]
'@
        $IncludeMarkdown = @"
---
title: Single category role
---
A test role with one classified service category.
<!-- autogenerated content starts here -->
| Actions | Description |
| --- | --- |
| $FirstAction | First test action |
| $SecondAction | Second test action |
"@

        Mock Invoke-WebRequest {
            if ($Uri -eq $ReferenceUri) {
                return [pscustomobject]@{ Content = $ReferenceMarkdown }
            }
            if ($Uri -eq 'https://example.test/includes/single-category-role.md') {
                return [pscustomobject]@{ Content = $IncludeMarkdown }
            }
            throw "Unexpected URI: $Uri"
        }

        Invoke-InFixtureRoot -Root $Root -Body {
            Export-EntraOpsClassificationDirectoryRolesFromMsftDocs `
                -PermissionsReferenceUri $ReferenceUri `
                -ClassificationFilePath './EntraOps_Classification/Classification_AadResources.json' `
                -OutputFilePath $ExportFile | Out-Null
        }

        $Role = (Get-ExportedRoles -Path $ExportFile)[0]
        $Role.Categories | Should -BeExactly 'Privileged IAM,User Management'
    }
}

