#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsPathWithinRoot.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Save-EntraOpsPrivilegedEAMWatchLists.ps1"

    function New-TestRoleAssignment {
        param(
            [string]$RoleAssignmentId,
            [string]$ScopeId = '/',
            [string]$RoleDefinitionId,
            [string]$RoleDefinitionName = 'Role',
            [string]$TransitiveByObjectId,
            [object[]]$Classification = @([pscustomobject]@{ AdminTierLevel = '0'; AdminTierLevelName = 'ControlPlane'; Service = 'Service' })
        )
        [pscustomobject]@{
            RoleAssignmentId      = $RoleAssignmentId
            RoleAssignmentScopeId = $ScopeId
            RoleDefinitionId      = $RoleDefinitionId
            RoleDefinitionName    = $RoleDefinitionName
            TransitiveByObjectId  = $TransitiveByObjectId
            Classification        = $Classification
        }
    }

    function Save-TestRbacSystem {
        param([string]$Root, [string]$RbacSystem, [object[]]$Objects)
        $Folder = Join-Path $Root $RbacSystem
        New-Item -ItemType Directory -Path $Folder -Force | Out-Null
        ConvertTo-Json -InputObject @($Objects) -Depth 10 | Set-Content -LiteralPath (Join-Path $Folder "$RbacSystem.json")
    }
}

Describe 'Save-EntraOpsPrivilegedEAMWatchLists watchlist keys' {
    BeforeAll {
        $Global:EntraOpsBaseFolder = $TestDrive
        $script:ImportPath = Join-Path $TestDrive 'PrivilegedEAM'
        $script:ExportPath = Join-Path $TestDrive 'Export'
        New-Item -ItemType Directory -Path $script:ExportPath -Force | Out-Null

        # Group-transitive assignment: the same RoleAssignmentId reaches two members.
        $AzureObjects = foreach ($MemberId in '11111111-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000002') {
            [pscustomobject]@{
                ObjectId        = $MemberId
                ObjectType      = 'user'
                RoleAssignments = @(New-TestRoleAssignment -RoleAssignmentId 'shared-assignment' -ScopeId '/subscriptions/1' -RoleDefinitionId 'owner' -TransitiveByObjectId 'group-1')
            }
        }
        # ResourceApps delegated grant: one RoleAssignmentId across scopes, one permission unresolved (no RoleDefinitionId).
        $ResourceAppsObjects = @([pscustomobject]@{
                ObjectId        = '22222222-0000-0000-0000-000000000001'
                ObjectType      = 'serviceprincipal'
                RoleAssignments = @(
                    (New-TestRoleAssignment -RoleAssignmentId 'grant-1' -ScopeId 'resource-a' -RoleDefinitionId 'perm-1'),
                    (New-TestRoleAssignment -RoleAssignmentId 'grant-1' -ScopeId 'resource-b' -RoleDefinitionId 'perm-1'),
                    (New-TestRoleAssignment -RoleAssignmentId 'grant-1' -ScopeId 'resource-b' -RoleDefinitionName 'Unresolved.One'),
                    (New-TestRoleAssignment -RoleAssignmentId 'grant-1' -ScopeId 'resource-b' -RoleDefinitionName 'Unresolved.Two')
                )
            })
        # The same RoleAssignmentId in another RBAC system must not collide with the Azure one.
        $EntraIdObjects = @([pscustomobject]@{
                ObjectId        = '33333333-0000-0000-0000-000000000001'
                ObjectType      = 'user'
                RoleAssignments = @(New-TestRoleAssignment -RoleAssignmentId 'shared-assignment' -ScopeId '/subscriptions/1' -RoleDefinitionId 'owner')
            })

        Save-TestRbacSystem -Root $script:ImportPath -RbacSystem 'Azure' -Objects $AzureObjects
        Save-TestRbacSystem -Root $script:ImportPath -RbacSystem 'ResourceApps' -Objects $ResourceAppsObjects
        Save-TestRbacSystem -Root $script:ImportPath -RbacSystem 'EntraID' -Objects $EntraIdObjects

        Save-EntraOpsPrivilegedEAMWatchLists -ImportPath $script:ImportPath -ExportFolder $script:ExportPath `
            -RbacSystems 'Azure', 'EntraID', 'ResourceApps' -SkipUploadSaveLocal $true | Out-Null

        $script:RoleAssignmentRows = @(Import-Csv (Join-Path $script:ExportPath 'EntraOps_RoleAssignments.csv'))
        $script:ClassificationRows = @(Import-Csv (Join-Path $script:ExportPath 'EntraOps_RoleClassifications.csv'))
    }

    AfterAll {
        Remove-Variable -Name EntraOpsBaseFolder -Scope Global -ErrorAction SilentlyContinue
    }

    It 'writes one role assignment row with a unique key per principal and assignment' {
        $script:RoleAssignmentRows.Count | Should -Be 7
        @($script:RoleAssignmentRows.UniqueId | Sort-Object -Unique).Count | Should -Be 7
        $script:RoleAssignmentRows.UniqueId | Should -Not -Match '_$'
    }

    It 'keeps a classification row for every assignment the parser joins' {
        $ClassificationKeys = @($script:ClassificationRows | ForEach-Object { "$($_.RoleAssignmentId)|$($_.RoleAssignmentScopeId)|$($_.RoleSystem)|$($_.RoleDefinitionId)" })
        foreach ($Row in $script:RoleAssignmentRows) {
            "$($Row.RoleAssignmentId)|$($Row.RoleAssignmentScopeId)|$($Row.RoleSystem)|$($Row.RoleDefinitionId)" | Should -BeIn $ClassificationKeys
        }
    }

    It 'deduplicates classification rows shared by several principals of the same assignment' {
        @($script:ClassificationRows | Where-Object { $_.RoleSystem -eq 'Azure' }).Count | Should -Be 1
        @($script:ClassificationRows.UniqueId | Sort-Object -Unique).Count | Should -Be $script:ClassificationRows.Count
    }
}
