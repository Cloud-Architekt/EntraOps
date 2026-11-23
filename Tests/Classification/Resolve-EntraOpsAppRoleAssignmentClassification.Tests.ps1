#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsAppRoleAssignmentClassification.ps1"

    $script:ResourceScopeId = '3a9835db-ac98-4e98-9c1a-640c09644aba'
    $script:ResourceAppId = '00000003-0000-0ff1-ce00-000000000000'

    function New-ClassificationDefinition {
        param([string]$Action, [string]$ResourceScope = 'All', [string]$TierName = 'ControlPlane', [string]$TierValue = '0', [string]$Service = 'SharePoint')
        [pscustomobject]@{
            EAMTierLevelName              = $TierName
            EAMTierLevelTagValue          = $TierValue
            Service                       = $Service
            RoleDefinitionActions         = $Action
            ExcludedRoleDefinitionActions = $null
            ResourceAppId                 = $script:ResourceAppId
            ResourceScope                 = $ResourceScope
        }
    }

    function New-PermissionAssignment {
        param([string]$Name, [string]$RoleType = 'Delegated', [AllowNull()][string]$RoleDefinitionId = $null, [string]$ObjectId = '11111111-1111-1111-1111-111111111111')
        [pscustomobject]@{
            ObjectId              = $ObjectId
            RoleDefinitionId      = $(if ([string]::IsNullOrEmpty($RoleDefinitionId)) { $null } else { $RoleDefinitionId })
            RoleDefinitionName    = $Name
            RoleType              = $RoleType
            RoleAssignmentScopeId = $script:ResourceScopeId
            ResourceAppId         = $script:ResourceAppId
        }
    }
}

Describe 'Resolve-EntraOpsAppRoleAssignmentClassification' {
    It 'does not mix classifications of delegated permissions without RoleDefinitionId on the same resource' {
        $Definitions = @(New-ClassificationDefinition -Action 'Sites.FullControl.All')
        $Assignments = @(
            New-PermissionAssignment -Name 'Sites.FullControl.All'
            New-PermissionAssignment -Name 'Files.Read.All'
        )

        $Result = @(Resolve-EntraOpsAppRoleAssignmentClassification -AppRoleAssignments $Assignments -ClassificationDefinitions $Definitions)

        $Result.Count | Should -Be 2
        @($Result[0].Classification.AdminTierLevelName) | Should -Be @('ControlPlane')
        @($Result[1].Classification.AdminTierLevelName) | Should -Be @('Unclassified')
    }

    It 'keeps application and delegated permissions sharing an ID separate' {
        $SharedId = '22222222-2222-2222-2222-222222222222'
        $Definitions = @(New-ClassificationDefinition -Action 'Sites.FullControl.All' -ResourceScope 'Application')
        $Assignments = @(
            New-PermissionAssignment -Name 'Sites.FullControl.All' -RoleType 'Application' -RoleDefinitionId $SharedId
            New-PermissionAssignment -Name 'Sites.FullControl.All' -RoleType 'Delegated' -RoleDefinitionId $SharedId
        )

        $Result = @(Resolve-EntraOpsAppRoleAssignmentClassification -AppRoleAssignments $Assignments -ClassificationDefinitions $Definitions)

        @($Result[0].Classification.AdminTierLevelName) | Should -Be @('ControlPlane')
        @($Result[1].Classification.AdminTierLevelName) | Should -Be @('Unclassified')
    }

    It 'applies the same classification to every assignment of one permission' {
        $Definitions = @(New-ClassificationDefinition -Action 'Sites.*' -TierName 'ManagementPlane' -TierValue '1')
        $Assignments = @(
            New-PermissionAssignment -Name 'Sites.ReadWrite.All' -ObjectId '11111111-1111-1111-1111-111111111111'
            New-PermissionAssignment -Name 'Sites.ReadWrite.All' -ObjectId '33333333-3333-3333-3333-333333333333'
        )

        $Result = @(Resolve-EntraOpsAppRoleAssignmentClassification -AppRoleAssignments $Assignments -ClassificationDefinitions $Definitions)

        $Result.ObjectId | Should -Be @('11111111-1111-1111-1111-111111111111', '33333333-3333-3333-3333-333333333333')
        foreach ($Assignment in $Result) {
            @($Assignment.Classification).Count | Should -Be 1
            $Assignment.Classification[0].AdminTierLevelName | Should -Be 'ManagementPlane'
            @($Assignment.Classification[0].MatchedActions) | Should -Be @('Sites.ReadWrite.All')
        }
    }

    It 'returns an empty result for no assignments' {
        @(Resolve-EntraOpsAppRoleAssignmentClassification -AppRoleAssignments @() -ClassificationDefinitions @()).Count | Should -Be 0
    }

    It 'applies the exclusions of a definition: <Case>' -ForEach @(
        @{ Case = 'no exclusions'; Excluded = $null; Expected = 'ControlPlane' }
        @{ Case = 'an empty list'; Excluded = @(); Expected = 'ControlPlane' }
        @{ Case = 'the permission'; Excluded = @('Sites.FullControl.All'); Expected = 'Unclassified' }
        @{ Case = 'the permission and another one'; Excluded = @('Files.Read.All', 'Sites.FullControl.All'); Expected = 'Unclassified' }
        @{ Case = 'a wildcard pattern'; Excluded = @('Sites.*'); Expected = 'Unclassified' }
        @{ Case = 'another permission only'; Excluded = @('Files.Read.All'); Expected = 'ControlPlane' }
    ) {
        $Definition = New-ClassificationDefinition -Action 'Sites.FullControl.All'
        $Definition.ExcludedRoleDefinitionActions = $Excluded

        $Result = Resolve-EntraOpsAppRoleAssignmentClassification -AppRoleAssignments @(New-PermissionAssignment -Name 'Sites.FullControl.All' -RoleType 'Application') -ClassificationDefinitions @($Definition)

        @($Result.Classification.AdminTierLevelName) | Should -Be @($Expected)
    }

    It 'classifies a delegated permission of an entry that an earlier version split as "Delegated"' {
        $Definitions = @(New-ClassificationDefinition -Action 'Sites.FullControl.All' -ResourceScope 'Delegated')

        $Result = Resolve-EntraOpsAppRoleAssignmentClassification -AppRoleAssignments @(New-PermissionAssignment -Name 'Sites.FullControl.All') -ClassificationDefinitions $Definitions

        @($Result.Classification.AdminTierLevelName) | Should -Be @('ControlPlane')
    }
}
