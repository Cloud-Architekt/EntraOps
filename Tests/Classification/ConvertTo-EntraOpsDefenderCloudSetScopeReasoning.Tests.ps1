#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . (Join-Path $script:TestRepositoryRoot 'EntraOps/Private/ConvertTo-EntraOpsDefenderCloudSetScopeReasoning.ps1')

    function New-CloudSetAssignment {
        param([string]$Id = '/CloudSet/aaa', [string]$Name = 'CloudSet A', [object[]]$SubscriptionScopes = @(), [string]$Status = 'Resolved')
        [pscustomobject]@{ CloudSetId = $Id; CloudSetName = $Name; SubscriptionScopes = $SubscriptionScopes; ResolutionStatus = $Status }
    }

    $script:Tier0Sub = '/subscriptions/00000000-0000-0000-0000-000000000000'
    $script:Tier1Sub = '/subscriptions/11111111-1111-1111-1111-111111111111'
    $script:OtherSub = '/subscriptions/22222222-2222-2222-2222-222222222222'
    $script:Common = @{ Tier0IncludedResourceScope = @($script:Tier0Sub); Tier1IncludedResourceScope = @($script:Tier1Sub); ResourceScopeDetails = @() }
}

Describe 'ConvertTo-EntraOpsDefenderCloudSetScopeReasoning' {
    It 'reports a resolved CloudSet without subscriptions as Unresolved and UnknownBoundedScope' {
        # Lab shape: ScopeResolutionStatus Resolved, CloudSetSubscriptionScopes null.
        $Result = @(ConvertTo-EntraOpsDefenderCloudSetScopeReasoning -CloudSetAssignments @(New-CloudSetAssignment -SubscriptionScopes $null) @script:Common)

        $Result.Count | Should -Be 1
        $Result[0].ResolutionStatus | Should -BeExactly 'Unresolved'
        $Result[0].ResultingScope | Should -BeExactly 'UnknownBoundedScope'
        $Result[0].Reason | Should -Match 'resolved by Defender, but no Azure subscription'
        @($Result | Where-Object { $_.ResolutionStatus -eq 'Unresolved' }).Count | Should -Be 1
    }

    It 'reports an unresolved app scope as Unresolved with its own reason' {
        $Result = @(ConvertTo-EntraOpsDefenderCloudSetScopeReasoning -CloudSetAssignments @(New-CloudSetAssignment -Status 'Unresolved') @script:Common)

        $Result[0].ResolutionStatus | Should -BeExactly 'Unresolved'
        $Result[0].ResultingScope | Should -BeExactly 'UnknownBoundedScope'
        $Result[0].Reason | Should -Match 'could not be resolved by Defender'
    }

    It 'never emits an empty ResolutionStatus' {
        $Assignments = @(
            New-CloudSetAssignment -Id '/CloudSet/a' -Status 'Resolved'
            New-CloudSetAssignment -Id '/CloudSet/b' -Status ''
            New-CloudSetAssignment -Id '/CloudSet/c' -SubscriptionScopes @($script:OtherSub)
        )
        $Result = @(ConvertTo-EntraOpsDefenderCloudSetScopeReasoning -CloudSetAssignments $Assignments @script:Common)

        $Result.ResolutionStatus | Should -Be @('Unresolved', 'Unresolved', 'Resolved')
        $Result.ResultingScope | Should -Be @('UnknownBoundedScope', 'UnknownBoundedScope', 'Unclassified')
    }

    It 'maps member subscriptions to the most privileged tier' {
        $Assignments = @(
            New-CloudSetAssignment -Id '/CloudSet/t0' -SubscriptionScopes @($script:Tier1Sub, $script:Tier0Sub)
            New-CloudSetAssignment -Id '/CloudSet/t1' -SubscriptionScopes @($script:Tier1Sub, $script:OtherSub)
        )
        $Result = @(ConvertTo-EntraOpsDefenderCloudSetScopeReasoning -CloudSetAssignments $Assignments @script:Common)

        $Result[0].ResultingScope | Should -BeExactly 'Tier0'
        $Result[0].Tier0SubscriptionScopes | Should -Be @($script:Tier0Sub)
        $Result[1].ResultingScope | Should -BeExactly 'Tier1'
        $Result[1].Tier1SubscriptionScopes | Should -Be @($script:Tier1Sub)
        $Result[1].AzureScopeEvidence.ResultingScope | Should -Be @('Tier1', 'Unclassified')
    }

    It 'merges assignments of the same CloudSet and emits CloudSetName as a string' {
        $Assignments = @(
            New-CloudSetAssignment -Name 'Zeta' -SubscriptionScopes @($script:OtherSub)
            New-CloudSetAssignment -Name 'Alpha' -SubscriptionScopes @($script:OtherSub, $script:Tier1Sub)
        )
        $Result = @(ConvertTo-EntraOpsDefenderCloudSetScopeReasoning -CloudSetAssignments $Assignments @script:Common)

        $Result.Count | Should -Be 1
        $Result[0].CloudSetName | Should -BeOfType [string]
        $Result[0].CloudSetName | Should -BeExactly 'Alpha'
        $Result[0].SubscriptionScopes | Should -Be @($script:Tier1Sub, $script:OtherSub)
    }

    It 'returns an empty array without CloudSet assignments' {
        @(ConvertTo-EntraOpsDefenderCloudSetScopeReasoning -CloudSetAssignments @() @script:Common).Count | Should -Be 0
    }

    It 'serializes ResolutionStatus and the unresolved list for the lab CloudSet' {
        $Reasoning = @(ConvertTo-EntraOpsDefenderCloudSetScopeReasoning -CloudSetAssignments @(New-CloudSetAssignment -Id '/CloudSet/8de1e7c6d6a142498f97bf65c1d501d2' -Name 'Control Plane Subscriptions') @script:Common)
        $Json = [pscustomobject]@{
            CloudSetDetails     = $Reasoning
            UnresolvedCloudSets = @($Reasoning | Where-Object { $_.ResolutionStatus -eq 'Unresolved' })
        } | ConvertTo-Json -Depth 8 | ConvertFrom-Json

        $Json.CloudSetDetails[0].ResolutionStatus | Should -BeExactly 'Unresolved'
        $Json.CloudSetDetails[0].CloudSetName | Should -BeExactly 'Control Plane Subscriptions'
        @($Json.UnresolvedCloudSets).Count | Should -Be 1
    }
}
