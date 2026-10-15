#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsAzureConstrainedDelegationTier.ps1"

    $Scope = '/subscriptions/00000000-0000-0000-0000-000000000001'
    $Tier0ResourceScope = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/identity'

    $AssignedRoleId = 'aaaaaaaa-0000-0000-0000-000000000001'   # Role Based Access Control Administrator equivalent
    $ManagementPlaneRoleId = 'bbbbbbbb-0000-0000-0000-000000000002' # classifies as ManagementPlane at $Scope
    $ControlPlaneRoleId = 'cccccccc-0000-0000-0000-000000000003'    # classifies as ControlPlane at $Scope
    $UserAccessRoleId = 'dddddddd-0000-0000-0000-000000000004'      # classifies as UserAccess at $Scope
    $UnknownRoleId = 'eeeeeeee-0000-0000-0000-000000000005'         # deliberately absent from the role cache
    $BroadAuthorizationRoleId = 'ffffffff-0000-0000-0000-000000000006'

    $TierNameByTag = @{ '0' = 'ControlPlane'; '1' = 'ManagementPlane'; '2' = 'UserAccess' }

    function New-RoleDefinition {
        param (
            [string[]]$Actions = @(),
            [string[]]$NotActions = @(),
            [string[]]$DataActions = @(),
            [string]$Condition,
            [string]$ConditionVersion
        )

        $Permission = [ordered]@{
            actions     = $Actions
            notActions  = $NotActions
            dataActions = $DataActions
        }
        if ($PSBoundParameters.ContainsKey('Condition')) { $Permission['condition'] = $Condition }
        if ($PSBoundParameters.ContainsKey('ConditionVersion')) { $Permission['conditionVersion'] = $ConditionVersion }

        return [PSCustomObject]@{ properties = [PSCustomObject]@{ permissions = @([PSCustomObject]$Permission) } }
    }

    $ClassificationDefinitions = @(
        [PSCustomObject]@{
            EAMTierLevelName               = 'ControlPlane'
            EAMTierLevelTagValue           = '0'
            Service                        = 'Authorization'
            RoleAssignmentScopeName        = '/subscriptions/*'
            ExcludedRoleAssignmentScopeName = @()
            RoleDefinitionActions          = @('Microsoft.Authorization/roleAssignments/write', 'Microsoft.Authorization/roleAssignments/delete', 'Microsoft.Authorization/roleDefinitions/write')
            ExcludedRoleDefinitionActions  = @()
            ActionType                     = 'Action'
        }
        [PSCustomObject]@{
            EAMTierLevelName               = 'ControlPlane'
            EAMTierLevelTagValue           = '0'
            Service                        = 'Identity Infrastructure'
            RoleAssignmentScopeName        = $Tier0ResourceScope
            ExcludedRoleAssignmentScopeName = @()
            RoleDefinitionActions          = @('Microsoft.Compute/virtualMachines/write')
            ExcludedRoleDefinitionActions  = @()
            ActionType                     = 'Action'
        }
        [PSCustomObject]@{
            EAMTierLevelName               = 'ManagementPlane'
            EAMTierLevelTagValue           = '1'
            Service                        = 'Compute'
            RoleAssignmentScopeName        = '/subscriptions/*'
            ExcludedRoleAssignmentScopeName = @($Tier0ResourceScope)
            RoleDefinitionActions          = @('Microsoft.Compute/virtualMachines/write')
            ExcludedRoleDefinitionActions  = @()
            ActionType                     = 'Action'
        }
        [PSCustomObject]@{
            EAMTierLevelName               = 'UserAccess'
            EAMTierLevelTagValue           = '2'
            Service                        = 'Compute Login'
            RoleAssignmentScopeName        = '/subscriptions/*'
            ExcludedRoleAssignmentScopeName = @()
            RoleDefinitionActions          = @('Microsoft.Compute/virtualMachines/login/action')
            ExcludedRoleDefinitionActions  = @()
            ActionType                     = 'Action'
        }
    )

    $RoleDefinitionCache = @{
        $AssignedRoleId           = New-RoleDefinition -Actions @('Microsoft.Authorization/roleAssignments/write', 'Microsoft.Authorization/roleAssignments/delete', '*/read')
        $ManagementPlaneRoleId    = New-RoleDefinition -Actions @('Microsoft.Compute/virtualMachines/write')
        $ControlPlaneRoleId       = New-RoleDefinition -Actions @('Microsoft.Authorization/roleAssignments/write')
        $UserAccessRoleId         = New-RoleDefinition -Actions @('Microsoft.Compute/virtualMachines/login/action')
        $BroadAuthorizationRoleId = New-RoleDefinition -Actions @('Microsoft.Authorization/*')
    }

    function New-Condition {
        param (
            [string[]]$GuardedActions = @('write', 'delete'),
            [string]$Operator = 'GuidEquals',
            [string[]]$RoleDefinitionIds,
            [string]$Quantifier = 'ForAnyOfAnyValues',
            [string]$AttributeSource = '@Request'
        )

        $Clauses = foreach ($GuardedAction in $GuardedActions) {
            @"
(
 (
  !(ActionMatches{'Microsoft.Authorization/roleAssignments/$GuardedAction'})
 )
 OR
 (
  $AttributeSource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ${Quantifier}:$Operator {$($RoleDefinitionIds -join ', ')}
 )
)
"@
        }

        return ($Clauses -join "`nAND`n")
    }

    function New-Assignment {
        param (
            [string]$Condition,
            [string]$ConditionVersion = '2.0',
            [string]$ScopeId = $Scope,
            [string]$RoleDefinitionId = $AssignedRoleId,
            [object[]]$Classification
        )

        if (-not $PSBoundParameters.ContainsKey('Classification')) {
            $Classification = @(
                [PSCustomObject]@{
                    AdminTierLevel             = '0'
                    AdminTierLevelName         = 'ControlPlane'
                    Service                    = 'Authorization'
                    MatchedActions             = @('Microsoft.Authorization/roleAssignments/write', 'Microsoft.Authorization/roleAssignments/delete')
                    ScopedObjects              = $null
                    TaggedBy                   = 'JSONwithAction'
                    TaggedByObjectIds          = $null
                    TaggedByObjectDisplayNames = $null
                    TaggedByRoleSystem         = 'Azure'
                }
            )
        }

        return [PSCustomObject]@{
            RoleAssignmentCondition        = $Condition
            RoleAssignmentConditionVersion = $ConditionVersion
            RoleAssignmentScopeId          = $ScopeId
            RoleDefinitionId               = $RoleDefinitionId
            Classification                 = $Classification
        }
    }

    function Invoke-Resolver {
        param ([PSObject]$Assignment)

        return @(Resolve-EntraOpsAzureConstrainedDelegationTier `
                -Assignment $Assignment `
                -ClassificationDefinitions $ClassificationDefinitions `
                -RoleDefinitionCache $RoleDefinitionCache `
                -TierNameByTag $TierNameByTag)
    }
}

Describe 'Resolve-EntraOpsAzureConstrainedDelegationTier' {

    Context 'Downgrade of a provably constrained delegation' {
        It 'downgrades to the most privileged tier reachable through the allow-list' {
            $Assignment = New-Assignment -Condition (New-Condition -RoleDefinitionIds @($ManagementPlaneRoleId))

            $Result = Invoke-Resolver -Assignment $Assignment

            $Result.Count | Should -Be 1
            $Result[0].AdminTierLevel | Should -Be '1'
            $Result[0].AdminTierLevelName | Should -Be 'ManagementPlane'
            $Result[0].TaggedBy | Should -Be 'JSONwithConditionInScope'
            $Result[0].Service | Should -Be 'Authorization'
            $Result[0].MatchedActions | Should -Be @('Microsoft.Authorization/roleAssignments/write', 'Microsoft.Authorization/roleAssignments/delete')
        }

        It 'takes the most privileged tier when the allow-list spans several tiers' {
            $Assignment = New-Assignment -Condition (New-Condition -RoleDefinitionIds @($UserAccessRoleId, $ManagementPlaneRoleId))

            $Result = Invoke-Resolver -Assignment $Assignment

            $Result[0].AdminTierLevel | Should -Be '1'
            $Result[0].AdminTierLevelName | Should -Be 'ManagementPlane'
        }

        It 'downgrades when the condition is defined on the role definition instead of the assignment' {
            $RoleWithCondition = New-RoleDefinition -Actions @('Microsoft.Authorization/roleAssignments/write', 'Microsoft.Authorization/roleAssignments/delete') `
                -Condition (New-Condition -RoleDefinitionIds @($ManagementPlaneRoleId)) -ConditionVersion '2.0'
            $LocalCache = $RoleDefinitionCache.Clone()
            $LocalCache['11111111-0000-0000-0000-00000000000a'] = $RoleWithCondition

            $Assignment = New-Assignment -Condition $null -ConditionVersion $null -RoleDefinitionId '11111111-0000-0000-0000-00000000000a'
            $Result = @(Resolve-EntraOpsAzureConstrainedDelegationTier -Assignment $Assignment `
                    -ClassificationDefinitions $ClassificationDefinitions -RoleDefinitionCache $LocalCache -TierNameByTag $TierNameByTag)

            $Result[0].AdminTierLevelName | Should -Be 'ManagementPlane'
            $Result[0].TaggedBy | Should -Be 'JSONwithConditionInScope'
        }

        It 'intersects the allow-lists of the assignment and role definition conditions' {
            $RoleWithCondition = New-RoleDefinition -Actions @('Microsoft.Authorization/roleAssignments/write', 'Microsoft.Authorization/roleAssignments/delete') `
                -Condition (New-Condition -RoleDefinitionIds @($ManagementPlaneRoleId, $UserAccessRoleId)) -ConditionVersion '2.0'
            $LocalCache = $RoleDefinitionCache.Clone()
            $LocalCache['22222222-0000-0000-0000-00000000000b'] = $RoleWithCondition

            # The assignment narrows the role's allow-list to the User Access role only.
            $Assignment = New-Assignment -Condition (New-Condition -RoleDefinitionIds @($UserAccessRoleId)) -RoleDefinitionId '22222222-0000-0000-0000-00000000000b'
            $Result = @(Resolve-EntraOpsAzureConstrainedDelegationTier -Assignment $Assignment `
                    -ClassificationDefinitions $ClassificationDefinitions -RoleDefinitionCache $LocalCache -TierNameByTag $TierNameByTag)

            $Result[0].AdminTierLevel | Should -Be '2'
            $Result[0].AdminTierLevelName | Should -Be 'UserAccess'
        }

        It 'accepts a GuidEquals allow-list expressed against @Resource' {
            $Assignment = New-Assignment -Condition (New-Condition -RoleDefinitionIds @($ManagementPlaneRoleId) -AttributeSource '@Resource')

            (Invoke-Resolver -Assignment $Assignment)[0].AdminTierLevelName | Should -Be 'ManagementPlane'
        }

        It 'accepts a ForAllOfAnyValues quantifier' {
            $Assignment = New-Assignment -Condition (New-Condition -RoleDefinitionIds @($ManagementPlaneRoleId) -Quantifier 'ForAllOfAnyValues')

            (Invoke-Resolver -Assignment $Assignment)[0].AdminTierLevelName | Should -Be 'ManagementPlane'
        }
    }

    Context 'Fail-closed behaviour' {
        It 'keeps Control Plane when the assignment has no condition' {
            $Assignment = New-Assignment -Condition '' -ConditionVersion ''

            $Result = Invoke-Resolver -Assignment $Assignment

            $Result[0].AdminTierLevelName | Should -Be 'ControlPlane'
            $Result[0].TaggedBy | Should -Be 'JSONwithAction'
        }

        It 'keeps Control Plane for a GuidNotEquals deny-list' {
            # The excluded role is Management Plane on purpose: if the deny-list guard were dropped and the
            # list were treated as an allow-list, the entry would downgrade instead of staying Control Plane.
            $Assignment = New-Assignment -Condition (New-Condition -Operator 'GuidNotEquals' -RoleDefinitionIds @($ManagementPlaneRoleId))

            $Result = Invoke-Resolver -Assignment $Assignment

            $Result.Count | Should -Be 1
            $Result[0].AdminTierLevelName | Should -Be 'ControlPlane'
            $Result[0].TaggedBy | Should -Be 'JSONwithAction'
        }

        It 'keeps Control Plane for an unsupported condition version' {
            $Assignment = New-Assignment -Condition (New-Condition -RoleDefinitionIds @($ManagementPlaneRoleId)) -ConditionVersion '1.0'

            (Invoke-Resolver -Assignment $Assignment)[0].AdminTierLevelName | Should -Be 'ControlPlane'
        }

        It 'keeps Control Plane when no negated ActionMatches guard is present' {
            $Unguarded = "(@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {$ManagementPlaneRoleId})"
            $Assignment = New-Assignment -Condition $Unguarded

            (Invoke-Resolver -Assignment $Assignment)[0].AdminTierLevelName | Should -Be 'ControlPlane'
        }

        It 'keeps Control Plane when the guard names an unrelated action' {
            $Condition = @"
(
 (
  !(ActionMatches{'Microsoft.Authorization/roleDefinitions/write'})
 )
 OR
 (
  @Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {$ManagementPlaneRoleId}
 )
)
"@
            $Assignment = New-Assignment -Condition $Condition

            (Invoke-Resolver -Assignment $Assignment)[0].AdminTierLevelName | Should -Be 'ControlPlane'
        }

        It 'keeps Control Plane for an empty GUID set' {
            $Assignment = New-Assignment -Condition (New-Condition -RoleDefinitionIds @())

            (Invoke-Resolver -Assignment $Assignment)[0].AdminTierLevelName | Should -Be 'ControlPlane'
        }

        It 'keeps Control Plane when a condition mentions roleAssignments but has no RoleDefinitionId constraint' {
            $Condition = "((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})) OR (@Request[Microsoft.Authorization/roleAssignments:PrincipalType] StringEquals 'User'))"
            $Assignment = New-Assignment -Condition $Condition

            (Invoke-Resolver -Assignment $Assignment)[0].AdminTierLevelName | Should -Be 'ControlPlane'
        }

        It 'keeps Control Plane when an allow-listed role definition cannot be resolved' {
            # Pairing the unknown role with a Management Plane role proves the whole allow-list fails closed
            # rather than silently downgrading on the roles that happen to resolve.
            $Assignment = New-Assignment -Condition (New-Condition -RoleDefinitionIds @($ManagementPlaneRoleId, $UnknownRoleId))

            $Result = Invoke-Resolver -Assignment $Assignment

            $Result[0].AdminTierLevelName | Should -Be 'ControlPlane'
            $Result[0].TaggedBy | Should -Be 'JSONwithAction'
        }

        It 'keeps Control Plane when an allow-listed role definition matches no classification' {
            $UnclassifiableRoleId = '33333333-0000-0000-0000-00000000000c'
            $LocalCache = $RoleDefinitionCache.Clone()
            $LocalCache[$UnclassifiableRoleId] = New-RoleDefinition -Actions @('Microsoft.Fabrikam/widgets/write')

            $Assignment = New-Assignment -Condition (New-Condition -RoleDefinitionIds @($ManagementPlaneRoleId, $UnclassifiableRoleId))
            $Result = @(Resolve-EntraOpsAzureConstrainedDelegationTier -Assignment $Assignment `
                    -ClassificationDefinitions $ClassificationDefinitions -RoleDefinitionCache $LocalCache -TierNameByTag $TierNameByTag)

            $Result[0].AdminTierLevelName | Should -Be 'ControlPlane'
            $Result[0].TaggedBy | Should -Be 'JSONwithAction'
        }

        It 'keeps Control Plane when the allow-list still reaches a Control Plane role' {
            $Assignment = New-Assignment -Condition (New-Condition -RoleDefinitionIds @($ControlPlaneRoleId))

            $Result = Invoke-Resolver -Assignment $Assignment

            $Result[0].AdminTierLevelName | Should -Be 'ControlPlane'
            # A re-tier to Control Plane would still be a behaviour change, so provenance must be untouched.
            $Result[0].TaggedBy | Should -Be 'JSONwithAction'
        }

        It 'keeps Control Plane when the assignment scope is itself a concrete Control Plane scope' {
            # The User Access role classifies as tier 2 at this scope, so only the scope guard prevents a downgrade.
            $Assignment = New-Assignment -Condition (New-Condition -RoleDefinitionIds @($UserAccessRoleId)) -ScopeId $Tier0ResourceScope

            $Result = Invoke-Resolver -Assignment $Assignment

            $Result[0].AdminTierLevelName | Should -Be 'ControlPlane'
            $Result[0].TaggedBy | Should -Be 'JSONwithAction'
        }

        It 'keeps Control Plane when the resolved tier has no name in the tier map' {
            $Assignment = New-Assignment -Condition (New-Condition -RoleDefinitionIds @($ManagementPlaneRoleId))
            $Result = @(Resolve-EntraOpsAzureConstrainedDelegationTier -Assignment $Assignment `
                    -ClassificationDefinitions $ClassificationDefinitions -RoleDefinitionCache $RoleDefinitionCache `
                    -TierNameByTag @{ '0' = 'ControlPlane' })

            $Result[0].AdminTierLevelName | Should -Be 'ControlPlane'
        }
    }

    Context 'Scope of the downgrade' {
        It 'splits the entry so unconstrained Authorization powers stay Control Plane' {
            $Classification = @(
                [PSCustomObject]@{
                    AdminTierLevel             = '0'
                    AdminTierLevelName         = 'ControlPlane'
                    Service                    = 'Authorization'
                    MatchedActions             = @('Microsoft.Authorization/roleAssignments/write', 'Microsoft.Authorization/roleDefinitions/write')
                    ScopedObjects              = $null
                    TaggedBy                   = 'JSONwithAction'
                    TaggedByObjectIds          = $null
                    TaggedByObjectDisplayNames = $null
                    TaggedByRoleSystem         = 'Azure'
                }
            )
            $Assignment = New-Assignment -Condition (New-Condition -GuardedActions @('write') -RoleDefinitionIds @($ManagementPlaneRoleId)) `
                -RoleDefinitionId $BroadAuthorizationRoleId -Classification $Classification

            $Result = Invoke-Resolver -Assignment $Assignment

            $Result.Count | Should -Be 2
            $Retained = @($Result | Where-Object { $_.AdminTierLevelName -eq 'ControlPlane' })
            $Downgraded = @($Result | Where-Object { $_.TaggedBy -eq 'JSONwithConditionInScope' })
            $Retained.Count | Should -Be 1
            $Retained[0].MatchedActions | Should -Be @('Microsoft.Authorization/roleDefinitions/write')
            $Downgraded.Count | Should -Be 1
            $Downgraded[0].MatchedActions | Should -Be @('Microsoft.Authorization/roleAssignments/write')
            $Downgraded[0].AdminTierLevelName | Should -Be 'ManagementPlane'
        }

        It 'leaves an unguarded delete at Control Plane when only write is constrained' {
            $Assignment = New-Assignment -Condition (New-Condition -GuardedActions @('write') -RoleDefinitionIds @($ManagementPlaneRoleId))

            $Result = Invoke-Resolver -Assignment $Assignment

            $Result.Count | Should -Be 2
            @($Result | Where-Object { $_.AdminTierLevelName -eq 'ControlPlane' })[0].MatchedActions |
                Should -Be @('Microsoft.Authorization/roleAssignments/delete')
            @($Result | Where-Object { $_.TaggedBy -eq 'JSONwithConditionInScope' })[0].MatchedActions |
                Should -Be @('Microsoft.Authorization/roleAssignments/write')
        }

        It 'leaves classifications from the role own actions untouched' {
            $Classification = @(
                [PSCustomObject]@{
                    AdminTierLevel             = '0'
                    AdminTierLevelName         = 'ControlPlane'
                    Service                    = 'Authorization'
                    MatchedActions             = @('Microsoft.Authorization/roleAssignments/write', 'Microsoft.Authorization/roleAssignments/delete')
                    ScopedObjects              = $null
                    TaggedBy                   = 'JSONwithAction'
                    TaggedByObjectIds          = $null
                    TaggedByObjectDisplayNames = $null
                    TaggedByRoleSystem         = 'Azure'
                }
                [PSCustomObject]@{
                    AdminTierLevel             = '1'
                    AdminTierLevelName         = 'ManagementPlane'
                    Service                    = 'Compute'
                    MatchedActions             = @('Microsoft.Compute/virtualMachines/write')
                    ScopedObjects              = $null
                    TaggedBy                   = 'JSONwithAction'
                    TaggedByObjectIds          = $null
                    TaggedByObjectDisplayNames = $null
                    TaggedByRoleSystem         = 'Azure'
                }
            )
            $Assignment = New-Assignment -Condition (New-Condition -RoleDefinitionIds @($ManagementPlaneRoleId)) -Classification $Classification

            $Result = Invoke-Resolver -Assignment $Assignment

            $Compute = @($Result | Where-Object { $_.Service -eq 'Compute' })
            $Compute.Count | Should -Be 1
            $Compute[0].TaggedBy | Should -Be 'JSONwithAction'
            $Compute[0].AdminTierLevelName | Should -Be 'ManagementPlane'
        }

        It 'preserves provenance fields on the downgraded entry' {
            $Classification = @(
                [PSCustomObject]@{
                    AdminTierLevel             = '0'
                    AdminTierLevelName         = 'ControlPlane'
                    Service                    = 'Authorization'
                    MatchedActions             = @('Microsoft.Authorization/roleAssignments/write')
                    ScopedObjects              = 'scoped-object'
                    TaggedBy                   = 'JSONwithAction'
                    TaggedByObjectIds          = @('object-id')
                    TaggedByObjectDisplayNames = @('object-name')
                    TaggedByRoleSystem         = 'Azure'
                }
            )
            $Assignment = New-Assignment -Condition (New-Condition -GuardedActions @('write') -RoleDefinitionIds @($ManagementPlaneRoleId)) -Classification $Classification

            $Result = Invoke-Resolver -Assignment $Assignment

            $Result[0].ScopedObjects | Should -Be 'scoped-object'
            $Result[0].TaggedByObjectIds | Should -Be @('object-id')
            $Result[0].TaggedByObjectDisplayNames | Should -Be @('object-name')
            $Result[0].TaggedByRoleSystem | Should -Be 'Azure'
        }

        It 'returns an empty classification unchanged' {
            $Assignment = New-Assignment -Condition (New-Condition -RoleDefinitionIds @($ManagementPlaneRoleId)) -Classification @()

            (Invoke-Resolver -Assignment $Assignment).Count | Should -Be 0
        }

        It 'does not touch an assignment without a Control Plane Authorization entry' {
            $Classification = @(
                [PSCustomObject]@{
                    AdminTierLevel             = '1'
                    AdminTierLevelName         = 'ManagementPlane'
                    Service                    = 'Compute'
                    MatchedActions             = @('Microsoft.Compute/virtualMachines/write')
                    ScopedObjects              = $null
                    TaggedBy                   = 'JSONwithAction'
                    TaggedByObjectIds          = $null
                    TaggedByObjectDisplayNames = $null
                    TaggedByRoleSystem         = 'Azure'
                }
            )
            $Assignment = New-Assignment -Condition (New-Condition -RoleDefinitionIds @($ManagementPlaneRoleId)) -Classification $Classification

            $Result = Invoke-Resolver -Assignment $Assignment

            $Result.Count | Should -Be 1
            $Result[0].TaggedBy | Should -Be 'JSONwithAction'
            $Result[0].AdminTierLevelName | Should -Be 'ManagementPlane'
        }
    }
}

