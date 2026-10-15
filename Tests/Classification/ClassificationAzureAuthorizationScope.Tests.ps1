#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

# Regression cover for the Azure RBAC "Authorization" classification scope coverage.
#
# Before this was fixed, the parameterized Azure template classified the Authorization service
# (role assignment write/delete) only at explicitly enumerated Tier 0 and Tier 1 scopes. A
# "Role Based Access Control Administrator" assignment on an ordinary resource group therefore
# produced no Authorization classification at all: the delegation capability was missing from
# MatchedActions and the constrained-delegation (ABAC) evaluation had nothing to downgrade.

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:TemplatePath = "$script:TestRepositoryRoot/Classification/Templates/Classification_Azure.Param.json"

    # Tier 0 scopes as Update-EntraOpsClassificationControlPlaneScope would substitute them.
    $script:Tier0Scopes = @(
        '/',
        '/providers/microsoft.management/managementgroups/contoso-identity',
        '/subscriptions/11111111-1111-1111-1111-111111111111',
        '/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/identity-rg'
    )

    # Mirrors the placeholder substitution: a quoted, comma-joined list per placeholder.
    function Get-SubstitutedAzureClassification {
        param([string[]]$Tier0, [string[]]$Tier1)
        $Raw = [System.IO.File]::ReadAllText((Resolve-Path $script:TemplatePath))
        $Raw = $Raw -replace '<Tier0IncludedResourceScope>', (($Tier0 | ForEach-Object { '"' + $_ + '"' }) -join ',')
        $Raw = $Raw -replace '<Tier1IncludedResourceScope>', (($Tier1 | ForEach-Object { '"' + $_ + '"' }) -join ',')
        # Any remaining placeholder resolves to an empty list entry.
        $Raw = $Raw -replace ',\s*<[A-Za-z0-9_]+>', ''
        $Raw = $Raw -replace '<[A-Za-z0-9_]+>\s*,\s*', ''
        $Raw = $Raw -replace '<[A-Za-z0-9_]+>', ''
        return $Raw | ConvertFrom-Json
    }

    # Scope matching as implemented by Get-EntraOpsPrivilegedEAMAzure: one-directional
    # (assignment scope -like classification pattern) with one-directional exclusions.
    function Get-MatchedServices {
        param($Classification, [string]$TierName, [string]$ScopeId, [string[]]$RoleActions)
        $Tier = $Classification | Where-Object { $_.EAMTierLevelName -eq $TierName }
        $Matched = [System.Collections.Generic.List[string]]::new()
        foreach ($Definition in $Tier.TierLevelDefinition) {
            $ScopeMatch = $false
            foreach ($Pattern in @($Definition.RoleAssignmentScopeName)) {
                if (-not [string]::IsNullOrEmpty($Pattern) -and $ScopeId -like $Pattern) { $ScopeMatch = $true; break }
            }
            if (-not $ScopeMatch) { continue }
            foreach ($Excluded in @($Definition.ExcludedRoleAssignmentScopeName)) {
                if (-not [string]::IsNullOrEmpty($Excluded) -and $ScopeId -like $Excluded) { $ScopeMatch = $false; break }
            }
            if (-not $ScopeMatch) { continue }
            # Action matching is bidirectional in the collector.
            foreach ($RoleAction in $RoleActions) {
                foreach ($ClassAction in @($Definition.RoleDefinitionActions)) {
                    if ($RoleAction -like $ClassAction -or $ClassAction -like $RoleAction) {
                        if (-not $Matched.Contains($Definition.Service)) { $Matched.Add($Definition.Service) }
                        break
                    }
                }
            }
        }
        return , @($Matched)
    }

    # Real allowedResourceActions of the built-in Role Based Access Control Administrator.
    $script:RbacAdminActions = @(
        '*/read',
        'Microsoft.Authorization/roleAssignments/write',
        'Microsoft.Authorization/roleAssignments/delete',
        'Microsoft.Support/*'
    )
}

Describe 'Classification_Azure.Param.json - Authorization scope coverage' {

    It 'classifies role-assignment delegation at an ordinary resource group as Management Plane' {
        $Classification = Get-SubstitutedAzureClassification -Tier0 $script:Tier0Scopes -Tier1 @()
        $Services = Get-MatchedServices -Classification $Classification -TierName 'ManagementPlane' `
            -ScopeId '/subscriptions/99999999-9999-9999-9999-999999999999/resourcegroups/workload-rg' `
            -RoleActions $script:RbacAdminActions
        $Services | Should -Contain 'Authorization'
    }

    It 'does not classify Authorization as Management Plane at a Control Plane scope' {
        $Classification = Get-SubstitutedAzureClassification -Tier0 $script:Tier0Scopes -Tier1 @()
        $Services = Get-MatchedServices -Classification $Classification -TierName 'ManagementPlane' `
            -ScopeId '/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/identity-rg' `
            -RoleActions $script:RbacAdminActions
        $Services | Should -Not -Contain 'Authorization'
    }

    It 'still classifies Authorization as Control Plane at a Control Plane scope' {
        $Classification = Get-SubstitutedAzureClassification -Tier0 $script:Tier0Scopes -Tier1 @()
        $Services = Get-MatchedServices -Classification $Classification -TierName 'ControlPlane' `
            -ScopeId '/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/identity-rg' `
            -RoleActions $script:RbacAdminActions
        $Services | Should -Contain 'Authorization'
    }

    It 'classifies Authorization at an ordinary subscription scope' {
        $Classification = Get-SubstitutedAzureClassification -Tier0 $script:Tier0Scopes -Tier1 @()
        $Services = Get-MatchedServices -Classification $Classification -TierName 'ManagementPlane' `
            -ScopeId '/subscriptions/99999999-9999-9999-9999-999999999999' `
            -RoleActions $script:RbacAdminActions
        $Services | Should -Contain 'Authorization'
    }

    It 'keeps the tenant root scope Control Plane only' {
        $Classification = Get-SubstitutedAzureClassification -Tier0 $script:Tier0Scopes -Tier1 @()
        $Management = Get-MatchedServices -Classification $Classification -TierName 'ManagementPlane' `
            -ScopeId '/' -RoleActions $script:RbacAdminActions
        $Control = Get-MatchedServices -Classification $Classification -TierName 'ControlPlane' `
            -ScopeId '/' -RoleActions $script:RbacAdminActions
        $Management | Should -Not -Contain 'Authorization'
        $Control | Should -Contain 'Authorization'
    }

    It 'covers Owner (wildcard action) at an ordinary resource group' {
        $Classification = Get-SubstitutedAzureClassification -Tier0 $script:Tier0Scopes -Tier1 @()
        $Services = Get-MatchedServices -Classification $Classification -TierName 'ManagementPlane' `
            -ScopeId '/subscriptions/99999999-9999-9999-9999-999999999999/resourcegroups/workload-rg' `
            -RoleActions @('*')
        $Services | Should -Contain 'Authorization'
    }
}

