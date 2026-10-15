#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

# Regression cover for Identity Governance classification scope coverage.
#
# "Catalog creator" is assigned at directory scope ("/") because it grants the right to create new
# catalogs rather than rights inside an existing one. The entry carrying
# microsoft.entitlementManagement/AccessPackageCatalog/Create previously only listed
# "/AccessPackageCatalog/*" (and "/AccessPackage/*") as scopes, and scope matching is
# one-directional, so "/" never matched and the role was silently reported as unclassified.

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:TemplateDir = "$script:TestRepositoryRoot/Classification/Templates"

    function Get-IdGovClassification {
        param([switch]$Parameterized)
        $Name = if ($Parameterized) { 'Classification_IdentityGovernance.Param.json' } else { 'Classification_IdentityGovernance.json' }
        $Raw = [System.IO.File]::ReadAllText((Resolve-Path (Join-Path $script:TemplateDir $Name)))
        if ($Parameterized) {
            $Raw = $Raw -replace '<Tier0ExcludedIdGovScope>', '"/AccessPackageCatalog/excluded"'
            $Raw = $Raw -replace '<Tier1IncludedIdGovScope>', '"/AccessPackageCatalog/tier1"'
            $Raw = $Raw -replace '<Tier2IncludedIdGovScope>', '"/AccessPackageCatalog/tier2"'
            $Raw = $Raw -replace ',\s*<[A-Za-z0-9_]+>', ''
            $Raw = $Raw -replace '<[A-Za-z0-9_]+>\s*,\s*', ''
            $Raw = $Raw -replace '<[A-Za-z0-9_]+>', ''
        }
        return $Raw | ConvertFrom-Json
    }

    # Scope matching as implemented by the collectors: one-directional, with one-directional exclusions.
    function Get-MatchedTiers {
        param($Classification, [string]$ScopeId, [string[]]$RoleActions)
        $Matched = [System.Collections.Generic.List[string]]::new()
        foreach ($Tier in $Classification) {
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
                foreach ($RoleAction in $RoleActions) {
                    foreach ($ClassAction in @($Definition.RoleDefinitionActions)) {
                        if ($RoleAction -like $ClassAction -or $ClassAction -like $RoleAction) {
                            if (-not $Matched.Contains($Tier.EAMTierLevelName)) { $Matched.Add($Tier.EAMTierLevelName) }
                            break
                        }
                    }
                }
            }
        }
        return , @($Matched)
    }

    $script:CatalogCreatorActions = @('microsoft.entitlementManagement/AccessPackageCatalog/Create')
    $script:CatalogOwnerActions = @('microsoft.entitlementManagement/AccessPackageCatalog/AccessPackage/allTasks')
}

Describe 'Classification_IdentityGovernance - directory scope coverage' {

    It 'classifies Catalog creator at directory scope in the base template' {
        $Tiers = Get-MatchedTiers -Classification (Get-IdGovClassification) -ScopeId '/' -RoleActions $script:CatalogCreatorActions
        $Tiers | Should -Contain 'ManagementPlane'
    }

    It 'classifies Catalog creator at directory scope in the parameterized template' {
        $Tiers = Get-MatchedTiers -Classification (Get-IdGovClassification -Parameterized) -ScopeId '/' -RoleActions $script:CatalogCreatorActions
        $Tiers | Should -Contain 'ManagementPlane'
    }

    It 'does not raise Catalog creator to Control Plane' {
        $Tiers = Get-MatchedTiers -Classification (Get-IdGovClassification -Parameterized) -ScopeId '/' -RoleActions $script:CatalogCreatorActions
        $Tiers | Should -Not -Contain 'ControlPlane'
    }

    It 'still classifies catalog-scoped delegation as Control Plane' {
        $Tiers = Get-MatchedTiers -Classification (Get-IdGovClassification -Parameterized) `
            -ScopeId '/AccessPackageCatalog/a1d1ce95-2b4d-4150-b23c-9588eeac5574' -RoleActions $script:CatalogOwnerActions
        $Tiers | Should -Contain 'ControlPlane'
    }

    It 'still honours the Tier 2 scope exclusion for catalog creation' {
        $Tiers = Get-MatchedTiers -Classification (Get-IdGovClassification -Parameterized) `
            -ScopeId '/AccessPackageCatalog/tier2' -RoleActions $script:CatalogCreatorActions
        $Tiers | Should -Not -Contain 'ManagementPlane'
    }
}

