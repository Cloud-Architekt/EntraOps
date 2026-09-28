#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsClassificationActionMatch.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Build-EntraOpsClassificationActionMatcher.ps1"

    # Inline evaluation mirroring the hot-loop call sites.
    function Test-MatcherAllowed {
        param($Matcher, [AllowEmptyString()][string]$Action)
        if ([string]::IsNullOrEmpty($Action)) { return $false }
        if ($Matcher.AllowedExact.Contains($Action)) { return $true }
        foreach ($Pattern in $Matcher.AllowedWildcards) { if ($Action -like $Pattern) { return $true } }
        return $false
    }
    function Test-MatcherExcluded {
        param($Matcher, [AllowEmptyString()][string]$Action)
        if ([string]::IsNullOrEmpty($Action)) { return $false }
        if ($Matcher.ExcludedExact.Contains($Action)) { return $true }
        foreach ($Pattern in $Matcher.ExcludedWildcards) { if ($Action -like $Pattern) { return $true } }
        return $false
    }
}

Describe "Build-EntraOpsClassificationActionMatcher" {
    It "agrees with Test-EntraOpsClassificationActionMatch for <Case>" -TestCases @(
        @{ Case = "exact match"; Actions = @("microsoft.directory/users/create"); Action = "microsoft.directory/users/create" }
        @{ Case = "case-difference match"; Actions = @("Microsoft.Directory/Users/Create"); Action = "microsoft.directory/users/create" }
        @{ Case = "wildcard match"; Actions = @("microsoft.directory/users/*"); Action = "microsoft.directory/users/password/update" }
        @{ Case = "non-match"; Actions = @("microsoft.directory/groups/create"); Action = "microsoft.directory/users/create" }
        @{ Case = "empty action"; Actions = @("microsoft.directory/users/*"); Action = "" }
        @{ Case = "empty classification array"; Actions = @(); Action = "microsoft.directory/users/create" }
        @{ Case = "null classification"; Actions = $null; Action = "microsoft.directory/users/create" }
        @{ Case = "null entries ignored"; Actions = @($null, "", "microsoft.directory/users/create"); Action = "microsoft.directory/users/create" }
        @{ Case = "mixed exact and wildcard"; Actions = @("microsoft.directory/groups/create", "microsoft.directory/users/?assword/*"); Action = "microsoft.directory/users/password/update" }
    ) {
        $Matcher = Build-EntraOpsClassificationActionMatcher -RoleDefinitionActions $Actions -ExcludedRoleDefinitionActions $Actions

        Test-MatcherAllowed -Matcher $Matcher -Action $Action | Should -Be (Test-EntraOpsClassificationActionMatch -ClassificationActions $Actions -Action $Action)
        Test-MatcherExcluded -Matcher $Matcher -Action $Action | Should -Be (Test-EntraOpsClassificationActionMatch -ClassificationActions $Actions -Action $Action)
    }

    It "separates allowed and excluded action sets independently" {
        $Matcher = Build-EntraOpsClassificationActionMatcher -RoleDefinitionActions @("microsoft.directory/users/*") -ExcludedRoleDefinitionActions @("microsoft.directory/users/standard/read")

        Test-MatcherAllowed -Matcher $Matcher -Action "microsoft.directory/users/standard/read" | Should -BeTrue
        Test-MatcherExcluded -Matcher $Matcher -Action "microsoft.directory/users/standard/read" | Should -BeTrue
        Test-MatcherExcluded -Matcher $Matcher -Action "microsoft.directory/users/password/update" | Should -BeFalse
    }
}

