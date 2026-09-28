#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

Describe 'Update-EntraOpsDocsContent deployment generation' {
    It 'preserves an embedded changelog when a deployment has no root CHANGELOG.md' {
        $FixtureRoot = Join-Path $TestDrive 'deployment'
        $ContentRoot = Join-Path $FixtureRoot 'Docs/content'
        $DataRoot = Join-Path $FixtureRoot 'Docs/data'
        New-Item -Path $ContentRoot, $DataRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $ContentRoot 'overview.md') -Value '# Overview' -Encoding utf8
        Set-Content -LiteralPath (Join-Path $DataRoot 'content.js') -Value @'
// existing deployment bundle
window.EODOCS_DEPLOYMENT_MODE = "EntraOps";
window.EODOCS_CONTENT = {"overview":"# Old","changelog":"# Existing changelog\n\nKeep this history."};
'@ -Encoding utf8

        & (Join-Path $script:TestRepositoryRoot 'Docs/Update-EntraOpsDocsContent.ps1') -RepoRoot $FixtureRoot -WarningAction SilentlyContinue

        $Bundle = Get-Content -LiteralPath (Join-Path $DataRoot 'content.js') -Raw
        $Match = [regex]::Match($Bundle, 'window\.EODOCS_CONTENT\s*=\s*(?<Json>\{.*\});\s*$', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        $Match.Success | Should -BeTrue
        $Generated = $Match.Groups['Json'].Value | ConvertFrom-Json
        $Generated.overview | Should -Match '# Overview'
        $Generated.changelog | Should -Be "# Existing changelog`n`nKeep this history."
    }
}

