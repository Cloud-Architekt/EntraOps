#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    # Deployments keep their own workflows when Tests are updated (./.github/workflows is not a default update target),
    # so only assert the template workflows upstream.
    $script:IsConfiguredDeployment = Test-Path -LiteralPath (Join-Path $script:TestRepositoryRoot 'EntraOpsConfig.json')
    $script:WorkflowCases = @(Get-ChildItem -Path (Join-Path $script:TestRepositoryRoot '.github/workflows') -File |
            Where-Object { $_.Extension -in '.yml', '.yaml' } |
            ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
}

Describe 'Workflow checkout credentials in <Name>' -ForEach $script:WorkflowCases {
    It 'does not keep the GitHub token in .git/config' -Skip:$IsConfiguredDeployment {
        # Jobs run third-party code (npm, Playwright, PowerShell modules) after the checkout; git pushes pass
        # their token explicitly, so no checkout needs to persist credentials.
        $Lines = Get-Content -LiteralPath $Path
        $Unprotected = for ($Index = 0; $Index -lt $Lines.Count; $Index++) {
            if ($Lines[$Index] -notmatch '^(?<Indent>\s*)(-\s+)?uses:\s*actions/checkout@') { continue }
            $StepIndent = $Matches.Indent.Length
            $StepLines = for ($Next = $Index + 1; $Next -lt $Lines.Count; $Next++) {
                $Line = $Lines[$Next]
                if ($Line.Trim() -and ($Line.Length - $Line.TrimStart().Length) -le $StepIndent -and $Line.TrimStart() -notmatch '^with:') { break }
                if ($Line.Trim() -and ($Line.Length - $Line.TrimStart().Length) -lt $StepIndent) { break }
                $Line
            }
            if (-not ($StepLines -match '^\s*persist-credentials:\s*false\s*$')) { "line $($Index + 1)" }
        }
        @($Unprotected) | Should -BeNullOrEmpty
    }
}
