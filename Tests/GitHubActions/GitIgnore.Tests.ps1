#Requires -Modules Pester

BeforeDiscovery {
    $script:GitAvailable = [bool](Get-Command -Name git -CommandType Application -ErrorAction SilentlyContinue)
    # Paths that customer deployments commit explicitly (get-started docs) or publish from the pull workflows.
    $script:CommittedPaths = @(
        'EntraOpsConfig.json'
        'PrivilegedEAM'
        'PrivilegedEAM/EntraID/EntraID.json'
        'Classification/Templates/Classification_AadResources.json'
        'Classification/contoso.onmicrosoft.com/Classification_AadResources.json'
        'TenantGovernance/TenantGovernance.json'
        '.github/workflows/Pull-EntraOpsPrivilegedEAM.yaml'
    )
}

Describe '.gitignore' -Skip:(-not $script:GitAvailable) {
    BeforeAll {
        $script:RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        # Isolate from the developer's global excludes file so only the repository .gitignore is evaluated.
        $script:NoGlobalExcludes = Join-Path $TestDrive 'no-global-excludes'
    }

    It 'does not ignore deployment path <_>' -ForEach $script:CommittedPaths {
        & git -C $script:RepositoryRoot -c "core.excludesFile=$script:NoGlobalExcludes" check-ignore --quiet --no-index -- $_
        $LASTEXITCODE | Should -Be 1 -Because "'$_' must be committable by deployments and publishing workflows"
    }
}
