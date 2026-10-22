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
        $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        # Evaluate the .gitignore in a scratch repository: update candidates are validated from an
        # extracted archive without .git, and this also excludes the developer's .git/info/exclude.
        $script:IgnoreRepository = Join-Path $TestDrive 'gitignore-check'
        New-Item -ItemType Directory -Path $script:IgnoreRepository -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $RepositoryRoot '.gitignore') -Destination $script:IgnoreRepository
        & git -C $script:IgnoreRepository init --quiet
        if ($LASTEXITCODE -ne 0) { throw "git init failed with exit code $LASTEXITCODE." }
        # Isolate from the developer's global excludes file so only the repository .gitignore is evaluated.
        $script:NoGlobalExcludes = Join-Path $TestDrive 'no-global-excludes'
    }

    It 'does not ignore deployment path <_>' -ForEach $script:CommittedPaths {
        & git -C $script:IgnoreRepository -c "core.excludesFile=$script:NoGlobalExcludes" check-ignore --quiet --no-index -- $_
        $LASTEXITCODE | Should -Be 1 -Because "'$_' must be committable by deployments and publishing workflows"
    }
}
