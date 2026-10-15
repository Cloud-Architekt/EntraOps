#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $ValidatorPath = Join-Path $script:TestRepositoryRoot '.github/scripts/Test-GitHubActionReferences.ps1'
    $RepositoryRoot = $script:TestRepositoryRoot

    function New-TestWorkflow {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Root,

            [Parameter(Mandatory = $true)]
            [string[]]$ActionReferences
        )

        $WorkflowPath = Join-Path $Root '.github/workflows'
        New-Item -Path $WorkflowPath -ItemType Directory -Force | Out-Null
        $Steps = $ActionReferences | ForEach-Object { "      - uses: $_" }
        @(
            'name: Test'
            'jobs:'
            '  test:'
            '    runs-on: ubuntu-latest'
            '    steps:'
            $Steps
        ) | Set-Content -LiteralPath (Join-Path $WorkflowPath 'test.yml') -Encoding UTF8
    }
}

Describe 'Test-GitHubActionReferences' {
    It 'accepts the repository action references' {
        & $ValidatorPath -RepositoryRoot $RepositoryRoot | Should -Match 'Validated \d+ immutable GitHub Action reference'
    }

    It 'rejects a mutable action tag' {
        New-TestWorkflow -Root $TestDrive -ActionReferences 'actions/checkout@v4'

        { & $ValidatorPath -RepositoryRoot $TestDrive } | Should -Throw '*mutable or invalid external action reference*'
    }

    It 'rejects a pinned action without a version annotation' {
        New-TestWorkflow -Root $TestDrive -ActionReferences 'actions/checkout@1111111111111111111111111111111111111111'

        { & $ValidatorPath -RepositoryRoot $TestDrive } | Should -Throw '*must annotate*'
    }

    It 'rejects inconsistent commits for the same action' {
        New-TestWorkflow -Root $TestDrive -ActionReferences @(
            'actions/checkout@1111111111111111111111111111111111111111 # v4'
            'actions/checkout@2222222222222222222222222222222222222222 # v4'
        )

        { & $ValidatorPath -RepositoryRoot $TestDrive } | Should -Throw '*inconsistent pinned commits*'
    }
}
