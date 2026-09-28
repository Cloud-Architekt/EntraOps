#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    function Update-EntraOpsClassificationExplorerData {
        [CmdletBinding(SupportsShouldProcess = $true)]
        param (
            [string]$Mode,
            [string]$RepoRoot,
            [string]$EntraOpsRoot,
            [string]$AppRoot,
            [switch]$SkipManifest,
            [switch]$SkipEmbed,
            [switch]$SkipHistory,
            [switch]$PassThru
        )

        $script:ReceivedSkipHistory = $SkipHistory.IsPresent
        $script:ReceivedSkipHistoryBinding = $PSBoundParameters.ContainsKey('SkipHistory')
    }

    . "$script:TestRepositoryRoot/EntraOps/Public/Reportings/New-EntraOpsClassificationExplorerData.ps1"
}

Describe 'New-EntraOpsClassificationExplorerData history configuration' {
    BeforeEach {
        $script:ReceivedSkipHistory = $null
        $script:ReceivedSkipHistoryBinding = $false
        $script:EntraOpsRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -Path $script:EntraOpsRoot -ItemType Directory -Force | Out-Null
    }

    It 'skips history when the configuration file is missing' {
        New-EntraOpsClassificationExplorerData -RepoRoot $TestDrive -EntraOpsRoot $script:EntraOpsRoot

        $script:ReceivedSkipHistoryBinding | Should -BeTrue
        $script:ReceivedSkipHistory | Should -BeTrue
    }

    It 'maps GenerateChangeHistory false to SkipHistory true' {
        @{ ClassificationExplorer = @{ GenerateChangeHistory = $false } } |
            ConvertTo-Json -Depth 3 |
            Set-Content -LiteralPath (Join-Path $script:EntraOpsRoot 'EntraOpsConfig.json') -Encoding UTF8

        New-EntraOpsClassificationExplorerData -RepoRoot $TestDrive -EntraOpsRoot $script:EntraOpsRoot

        $script:ReceivedSkipHistory | Should -BeTrue
    }

    It 'maps GenerateChangeHistory true to SkipHistory false' {
        @{ ClassificationExplorer = @{ GenerateChangeHistory = $true } } |
            ConvertTo-Json -Depth 3 |
            Set-Content -LiteralPath (Join-Path $script:EntraOpsRoot 'EntraOpsConfig.json') -Encoding UTF8

        New-EntraOpsClassificationExplorerData -RepoRoot $TestDrive -EntraOpsRoot $script:EntraOpsRoot

        $script:ReceivedSkipHistoryBinding | Should -BeTrue
        $script:ReceivedSkipHistory | Should -BeFalse
    }

    It 'lets an explicit SkipHistory false override configuration' {
        @{ ClassificationExplorer = @{ GenerateChangeHistory = $false } } |
            ConvertTo-Json -Depth 3 |
            Set-Content -LiteralPath (Join-Path $script:EntraOpsRoot 'EntraOpsConfig.json') -Encoding UTF8

        New-EntraOpsClassificationExplorerData -RepoRoot $TestDrive -EntraOpsRoot $script:EntraOpsRoot -SkipHistory:$false

        $script:ReceivedSkipHistoryBinding | Should -BeTrue
        $script:ReceivedSkipHistory | Should -BeFalse
    }
}

