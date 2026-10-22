#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Public/Reportings/Update-EntraOpsClassificationExplorerData.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Save-EntraOpsReportDataFile.ps1"
}

Describe 'Update-EntraOpsClassificationExplorerData skipped history notifications' {
    BeforeEach {
        $Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $AppRoot = Join-Path $Root 'App'
        New-Item -ItemType Directory -Path "$Root/Classification/Templates", "$AppRoot/js", "$AppRoot/data" -Force | Out-Null
        Set-Content -LiteralPath "$Root/Classification/Templates/Classification_AadResources.json" -Value '[]'
        Set-Content -LiteralPath "$AppRoot/js/mode.js" -Value "window.EOCE_MODE = 'entraops';"
        Set-Content -LiteralPath "$AppRoot/index.html" -Value '<html></html>'
        $script:NotificationPath = Join-Path $AppRoot 'data/notification-data.js'
        $script:HistoryPath = Join-Path $AppRoot 'data/history-data.js'
        Set-Content -LiteralPath $script:HistoryPath -Value 'window.EOCE_HISTORY = {"sources":{}};'
        $script:OriginalHistory = [System.IO.File]::ReadAllBytes($script:HistoryPath)
        $script:Parameters = @{
            Mode = 'EntraOps'; RepoRoot = $Root; EntraOpsRoot = $Root; AppRoot = $AppRoot
            SkipHistory = $true; SkipManifest = $true; SkipEmbed = $true
            WarningAction = 'SilentlyContinue'
        }
        Mock Write-Host {}
    }

    It 'creates a placeholder when the notification file is missing' {
        Update-EntraOpsClassificationExplorerData @script:Parameters

        Get-Content -LiteralPath $script:NotificationPath -Raw | Should -Match 'window\.EOCE_NOTIFICATION_DATA = null;'
        [System.IO.File]::ReadAllBytes($script:HistoryPath) | Should -Be $script:OriginalHistory
    }

    It 'preserves an existing notification summary byte for byte' {
        $Summary = 'window.EOCE_NOTIFICATION_DATA = {"sources":{"EntraID":{"commits":[{"added":[1,2,3,4]}]}}};'
        Set-Content -LiteralPath $script:NotificationPath -Value $Summary -NoNewline
        $Original = [System.IO.File]::ReadAllBytes($script:NotificationPath)

        Update-EntraOpsClassificationExplorerData @script:Parameters

        [System.IO.File]::ReadAllBytes($script:NotificationPath) | Should -Be $Original
        [System.IO.File]::ReadAllBytes($script:HistoryPath) | Should -Be $script:OriginalHistory
    }

    It 'does not create the placeholder with WhatIf' {
        Update-EntraOpsClassificationExplorerData @script:Parameters -WhatIf

        Test-Path -LiteralPath $script:NotificationPath | Should -BeFalse
    }

    It 'preserves existing notifications with WhatIf' {
        Set-Content -LiteralPath $script:NotificationPath -Value 'window.EOCE_NOTIFICATION_DATA = {"sources":{}};'
        $Original = [System.IO.File]::ReadAllBytes($script:NotificationPath)

        Update-EntraOpsClassificationExplorerData @script:Parameters -WhatIf

        [System.IO.File]::ReadAllBytes($script:NotificationPath) | Should -Be $Original
    }
}
