#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $RepositoryRoot = $script:TestRepositoryRoot
    $YamlModuleAvailable = [bool](Get-Module -ListAvailable -Name powershell-yaml)

    function New-WorkflowFixture {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Root
        )

        Copy-Item -Path (Join-Path $script:TestRepositoryRoot '.github') -Destination $Root -Recurse -Force
        $ConfigPath = Join-Path $Root 'EntraOpsConfig.json'
        @{
            TenantId                      = '11111111-1111-1111-1111-111111111111'
            TenantName                    = 'contoso.onmicrosoft.com'
            ClientId                      = '22222222-2222-2222-2222-222222222222'
            AuthenticationType            = 'FederatedCredentials'
            AutomatedEntraOpsUpdate       = @{
                ApplyAutomatedEntraOpsUpdate = $false
                UpdateScheduledTrigger       = $false
                UpdateScheduledCron          = '0 9 * * 3'
                Branch                       = 'main'
            }
            AutomatedReportingGeneration  = @{
                ApplyAutomatedReportingGeneration = $false
                PublishReportsAsRelease           = $false
                ReportingReleasesToKeep           = 10
            }
            AutomatedElmCatalogProtection = @{
                ApplyPrivilegedElmCatalogProtection = $false
            }
            WorkflowTrigger               = @{
                PullScheduledTrigger                  = $true
                PullScheduledCron                     = '30 9 * * *'
                PushAfterPullWorkflowTrigger          = $true
                PushReportingAfterPullWorkflowTrigger = $true
                PushReportingScheduledTrigger         = $false
                PushReportingScheduledCron            = '0 9 * * 1'
            }
            TenantGovernanceSnapshot      = @{
                EnableTenantGovernanceSnapshot       = $false
                SnapshotScheduledTrigger             = $true
                SnapshotScheduledCron                = '0 6 * * *'
                SnapshotScheduledCronComplete        = '0 7 * * *'
                SnapshotScheduledCronCompleteRetry1  = '30 7 * * *'
                SnapshotScheduledCronCompleteRetry2  = '0 8 * * *'
            }
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8

        return $ConfigPath
    }
}

Describe 'Update-EntraOpsRequiredWorkflowParameters' -Skip:(-not [bool](Get-Module -ListAvailable -Name powershell-yaml)) {
    BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps') -Force
    }

    It 'materializes the deployment workflows without failing on CI workflows' {
        $FixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -Path $FixtureRoot -ItemType Directory -Force | Out-Null
        $ConfigPath = New-WorkflowFixture -Root $FixtureRoot

        Push-Location $FixtureRoot
        try {
            { Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop } | Should -Not -Throw
        } finally {
            Pop-Location
        }

        $UpdateWorkflow = Get-Content -LiteralPath (Join-Path $FixtureRoot '.github/workflows/Update-EntraOps.yaml') -Raw
        $UpdateWorkflow | Should -Match 'ClientId:\s*22222222-2222-2222-2222-222222222222'
        $UpdateWorkflow | Should -Match 'TenantName:\s*contoso\.onmicrosoft\.com'
        # Older configurations receive safe defaults for the newly introduced validation options.
        $UpdateWorkflow | Should -Match 'ValidationFrequency:\s*OnChange'
        $UpdateWorkflow | Should -Match 'RunBrowserTests:\s*true'
        $UpdateWorkflow | Should -Match 'PublicationMode:\s*PullRequest'
        $UpdateWorkflowObject = Get-Content -LiteralPath (Join-Path $FixtureRoot '.github/workflows/Update-EntraOps.yaml') -Raw | ConvertFrom-Yaml
        $PublicationInput = $UpdateWorkflowObject['on'].workflow_dispatch.inputs.publication_mode
        $PublicationInput.default | Should -Be 'configured'
        @($PublicationInput.options) | Should -Contain 'pull-request'
        @($PublicationInput.options) | Should -Contain 'direct-push'
        $ValidationInput = ($UpdateWorkflow -split '(?m)^      validation_required:\s*$')[1] -split '(?m)^      run_browser_tests:\s*$' | Select-Object -First 1
        $BrowserInput = ($UpdateWorkflow -split '(?m)^      run_browser_tests:\s*$')[1] -split '(?m)^  # The schedule trigger' | Select-Object -First 1
        foreach ($OverrideInput in @($ValidationInput, $BrowserInput)) {
            $OverrideInput | Should -Match 'default:\s*configured'
            $OverrideInput | Should -Match 'type:\s*choice'
            $OverrideInput | Should -Match '-\s+"true"'
            $OverrideInput | Should -Match '-\s+"false"'
        }

        $ReportingWorkflow = Get-Content -LiteralPath (Join-Path $FixtureRoot '.github/workflows/Push-EntraOpsPrivilegedReporting.yaml') -Raw
        $ReportingWorkflow | Should -Match 'ClassificationExplorerGenerateChangeHistory:\s*false'
    }

    It 'materializes an enabled Classification Explorer history setting for checkout depth' {
        $FixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -Path $FixtureRoot -ItemType Directory -Force | Out-Null
        $ConfigPath = New-WorkflowFixture -Root $FixtureRoot
        $Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        $Config | Add-Member -NotePropertyName ClassificationExplorer -NotePropertyValue ([pscustomobject]@{ GenerateChangeHistory = $true })
        $Config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8

        Push-Location $FixtureRoot
        try {
            Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop
        } finally {
            Pop-Location
        }

        $ReportingWorkflow = Get-Content -LiteralPath (Join-Path $FixtureRoot '.github/workflows/Push-EntraOpsPrivilegedReporting.yaml') -Raw
        $ReportingWorkflow | Should -Match 'ClassificationExplorerGenerateChangeHistory:\s*true'
    }

    It 'does not schedule Tenant Governance while its master switch is disabled' {
        $FixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -Path $FixtureRoot -ItemType Directory -Force | Out-Null
        $ConfigPath = New-WorkflowFixture -Root $FixtureRoot

        Push-Location $FixtureRoot
        try {
            Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop
        } finally {
            Pop-Location
        }

        $WorkflowObject = Get-Content -LiteralPath (Join-Path $FixtureRoot '.github/workflows/Pull-EntraOpsTenantGovernance.yaml') -Raw | ConvertFrom-Yaml
        $WorkflowObject['on'].Contains('schedule') | Should -BeFalse
        $WorkflowObject.env.EnableTenantGovernanceSnapshot | Should -BeFalse
    }

    It 'adds all Tenant Governance schedules when the feature and trigger are enabled' {
        $FixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -Path $FixtureRoot -ItemType Directory -Force | Out-Null
        $ConfigPath = New-WorkflowFixture -Root $FixtureRoot
        $Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        $Config.TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot = $true
        $Config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8

        Push-Location $FixtureRoot
        try {
            Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop
        } finally {
            Pop-Location
        }

        $WorkflowObject = Get-Content -LiteralPath (Join-Path $FixtureRoot '.github/workflows/Pull-EntraOpsTenantGovernance.yaml') -Raw | ConvertFrom-Yaml
        @($WorkflowObject['on'].schedule).Count | Should -Be 4
        @($WorkflowObject['on'].schedule.cron) | Should -Be @('0 6 * * *', '0 7 * * *', '30 7 * * *', '0 8 * * *')
        $WorkflowObject.env.EnableTenantGovernanceSnapshot | Should -BeTrue
    }

    It 'materializes configured update validation options' {
        $FixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -Path $FixtureRoot -ItemType Directory -Force | Out-Null
        $ConfigPath = New-WorkflowFixture -Root $FixtureRoot
        $Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        $Config.AutomatedEntraOpsUpdate | Add-Member -NotePropertyName ValidationFrequency -NotePropertyValue Never
        $Config.AutomatedEntraOpsUpdate | Add-Member -NotePropertyName RunBrowserTests -NotePropertyValue $false
        $Config.AutomatedEntraOpsUpdate | Add-Member -NotePropertyName PublicationMode -NotePropertyValue DirectPush
        $Config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8

        Push-Location $FixtureRoot
        try {
            Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop
        } finally {
            Pop-Location
        }

        $UpdateWorkflow = Get-Content -LiteralPath (Join-Path $FixtureRoot '.github/workflows/Update-EntraOps.yaml') -Raw
        $UpdateWorkflow | Should -Match 'ValidationFrequency:\s*Never'
        $UpdateWorkflow | Should -Match 'RunBrowserTests:\s*false'
        $UpdateWorkflow | Should -Match 'PublicationMode:\s*DirectPush'
    }

    It 'rejects invalid update validation options' {
        $FixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -Path $FixtureRoot -ItemType Directory -Force | Out-Null
        $ConfigPath = New-WorkflowFixture -Root $FixtureRoot
        $Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        $Config.AutomatedEntraOpsUpdate | Add-Member -NotePropertyName ValidationFrequency -NotePropertyValue Sometimes
        $Config.AutomatedEntraOpsUpdate | Add-Member -NotePropertyName RunBrowserTests -NotePropertyValue 'false'
        $Config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8

        Push-Location $FixtureRoot
        try {
            { Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop } |
                Should -Throw '*ValidationFrequency*'

            $Config.AutomatedEntraOpsUpdate.ValidationFrequency = 'OnChange'
            $Config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
            { Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop } |
                Should -Throw '*RunBrowserTests*JSON boolean*'

            $Config.AutomatedEntraOpsUpdate.RunBrowserTests = $true
            $Config.AutomatedEntraOpsUpdate | Add-Member -NotePropertyName PublicationMode -NotePropertyValue MergeQueue
            $Config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
            { Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop } |
                Should -Throw '*PublicationMode*'
        } finally {
            Pop-Location
        }
    }

    It 'leaves the CI test workflow byte-identical' {
        $FixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -Path $FixtureRoot -ItemType Directory -Force | Out-Null
        $ConfigPath = New-WorkflowFixture -Root $FixtureRoot

        $TestWorkflowPath = Join-Path $FixtureRoot '.github/workflows/Test-EntraOps.yaml'
        $Before = Get-Content -LiteralPath $TestWorkflowPath -Raw

        Push-Location $FixtureRoot
        try {
            Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop
        } finally {
            Pop-Location
        }

        Get-Content -LiteralPath $TestWorkflowPath -Raw | Should -BeExactly $Before
    }

    It 'preserves immutable action version annotations' {
        $FixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -Path $FixtureRoot -ItemType Directory -Force | Out-Null
        $ConfigPath = New-WorkflowFixture -Root $FixtureRoot

        Push-Location $FixtureRoot
        try {
            Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop
            { & (Join-Path $FixtureRoot '.github/scripts/Test-GitHubActionReferences.ps1') -RepositoryRoot $FixtureRoot } |
            Should -Not -Throw
        } finally {
            Pop-Location
        }
    }

    It 'is idempotent across repeated runs' {
        $FixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -Path $FixtureRoot -ItemType Directory -Force | Out-Null
        $ConfigPath = New-WorkflowFixture -Root $FixtureRoot

        Push-Location $FixtureRoot
        try {
            Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop
            $FirstRun = Get-ChildItem -Path (Join-Path $FixtureRoot '.github/workflows') -Filter '*.yaml' |
            ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }

            Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop
            $SecondRun = Get-ChildItem -Path (Join-Path $FixtureRoot '.github/workflows') -Filter '*.yaml' |
            ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }
        } finally {
            Pop-Location
        }

        $SecondRun | Should -BeExactly $FirstRun
    }

    It 'restores a schedule trigger that was previously disabled' {
        $FixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -Path $FixtureRoot -ItemType Directory -Force | Out-Null
        $ConfigPath = New-WorkflowFixture -Root $FixtureRoot
        $UpdateWorkflowPath = Join-Path $FixtureRoot '.github/workflows/Update-EntraOps.yaml'

        Push-Location $FixtureRoot
        try {
            Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop
            Get-Content -LiteralPath $UpdateWorkflowPath -Raw | Should -Not -Match 'schedule:'

            $Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
            $Config.AutomatedEntraOpsUpdate.UpdateScheduledTrigger = $true
            $Config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8

            Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop
        } finally {
            Pop-Location
        }

        $UpdateWorkflow = Get-Content -LiteralPath $UpdateWorkflowPath -Raw
        $UpdateWorkflow | Should -Match 'schedule:'
        $UpdateWorkflow | Should -Match 'cron: 0 9 \* \* 3'
    }

    It 'persists false automation and release switches over permissive workflow defaults' {
        $FixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -Path $FixtureRoot -ItemType Directory -Force | Out-Null
        $ConfigPath = New-WorkflowFixture -Root $FixtureRoot
        $ReportingWorkflowPath = Join-Path $FixtureRoot '.github/workflows/Push-EntraOpsPrivilegedReporting.yaml'
        $PushWorkflowPath = Join-Path $FixtureRoot '.github/workflows/Push-EntraOpsPrivilegedEAM.yaml'

        # The shipped templates already default these to false, so seed the permissive value the
        # reconciler has to overwrite - otherwise the assertions below would pass without it running.
        (Get-Content -LiteralPath $ReportingWorkflowPath -Raw) `
            -replace '(?m)^(\s*ApplyAutomatedReportingGeneration:\s*)false(?=\r?$)', '${1}true' `
            -replace '(?m)^(\s*PublishReportsAsRelease:\s*)false(?=\r?$)', '${1}true' |
        Set-Content -LiteralPath $ReportingWorkflowPath -Encoding UTF8
        (Get-Content -LiteralPath $PushWorkflowPath -Raw) `
            -replace '(?m)^(\s*ApplyPrivilegedElmCatalogProtection:\s*)false(?=\r?$)', '${1}true' |
        Set-Content -LiteralPath $PushWorkflowPath -Encoding UTF8

        Get-Content -LiteralPath $ReportingWorkflowPath -Raw | Should -Match 'ApplyAutomatedReportingGeneration:\s*true'
        Get-Content -LiteralPath $PushWorkflowPath -Raw | Should -Match 'ApplyPrivilegedElmCatalogProtection:\s*true'

        Push-Location $FixtureRoot
        try {
            Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop
        } finally {
            Pop-Location
        }

        $ReportingWorkflow = Get-Content -LiteralPath $ReportingWorkflowPath -Raw
        $PushWorkflow = Get-Content -LiteralPath $PushWorkflowPath -Raw
        $ReportingWorkflow | Should -Match 'ApplyAutomatedReportingGeneration:\s*false'
        $ReportingWorkflow | Should -Match 'PublishReportsAsRelease:\s*false'
        $PushWorkflow | Should -Match 'ApplyPrivilegedElmCatalogProtection:\s*false'
    }

    It 'restores workflow_run triggers after they were disabled' {
        $FixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -Path $FixtureRoot -ItemType Directory -Force | Out-Null
        $ConfigPath = New-WorkflowFixture -Root $FixtureRoot
        $PushWorkflowPath = Join-Path $FixtureRoot '.github/workflows/Push-EntraOpsPrivilegedEAM.yaml'
        $ReportingWorkflowPath = Join-Path $FixtureRoot '.github/workflows/Push-EntraOpsPrivilegedReporting.yaml'

        Push-Location $FixtureRoot
        try {
            $Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
            $Config.WorkflowTrigger.PushAfterPullWorkflowTrigger = $false
            $Config.WorkflowTrigger.PushReportingAfterPullWorkflowTrigger = $false
            $Config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
            Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop
            Get-Content -LiteralPath $PushWorkflowPath -Raw | Should -Not -Match 'workflow_run:'
            Get-Content -LiteralPath $ReportingWorkflowPath -Raw | Should -Not -Match 'workflow_run:'

            $Config.WorkflowTrigger.PushAfterPullWorkflowTrigger = $true
            $Config.WorkflowTrigger.PushReportingAfterPullWorkflowTrigger = $true
            $Config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
            Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop
        } finally {
            Pop-Location
        }

        Get-Content -LiteralPath $PushWorkflowPath -Raw | Should -Match 'workflow_run:'
        Get-Content -LiteralPath $ReportingWorkflowPath -Raw | Should -Match 'workflow_run:'
    }

    It 'keeps an explicitly empty release retention and falls back only when it is absent' {
        $FixtureRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -Path $FixtureRoot -ItemType Directory -Force | Out-Null
        $ConfigPath = New-WorkflowFixture -Root $FixtureRoot
        $ReportingWorkflowPath = Join-Path $FixtureRoot '.github/workflows/Push-EntraOpsPrivilegedReporting.yaml'

        Push-Location $FixtureRoot
        try {
            $Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
            $Config.AutomatedReportingGeneration.ReportingReleasesToKeep = ''
            $Config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
            Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop
            Get-Content -LiteralPath $ReportingWorkflowPath -Raw | Should -Match 'ReportingReleasesToKeep:\s*[''"]{2}'

            $Config.AutomatedReportingGeneration.PSObject.Properties.Remove('ReportingReleasesToKeep')
            $Config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
            Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigPath -ErrorAction Stop
        } finally {
            Pop-Location
        }

        Get-Content -LiteralPath $ReportingWorkflowPath -Raw | Should -Match 'ReportingReleasesToKeep:\s*[''"]?10'
    }
}

