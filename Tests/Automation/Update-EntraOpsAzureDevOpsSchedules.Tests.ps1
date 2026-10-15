#Requires -Modules Pester

BeforeDiscovery {
    # .azure-pipelines is not part of the default Update-EntraOps targets, so deployments may not ship it.
    $HasAdoPipelines = Test-Path -LiteralPath (Join-Path $PSScriptRoot '../../.azure-pipelines') -PathType Container
    # Deployments of pre-release versions can keep pipelines with former file names (azure-pipelines-*.yml).
    $IsConfiguredDeployment = Test-Path -LiteralPath (Join-Path $PSScriptRoot '../../EntraOpsConfig.json')
    $HasOutdatedDeploymentPipelines = $IsConfiguredDeployment -and @(
        'entraops-pull.yml', 'entraops-push-reporting.yml', 'entraops-update.yml', 'entraops-pull-tenant-governance.yml' |
        Where-Object { -not (Test-Path -LiteralPath (Join-Path $PSScriptRoot "../../.azure-pipelines/$_") -PathType Leaf) }
    ).Count -gt 0
    $SkipScheduleTests = -not $HasAdoPipelines -or $HasOutdatedDeploymentPipelines
}

BeforeAll {
    $script:RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $script:RepositoryRoot 'EntraOps/EntraOps.psd1') -Force

    function New-AdoScheduleFixture {
        param ([Parameter(Mandatory = $true)][string]$Root)

        $PipelineFolder = Join-Path $Root '.azure-pipelines'
        New-Item -Path $PipelineFolder -ItemType Directory -Force | Out-Null
        Get-ChildItem -Path (Join-Path $script:RepositoryRoot '.azure-pipelines') -Filter '*.yml' |
        Copy-Item -Destination $PipelineFolder -Force

        $ConfigPath = Join-Path $Root 'EntraOpsConfig.json'
        [ordered]@{
            WorkflowTrigger          = [ordered]@{
                PullScheduledTrigger          = $true
                PullScheduledCron             = '15 4 * * *'
                PushReportingScheduledTrigger = $true
                PushReportingScheduledCron    = '45 5 * * 1'
            }
            AutomatedEntraOpsUpdate  = [ordered]@{
                UpdateScheduledTrigger = $true
                UpdateScheduledCron    = '30 6 * * 3'
            }
            TenantGovernanceSnapshot = [ordered]@{
                EnableTenantGovernanceSnapshot      = $true
                SnapshotScheduledTrigger            = $true
                SnapshotScheduledCron               = '0 1 * * *'
                SnapshotScheduledCronComplete       = '0 2 * * *'
                SnapshotScheduledCronCompleteRetry1 = '30 2 * * *'
                SnapshotScheduledCronCompleteRetry2 = '0 3 * * *'
            }
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8

        return @{ ConfigPath = $ConfigPath; PipelineFolder = $PipelineFolder }
    }
}

Describe 'Update-EntraOpsAzureDevOpsSchedules' {
    It 'is exported by the EntraOps module' {
        Get-Command Update-EntraOpsAzureDevOpsSchedules -Module EntraOps | Should -Not -BeNullOrEmpty
    }

    It 'materializes every configured schedule and target branch' -Skip:$SkipScheduleTests {
        $Fixture = New-AdoScheduleFixture -Root (Join-Path $TestDrive 'enabled')

        Update-EntraOpsAzureDevOpsSchedules -ConfigFile $Fixture.ConfigPath -PipelineFolder $Fixture.PipelineFolder -BranchName 'production'

        $Pull = Get-Content -LiteralPath (Join-Path $Fixture.PipelineFolder 'entraops-pull.yml') -Raw
        $Reporting = Get-Content -LiteralPath (Join-Path $Fixture.PipelineFolder 'entraops-push-reporting.yml') -Raw
        $Update = Get-Content -LiteralPath (Join-Path $Fixture.PipelineFolder 'entraops-update.yml') -Raw
        $TenantGovernance = Get-Content -LiteralPath (Join-Path $Fixture.PipelineFolder 'entraops-pull-tenant-governance.yml') -Raw

        $Pull | Should -Match "cron: '15 4 \* \* \*'"
        $Reporting | Should -Match "cron: '45 5 \* \* 1'"
        $Update | Should -Match "cron: '30 6 \* \* 3'"
        @([regex]::Matches($TenantGovernance, '(?m)^- cron:')).Count | Should -Be 4
        @($Pull, $Reporting, $Update, $TenantGovernance) | ForEach-Object { $_ | Should -Match "- 'production'" }
    }

    It 'removes managed schedules when their switches are disabled' -Skip:$SkipScheduleTests {
        $Fixture = New-AdoScheduleFixture -Root (Join-Path $TestDrive 'disabled')
        $Config = Get-Content -LiteralPath $Fixture.ConfigPath -Raw | ConvertFrom-Json
        $Config.WorkflowTrigger.PullScheduledTrigger = $false
        $Config.WorkflowTrigger.PushReportingScheduledTrigger = $false
        $Config.AutomatedEntraOpsUpdate.UpdateScheduledTrigger = $false
        $Config.TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot = $false
        $Config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Fixture.ConfigPath -Encoding UTF8

        Update-EntraOpsAzureDevOpsSchedules -ConfigFile $Fixture.ConfigPath -PipelineFolder $Fixture.PipelineFolder

        Get-ChildItem -Path $Fixture.PipelineFolder -Filter '*.yml' | ForEach-Object {
            (Get-Content -LiteralPath $_.FullName -Raw) | Should -Not -Match '(?m)^schedules:'
        }
    }

    It 'is idempotent' -Skip:$SkipScheduleTests {
        $Fixture = New-AdoScheduleFixture -Root (Join-Path $TestDrive 'idempotent')

        Update-EntraOpsAzureDevOpsSchedules -ConfigFile $Fixture.ConfigPath -PipelineFolder $Fixture.PipelineFolder
        $FirstRun = Get-ChildItem -Path $Fixture.PipelineFolder -Filter '*.yml' | Sort-Object Name | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }
        Update-EntraOpsAzureDevOpsSchedules -ConfigFile $Fixture.ConfigPath -PipelineFolder $Fixture.PipelineFolder
        $SecondRun = Get-ChildItem -Path $Fixture.PipelineFolder -Filter '*.yml' | Sort-Object Name | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }

        $SecondRun | Should -BeExactly $FirstRun
    }

    It 'writes the configured service connection into every pipeline that signs in to Azure' -Skip:$SkipScheduleTests {
        $Fixture = New-AdoScheduleFixture -Root (Join-Path $TestDrive 'service-connection')
        $Config = Get-Content -LiteralPath $Fixture.ConfigPath -Raw | ConvertFrom-Json
        $Config | Add-Member -NotePropertyName AzureDevOpsServiceConnection -NotePropertyValue "Contoso's EntraOps"
        $Config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Fixture.ConfigPath -Encoding UTF8

        Update-EntraOpsAzureDevOpsSchedules -ConfigFile $Fixture.ConfigPath -PipelineFolder $Fixture.PipelineFolder

        Import-Module powershell-yaml -ErrorAction Stop
        foreach ($PipelineName in 'entraops-pull.yml', 'entraops-push.yml', 'entraops-push-reporting.yml', 'entraops-pull-tenant-governance.yml') {
            $Pipeline = Get-Content -LiteralPath (Join-Path $Fixture.PipelineFolder $PipelineName) -Raw | ConvertFrom-Yaml
            ($Pipeline.parameters | Where-Object name -EQ 'serviceConnection').default | Should -BeExactly "Contoso's EntraOps" -Because $PipelineName
        }
        Get-Content -LiteralPath (Join-Path $Fixture.PipelineFolder 'entraops-update.yml') -Raw | Should -Not -Match 'serviceConnection'
    }

    It 'uses the default service connection when the configuration does not define one' -Skip:$SkipScheduleTests {
        $Fixture = New-AdoScheduleFixture -Root (Join-Path $TestDrive 'service-connection-default')

        Update-EntraOpsAzureDevOpsSchedules -ConfigFile $Fixture.ConfigPath -PipelineFolder $Fixture.PipelineFolder

        Get-Content -LiteralPath (Join-Path $Fixture.PipelineFolder 'entraops-pull.yml') -Raw | Should -Match "default: 'EntraOps-ServiceConnection'"
    }

    It 'rejects a multi-line service connection name' -Skip:$SkipScheduleTests {
        $Fixture = New-AdoScheduleFixture -Root (Join-Path $TestDrive 'service-connection-invalid')
        $Config = Get-Content -LiteralPath $Fixture.ConfigPath -Raw | ConvertFrom-Json
        $Config | Add-Member -NotePropertyName AzureDevOpsServiceConnection -NotePropertyValue "EntraOps`nschedules:"
        $Config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Fixture.ConfigPath -Encoding UTF8

        $PullPath = Join-Path $Fixture.PipelineFolder 'entraops-pull.yml'
        $Before = Get-Content -LiteralPath $PullPath -Raw

        { Update-EntraOpsAzureDevOpsSchedules -ConfigFile $Fixture.ConfigPath -PipelineFolder $Fixture.PipelineFolder } |
        Should -Throw '*single-line service connection name*'
        Get-Content -LiteralPath $PullPath -Raw | Should -BeExactly $Before
    }

    It 'rejects a malformed cron before changing its pipeline' -Skip:$SkipScheduleTests {
        $Fixture = New-AdoScheduleFixture -Root (Join-Path $TestDrive 'invalid')
        $PullPath = Join-Path $Fixture.PipelineFolder 'entraops-pull.yml'
        $Before = Get-Content -LiteralPath $PullPath -Raw
        $Config = Get-Content -LiteralPath $Fixture.ConfigPath -Raw | ConvertFrom-Json
        $Config.WorkflowTrigger.PullScheduledCron = 'not-a-cron'
        $Config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Fixture.ConfigPath -Encoding UTF8

        { Update-EntraOpsAzureDevOpsSchedules -ConfigFile $Fixture.ConfigPath -PipelineFolder $Fixture.PipelineFolder } |
        Should -Throw '*five-field cron expression*'
        Get-Content -LiteralPath $PullPath -Raw | Should -BeExactly $Before
    }
}