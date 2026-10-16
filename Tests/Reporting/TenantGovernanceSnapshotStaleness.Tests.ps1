#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue

    function New-StalenessTestConfig {
        param([string]$Path, [string]$Action, [string]$Cron = '0 6 * * *', $MaxAgeHours)
        $ConfigurationAnalyzer = @{ AllowPartialTenantGovernanceSnapshot = $true }
        if ($Action) { $ConfigurationAnalyzer.StaleTenantGovernanceSnapshotAction = $Action }
        if ($null -ne $MaxAgeHours) { $ConfigurationAnalyzer.MaxTenantGovernanceSnapshotAgeHours = $MaxAgeHours }
        @{
            TenantName                   = 'contoso.onmicrosoft.com'
            AutomatedReportingGeneration = @{
                ApplyAutomatedReportingGeneration = $true
                GenerateClassificationExplorer    = $false
                GenerateTierBreachAnalyzer        = $false
                GenerateEamDashboard              = $false
                GenerateAccessPathMap             = $false
                GeneratePrivilegeHistory          = $false
                GenerateConfigurationAnalyzer     = $true
                GenerateAccessPackageFlow         = $false
                GeneratePrivilegedAssets          = $false
            }
            TenantGovernanceSnapshot     = @{ EnableTenantGovernanceSnapshot = $true; SnapshotScheduledCron = $Cron }
            PrivilegeHistory             = @{ EnablePrivilegeHistory = $false }
            ConfigurationAnalyzer        = $ConfigurationAnalyzer
        } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path
    }

    function Invoke-WithSnapshotAge {
        param([double]$AgeHours, [scriptblock]$ScriptBlock)
        $Root = Join-Path $TestDrive ([guid]::NewGuid())
        $SnapshotFolder = Join-Path $Root 'TenantGovernance/Snapshots'
        New-Item -Path $SnapshotFolder -ItemType Directory -Force | Out-Null
        @{
            SnapshotJobStatus = 'succeeded'
            IsComplete        = $true
            CapturedDateTime  = (Get-Date).ToUniversalTime().AddHours(-1 * $AgeHours).ToString('o')
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $SnapshotFolder '.SnapshotManifest.json')
        $PreviousBaseFolder = InModuleScope EntraOps { $EntraOpsBaseFolder }
        try {
            InModuleScope EntraOps -Parameters @{ Path = $Root } { param($Path) Set-Variable -Name EntraOpsBaseFolder -Value $Path -Scope Script -Force }
            & $ScriptBlock
        } finally {
            InModuleScope EntraOps -Parameters @{ Path = $PreviousBaseFolder } { param($Path) Set-Variable -Name EntraOpsBaseFolder -Value $Path -Scope Script -Force }
        }
    }
}

Describe 'Resolve-EntraOpsTenantGovernanceSnapshotMaxAge' {
    It 'derives <Expected> hours from the snapshot schedule <Cron>' -TestCases @(
        @{ Cron = '0 6 * * *'; Expected = 30 }
        @{ Cron = '0 6 * * 5'; Expected = 174 }
        @{ Cron = '0 6 1 * *'; Expected = 750 }
        @{ Cron = ''; Expected = 30 }
    ) {
        param($Cron, $Expected)
        InModuleScope EntraOps -Parameters @{ Cron = $Cron; Expected = $Expected } {
            param($Cron, $Expected)
            $Config = [pscustomobject]@{ TenantGovernanceSnapshot = [pscustomobject]@{ SnapshotScheduledCron = $Cron } }
            Resolve-EntraOpsTenantGovernanceSnapshotMaxAge -Config $Config | Should -Be $Expected
        }
    }

    It 'prefers the configured maximum age and rejects invalid values' {
        InModuleScope EntraOps {
            $Config = [pscustomobject]@{
                ConfigurationAnalyzer    = [pscustomobject]@{ MaxTenantGovernanceSnapshotAgeHours = 48 }
                TenantGovernanceSnapshot = [pscustomobject]@{ SnapshotScheduledCron = '0 6 * * 5' }
            }
            Resolve-EntraOpsTenantGovernanceSnapshotMaxAge -Config $Config | Should -Be 48
            $Config.ConfigurationAnalyzer.MaxTenantGovernanceSnapshotAgeHours = 0
            { Resolve-EntraOpsTenantGovernanceSnapshotMaxAge -Config $Config } | Should -Throw '*between 1 and 8760*'
            Resolve-EntraOpsTenantGovernanceSnapshotMaxAge -Config $null | Should -Be 30
        }
    }
}

Describe 'Invoke-EntraOpsReportingGeneration with a stale Tenant Governance snapshot' {
    BeforeEach {
        $script:ConfigPath = Join-Path $TestDrive "$([guid]::NewGuid()).json"
        Mock Connect-EntraOps -ModuleName EntraOps {}
        Mock Disconnect-EntraOps -ModuleName EntraOps {}
        Mock New-EntraOpsReportingData -ModuleName EntraOps { @() }
    }

    It 'generates the Configuration Analyzer and marks the snapshot as stale with the default action Warn' {
        New-StalenessTestConfig -Path $script:ConfigPath
        Invoke-WithSnapshotAge -AgeHours 41 {
            $Warnings = @()
            $Result = Invoke-EntraOpsReportingGeneration -ConfigFilePath $script:ConfigPath -WarningVariable +Warnings -WarningAction SilentlyContinue
            $Result.Status | Should -Be 'Generated'
            ($Warnings.Message -join "`n") | Should -Match 'StaleTenantGovernanceSnapshotAction = Warn'
        }
        Should -Invoke New-EntraOpsReportingData -ModuleName EntraOps -Times 1 -ParameterFilter {
            -not $SkipConfigurationAnalyzer -and $AllowStaleTenantGovernanceSnapshot -and $ConfigurationAnalyzerMaxSnapshotAgeHours -eq 30
        }
    }

    It 'skips only the Configuration Analyzer with the action Skip' {
        New-StalenessTestConfig -Path $script:ConfigPath -Action 'Skip'
        Invoke-WithSnapshotAge -AgeHours 41 {
            Invoke-EntraOpsReportingGeneration -ConfigFilePath $script:ConfigPath -WarningAction SilentlyContinue | Out-Null
        }
        Should -Invoke Connect-EntraOps -ModuleName EntraOps -Times 0
        Should -Invoke New-EntraOpsReportingData -ModuleName EntraOps -Times 1 -ParameterFilter { $SkipConfigurationAnalyzer }
    }

    It 'fails before connecting with the action Fail' {
        New-StalenessTestConfig -Path $script:ConfigPath -Action 'Fail'
        Invoke-WithSnapshotAge -AgeHours 41 {
            { Invoke-EntraOpsReportingGeneration -ConfigFilePath $script:ConfigPath } | Should -Throw '*exceeding the 30-hour limit*'
        }
        Should -Invoke Connect-EntraOps -ModuleName EntraOps -Times 0
        Should -Invoke New-EntraOpsReportingData -ModuleName EntraOps -Times 0
    }

    It 'does not treat a snapshot of a weekly schedule as stale within the week' {
        New-StalenessTestConfig -Path $script:ConfigPath -Action 'Fail' -Cron '0 6 * * 5'
        Invoke-WithSnapshotAge -AgeHours 100 {
            $Warnings = @()
            Invoke-EntraOpsReportingGeneration -ConfigFilePath $script:ConfigPath -WarningVariable +Warnings | Out-Null
            ($Warnings.Message -join "`n") | Should -Not -Match 'hour\(s\) old'
        }
        # Decided once before the run: a snapshot crossing the limit while other reports are generated must not fail the run.
        Should -Invoke New-EntraOpsReportingData -ModuleName EntraOps -Times 1 -ParameterFilter {
            -not $SkipConfigurationAnalyzer -and $AllowStaleTenantGovernanceSnapshot -and $ConfigurationAnalyzerMaxSnapshotAgeHours -eq 174
        }
    }

    It 'lets an explicit manual override win over the action Fail' {
        New-StalenessTestConfig -Path $script:ConfigPath -Action 'Fail'
        Invoke-WithSnapshotAge -AgeHours 41 {
            { Invoke-EntraOpsReportingGeneration -ConfigFilePath $script:ConfigPath -AllowStaleTenantGovernanceSnapshot $true } | Should -Not -Throw
        }
        Should -Invoke New-EntraOpsReportingData -ModuleName EntraOps -Times 1 -ParameterFilter {
            -not $SkipConfigurationAnalyzer -and $AllowStaleTenantGovernanceSnapshot
        }
    }

    It 'applies the configured action when the pipeline passes no override' {
        New-StalenessTestConfig -Path $script:ConfigPath -Action 'Fail'
        Invoke-WithSnapshotAge -AgeHours 41 {
            { Invoke-EntraOpsReportingGeneration -ConfigFilePath $script:ConfigPath -AllowStaleTenantGovernanceSnapshot $false } | Should -Throw '*exceeding the 30-hour limit*'
        }
    }

    It 'rejects an unknown stale snapshot action' {
        New-StalenessTestConfig -Path $script:ConfigPath -Action 'Ignore'
        { Invoke-EntraOpsReportingGeneration -ConfigFilePath $script:ConfigPath } | Should -Throw "*must be 'Warn', 'Skip' or 'Fail'*"
    }
}

Describe 'New-EntraOpsReportingData Configuration Analyzer bounds' {
    BeforeAll {
        $script:OriginalBaseFolder = $Global:EntraOpsBaseFolder
    }

    AfterAll {
        $Global:EntraOpsBaseFolder = $script:OriginalBaseFolder
    }

    BeforeEach {
        $script:Workspace = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $Global:EntraOpsBaseFolder = $script:Workspace
        New-Item -ItemType Directory -Path "$script:Workspace/Reports/ConfigurationAnalyzer", "$script:Workspace/TenantGovernance/Snapshots" -Force | Out-Null
        Set-Content -LiteralPath "$script:Workspace/Reports/index.html" -Value 'portal'
        Set-Content -LiteralPath "$script:Workspace/Reports/ConfigurationAnalyzer/index.html" -Value 'app'
        $script:ReportingConfigPath = Join-Path $script:Workspace 'EntraOpsConfig.json'
        $script:Parameters = @{
            ConfigFilePath             = $script:ReportingConfigPath
            SkipClassificationExplorer = $true
            SkipTierBreachAnalyzer     = $true
            SkipEamDashboard           = $true
            SkipPrivilegedAssets       = $true
            SkipAccessPathMap          = $true
            SkipPrivilegeHistory       = $true
            SkipAccessPackageFlow      = $true
        }
        Mock -ModuleName EntraOps New-EntraOpsTenantGovernanceConfigurationAnalyzerData {}
        Mock -ModuleName EntraOps Write-Host {}
    }

    It 'bounds the dataset to 365 days and weekly snapshots when the configuration has no settings' {
        @{ TenantGovernanceSnapshot = @{ SnapshotScheduledCron = '0 6 * * 5' } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:ReportingConfigPath

        New-EntraOpsReportingData @script:Parameters

        Should -Invoke -ModuleName EntraOps New-EntraOpsTenantGovernanceConfigurationAnalyzerData -Times 1 -Exactly -ParameterFilter {
            $TimeRangeInDays -eq 365 -and $SnapshotInterval -eq 'P1W' -and $MaxSnapshotAgeHours -eq 174
        }
    }

    It 'derives the snapshot age limit from the schedule when -ConfigurationAnalyzerMaxSnapshotAgeHours is passed as null' {
        @{ TenantGovernanceSnapshot = @{ SnapshotScheduledCron = '0 6 * * 5' } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:ReportingConfigPath

        New-EntraOpsReportingData @script:Parameters -ConfigurationAnalyzerMaxSnapshotAgeHours $null

        Should -Invoke -ModuleName EntraOps New-EntraOpsTenantGovernanceConfigurationAnalyzerData -Times 1 -Exactly -ParameterFilter {
            $MaxSnapshotAgeHours -eq 174
        }
    }

    It 'rejects a snapshot age limit outside 1..8760 hours' {
        @{ TenantGovernanceSnapshot = @{ SnapshotScheduledCron = '0 6 * * 5' } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:ReportingConfigPath

        { New-EntraOpsReportingData @script:Parameters -ConfigurationAnalyzerMaxSnapshotAgeHours 0 } | Should -Throw '*between 1 and 8760*'
    }

    It 'ignores invalid Configuration Analyzer settings when the Configuration Analyzer is skipped' {
        @{ ConfigurationAnalyzer = @{ TimeRangeInDays = 0; SnapshotInterval = 'weekly'; MaxTenantGovernanceSnapshotAgeHours = 0 } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:ReportingConfigPath

        { New-EntraOpsReportingData @script:Parameters -SkipConfigurationAnalyzer } | Should -Not -Throw
        Should -Invoke -ModuleName EntraOps New-EntraOpsTenantGovernanceConfigurationAnalyzerData -Times 0 -Exactly
    }

    It 'rejects an invalid ConfigurationAnalyzer.SnapshotInterval before generating any report' {
        @{ ConfigurationAnalyzer = @{ SnapshotInterval = 'weekly' } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:ReportingConfigPath

        { New-EntraOpsReportingData @script:Parameters } | Should -Throw "*ConfigurationAnalyzer.SnapshotInterval*'weekly'*"
        Should -Invoke -ModuleName EntraOps New-EntraOpsTenantGovernanceConfigurationAnalyzerData -Times 0 -Exactly
    }

    It 'uses defaults instead of a caller variable when the config file does not exist' {
        $EntraOpsConfig = [pscustomobject]@{ ConfigurationAnalyzer = [pscustomobject]@{ TimeRangeInDays = 7; SnapshotInterval = 'P1D' } }
        $Global:EntraOpsConfigBackup = $Global:EntraOpsConfig
        $Global:EntraOpsConfig = $EntraOpsConfig
        try {
            New-EntraOpsReportingData @script:Parameters -ConfigFilePath (Join-Path $script:Workspace 'missing.json')
        } finally {
            $Global:EntraOpsConfig = $Global:EntraOpsConfigBackup
            Remove-Variable -Name EntraOpsConfigBackup -Scope Global -ErrorAction SilentlyContinue
        }

        Should -Invoke -ModuleName EntraOps New-EntraOpsTenantGovernanceConfigurationAnalyzerData -Times 1 -Exactly -ParameterFilter {
            $TimeRangeInDays -eq 365 -and $SnapshotInterval -eq 'P1W'
        }
    }

    It 'rejects a ConfigurationAnalyzer.TimeRangeInDays that is not a positive whole number' -ForEach @(
        @{ Value = 'all' }
        @{ Value = 0 }
    ) {
        @{ ConfigurationAnalyzer = @{ TimeRangeInDays = $Value } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:ReportingConfigPath

        { New-EntraOpsReportingData @script:Parameters } | Should -Throw '*ConfigurationAnalyzer.TimeRangeInDays*at least 1*'
        Should -Invoke -ModuleName EntraOps New-EntraOpsTenantGovernanceConfigurationAnalyzerData -Times 0 -Exactly
    }

    It 'keeps the full history when the configuration sets TimeRangeInDays to null and SnapshotInterval to None' {
        @{ ConfigurationAnalyzer = @{ TimeRangeInDays = $null; SnapshotInterval = 'None'; MaxTenantGovernanceSnapshotAgeHours = 72 } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:ReportingConfigPath

        New-EntraOpsReportingData @script:Parameters

        Should -Invoke -ModuleName EntraOps New-EntraOpsTenantGovernanceConfigurationAnalyzerData -Times 1 -Exactly -ParameterFilter {
            -not $PSBoundParameters.ContainsKey('TimeRangeInDays') -and $SnapshotInterval -eq 'None' -and $MaxSnapshotAgeHours -eq 72
        }
    }
}
