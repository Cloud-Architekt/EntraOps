#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
    $script:PreviousBaseFolder = $Global:EntraOpsBaseFolder
    $script:PreviousEntraOpsRoot = $env:ENTRAOPS_ROOT
    $script:PreviousTenantIdContext = $Global:TenantIdContext
    $script:PreviousEntraOpsConfig = Get-Variable -Name EntraOpsConfig -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    $script:ConnectedTenantId = '00000000-0000-0000-0000-000000000001'

    # Pester mocks only existing commands: without Microsoft.Graph.Authentication and Az.Accounts (CI runners), stubs
    # stand in for the cmdlets the assessment calls. The tests mock them, so the stubs never run.
    $script:GraphStubs = @(foreach ($Name in 'Get-MgContext', 'Connect-MgGraph', 'Get-AzContext') { if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) { $Name } })
    if ('Get-MgContext' -in $script:GraphStubs) {
        function global:Get-MgContext { [CmdletBinding()] param() throw 'Get-MgContext must be mocked.' }
    }
    if ('Connect-MgGraph' -in $script:GraphStubs) {
        function global:Connect-MgGraph { [CmdletBinding()] param([string]$TenantId, [string[]]$Scopes, [switch]$NoWelcome, [switch]$UseDeviceAuthentication, [switch]$Identity, [string]$ContextScope) throw 'Connect-MgGraph must be mocked.' }
    }
    if ('Get-AzContext' -in $script:GraphStubs) {
        function global:Get-AzContext { [CmdletBinding()] param() throw 'Get-AzContext must be mocked.' }
    }

    function New-AssessmentWorkingFolder {
        param([switch]$WithoutReports)
        $Root = Join-Path $TestDrive ([guid]::NewGuid())
        New-Item -Path $Root -ItemType Directory -Force | Out-Null
        if (-not $WithoutReports) {
            New-Item -Path (Join-Path $Root 'Reports') -ItemType Directory -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $Root 'Reports/index.html') -Value '<html></html>'
            # The marker of reporting apps with the Findings view of Privileged Assets.
            New-Item -Path (Join-Path $Root 'Reports/PrivilegedAssets/js') -ItemType Directory -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $Root 'Reports/PrivilegedAssets/js/findings.js') -Value ''
        }
        $Global:EntraOpsBaseFolder = $Root
        $Root
    }

    # Mocks of the building blocks. $script:Calls records the order of the steps.
    function Set-AssessmentMock {
        param(
            [hashtable]$Prerequisite = @{ IsReady = $true; HasConfigurationMonitoringPermission = $true; UtcmServicePrincipalExists = $true; MissingUtcmPermissions = @(); Issues = @() },
            [switch]$SnapshotStaysPending
        )
        $script:Calls = [System.Collections.Generic.List[string]]::new()
        $script:Prerequisites = [System.Collections.Generic.Queue[object]]::new()
        $script:Prerequisites.Enqueue([pscustomobject]$Prerequisite)
        $script:SnapshotStaysPending = [bool]$SnapshotStaysPending
        # Number of collects that still find the snapshot pending before it is captured.
        $script:PendingCollects = 0
        # The manifest the collect writes; a partiallySuccessful capture with -PartialManifest.
        $script:CollectedManifest = @{ CapturedResourceCount = 42 }
        $script:MissingRefs = @()
        $script:HistorySource = 'git'
        $script:SessionConfigFilePath = $null
        # The configuration Connect-EntraOps loads into the session ($EntraOpsConfig, a hashtable).
        $script:SessionConfig = $null

        Mock -ModuleName EntraOps Connect-EntraOps {
            $script:Calls.Add('Connect')
            # Like Connect-EntraOps: the tenant, the configuration and the configuration file of the session.
            $Global:TenantIdContext = $script:ConnectedTenantId
            Remove-Variable -Name EntraOpsConfig -Scope Global -Force -ErrorAction SilentlyContinue
            if ($null -ne $script:SessionConfig) { $Global:EntraOpsConfig = $script:SessionConfig }
            & (Get-Module EntraOps) {
                param($Path)
                if ($Path) { $__EntraOpsSession['ConfigFilePath'] = $Path } else { $__EntraOpsSession.Remove('ConfigFilePath') }
            } $(if ($ConfigFilePath) { $ConfigFilePath } else { $script:SessionConfigFilePath })
        }
        Mock -ModuleName EntraOps Disconnect-EntraOps { $script:Calls.Add('Disconnect') }
        Mock -ModuleName EntraOps Clear-EntraOpsCache { $script:Calls.Add('ClearCache') }
        $script:NoMatchingApps = $false
        $script:ModuleVersion = InModuleScope EntraOps { Get-EntraOpsModuleVersion }
        Mock -ModuleName EntraOps Install-EntraOpsReportingFolder {
            $script:Calls.Add('InstallReports')
            if ($Ref -and $Ref -in $script:MissingRefs) { throw "Download of Cloud-Architekt/EntraOps at '$Ref' failed: 404 (Not Found)." }
            $Source = [pscustomobject]@{ Path = $DestinationPath; Repository = 'Cloud-Architekt/EntraOps'; Ref = $(if ($Ref) { $Ref } else { 'main' }); ContentVersion = $script:ModuleVersion; Matched = $true; InstalledFile = 3; KeptDataFile = 0 }
            if ($script:NoMatchingApps) {
                $Source.ContentVersion = [version]'1.1.0'; $Source.Matched = $false
                if ($KeepExistingWithoutMatch -and (Test-Path -LiteralPath (Join-Path $DestinationPath 'index.html'))) { $Source.InstalledFile = 0; return $Source }
            }
            New-Item -Path $DestinationPath -ItemType Directory -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $DestinationPath 'index.html') -Value '<html></html>'
            Write-Host 'Installed reporting app file(s): notes of Install-EntraOpsReportingFolder'
            $Source
        }
        # No console that can ask, as in a pipeline.
        Mock -ModuleName EntraOps Test-EntraOpsInteractiveHost { $false }
        Mock -ModuleName EntraOps Remove-EntraOpsReportingData { $script:Calls.Add('RemoveReports') }
        Mock -ModuleName EntraOps Get-MgContext { [pscustomobject]@{ TenantId = '00000000-0000-0000-0000-000000000001'; Scopes = @('Directory.Read.All') } }
        Mock -ModuleName EntraOps Get-AzContext { [pscustomobject]@{ Account = [pscustomobject]@{ Id = 'AdeleV@contoso.com' }; Tenant = [pscustomobject]@{ Id = '00000000-0000-0000-0000-000000000001' } } }
        # The account reads one Azure subscription: Azure RBAC is classified.
        Mock -ModuleName EntraOps Invoke-EntraOpsAzGraphQuery { [pscustomobject]@{ subscriptionId = '11111111-1111-1111-1111-111111111111' } }
        Mock -ModuleName EntraOps Connect-MgGraph { $script:Calls.Add('ConnectMgGraph') }
        Mock -ModuleName EntraOps Test-EntraOpsTenantGovernancePrerequisite {
            $script:Calls.Add('Prerequisite')
            if ($script:Prerequisites.Count -gt 1) { $script:Prerequisites.Dequeue() } else { $script:Prerequisites.Peek() }
        }
        Mock -ModuleName EntraOps Save-EntraOpsTenantGovernanceSnapshotJson {
            $script:Calls.Add("Snapshot$Operation")
            New-Item -Path $ExportFolder -ItemType Directory -Force | Out-Null
            $PendingFile = Join-Path $ExportFolder '.PendingSnapshotJob.json'
            if ($Operation -eq 'Start' -or $script:SnapshotStaysPending -or $script:PendingCollects -gt 0) {
                if ($Operation -eq 'Collect') { $script:PendingCollects-- }
                @{ SnapshotJobId = 'job1'; LastKnownStatus = 'running' } | ConvertTo-Json | Set-Content -LiteralPath $PendingFile
            } else {
                Remove-Item -LiteralPath $PendingFile -Force -ErrorAction SilentlyContinue
                $script:CollectedManifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ExportFolder '.SnapshotManifest.json')
            }
            'Snapshot output'
            if ($Operation -eq 'Start') { [pscustomobject]@{ SnapshotJobId = 'job1'; ResourcesToInclude = @('microsoft.entra.user', 'microsoft.entra.group') } }
        }
        Mock -ModuleName EntraOps Invoke-EntraOpsPrivilegedEAM { $script:Calls.Add('PrivilegedEam'); 'EAM output' }
        Mock -ModuleName EntraOps New-EntraOpsReportingData {
            $script:Calls.Add('Reports')
            $Folder = Join-Path $Global:EntraOpsBaseFolder 'Reports/Findings/data'
            New-Item -Path $Folder -ItemType Directory -Force | Out-Null
            @{
                Rules = @(
                    @{ RuleId = 'EO.1001'; Title = 'Tier breach'; Severity = 'Critical'; Status = 'Failed'; FailedCount = 2 }
                    @{ RuleId = 'EO.4001'; Title = 'Account'; Severity = 'Medium'; Status = 'Failed'; FailedCount = 5 }
                    @{ RuleId = 'EO.2001'; Title = 'Classification'; Severity = 'High'; Status = 'Passed'; FailedCount = 0 }
                    @{ RuleId = 'EO.8001'; Title = 'Drift'; Severity = 'Info'; Status = 'Skipped'; FailedCount = 0 }
                )
            } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Folder 'findings.json')
            [pscustomobject]@{ App = 'PrivilegedAssets' }
            [pscustomobject]@{ App = 'PrivilegeHistory'; Result = [pscustomobject]@{ historySource = $script:HistorySource } }
            [pscustomobject]@{ App = 'Findings' }
        }
        Mock -ModuleName EntraOps Start-Sleep { }
        # No console that reports key presses, as in a pipeline.
        Mock -ModuleName EntraOps Test-EntraOpsConsoleKeyPress { $null }
        Mock -ModuleName EntraOps Register-EntraOpsTenantGovernanceServicePrincipal {
            $script:Calls.Add('Setup')
            'Microsoft Tenant Configuration Management service principal is configured. 20 new permission(s) assigned, 0 already present.'
            [pscustomobject]@{ ServicePrincipalId = 'utcm' }
        }
    }

    # The manifest of a captured snapshot of the connected tenant, $Hours old.
    function New-SnapshotManifest {
        param([string]$Root, [double]$Hours)
        $Folder = Join-Path $Root 'TenantGovernance/Snapshots'
        New-Item -Path $Folder -ItemType Directory -Force | Out-Null
        @{ TenantId = $script:ConnectedTenantId; CapturedDateTime = [datetime]::UtcNow.AddHours(-$Hours).ToString('o'); CapturedResourceCount = 42 } |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Folder '.SnapshotManifest.json')
    }
}

AfterAll {
    $Global:EntraOpsBaseFolder = $script:PreviousBaseFolder
    $env:ENTRAOPS_ROOT = $script:PreviousEntraOpsRoot
    $Global:TenantIdContext = $script:PreviousTenantIdContext
    if ($null -ne $script:PreviousEntraOpsConfig) { $Global:EntraOpsConfig = $script:PreviousEntraOpsConfig } else { Remove-Variable -Name EntraOpsConfig -Scope Global -Force -ErrorAction SilentlyContinue }
    & (Get-Module EntraOps) { $__EntraOpsSession.Remove('ConfigFilePath') }
    foreach ($Name in $script:GraphStubs) { Remove-Item -LiteralPath "Function:\$Name" -ErrorAction SilentlyContinue }
}

Describe 'Invoke-EntraOpsAssessment' {
    BeforeEach {
        Push-Location -LiteralPath $TestDrive
    }
    AfterEach {
        Pop-Location
    }

    It 'starts the snapshot before the classification, collects it afterwards and generates the reports' {
        $Root = New-AssessmentWorkingFolder
        Set-AssessmentMock

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -PassThru 6>$null

        $script:Calls | Should -Be @('Connect', 'Prerequisite', 'SnapshotStart', 'PrivilegedEam', 'SnapshotCollect', 'Reports', 'Disconnect')
        Should -Invoke -ModuleName EntraOps Install-EntraOpsReportingFolder -Times 0
        # NoWelcome: no banner, cache details or reminder to disconnect; the assessment disconnects itself.
        Should -Invoke -ModuleName EntraOps Connect-EntraOps -Times 1 -ParameterFilter { $AuthenticationType -eq 'UserInteractive' -and $TenantName -eq 'contoso.onmicrosoft.com' -and $NoWelcome }
        # Reuse by default: a second run never stops at a prompt. Azure is readable: the default RBAC systems, and the
        # default classification scope with Identity Governance.
        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsPrivilegedEAM -Times 1 -ParameterFilter {
            $KeepConnection -and $KeepClassificationFiles -and $ExistingClassificationAction -eq 'Reuse' -and $ControlPlaneScopeAction -eq 'Refresh' -and
            -not $PSBoundParameters.ContainsKey('RbacSystems') -and -not $PSBoundParameters.ContainsKey('PrivilegedObjectClassificationSource') -and
            ($ClassificationParameterScope -join ',') -eq 'EntraID,DeviceManagement,Azure,IdentityGovernance'
        }
        $Result.AzureRbac.Status | Should -Be 'Included'
        Should -Invoke -ModuleName EntraOps Save-EntraOpsTenantGovernanceSnapshotJson -ParameterFilter { $SkipPrerequisiteCheck -and $ExportFolder -eq (Join-Path $Root 'TenantGovernance/Snapshots') }
        # Like the reporting pipeline: a partially successful snapshot is analyzed by default.
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 1 -ParameterFilter { -not $PSBoundParameters.ContainsKey('HistorySource') -and $EntraOpsRoot -eq $Root -and $FailureAction -eq 'Continue' -and $InstallMissingReportingFolder -and -not $SkipConfigurationAnalyzer -and $AllowPartialTenantGovernanceSnapshot }
        Should -Invoke -ModuleName EntraOps Remove-EntraOpsReportingData -Times 0

        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Captured'
        $Result.WorkingFolder | Should -Be $Root
        $Result.Reports | Should -Be @('PrivilegedAssets', 'PrivilegeHistory', 'Findings')
        $Result.FindingsPath | Should -Be (Join-Path $Root 'Reports/Findings/data/findings.json')
        $Result.Findings.Rules | Should -Be 4
        $Result.Findings.Failed | Should -Be 2
        $Result.Findings.Passed | Should -Be 1
        $Result.Findings.Skipped | Should -Be 1
        $Result.Findings.Severity.Critical | Should -Be 1
        $Result.Findings.Severity.Medium | Should -Be 1
        $Result.Findings.Severity.High | Should -Be 0
    }

    It 'returns nothing without -PassThru, also not the output of the steps' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock

        $Output = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' 6>$null

        $Output | Should -BeNullOrEmpty
    }

    It 'installs the reporting apps when they are missing, from -Ref' {
        $Root = New-AssessmentWorkingFolder -WithoutReports
        Set-AssessmentMock

        $Output = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -Ref 'dev' 6>&1

        Should -Invoke -ModuleName EntraOps Install-EntraOpsReportingFolder -Times 1 -Exactly -ParameterFilter { $DestinationPath -eq (Join-Path $Root 'Reports') -and $Ref -eq 'dev' -and $Repository -eq 'EntraOps' -and -not $Force -and -not $KeepExistingWithoutMatch }
        $script:Calls[0] | Should -Be 'InstallReports'
        # The notes of Install-EntraOpsReportingFolder don't interrupt the assessment, which prints its own line.
        $Text = $Output -join "`n"
        $Text | Should -Not -Match 'notes of Install-EntraOpsReportingFolder'
        $Text | Should -Match "Reporting apps : installed \(version $([regex]::Escape("$script:ModuleVersion"))\) from Cloud-Architekt/EntraOps at 'dev'"
    }

    It 'installs the reporting apps of the module version without -ContentRef' {
        $Root = New-AssessmentWorkingFolder -WithoutReports
        Set-AssessmentMock

        Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -ContentRepository 'EntraOps-Insiders' 6>$null

        Should -Invoke -ModuleName EntraOps Install-EntraOpsReportingFolder -Times 1 -Exactly -ParameterFilter { -not $PSBoundParameters.ContainsKey('Ref') -and $Repository -eq 'EntraOps-Insiders' }
        Join-Path $Root 'Reports/index.html' | Should -Exist
    }

    It 'installs the reporting apps of the release channel of the deployment (AutomatedEntraOpsUpdate.Repository)' {
        $Root = New-AssessmentWorkingFolder -WithoutReports
        $ConfigFile = Join-Path $Root 'EntraOpsConfig.json'
        @{ TenantName = 'contoso.onmicrosoft.com'; AutomatedEntraOpsUpdate = @{ Repository = 'EntraOps-Insiders' } } | ConvertTo-Json | Set-Content -LiteralPath $ConfigFile
        Set-AssessmentMock

        $Output = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot 6>&1

        Should -Invoke -ModuleName EntraOps Install-EntraOpsReportingFolder -Times 1 -Exactly -ParameterFilter { $Repository -eq 'EntraOps-Insiders' -and -not $PSBoundParameters.ContainsKey('Ref') -and $KeepExistingWithoutMatch }
        ($Output -join "`n") | Should -Match "Content repo   : EntraOps-Insiders \(AutomatedEntraOpsUpdate.Repository in $([regex]::Escape($ConfigFile))\)"
    }

    It 'prefers -ContentRepository over the configuration' {
        $Root = New-AssessmentWorkingFolder -WithoutReports
        @{ TenantName = 'contoso.onmicrosoft.com'; AutomatedEntraOpsUpdate = @{ Repository = 'EntraOps-Insiders' } } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'EntraOpsConfig.json')
        Set-AssessmentMock

        $Output = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -ContentRepository 'EntraOps' -SkipTenantGovernanceSnapshot 6>&1

        Should -Invoke -ModuleName EntraOps Install-EntraOpsReportingFolder -Times 1 -Exactly -ParameterFilter { $Repository -eq 'EntraOps' }
        ($Output -join "`n") | Should -Match 'Content repo   : EntraOps \(-ContentRepository\)'
    }

    It 'fails without a connection when an explicit -ContentRef cannot be installed' {
        New-AssessmentWorkingFolder -WithoutReports | Out-Null
        Set-AssessmentMock
        $script:MissingRefs = @('v9.9.9')

        { Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -ContentRef 'v9.9.9' 6>$null } | Should -Throw '*v9.9.9*'
        Should -Invoke -ModuleName EntraOps Connect-EntraOps -Times 0
    }

    It 'updates reporting apps without the Findings view, keeping the generated data' {
        $Root = New-AssessmentWorkingFolder
        Remove-Item -LiteralPath (Join-Path $Root 'Reports/PrivilegedAssets/js/findings.js')
        Set-AssessmentMock

        Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot 6>$null

        Should -Invoke -ModuleName EntraOps Install-EntraOpsReportingFolder -Times 1 -Exactly -ParameterFilter { $DestinationPath -eq (Join-Path $Root 'Reports') -and $Force -and $KeepExistingWithoutMatch }
    }

    It 'updates reporting apps of another version than the module' {
        $Root = New-AssessmentWorkingFolder
        @{ ContentVersion = '1.0.0' } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'Reports/.EntraOpsContent.json')
        Set-AssessmentMock

        Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot 6>$null

        Should -Invoke -ModuleName EntraOps Install-EntraOpsReportingFolder -Times 1 -Exactly -ParameterFilter { $Force -and $KeepExistingWithoutMatch }
    }

    It 'keeps the reporting apps of the module version without updating them' {
        $Root = New-AssessmentWorkingFolder
        @{ ContentVersion = "$script:ModuleVersion" } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'Reports/.EntraOpsContent.json')
        Set-AssessmentMock

        Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot 6>$null

        Should -Invoke -ModuleName EntraOps Install-EntraOpsReportingFolder -Times 0
    }

    It 'keeps existing reporting apps and says so when no apps of the module version are available' {
        $Root = New-AssessmentWorkingFolder
        Remove-Item -LiteralPath (Join-Path $Root 'Reports/PrivilegedAssets/js/findings.js')
        Set-AssessmentMock
        $script:NoMatchingApps = $true

        $Output = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot 6>&1

        $Text = $Output -join "`n"
        $Text | Should -Match "Reporting apps : kept, no apps of version $([regex]::Escape("$script:ModuleVersion")) available"
        # The summary doesn't point to a Findings view that the kept apps don't have.
        $Text | Should -Match 'These reporting apps have no Findings view'
    }

    It 'continues with the existing reporting apps when they cannot be updated' {
        $Root = New-AssessmentWorkingFolder
        Remove-Item -LiteralPath (Join-Path $Root 'Reports/PrivilegedAssets/js/findings.js')
        Set-AssessmentMock
        $script:MissingRefs = @('main')

        Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -ContentRef 'main' -SkipTenantGovernanceSnapshot -WarningVariable Warnings -WarningAction SilentlyContinue 6>$null

        ($Warnings -join ' ') | Should -Match 'Install-EntraOpsReportingFolder -Force'
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 1
    }

    It 'asks once after the sign-in whether to reuse the classification of an earlier run (<Answer>)' -ForEach @(
        @{ Answer = 'U'; Templates = 'Reuse'; Scope = 'Reuse' }
        @{ Answer = 'F'; Templates = 'Reuse'; Scope = 'Refresh' }
        @{ Answer = 'G'; Templates = 'Regenerate'; Scope = 'Refresh' }
    ) {
        $Root = New-AssessmentWorkingFolder
        $TenantFolder = Join-Path $Root 'Classification/contoso.onmicrosoft.com'
        New-Item -Path $TenantFolder -ItemType Directory -Force | Out-Null
        foreach ($Name in 'Classification_AadResources.json', 'Classification_DeviceManagement.json', 'Classification_Azure.json', 'Classification_IdentityGovernance.json', 'ScopeReasoning_ControlPlane.json') { Set-Content -LiteralPath (Join-Path $TenantFolder $Name) -Value '{}' }
        Set-AssessmentMock
        Mock -ModuleName EntraOps Test-EntraOpsInteractiveHost { $true }
        Mock -ModuleName EntraOps Read-Host { $Answer }

        Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot 6>$null

        Should -Invoke -ModuleName EntraOps Read-Host -Times 1 -Exactly
        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsPrivilegedEAM -Times 1 -Exactly -ParameterFilter { $ExistingClassificationAction -eq $Templates -and $ControlPlaneScopeAction -eq $Scope }
        # Asked before the run starts its work.
        $script:Calls.IndexOf('Connect') | Should -BeLessThan $script:Calls.IndexOf('PrivilegedEam')
    }

    It 'does not ask <Case>' -ForEach @(
        @{ Case = 'without a console that can ask'; Interactive = $false; Arguments = @{} }
        @{ Case = 'with an explicit choice'; Interactive = $true; Arguments = @{ ControlPlaneScopeAction = 'Reuse' } }
    ) {
        $Root = New-AssessmentWorkingFolder
        $TenantFolder = Join-Path $Root 'Classification/contoso.onmicrosoft.com'
        New-Item -Path $TenantFolder -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $TenantFolder 'Classification_AadResources.json') -Value '{}'
        Set-AssessmentMock
        Mock -ModuleName EntraOps Test-EntraOpsInteractiveHost { $Interactive }
        Mock -ModuleName EntraOps Read-Host { 'U' }

        Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot @Arguments 6>$null

        Should -Invoke -ModuleName EntraOps Read-Host -Times 0
    }

    It 'names the share of unclassified objects in the summary' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        Mock -ModuleName EntraOps New-EntraOpsReportingData {
            $Folder = Join-Path $Global:EntraOpsBaseFolder 'Reports/Findings/data'
            New-Item -Path $Folder -ItemType Directory -Force | Out-Null
            $Unclassified = @{ Instance = @{ AdminTierLevelName = 'Unclassified' } }
            @{
                Rules = @(
                    @{ RuleId = 'EO.1001'; Title = 'Tier breach'; Severity = 'Critical'; Status = 'Failed'; FailedCount = 3; Results = @($Unclassified, $Unclassified, @{ Instance = @{ AdminTierLevelName = 'ManagementPlane' } }) }
                    @{ RuleId = 'EO.2001'; Title = 'Unclassified object'; Severity = 'Medium'; Status = 'Failed'; FailedCount = 7; Results = @() }
                )
            } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $Folder 'findings.json')
            [pscustomobject]@{ App = 'Findings' }
        }

        $Output = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot 6>&1

        ($Output -join "`n") | Should -Match 'Classification    : 7 privileged object\(s\) have no designated tier \(EO\.2001\); 2 of the 3 results listed above concern them'
    }

    It 'uses -Path as working folder of the session' {
        New-AssessmentWorkingFolder | Out-Null
        $Target = Join-Path $TestDrive "assessment-$([guid]::NewGuid())"
        Set-AssessmentMock

        try {
            $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -Path $Target -PassThru 6>$null

            $Result.WorkingFolder | Should -Be $Target
            $Global:EntraOpsBaseFolder | Should -Be $Target
            $env:ENTRAOPS_ROOT | Should -Be $Target
            Should -Invoke -ModuleName EntraOps Install-EntraOpsReportingFolder -Times 1 -ParameterFilter { $DestinationPath -eq (Join-Path $Target 'Reports') }
        } finally {
            $env:ENTRAOPS_ROOT = $script:PreviousEntraOpsRoot
        }
    }

    It 'skips the snapshot with guidance when the tenant is not prepared, and generates the reports' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock -Prerequisite @{ IsReady = $false; HasConfigurationMonitoringPermission = $false; UtcmServicePrincipalExists = $false; MissingUtcmPermissions = @(); Issues = @('The UTCM service principal was not found.') }

        $Output = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -PassThru -WarningVariable Warnings -WarningAction SilentlyContinue 6>&1
        $Result = $Output | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] }
        $Text = ($Output | Where-Object { $_ -is [System.Management.Automation.InformationRecord] }) -join "`n"

        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Skipped'
        $Result.TenantGovernanceSnapshot.Reason | Should -Match 'no Microsoft Tenant Configuration Management service principal'
        # The setup in the same command, or the standalone cmdlet.
        $Result.TenantGovernanceSnapshot.Next | Should -Match "^as Global Administrator or Privileged Role Administrator, Invoke-EntraOpsAssessment -TenantName 'contoso\.onmicrosoft\.com' -SetupTenantGovernance"
        $Result.TenantGovernanceSnapshot.Next | Should -Match 'Register-EntraOpsTenantGovernanceServicePrincipal -TenantId 00000000-0000-0000-0000-000000000001'
        ($Warnings -join ' ') | Should -Match 'Next: as Global Administrator or Privileged Role Administrator'
        # What the setup changes, before an administrator runs it.
        $Text | Should -Match "The setup creates Microsoft's service principal 'Microsoft Tenant Configuration Management' and grants it \d+ Microsoft Graph read permission\(s\)"
        $Text | Should -Match 'ConfigurationMonitoring\.ReadWrite\.All to start snapshots'
        # No app-permission advice for an interactive sign-in, and no change of the tenant without -SetupTenantGovernance.
        ($Warnings -join ' ') | Should -Not -Match 'New-EntraOpsWorkloadIdentity'
        Should -Invoke -ModuleName EntraOps Register-EntraOpsTenantGovernanceServicePrincipal -Times 0
        $Result.TenantGovernanceSnapshot.Setup | Should -BeNullOrEmpty
        Should -Invoke -ModuleName EntraOps Save-EntraOpsTenantGovernanceSnapshotJson -Times 0
        Should -Invoke -ModuleName EntraOps Connect-MgGraph -Times 0
        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsPrivilegedEAM -Times 1
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 1
    }

    It 'requests ConfigurationMonitoring.ReadWrite.All when only the delegated permission is missing' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock -Prerequisite @{ IsReady = $false; HasConfigurationMonitoringPermission = $false; UtcmServicePrincipalExists = $true; MissingUtcmPermissions = @(); Issues = @('Permission missing.') }
        $script:Prerequisites.Enqueue([pscustomobject]@{ IsReady = $true; HasConfigurationMonitoringPermission = $true; UtcmServicePrincipalExists = $true; MissingUtcmPermissions = @(); Issues = @() })

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -AuthenticationType DeviceAuthentication -PassThru 6>$null

        Should -Invoke -ModuleName EntraOps Connect-MgGraph -Times 1 -ParameterFilter {
            $Scopes -contains 'ConfigurationMonitoring.ReadWrite.All' -and $Scopes -contains 'Directory.Read.All' -and $UseDeviceAuthentication -and $TenantId -eq '00000000-0000-0000-0000-000000000001' -and $ContextScope -eq 'Process'
        }
        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Captured'
    }

    It 'does not request the permission for an already authenticated session, and tells how to reconnect' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock -Prerequisite @{ IsReady = $false; HasConfigurationMonitoringPermission = $false; UtcmServicePrincipalExists = $true; MissingUtcmPermissions = @(); Issues = @('Permission missing. Run New-EntraOpsWorkloadIdentity.') }

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -AuthenticationType AlreadyAuthenticated -PassThru -WarningVariable Warnings -WarningAction SilentlyContinue 6>$null

        Should -Invoke -ModuleName EntraOps Connect-MgGraph -Times 0
        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Skipped'
        $Result.TenantGovernanceSnapshot.Next | Should -Match '^Connect-MgGraph -TenantId 00000000-0000-0000-0000-000000000001 -Scopes ConfigurationMonitoring.ReadWrite.All'
        ($Warnings -join ' ') | Should -Not -Match 'New-EntraOpsWorkloadIdentity'
    }

    It 'says so when the consent to ConfigurationMonitoring.ReadWrite.All is declined' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock -Prerequisite @{ IsReady = $false; HasConfigurationMonitoringPermission = $false; UtcmServicePrincipalExists = $true; MissingUtcmPermissions = @(); Issues = @('Permission missing.') }
        Mock -ModuleName EntraOps Connect-MgGraph { throw 'AADSTS65004: User declined to consent.' }

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -PassThru -WarningAction SilentlyContinue 6>$null

        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Skipped'
        $Result.TenantGovernanceSnapshot.Reason | Should -Match 'consent to ConfigurationMonitoring.ReadWrite.All was declined'
        $Result.TenantGovernanceSnapshot.Next | Should -Match 'accept the consent prompt'
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 1
    }

    It 'points to Register-EntraOpsTenantGovernanceServicePrincipal when the service principal lacks permissions' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock -Prerequisite @{ IsReady = $false; HasConfigurationMonitoringPermission = $false; UtcmServicePrincipalExists = $true; MissingUtcmPermissions = @('Policy.Read.All', 'Group.Read.All'); Issues = @('Missing.') }

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -PassThru -WarningAction SilentlyContinue 6>$null

        Should -Invoke -ModuleName EntraOps Connect-MgGraph -Times 0
        $Result.TenantGovernanceSnapshot.Reason | Should -Match 'lacks 2 read permission'
        $Result.TenantGovernanceSnapshot.Next | Should -Match '-SetupTenantGovernance \(or Register-EntraOpsTenantGovernanceServicePrincipal'
    }

    It 'neither collects nor uses the snapshot of another tenant in the working folder (<File>)' -ForEach @(
        @{ File = '.SnapshotManifest.json' }
        @{ File = '.PendingSnapshotJob.json' }
    ) {
        $Root = New-AssessmentWorkingFolder
        New-Item -Path (Join-Path $Root 'TenantGovernance/Snapshots') -ItemType Directory -Force | Out-Null
        @{ SnapshotJobId = 'other'; TenantId = '99999999-9999-9999-9999-999999999999'; TenantName = 'fabrikam.onmicrosoft.com' } | ConvertTo-Json |
            Set-Content -LiteralPath (Join-Path $Root "TenantGovernance/Snapshots/$File")
        Set-AssessmentMock

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -PassThru -WarningVariable Warnings -WarningAction SilentlyContinue 6>$null

        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Skipped'
        $Result.TenantGovernanceSnapshot.Reason | Should -Match 'fabrikam.onmicrosoft.com'
        ($Warnings -join ' ') | Should -Match 'belongs to tenant fabrikam'
        Should -Invoke -ModuleName EntraOps Test-EntraOpsTenantGovernancePrerequisite -Times 0
        Should -Invoke -ModuleName EntraOps Save-EntraOpsTenantGovernanceSnapshotJson -Times 0
        Should -Invoke -ModuleName EntraOps Remove-EntraOpsReportingData -Times 1 -ParameterFilter { $EntraOpsRoot -eq $Root -and $SkipPrivilegedAssets -and $SkipFindings -and -not $SkipConfigurationAnalyzer -and -not $SkipPimRequestFlow -and -not $SkipAccessPackageFlow }
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 1 -ParameterFilter { $SkipConfigurationAnalyzer -and $SkipAccessPackageFlow }
    }

    It 'collects the snapshot of the connected tenant' {
        $Root = New-AssessmentWorkingFolder
        New-Item -Path (Join-Path $Root 'TenantGovernance/Snapshots') -ItemType Directory -Force | Out-Null
        @{ SnapshotJobId = 'earlier'; LastKnownStatus = 'running'; TenantId = $script:ConnectedTenantId } | ConvertTo-Json |
            Set-Content -LiteralPath (Join-Path $Root 'TenantGovernance/Snapshots/.PendingSnapshotJob.json')
        Set-AssessmentMock

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -PassThru 6>$null

        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Captured'
        Should -Invoke -ModuleName EntraOps Remove-EntraOpsReportingData -Times 0
    }

    It 'skips the snapshot with -SkipTenantGovernanceSnapshot' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot -PassThru 6>$null

        Should -Invoke -ModuleName EntraOps Test-EntraOpsTenantGovernancePrerequisite -Times 0
        Should -Invoke -ModuleName EntraOps Save-EntraOpsTenantGovernanceSnapshotJson -Times 0
        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Skipped'
    }

    It 'collects a pending snapshot of an earlier run instead of starting another one' {
        $Root = New-AssessmentWorkingFolder
        New-Item -Path (Join-Path $Root 'TenantGovernance/Snapshots') -ItemType Directory -Force | Out-Null
        @{ SnapshotJobId = 'earlier'; LastKnownStatus = 'running' } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'TenantGovernance/Snapshots/.PendingSnapshotJob.json')
        Set-AssessmentMock

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -PassThru 6>$null

        Should -Invoke -ModuleName EntraOps Test-EntraOpsTenantGovernancePrerequisite -Times 0
        Should -Invoke -ModuleName EntraOps Save-EntraOpsTenantGovernanceSnapshotJson -Times 0 -ParameterFilter { $Operation -eq 'Start' }
        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Captured'
        # The job started in an earlier run: no capture time of this run.
        $Result.TenantGovernanceSnapshot.Reason | Should -Be '42 resource(s) captured'
    }

    It 'leaves a snapshot that is not complete in time pending and generates the reports' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock -SnapshotStaysPending
        $script:Now = Get-Date
        Mock -ModuleName EntraOps Get-Date { $script:Now = $script:Now.AddSeconds(20); $script:Now }

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -TenantGovernanceTimeoutInSeconds 60 -PassThru -WarningVariable Warnings -WarningAction SilentlyContinue 6>$null

        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Pending'
        # The elapsed time, not the timeout: the classification can take longer than the timeout.
        $Result.TenantGovernanceSnapshot.Reason | Should -Match '^not complete after \d\d:\d\d$'
        # The next run collects it, in a new session too.
        $Result.TenantGovernanceSnapshot.Next | Should -Be "Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' collects it first"
        ($Warnings -join ' ') | Should -Match 'Microsoft Graph keeps capturing it'
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 2 -Exactly
    }

    It 'continues with the reports when the snapshot fails' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        Mock -ModuleName EntraOps Save-EntraOpsTenantGovernanceSnapshotJson -ParameterFilter { $Operation -eq 'Collect' } { throw 'Snapshot job failed.' }

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -PassThru -WarningAction SilentlyContinue 6>$null

        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Failed'
        $Result.TenantGovernanceSnapshot.Reason | Should -Be 'Snapshot job failed.'
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 1
    }

    It 'disconnects when the classification fails' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        Mock -ModuleName EntraOps Invoke-EntraOpsPrivilegedEAM { throw 'Classification failed.' }

        { Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot 6>$null } | Should -Throw 'Classification failed.'

        Should -Invoke -ModuleName EntraOps Disconnect-EntraOps -Times 1
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 0
    }

    It 'keeps the connection with -KeepConnection' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock

        Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot -KeepConnection 6>$null

        Should -Invoke -ModuleName EntraOps Disconnect-EntraOps -Times 0
    }

    It 'takes the tenant from the configuration file' {
        $Root = New-AssessmentWorkingFolder
        $ConfigFile = Join-Path $Root 'EntraOpsConfig.json'
        @{ TenantName = 'fabrikam.onmicrosoft.com' } | ConvertTo-Json | Set-Content -LiteralPath $ConfigFile
        Set-AssessmentMock

        Invoke-EntraOpsAssessment -ConfigFilePath $ConfigFile -SkipTenantGovernanceSnapshot 6>$null

        Should -Invoke -ModuleName EntraOps Connect-EntraOps -Times 1 -ParameterFilter { $TenantName -eq 'fabrikam.onmicrosoft.com' -and $ConfigFilePath -eq $ConfigFile }
        # The classification uses the configuration and the folders of the connection.
        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsPrivilegedEAM -Times 1 -ParameterFilter { -not $PSBoundParameters.ContainsKey('ConfigFilePath') }
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 1 -ParameterFilter { $ConfigFilePath -eq $ConfigFile }
    }

    It 'generates the reports with the configuration file that Connect-EntraOps found, not the one of the working folder' {
        $Root = New-AssessmentWorkingFolder
        @{ TenantName = 'contoso.onmicrosoft.com' } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'EntraOpsConfig.json')
        $Found = Join-Path $TestDrive "found-$([guid]::NewGuid()).json"
        @{ TenantName = 'contoso.onmicrosoft.com' } | ConvertTo-Json | Set-Content -LiteralPath $Found
        Set-AssessmentMock
        $script:SessionConfigFilePath = $Found

        Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot 6>$null

        Should -Invoke -ModuleName EntraOps Connect-EntraOps -Times 1 -ParameterFilter { -not $ConfigFilePath }
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 1 -ParameterFilter { $ConfigFilePath -eq $Found }
    }

    It 'shows one history line without git history, and the Maester commands' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        $script:HistorySource = 'folder'

        $Output = (Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot 6>&1) -join "`n"

        $Output | Should -Match 'History\s+: current run only \(no git history\)'
        $Output | Should -Match 'Invoke-Maester -Pack EOPS -SkipBuiltIn -SkipGraphConnect'
        $Output | Should -Match 'Reports/PrivilegedAssets|Tenant Governance : Skipped - with -SkipTenantGovernanceSnapshot'
    }

    It 'lists rules that could not be evaluated' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        Mock -ModuleName EntraOps New-EntraOpsReportingData {
            $Folder = Join-Path $Global:EntraOpsBaseFolder 'Reports/Findings/data'
            New-Item -Path $Folder -ItemType Directory -Force | Out-Null
            @{ Rules = @(@{ RuleId = 'EO.3001'; Title = 'PIM'; Severity = 'High'; Status = 'Error'; Reason = 'Evaluation failed: boom'; FailedCount = 0 }) } |
                ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Folder 'findings.json')
            [pscustomobject]@{ App = 'Findings' }
        }

        $Output = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot -PassThru 6>&1
        $Result = $Output | Where-Object { $_ -is [pscustomobject] -and $_.PSObject.Properties['Findings'] }

        $Result.Findings.Error | Should -Be 1
        ($Output -join "`n") | Should -Match 'EO\.3001\s+Error\s+PIM: Evaluation failed: boom'
    }

    It 'shows the account, the tenant and the configuration file of the connection' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock

        $Output = (Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot 6>&1) -join "`n"

        $Output | Should -Match 'Account\s+: AdeleV@contoso\.com'
        $Output | Should -Match 'Tenant\s+: contoso\.onmicrosoft\.com \(00000000-0000-0000-0000-000000000001\)'
        $Output | Should -Match 'Config file\s+: none, defaults apply'
    }

    It 'explains the admin consent when the sign-in needs it (<Code>)' -ForEach @(
        @{ Code = 'AADSTS90094' }
        @{ Code = 'AADSTS65001' }
    ) {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        $script:SignInError = "${Code}: The grant requires admin permission."
        Mock -ModuleName EntraOps Connect-EntraOps { throw $script:SignInError }

        { Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' 6>$null } | Should -Throw "*Consent on behalf of your organization*Error: ${Code}: The grant requires admin permission.*"
        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsPrivilegedEAM -Times 0
    }

    It 'rethrows other sign-in errors unchanged' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        Mock -ModuleName EntraOps Connect-EntraOps { throw 'The network is unreachable.' }

        { Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' 6>$null } | Should -Throw 'The network is unreachable.'
    }

    It 'skips Azure RBAC with guidance when <Case>, and classifies the other RBAC systems' -ForEach @(
        @{ Case = 'Azure Resource Graph is not accessible'; Query = { throw 'AuthorizationFailed' }; Reason = 'Azure Resource Graph is not accessible: AuthorizationFailed' }
        @{ Case = 'the account reads no Azure subscription'; Query = { }; Reason = "the account can't read any Azure subscription" }
    ) {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        Mock -ModuleName EntraOps Invoke-EntraOpsAzGraphQuery $Query

        $Output = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot -PassThru 6>&1
        $Result = $Output | Where-Object { $_ -is [pscustomobject] -and $_.PSObject.Properties['AzureRbac'] }

        $Result.AzureRbac.Status | Should -Be 'Skipped'
        $Result.AzureRbac.Reason | Should -Be $Reason
        $Result.AzureRbac.Next | Should -Match 'Reader on the tenant root management group'
        # Without Azure: no RBAC system, Control Plane source or classification scope that reads Azure Resource Graph.
        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsPrivilegedEAM -Times 1 -ParameterFilter {
            ($RbacSystems -join ',') -eq 'EntraID,IdentityGovernance,DeviceManagement,ResourceApps' -and
            ($PrivilegedObjectClassificationSource -join ',') -eq 'EntraOps,PrivilegedObjectIds,PrivilegedEdgesFromExposureManagement' -and
            ($ClassificationParameterScope -join ',') -eq 'EntraID,DeviceManagement'
        }
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 1
        $Text = ($Output | Where-Object { $_ -is [System.Management.Automation.InformationRecord] }) -join "`n"
        $Text | Should -Match "Azure RBAC is skipped: $([regex]::Escape($Reason))\. The other RBAC systems are classified\."
        $Text | Should -Match "Azure RBAC\s+: Skipped - $([regex]::Escape($Reason))"
    }

    It 'keeps the configured Control Plane sources and scope without the parts that read Azure Resource Graph' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        $script:SessionConfig = @{
            TenantName                       = 'contoso.onmicrosoft.com'
            AutomatedControlPlaneScopeUpdate = @{
                PrivilegedObjectClassificationSource = @('EntraOps', 'PrivilegedRolesFromAzGraph')
                ClassificationParameterScope         = @('EntraID', 'IdentityGovernance', 'Defender', 'Azure')
            }
        }
        Mock -ModuleName EntraOps Invoke-EntraOpsAzGraphQuery { throw 'AuthorizationFailed' }

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot -PassThru 6>$null

        $Result.AzureRbac.Status | Should -Be 'Skipped'
        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsPrivilegedEAM -Times 1 -ParameterFilter {
            ($PrivilegedObjectClassificationSource -join ',') -eq 'EntraOps' -and ($ClassificationParameterScope -join ',') -eq 'EntraID'
        }
    }

    It 'keeps the configured classification scope when Azure is readable' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        $script:SessionConfig = @{
            TenantName                       = 'contoso.onmicrosoft.com'
            AutomatedControlPlaneScopeUpdate = @{ ClassificationParameterScope = @('EntraID', 'Azure') }
        }

        Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot 6>$null

        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsPrivilegedEAM -Times 1 -ParameterFilter { -not $PSBoundParameters.ContainsKey('ClassificationParameterScope') }
    }

    It 'does not check the Azure access for the RBAC systems of <Source>' -ForEach @(
        @{ Source = '-RbacSystems'; Parameters = @{ RbacSystems = @('EntraID', 'Azure') }; Config = $null; Status = 'Included' }
        @{ Source = '-RbacSystems without Azure'; Parameters = @{ RbacSystems = @('EntraID') }; Config = $null; Status = 'NotSelected' }
        @{ Source = 'the configuration file'; Parameters = @{}; Config = @{ RbacSystems = @('EntraID', 'Azure') }; Status = 'Included' }
    ) {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        $script:SessionConfig = $Config
        Mock -ModuleName EntraOps Invoke-EntraOpsAzGraphQuery { throw 'AuthorizationFailed' }

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot -PassThru @Parameters 6>$null

        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsAzGraphQuery -Times 0
        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsPrivilegedEAM -Times 1 -ParameterFilter { -not $PSBoundParameters.ContainsKey('PrivilegedObjectClassificationSource') -and -not $PSBoundParameters.ContainsKey('ClassificationParameterScope') }
        $Result.AzureRbac.Status | Should -Be $Status
    }

    It 'points to the prerequisite check when the service principal could not be checked' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock -Prerequisite @{
            IsReady = $false; HasConfigurationMonitoringPermission = $false; UtcmServicePrincipalExists = $false; MissingUtcmPermissions = @()
            PermissionCheckSkippedReason = 'Could not verify the Microsoft Tenant Configuration Management service principal (insufficient permission or Graph error): 403 Forbidden'
            Issues = @('Permission missing.')
        }

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -PassThru -WarningAction SilentlyContinue 6>$null

        # A consent can't help while the state of the service principal is unknown.
        Should -Invoke -ModuleName EntraOps Connect-MgGraph -Times 0
        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Skipped'
        $Result.TenantGovernanceSnapshot.Reason | Should -Match 'service principal could not be checked'
        $Result.TenantGovernanceSnapshot.Next | Should -Match '^Test-EntraOpsTenantGovernancePrerequisite -Verbose'
        $Result.TenantGovernanceSnapshot.Next | Should -Not -Match 'consent prompt'
    }

    It 'reports a partially successful snapshot as Partial with the resource types kept from the previous snapshot' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        $script:CollectedManifest = @{
            SnapshotId = 'job1'; SnapshotJobStatus = 'partiallySuccessful'; CapturedResourceCount = 40; IsComplete = $false
            StaleResourceTypes = @('microsoft.entra.authenticationmethodpolicy', 'microsoft.entra.crosstenantaccesspolicy'); PublishedWithErrorsResourceTypes = @()
        }

        $Output = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -PassThru 6>&1
        $Result = $Output | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] }
        $Text = ($Output | Where-Object { $_ -is [System.Management.Automation.InformationRecord] }) -join "`n"

        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Partial'
        $Result.TenantGovernanceSnapshot.Reason | Should -Match '^40 resource\(s\) captured in \d\d:\d\d, 2 resource type\(s\) kept from the previous snapshot because of Microsoft Graph errors$'
        $Result.TenantGovernanceSnapshot.Next | Should -Be 'Get-EntraOpsTenantGovernanceSnapshotReport -SnapshotJobId job1 lists the errors'
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 1 -Exactly -ParameterFilter { $AllowPartialTenantGovernanceSnapshot -and -not $SkipConfigurationAnalyzer }
        $Text | Should -Match 'Tenant Governance : Partial - 40 resource\(s\) captured'
        $Text | Should -Match 'Next: Get-EntraOpsTenantGovernanceSnapshotReport -SnapshotJobId job1 lists the errors'
    }

    It 'keeps Configuration Analyzer strict when the configuration disallows partial snapshots' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        $script:SessionConfig = @{ ConfigurationAnalyzer = @{ AllowPartialTenantGovernanceSnapshot = $false } }
        $script:CollectedManifest = @{ SnapshotId = 'job1'; SnapshotJobStatus = 'partiallySuccessful'; CapturedResourceCount = 40; IsComplete = $false; PublishedWithErrorsResourceTypes = @('microsoft.entra.accesspackage'); ResourceTypeStates = @(@{ ResourceType = 'microsoft.entra.accesspackage'; Status = 'PublishedWithErrors'; RetainedResourceCount = 1 }) }

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -PassThru 6>$null

        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 1 -Exactly -ParameterFilter { -not $AllowPartialTenantGovernanceSnapshot }
        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Partial'
        $Result.TenantGovernanceSnapshot.Reason | Should -Match 'resources of 1 resource type\(s\) could not be exported and are kept from the previous snapshot; Configuration Analyzer is skipped \(ConfigurationAnalyzer.AllowPartialTenantGovernanceSnapshot is false\)$'
    }

    It 'does not claim resources were kept from the previous snapshot when none were retained' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        $script:CollectedManifest = @{ SnapshotId = 'job1'; SnapshotJobStatus = 'partiallySuccessful'; CapturedResourceCount = 40; IsComplete = $false; PublishedWithErrorsResourceTypes = @('microsoft.entra.conditionalaccesspolicy'); ResourceTypeStates = @(@{ ResourceType = 'microsoft.entra.conditionalaccesspolicy'; Status = 'PublishedWithErrors'; RetainedResourceCount = 0 }) }

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -PassThru 6>$null

        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Partial'
        $Result.TenantGovernanceSnapshot.Reason | Should -Match '1 resource type\(s\) with references that Microsoft Graph could not resolve$'
        $Result.TenantGovernanceSnapshot.Reason | Should -Not -Match 'kept from the previous snapshot'
    }

    It 'generates the reports that do not need the snapshot while it is captured, the others with it' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        # Pending after the classification and after these reports, captured at the next collect.
        $script:PendingCollects = 2

        $Output = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -PassThru 6>&1
        $Result = $Output | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] }
        $Text = ($Output | Where-Object { $_ -is [System.Management.Automation.InformationRecord] }) -join "`n"

        $script:Calls | Should -Be @('Connect', 'Prerequisite', 'SnapshotStart', 'PrivilegedEam', 'SnapshotCollect', 'Reports', 'SnapshotCollect', 'SnapshotCollect', 'Reports', 'Disconnect')
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 1 -Exactly -ParameterFilter {
            $SkipConfigurationAnalyzer -and $SkipAccessPackageFlow -and $SkipFindings -and -not $SkipPrivilegedAssets -and -not $SkipPrivilegeHistory
        }
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 1 -Exactly -ParameterFilter {
            $SkipTierBreachAnalyzer -and $SkipEamDashboard -and $SkipPrivilegedAssets -and $SkipAccessPathMap -and $SkipClassificationExplorer -and $SkipPrivilegeHistory -and
            -not $SkipConfigurationAnalyzer -and -not $SkipAccessPackageFlow -and -not $SkipFindings
        }
        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Captured'
        $Result.TenantGovernanceSnapshot.Reason | Should -Match '^42 resource\(s\) captured in \d\d:\d\d$'
        $Text | Should -Match 'still being captured: generating the reports that do not need it first'
        # Step 3 says that the snapshot is captured in the background and the run goes on.
        $Text | Should -Match 'Snapshot job job1 started: Microsoft Graph captures 2 resource types of the tenant configuration in the background'
        $Text | Should -Match 'then step 5 waits for it \(at most 15 minutes from now\)'
        $Text | Should -Not -Match 'Snapshot output'
        $Text | Should -Match 'Tenant Governance snapshot: still being captured \(status running\), \d\d:\d\d since its start'
        $Text | Should -Match 'Waiting for the Tenant Governance snapshot \(at most 15 minutes from its start\)'
        # No console that reports key presses: no hint to press a key.
        $Text | Should -Not -Match 'Press S'
        $Text | Should -Match 'Tenant Governance : Captured - 42 resource\(s\) captured'
    }

    It 'stops waiting for the snapshot on S, generates the reports and leaves the snapshot to the next run' {
        $Target = Join-Path $TestDrive "assessment-$([guid]::NewGuid())"
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        $script:PendingCollects = 100
        # The first call only checks the console and discards earlier keys; then S is pressed.
        $script:KeyChecks = 0
        Mock -ModuleName EntraOps Test-EntraOpsConsoleKeyPress { $script:KeyChecks++; $script:KeyChecks -gt 1 }

        try {
            $Output = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -Path $Target -PassThru -WarningVariable Warnings -WarningAction SilentlyContinue 6>&1
        } finally {
            $env:ENTRAOPS_ROOT = $script:PreviousEntraOpsRoot
        }
        $Result = $Output | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] }
        $Text = ($Output | Where-Object { $_ -is [System.Management.Automation.InformationRecord] }) -join "`n"

        $Text | Should -Match 'Press S to stop waiting'
        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Pending'
        $Result.TenantGovernanceSnapshot.Reason | Should -Match '^waiting was stopped after \d\d:\d\d$'
        # The working folder of -Path, so the next run in a new session finds the pending snapshot.
        $Result.TenantGovernanceSnapshot.Next | Should -Be "Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -Path '$Target' collects it first"
        ($Warnings -join ' ') | Should -Match 'not used: waiting was stopped'
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 2 -Exactly
        # Stopped before the next collect.
        @($script:Calls | Where-Object { $_ -eq 'SnapshotCollect' }).Count | Should -Be 2
    }

    It 'uses a snapshot younger than -TenantGovernanceSnapshotMaxAgeInHours without waiting' {
        $Root = New-AssessmentWorkingFolder
        New-SnapshotManifest -Root $Root -Hours 2
        Set-AssessmentMock

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -TenantGovernanceSnapshotMaxAgeInHours 24 -PassThru 6>$null

        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Reused'
        $Result.TenantGovernanceSnapshot.Reason | Should -Match '^captured 2 hour\(s\) ago$'
        Should -Invoke -ModuleName EntraOps Test-EntraOpsTenantGovernancePrerequisite -Times 0
        Should -Invoke -ModuleName EntraOps Save-EntraOpsTenantGovernanceSnapshotJson -Times 0
        # Within the default limit of Configuration Analyzer (30 hours): no other limit.
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 1 -Exactly -ParameterFilter { -not $PSBoundParameters.ContainsKey('ConfigurationAnalyzerMaxSnapshotAgeHours') -and -not $SkipConfigurationAnalyzer }
    }

    It 'lets Configuration Analyzer accept a reused snapshot older than its default limit' {
        $Root = New-AssessmentWorkingFolder
        New-SnapshotManifest -Root $Root -Hours 40
        Set-AssessmentMock

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -TenantGovernanceSnapshotMaxAgeInHours 48 -PassThru 6>$null

        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Reused'
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 1 -Exactly -ParameterFilter { $ConfigurationAnalyzerMaxSnapshotAgeHours -eq 48 }
    }

    It 'starts a new snapshot when the last one is older than -TenantGovernanceSnapshotMaxAgeInHours' {
        $Root = New-AssessmentWorkingFolder
        New-SnapshotManifest -Root $Root -Hours 2
        Set-AssessmentMock

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -TenantGovernanceSnapshotMaxAgeInHours 1 -PassThru 6>$null

        Should -Invoke -ModuleName EntraOps Save-EntraOpsTenantGovernanceSnapshotJson -Times 1 -Exactly -ParameterFilter { $Operation -eq 'Start' }
        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Captured'
    }

    It 'prepares the tenant with -SetupTenantGovernance and captures the snapshot in the same run' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock -Prerequisite @{ IsReady = $false; HasConfigurationMonitoringPermission = $false; UtcmServicePrincipalExists = $false; MissingUtcmPermissions = @(); Issues = @('The UTCM service principal was not found.') }
        $script:Prerequisites.Enqueue([pscustomobject]@{ IsReady = $true; HasConfigurationMonitoringPermission = $true; UtcmServicePrincipalExists = $true; MissingUtcmPermissions = @(); Issues = @() })

        $Output = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SetupTenantGovernance -PassThru 6>&1
        $Result = $Output | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] }
        $Text = ($Output | Where-Object { $_ -is [System.Management.Automation.InformationRecord] }) -join "`n"

        # One consent for the setup and the snapshot, keeping the scopes of the connection.
        Should -Invoke -ModuleName EntraOps Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
            $Scopes -contains 'Application.ReadWrite.All' -and $Scopes -contains 'AppRoleAssignment.ReadWrite.All' -and $Scopes -contains 'ConfigurationMonitoring.ReadWrite.All' -and
            $Scopes -contains 'Directory.Read.All' -and $TenantId -eq '00000000-0000-0000-0000-000000000001' -and $ContextScope -eq 'Process'
        }
        Should -Invoke -ModuleName EntraOps Register-EntraOpsTenantGovernanceServicePrincipal -Times 1 -Exactly -ParameterFilter { $TenantId -eq '00000000-0000-0000-0000-000000000001' }
        $script:Calls | Should -Be @('Connect', 'Prerequisite', 'ConnectMgGraph', 'Setup', 'Prerequisite', 'SnapshotStart', 'PrivilegedEam', 'SnapshotCollect', 'Reports', 'Disconnect')
        $Result.TenantGovernanceSnapshot.Setup | Should -Be 'Done'
        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Captured'
        # The status lines of the setup are shown, its result object is not returned.
        $Text | Should -Match 'service principal is configured\. 20 new permission'
        @($Result).Count | Should -Be 1
    }

    It 'continues without the snapshot when the setup fails' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock -Prerequisite @{ IsReady = $false; HasConfigurationMonitoringPermission = $false; UtcmServicePrincipalExists = $false; MissingUtcmPermissions = @(); Issues = @('The UTCM service principal was not found.') }
        Mock -ModuleName EntraOps Register-EntraOpsTenantGovernanceServicePrincipal { throw 'Insufficient privileges to complete the operation.' }

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SetupTenantGovernance -PassThru -WarningVariable Warnings -WarningAction SilentlyContinue 6>$null

        $Result.TenantGovernanceSnapshot.Setup | Should -Be 'Failed'
        $Result.TenantGovernanceSnapshot.Status | Should -Be 'Skipped'
        ($Warnings -join ' ') | Should -Match 'setup failed: Insufficient privileges.*Global Administrator or Privileged Role Administrator'
        Should -Invoke -ModuleName EntraOps Save-EntraOpsTenantGovernanceSnapshotJson -Times 0
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 1
    }

    It 'does not set up the tenant without an interactive sign-in' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock -Prerequisite @{ IsReady = $false; HasConfigurationMonitoringPermission = $false; UtcmServicePrincipalExists = $false; MissingUtcmPermissions = @(); Issues = @('The UTCM service principal was not found.') }

        $Result = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -AuthenticationType AlreadyAuthenticated -SetupTenantGovernance -PassThru -WarningVariable Warnings -WarningAction SilentlyContinue 6>$null

        Should -Invoke -ModuleName EntraOps Register-EntraOpsTenantGovernanceServicePrincipal -Times 0
        Should -Invoke -ModuleName EntraOps Connect-MgGraph -Times 0
        $Result.TenantGovernanceSnapshot.Setup | Should -Be 'NotPossible'
        ($Warnings -join ' ') | Should -Match 'needs an interactive sign-in'
    }

    It 'does not summarize the findings of an earlier run when the evaluation fails' {
        $Root = New-AssessmentWorkingFolder
        Set-AssessmentMock
        # findings.json of an earlier run (or of another tenant) stays in the working folder.
        New-Item -Path (Join-Path $Root 'Reports/Findings/data') -ItemType Directory -Force | Out-Null
        @{ Rules = @(@{ RuleId = 'EO.1001'; Title = 'Old'; Severity = 'Critical'; Status = 'Failed'; FailedCount = 9 }) } | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath (Join-Path $Root 'Reports/Findings/data/findings.json')
        Mock -ModuleName EntraOps New-EntraOpsReportingData { [pscustomobject]@{ App = 'PrivilegedAssets' } }

        $Output = Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot -PassThru 6>&1
        $Result = $Output | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] }
        $Text = ($Output | Where-Object { $_ -is [System.Management.Automation.InformationRecord] }) -join "`n"

        $Result.Findings.Rules | Should -Be 0
        $Result.Findings.Failed | Should -Be 0
        $Text | Should -Match 'Findings\s+: not evaluated in this run'
        $Text | Should -Not -Match 'EO\.1001'
    }

    It 'keeps the connections of the caller with -AuthenticationType AlreadyAuthenticated and clears the cache' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock

        Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -AuthenticationType AlreadyAuthenticated -SkipTenantGovernanceSnapshot 6>$null

        Should -Invoke -ModuleName EntraOps Disconnect-EntraOps -Times 0
        Should -Invoke -ModuleName EntraOps Clear-EntraOpsCache -Times 1 -Exactly -ParameterFilter { $CacheType -eq 'All' }
    }

    It 'disconnects after a failed interactive sign-in, which can leave Azure connected' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        Mock -ModuleName EntraOps Connect-EntraOps { throw 'The network is unreachable.' }

        { Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' 6>$null } | Should -Throw 'The network is unreachable.'
        Should -Invoke -ModuleName EntraOps Disconnect-EntraOps -Times 1 -Exactly

        # The connections of the caller are not touched.
        { Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -AuthenticationType AlreadyAuthenticated 6>$null } | Should -Throw 'The network is unreachable.'
        Should -Invoke -ModuleName EntraOps Disconnect-EntraOps -Times 1 -Exactly
    }

    It 'does not take unrelated sign-in errors that mention a consent for a missing admin consent' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock
        Mock -ModuleName EntraOps Connect-EntraOps { throw 'AADSTS650052: The app needs access to a service that your organization has not subscribed to. Contact your IT Admin to review the consent configuration.' }

        { Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' 6>$null } | Should -Throw 'AADSTS650052*'
    }

    It 'stops when the working folder holds the configuration of another tenant, which the reports would read' {
        $Root = New-AssessmentWorkingFolder
        @{ TenantName = 'fabrikam.onmicrosoft.com'; TenantId = '00000000-0000-0000-0000-000000000002' } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'EntraOpsConfig.json')
        Set-AssessmentMock

        { Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -WarningAction SilentlyContinue 6>$null } | Should -Throw '*configuration of another tenant (fabrikam.onmicrosoft.com)*-Path*'
        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsPrivilegedEAM -Times 0
        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 0
        Should -Invoke -ModuleName EntraOps Disconnect-EntraOps -Times 1
    }

    It 'accepts a working folder configuration of the connected tenant with another domain name' {
        $Root = New-AssessmentWorkingFolder
        @{ TenantName = 'contoso.com'; TenantId = $script:ConnectedTenantId } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'EntraOpsConfig.json')
        Set-AssessmentMock

        Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SkipTenantGovernanceSnapshot -WarningAction SilentlyContinue 6>$null

        Should -Invoke -ModuleName EntraOps New-EntraOpsReportingData -Times 1
    }

    It 'stops when the configuration of the working folder is not valid JSON' {
        $Root = New-AssessmentWorkingFolder
        Set-Content -LiteralPath (Join-Path $Root 'EntraOpsConfig.json') -Value '{ not json'
        Set-AssessmentMock

        { Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -WarningAction SilentlyContinue 6>$null } | Should -Throw '*EntraOpsConfig.json is not valid JSON*'
        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsPrivilegedEAM -Times 0
    }

    It 'requires a tenant for an interactive sign-in' {
        New-AssessmentWorkingFolder | Out-Null
        Set-AssessmentMock

        { Invoke-EntraOpsAssessment 6>$null } | Should -Throw '*-TenantName*'
        Should -Invoke -ModuleName EntraOps Connect-EntraOps -Times 0
    }
}

Describe 'Invoke-EntraOpsPrivilegedEAM -KeepConnection' {
    It 'is documented and declared' {
        $Command = Get-Command Invoke-EntraOpsPrivilegedEAM
        $Command.Parameters.ContainsKey('KeepConnection') | Should -BeTrue
        (Get-Help Invoke-EntraOpsPrivilegedEAM -Parameter KeepConnection).Description.Text | Should -Match 'Disconnect-EntraOps'
    }
}
