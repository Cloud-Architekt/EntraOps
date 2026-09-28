#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

Describe 'Azure DevOps pipeline templates' -Skip:(-not [bool](Get-Module -ListAvailable -Name powershell-yaml)) {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module powershell-yaml -ErrorAction Stop
        $script:PipelineRoot = Join-Path $script:TestRepositoryRoot '.azure-pipelines'
        $script:PipelineNames = @(
            'azure-pipelines-pull.yml'
            'azure-pipelines-push.yml'
            'azure-pipelines-push-reporting.yml'
            'azure-pipelines-pull-tenant-governance.yml'
            'azure-pipelines-update.yml'
            'azure-pipelines-test.yml'
        )
    }

    It 'ships all pipeline templates as valid YAML' {
        foreach ($PipelineName in $PipelineNames) {
            $PipelinePath = Join-Path $PipelineRoot $PipelineName
            Test-Path -LiteralPath $PipelinePath -PathType Leaf | Should -BeTrue
            { Get-Content -LiteralPath $PipelinePath -Raw | ConvertFrom-Yaml -ErrorAction Stop } | Should -Not -Throw
        }
    }

    It 'keeps every embedded PowerShell block parseable after template expansion' {
        foreach ($PipelineName in $PipelineNames) {
            $Pipeline = Get-Content -LiteralPath (Join-Path $PipelineRoot $PipelineName) -Raw | ConvertFrom-Yaml
            foreach ($Step in @($Pipeline.steps)) {
                $ScriptText = if ($Step.inputs.Inline) {
                    [string]$Step.inputs.Inline
                } elseif ($Step.inputs.targetType -eq 'inline' -and $Step.inputs.script) {
                    [string]$Step.inputs.script
                }
                if (-not [string]::IsNullOrWhiteSpace($ScriptText)) {
                    $ScriptText = $ScriptText `
                        -replace '\$\{\{\s*parameters\.operation\s*\}\}', 'RunAndWait' `
                        -replace '\$\{\{\s*parameters\.timeoutInSeconds\s*\}\}', '3300' `
                        -replace '\$\{\{\s*parameters\.allowStaleTenantGovernance\s*\}\}', 'false' `
                        -replace '\$\{\{\s*parameters\.allowPartialTenantGovernance\s*\}\}', 'true'
                    $ParseErrors = $null
                    [System.Management.Automation.Language.Parser]::ParseInput($ScriptText, [ref]$null, [ref]$ParseErrors) | Out-Null
                    @($ParseErrors) | Should -BeNullOrEmpty -Because "$PipelineName contains executable PowerShell"
                }
            }
        }
    }

    It 'uses the repository-local git helper from every writing pipeline' {
        foreach ($PipelineName in @('azure-pipelines-pull.yml', 'azure-pipelines-pull-tenant-governance.yml', 'azure-pipelines-update.yml')) {
            $Content = Get-Content -LiteralPath (Join-Path $PipelineRoot $PipelineName) -Raw
            $Content | Should -Match ([regex]::Escape('./.azure-pipelines/scripts/Ado-GitPush.ps1'))
            $Content | Should -Not -Match ([regex]::Escape('./scripts/ado/Ado-GitPush.ps1'))
        }
    }

    It 'force-stages generated PrivilegedEAM output for Azure DevOps commits' {
        $GitPushScript = Get-Content -LiteralPath (Join-Path $PipelineRoot 'scripts/Ado-GitPush.ps1') -Raw
        $GitPushScript | Should -Match "git add --force --all -- '\./PrivilegedEAM'"
    }

    It 'scopes the OAuth header and restores temporary git configuration' {
        $GitPushScript = Get-Content -LiteralPath (Join-Path $PipelineRoot 'scripts/Ado-GitPush.ps1') -Raw

        $GitPushScript | Should -Match '\$CollectionUri\s*=\s*\$env:SYSTEM_COLLECTIONURI'
        $GitPushScript | Should -Match '\$ExtraHeaderKey\s*=\s*"http\.\$\(\$CollectionUri\.TrimEnd'
        $GitPushScript | Should -Match "GIT_CONFIG_COUNT\s*=\s*'2'"
        $GitPushScript | Should -Match 'GIT_CONFIG_KEY_0\s*=\s*\$ExtraHeaderKey'
        $GitPushScript | Should -Match 'GIT_CONFIG_VALUE_0\s*=\s*'''
        $GitPushScript | Should -Match 'GIT_CONFIG_KEY_1\s*=\s*\$ExtraHeaderKey'
        $GitPushScript | Should -Not -Match "GIT_CONFIG_KEY_[01]\s*=\s*'http\.extraHeader'"
        $GitPushScript | Should -Match '(?s)finally\s*\{.*SetEnvironmentVariable\(\$Name, \$PreviousEnvironment\[\$Name\]\)'
    }

    It 'uses the documented service connection by default and allows an override' {
        foreach ($PipelineName in @('azure-pipelines-pull.yml', 'azure-pipelines-push.yml', 'azure-pipelines-push-reporting.yml', 'azure-pipelines-pull-tenant-governance.yml', 'azure-pipelines-update.yml')) {
            $Content = Get-Content -LiteralPath (Join-Path $PipelineRoot $PipelineName) -Raw
            $Content | Should -Match "AzureServiceConnection: \$\[ coalesce\(variables\['EntraOpsAzureServiceConnection'\], 'EntraOps-ServiceConnection'\) \]"
        }
    }

    It 'passes the configured tenant explicitly to EntraOps connections' {
        foreach ($PipelineName in @('azure-pipelines-pull.yml', 'azure-pipelines-push.yml')) {
            $Content = Get-Content -LiteralPath (Join-Path $PipelineRoot $PipelineName) -Raw
            $Content | Should -Match 'Connect-EntraOps -AuthenticationType FederatedCredentials -TenantName \$Config\.TenantName -ConfigFilePath'
        }
    }

    It 'uses the latest Az version for every Azure PowerShell task' {
        foreach ($PipelineName in $PipelineNames) {
            $Pipeline = Get-Content -LiteralPath (Join-Path $PipelineRoot $PipelineName) -Raw | ConvertFrom-Yaml
            foreach ($Step in @($Pipeline.steps | Where-Object task -Like 'AzurePowerShell@*')) {
                $Step.inputs.azurePowerShellVersion | Should -Be 'LatestVersion' -Because "$PipelineName should use the latest Az module version"
            }
        }
    }

    It 'covers GitHub push operations and Tenant Governance snapshots' {
        $PushContent = Get-Content -LiteralPath (Join-Path $PipelineRoot 'azure-pipelines-push.yml') -Raw
        foreach ($Command in @(
                'Save-EntraOpsPrivilegedEAMInsightsCustomTable'
                'Save-EntraOpsPrivilegedEAMWatchLists'
                'New-EntraOpsPrivilegedAdministrativeUnit'
                'New-EntraOpsPrivilegedUnprotectedAdministrativeUnit'
                'New-EntraOpsPrivilegedConditionalAccessGroup'
                'Update-EntraOpsPrivilegedUnprotectedElmCatalog')) {
            $PushContent | Should -Match $Command
        }

        $TenantGovernanceContent = Get-Content -LiteralPath (Join-Path $PipelineRoot 'azure-pipelines-pull-tenant-governance.yml') -Raw
        $TenantGovernanceContent | Should -Match 'Invoke-EntraOpsTenantGovernanceSnapshot'
        $TenantGovernanceContent | Should -Match 'BUILD_CRONSCHEDULE_DISPLAYNAME'
    }

    It 'keeps pull collection operations separate and validates generated artifacts' {
        $PullPipeline = Get-Content -LiteralPath (Join-Path $PipelineRoot 'azure-pipelines-pull.yml') -Raw | ConvertFrom-Yaml
        $DisplayNames = @($PullPipeline.steps | ForEach-Object { $_.displayName })
        $ExpectedSteps = @(
            'Get updated definition files for classification'
            'Get updated scope for definition of Control Plane in Entra ID'
            'Run Save-EntraOpsPrivilegedEAMJson'
            'Validate generated Privileged EAM artifacts'
        )

        foreach ($ExpectedStep in $ExpectedSteps) {
            $DisplayNames | Should -Contain $ExpectedStep
        }
        $DisplayNames.IndexOf($ExpectedSteps[0]) | Should -BeLessThan $DisplayNames.IndexOf($ExpectedSteps[1])
        $DisplayNames.IndexOf($ExpectedSteps[1]) | Should -BeLessThan $DisplayNames.IndexOf($ExpectedSteps[2])
        $DisplayNames.IndexOf($ExpectedSteps[2]) | Should -BeLessThan $DisplayNames.IndexOf($ExpectedSteps[3])

        $ClassificationStep = $PullPipeline.steps | Where-Object { $_.displayName -eq $ExpectedSteps[0] }
        $ControlPlaneStep = $PullPipeline.steps | Where-Object { $_.displayName -eq $ExpectedSteps[1] }
        $CollectionStep = $PullPipeline.steps | Where-Object { $_.displayName -eq $ExpectedSteps[2] }
        $ClassificationStep.task | Should -Be 'AzurePowerShell@5'
        $ClassificationStep.condition | Should -Match 'ApplyAutomatedClassificationUpdate'
        [string]$ClassificationStep.inputs.Inline | Should -Match 'Update-EntraOpsClassificationFiles'
        [string]$ClassificationStep.inputs.Inline | Should -Not -Match 'Update-EntraOpsClassificationControlPlaneScope|Save-EntraOpsPrivilegedEAMJson'
        $ControlPlaneStep.task | Should -Be 'AzurePowerShell@5'
        $ControlPlaneStep.condition | Should -Match 'ApplyAutomatedControlPlaneScopeUpdate'
        [string]$ControlPlaneStep.inputs.Inline | Should -Match 'Update-EntraOpsClassificationControlPlaneScope'
        [string]$ControlPlaneStep.inputs.Inline | Should -Not -Match 'Update-EntraOpsClassificationFiles|Save-EntraOpsPrivilegedEAMJson'
        $CollectionStep.task | Should -Be 'AzurePowerShell@5'
        [string]$CollectionStep.inputs.Inline | Should -Match 'Save-EntraOpsPrivilegedEAMJson'
        [string]$CollectionStep.inputs.Inline | Should -Not -Match 'Update-EntraOpsClassificationFiles|Update-EntraOpsClassificationControlPlaneScope'

        $PullContent = Get-Content -LiteralPath (Join-Path $PipelineRoot 'azure-pipelines-pull.yml') -Raw
        $PullContent | Should -Match 'Test-EntraOpsGeneratedArtifacts[^\r\n]*-FailOnContradictoryTierPair:\$Strict'
        $PullContent | Should -Match '-FailOnPrivilegedAssignmentWithoutClassification:\$StrictEmptyClassification'
    }

    It 'tests reports and gates artifacts on private project visibility' {
        $ReportingContent = Get-Content -LiteralPath (Join-Path $PipelineRoot 'azure-pipelines-push-reporting.yml') -Raw
        $ReportingContent | Should -Match 'task: UseNode@1'
        $ReportingContent | Should -Not -Match 'NodeTool@0'
        $ReportingContent | Should -Match 'Invoke-EntraOpsReportingGeneration'
        $ReportingContent | Should -Match 'npm run test:reports'
        $ReportingContent | Should -Match 'PublishPipelineArtifact@1'
        $ReportingContent | Should -Match "eq\(variables.ProjectIsPrivate, 'true'\)"
        $ReportingContent | Should -Match '_apis/projects/'
    }

    It 'runs repository, cross-platform Pester, and browser validation in ADO' {
        $TestContent = Get-Content -LiteralPath (Join-Path $PipelineRoot 'azure-pipelines-test.yml') -Raw
        $TestContent | Should -Match 'Test-ModuleManifest'
        $TestContent | Should -Match 'Pester -RequiredVersion 5\.7\.1'
        $TestContent | Should -Match 'ubuntu-latest'
        $TestContent | Should -Match 'windows-latest'
        $TestContent | Should -Match 'macos-latest'
        $TestContent | Should -Match 'npm run test:browser'
    }
}