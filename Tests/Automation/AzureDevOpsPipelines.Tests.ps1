#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    # .azure-pipelines is not part of the default Update-EntraOps targets, so deployments may not ship it.
    $script:HasAdoPipelines = Test-Path -LiteralPath (Join-Path $script:TestRepositoryRoot '.azure-pipelines') -PathType Container
    # Deployments keep their own (possibly older) pipelines while Tests are updated, so only assert template content upstream.
    $script:IsConfiguredDeployment = Test-Path -LiteralPath (Join-Path $script:TestRepositoryRoot 'EntraOpsConfig.json')
    # Deployments of pre-release versions can keep pipelines with former file names (azure-pipelines-*.yml).
    $script:HasOutdatedDeploymentPipelines = $script:IsConfiguredDeployment -and @(
        'entraops-pull.yml', 'entraops-push.yml', 'entraops-push-reporting.yml',
        'entraops-pull-tenant-governance.yml', 'entraops-update.yml', 'entraops-test.yml' |
        Where-Object { -not (Test-Path -LiteralPath (Join-Path $script:TestRepositoryRoot ".azure-pipelines/$_") -PathType Leaf) }
    ).Count -gt 0
}

Describe 'Azure DevOps pipeline templates' -Skip:(-not $HasAdoPipelines -or $HasOutdatedDeploymentPipelines -or -not [bool](Get-Module -ListAvailable -Name powershell-yaml)) {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module powershell-yaml -ErrorAction Stop
        $script:PipelineRoot = Join-Path $script:TestRepositoryRoot '.azure-pipelines'
        $script:PipelineNames = @(
            'entraops-pull.yml'
            'entraops-push.yml'
            'entraops-push-reporting.yml'
            'entraops-pull-tenant-governance.yml'
            'entraops-update.yml'
            'entraops-test.yml'
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
            foreach ($Step in @($Pipeline.steps) + @($Pipeline.jobs | ForEach-Object { $_.steps })) {
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

    It 'uses the repository-local git helper from every writing pipeline' -Skip:$IsConfiguredDeployment {
        foreach ($PipelineName in @('entraops-pull.yml', 'entraops-pull-tenant-governance.yml')) {
            $Content = Get-Content -LiteralPath (Join-Path $PipelineRoot $PipelineName) -Raw
            $Content | Should -Match ([regex]::Escape('./.azure-pipelines/scripts/Ado-GitPush.ps1'))
            $Content | Should -Not -Match ([regex]::Escape('./scripts/ado/Ado-GitPush.ps1'))
        }
    }

    It 'force-stages generated PrivilegedEAM output for Azure DevOps commits' -Skip:$IsConfiguredDeployment {
        $GitPushScript = Get-Content -LiteralPath (Join-Path $PipelineRoot 'scripts/Ado-GitPush.ps1') -Raw
        $GitPushScript | Should -Match "git add --force --all -- '\./PrivilegedEAM'"
    }

    It 'scopes the OAuth header and restores temporary git configuration' -Skip:$IsConfiguredDeployment {
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

    It 'refuses to push generated output to a public project and rebases before pushing' -Skip:$IsConfiguredDeployment {
        $GitPushScript = Get-Content -LiteralPath (Join-Path $PipelineRoot 'scripts/Ado-GitPush.ps1') -Raw

        # Visibility is checked before anything is staged, mirroring Publish-EntraOpsGitHubChanges.ps1
        $GitPushScript.IndexOf('_apis/projects/') | Should -BeGreaterThan -1
        $GitPushScript.IndexOf('_apis/projects/') | Should -BeLessThan $GitPushScript.IndexOf('git add --all')
        $GitPushScript | Should -Match "visibility -ne 'private'"
        $GitPushScript | Should -Match 'git fetch origin \$BranchName[\s\S]*git rebase --autostash "origin/\$BranchName"[\s\S]*git push origin HEAD:\$BranchName'
        # BUILD_SOURCEBRANCHNAME is only the last segment of the ref
        $GitPushScript | Should -Match "BUILD_SOURCEBRANCH -replace '\^refs/heads/'"
        $GitPushScript | Should -Not -Match 'BUILD_SOURCEBRANCHNAME,'
    }

    It 'splats the config sections loaded by Connect-EntraOps in the push pipeline' -Skip:$IsConfiguredDeployment {
        $Content = Get-Content -LiteralPath (Join-Path $PipelineRoot 'entraops-push.yml') -Raw
        foreach ($Section in 'LogAnalytics', 'SentinelWatchLists', 'AutomatedAdministrativeUnitManagement', 'AutomatedRmauAssignmentsForUnprotectedObjects', 'AutomatedConditionalAccessTargetGroups', 'AutomatedElmCatalogProtection') {
            $Content | Should -Match ('Params = \$EntraOpsConfig\.' + $Section + '\r?\n')
            $Content | Should -Not -Match ('Params = \$Config\.' + $Section + '\r?\n')
        }
    }

    It 'resolves the service connection from a compile-time parameter in a managed region' -Skip:$IsConfiguredDeployment {
        # Azure Pipelines authorizes service connections before runtime expressions are evaluated
        foreach ($PipelineName in @('entraops-pull.yml', 'entraops-push.yml', 'entraops-push-reporting.yml', 'entraops-pull-tenant-governance.yml')) {
            $Content = Get-Content -LiteralPath (Join-Path $PipelineRoot $PipelineName) -Raw
            $Pipeline = $Content | ConvertFrom-Yaml
            $Parameter = @($Pipeline.parameters | Where-Object { $_.name -eq 'serviceConnection' })
            $Parameter.Count | Should -Be 1 -Because $PipelineName
            $Parameter[0].default | Should -Be 'EntraOps-ServiceConnection'
            $Content | Should -Match '(?m)^\s*# BEGIN EntraOps managed service connection\r?$'
            $Content | Should -Not -Match 'AzureServiceConnection'
            $AzureSteps = @(@($Pipeline.steps) + @($Pipeline.jobs | ForEach-Object { $_.steps }) | Where-Object task -Like 'AzurePowerShell@*')
            $AzureSteps.Count | Should -BeGreaterThan 0
            foreach ($Step in $AzureSteps) {
                $Step.inputs.azureSubscription | Should -Be '${{ parameters.serviceConnection }}' -Because $PipelineName
            }
        }
    }

    It 'never persists the job access token in the git configuration' {
        foreach ($PipelineName in $PipelineNames) {
            $Content = Get-Content -LiteralPath (Join-Path $PipelineRoot $PipelineName) -Raw
            $Content | Should -Not -Match 'persistCredentials:\s*true' -Because "$PipelineName runs module code after checkout"
        }
    }

    It 'processes the latest branch commit in pipelines triggered by the pull pipeline' -Skip:$IsConfiguredDeployment {
        foreach ($PipelineName in @('entraops-push.yml', 'entraops-push-reporting.yml')) {
            $Pipeline = Get-Content -LiteralPath (Join-Path $PipelineRoot $PipelineName) -Raw | ConvertFrom-Yaml
            $Steps = @($Pipeline.steps) + @($Pipeline.jobs | ForEach-Object { $_.steps })
            $Steps = @($Steps | Where-Object { $null -ne $_ })
            $LatestIndex = [array]::FindIndex($Steps, [Predicate[object]] { param($Step) $Step.inputs.filePath -eq './.azure-pipelines/scripts/Ado-CheckoutLatest.ps1' })
            $AzureIndex = [array]::FindIndex($Steps, [Predicate[object]] { param($Step) $Step.task -like 'AzurePowerShell@*' })
            $LatestIndex | Should -Be 1 -Because "$PipelineName must switch to the latest commit right after checkout"
            $AzureIndex | Should -BeGreaterThan $LatestIndex
            $Steps[$LatestIndex].env.SYSTEM_ACCESSTOKEN | Should -Be '$(System.AccessToken)'
        }
    }

    It 'resolves, validates and applies updates in separate jobs and publishes a pull request without Azure credentials' -Skip:$IsConfiguredDeployment {
        $Content = Get-Content -LiteralPath (Join-Path $PipelineRoot 'entraops-update.yml') -Raw
        $Pipeline = $Content | ConvertFrom-Yaml
        @($Pipeline.jobs.job) | Should -Be @('Resolve', 'Validate', 'Apply')
        $Content | Should -Not -Match 'AzurePowerShell@|azureSubscription|Ado-GitPush'
        $Resolve, $Validate, $Apply = $Pipeline.jobs

        $ResolveStep = $Resolve.steps | Where-Object name -EQ 'resolve'
        $ResolveStep.inputs.filePath | Should -Be './.azure-pipelines/scripts/Resolve-EntraOpsAdoUpdate.ps1'
        $ResolveStep.env.ENTRAOPS_PAT | Should -Be '$(EntraOpsUpdatePat)'

        # Candidate code runs only in the validation job. A sparse checkout would still fetch the generated
        # tenant data into .git, so the job has no checkout and receives the trusted validators as an artifact.
        $Validate.condition | Should -Match "dependencies\.Resolve\.outputs\['resolve\.validation_required'\], 'true'"
        @($Validate.steps | Where-Object { $_.ContainsKey('checkout') }).checkout | Should -Be @('none')
        @($Validate.steps.download | Where-Object { $_ }) | Should -Be @('current', 'current')
        @($Validate.steps.artifact | Where-Object { $_ }) | Should -Be @('EntraOps-trusted-validators', 'EntraOps-update-candidate')
        $ValidatorArtifact = $Resolve.steps | Where-Object { $_.inputs.artifact -eq 'EntraOps-trusted-validators' }
        $ValidatorArtifact.inputs.targetPath | Should -Be '$(Build.ArtifactStagingDirectory)/EntraOps-trusted-validators'
        ($Validate.steps | ConvertTo-Json -Depth 10) | Should -Not -Match 'AccessToken|ENTRAOPS_PAT'
        $DependenciesStep = $Validate.steps | Where-Object displayName -EQ 'Install candidate validation dependencies'
        $DependenciesStep.inputs.filePath | Should -Be '$(Pipeline.Workspace)/EntraOps-trusted-validators/Install-EntraOpsUpdateValidationDependencies.ps1'
        $ValidationStep = $Validate.steps | Where-Object displayName -EQ 'Validate candidate'
        $ValidationStep.inputs.filePath | Should -Be '$(Pipeline.Workspace)/EntraOps-trusted-validators/Test-EntraOpsUpdateCandidate.ps1'
        $ValidationStep.inputs.arguments | Should -Match '\-ExpectedArchiveSha256 "\$\(CandidateDigest\)"'
        $ValidationStep.inputs.arguments | Should -Match ([regex]::Escape('-RunBrowserTests:$$(RunBrowserTests)'))

        $Apply.condition | Should -Match "eq\(dependencies\.Validate\.result, 'Succeeded'\)"
        $ApplySteps = @($Apply.steps | Where-Object { $_.displayName })
        $StageIndex = [array]::FindIndex($ApplySteps, [Predicate[object]] { param($Step) $Step.inputs.filePath -eq './.azure-pipelines/scripts/Prepare-EntraOpsAdoUpdate.ps1' })
        $InstallIndex = [array]::FindIndex($ApplySteps, [Predicate[object]] { param($Step) $Step.inputs.filePath -eq './.azure-pipelines/scripts/Install-EntraOpsAdoUpdate.ps1' })
        $PublishIndex = [array]::FindIndex($ApplySteps, [Predicate[object]] { param($Step) $Step.displayName -eq 'Publish update' })
        $StageIndex | Should -BeGreaterThan -1
        $StageIndex | Should -BeLessThan $InstallIndex
        $InstallIndex | Should -BeLessThan $PublishIndex
        $ApplySteps[$StageIndex].inputs.arguments | Should -Match ([regex]::Escape('-PublisherPath "$(Agent.TempDirectory)/EntraOpsPublisher"'))
        $ApplySteps[$PublishIndex].inputs.filePath | Should -Be '$(Agent.TempDirectory)/EntraOpsPublisher/Publish-EntraOpsAdoUpdate.ps1'
        $ApplySteps[$PublishIndex].inputs.arguments | Should -Match ([regex]::Escape('-PublicationMode "$(PublicationMode)"'))
        $Apply.variables.PublicationMode | Should -Be "`$[ dependencies.Resolve.outputs['resolve.publication_mode'] ]"
        $ResolveStep = $Resolve.steps | Where-Object { $_.name -eq 'resolve' }
        $ResolveStep.inputs.arguments | Should -Match ([regex]::Escape("-PublicationModeOverride '`${{ parameters.publicationMode }}'"))
        @($ApplySteps | Where-Object { $_.env.SYSTEM_ACCESSTOKEN }).Count | Should -Be 1
        $ApplySteps[$PublishIndex].env.SYSTEM_ACCESSTOKEN | Should -Be '$(System.AccessToken)'
        $ApplySteps[$InstallIndex].env | Should -BeNullOrEmpty
        ($ApplySteps | Where-Object { $_.env.ENTRAOPS_PAT }).inputs.filePath | Should -Be './.azure-pipelines/scripts/Prepare-EntraOpsAdoUpdate.ps1'
        # The template contains orchestration only; every PowerShell task delegates to a script.
        foreach ($Step in $Pipeline.jobs.steps | Where-Object task -EQ 'PowerShell@2') {
            $Step.inputs.targetType | Should -Be 'filePath'
            $Step.inputs.script | Should -BeNullOrEmpty
            $Step.inputs.filePath | Should -Not -BeNullOrEmpty
        }
    }

    It 'passes the configured tenant explicitly to EntraOps connections' -Skip:$IsConfiguredDeployment {
        foreach ($PipelineName in @('entraops-pull.yml', 'entraops-push.yml')) {
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

    It 'covers GitHub push operations and Tenant Governance snapshots' -Skip:$IsConfiguredDeployment {
        $PushContent = Get-Content -LiteralPath (Join-Path $PipelineRoot 'entraops-push.yml') -Raw
        foreach ($Command in @(
                'Save-EntraOpsPrivilegedEAMInsightsCustomTable'
                'Save-EntraOpsPrivilegedEAMWatchLists'
                'New-EntraOpsPrivilegedAdministrativeUnit'
                'New-EntraOpsPrivilegedUnprotectedAdministrativeUnit'
                'New-EntraOpsPrivilegedConditionalAccessGroup'
                'Update-EntraOpsPrivilegedUnprotectedElmCatalog')) {
            $PushContent | Should -Match $Command
        }

        $TenantGovernanceContent = Get-Content -LiteralPath (Join-Path $PipelineRoot 'entraops-pull-tenant-governance.yml') -Raw
        $TenantGovernanceContent | Should -Match 'Invoke-EntraOpsTenantGovernanceSnapshot'
        $TenantGovernanceContent | Should -Match 'BUILD_CRONSCHEDULE_DISPLAYNAME'
    }

    # Deployments keep their own workflows and pipelines when Tests are updated, so only assert the template content upstream.
    It 'commits a released snapshot job after a failed Tenant Governance run on both platforms' -Skip:$IsConfiguredDeployment {
        # Only a released job is committed; after a published snapshot the pending job is collected again
        $TenantGovernanceContent = Get-Content -LiteralPath (Join-Path $PipelineRoot 'entraops-pull-tenant-governance.yml') -Raw
        $TenantGovernanceContent | Should -Match ([regex]::Escape("-not (& `$IsChanged '.SnapshotManifest.json')"))
        $TenantGovernanceContent | Should -Match ([regex]::Escape('##vso[task.setvariable variable=EntraOpsReleasedSnapshotJob]true'))
        $TenantGovernanceContent | Should -Match "(?s)condition: and\(failed\(\), eq\(variables\['EntraOpsReleasedSnapshotJob'\], 'true'\)\).*-Paths `"TenantGovernance/Snapshots/\.PendingSnapshotJob\.json`",`"TenantGovernance/Snapshots/\.LastAttemptManifest\.json`""

        $GitHubWorkflow = Get-Content -LiteralPath (Join-Path $PipelineRoot '../.github/workflows/Pull-EntraOpsTenantGovernance.yaml') -Raw
        $GitHubWorkflow | Should -Match ([regex]::Escape("-not (& `$IsChanged '.SnapshotManifest.json')"))
        $GitHubWorkflow | Should -Match "(?s)if: failure\(\) && .*steps\.snapshot\.outputs\.releasedJob == 'true'.*paths: TenantGovernance/Snapshots/\.PendingSnapshotJob\.json TenantGovernance/Snapshots/\.LastAttemptManifest\.json"
    }

    It 'keeps pull collection operations separate and validates generated artifacts' -Skip:$IsConfiguredDeployment {
        $PullPipeline = Get-Content -LiteralPath (Join-Path $PipelineRoot 'entraops-pull.yml') -Raw | ConvertFrom-Yaml
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

        $PullContent = Get-Content -LiteralPath (Join-Path $PipelineRoot 'entraops-pull.yml') -Raw
        $PullContent | Should -Match 'Test-EntraOpsGeneratedArtifacts[^\r\n]*-FailOnContradictoryTierPair:\$Strict'
        $PullContent | Should -Match '-FailOnPrivilegedAssignmentWithoutClassification:\$StrictEmptyClassification'
    }

    It 'tests reports and gates artifacts on private project visibility and opted-in test success' -Skip:$IsConfiguredDeployment {
        $ReportingContent = Get-Content -LiteralPath (Join-Path $PipelineRoot 'entraops-push-reporting.yml') -Raw
        $ReportingContent | Should -Match 'task: UseNode@1'
        # UseNode@1 ignores versionSpec (NodeTool@0 input) and falls back to Node 10.x
        $ReportingContent | Should -Match 'task: UseNode@1[\s\S]*?inputs:\s*\r?\n\s*version: "22\.x"'
        $ReportingContent | Should -Not -Match 'versionSpec'
        $ReportingContent | Should -Not -Match 'NodeTool@0'
        $ReportingContent | Should -Match 'Invoke-EntraOpsReportingGeneration'
        $ReportingContent | Should -Match 'npm run test:reports'
        $ReportingContent | Should -Match 'PublishPipelineArtifact@1'
        $ReportingContent | Should -Match "eq\(dependencies.Generate.outputs\['visibility.ProjectIsPrivate'\], 'true'\)"
        $ReportingContent | Should -Match '_apis/projects/'
        $ReportingPipeline = $ReportingContent | ConvertFrom-Yaml
        $ReportingPipeline.variables.ContainsKey('RunGeneratedReportTests') | Should -BeFalse
        @($ReportingPipeline.jobs.job) | Should -Be @('Generate', 'Test', 'Publish')
        $Generate, $Test, $Publish = $ReportingPipeline.jobs
        $GenerationStep = $Generate.steps | Where-Object { $_.displayName -eq 'Generate configured reports' }
        $GenerationStep.inputs.Inline | Should -Match '\$Config\.AutomatedReportingGeneration\.RunGeneratedReportTests -eq \$true'
        $GenerationStep.inputs.Inline | Should -Match 'task.setvariable variable=RunGeneratedReportTests;isOutput=true'
        $Test.dependsOn | Should -Be 'Generate'
        $Test.condition | Should -Match "eq\(dependencies.Generate.outputs\['generate.RunGeneratedReportTests'\], 'true'\)"
        $Test.condition | Should -Match "eq\(dependencies.Generate.outputs\['visibility.ProjectIsPrivate'\], 'true'\)"
        $Test.steps[0].checkout | Should -Be 'none'
        ($Test | ConvertTo-Yaml) | Should -Not -Match 'AzurePowerShell|azureSubscription|SYSTEM_ACCESSTOKEN|System.AccessToken'
        @($Generate.steps | Where-Object { $_.script -match 'npm|npx' }).Count | Should -Be 0
        $TestSteps = @($Test.steps | Where-Object { $_.task -eq 'UseNode@1' -or $_.script -match 'npm|npx' })
        $TestSteps.Count | Should -Be 4
        $ReportUploads = @($Generate.steps | Where-Object { $_.task -eq 'PublishPipelineArtifact@1' -and $_.inputs.artifact -eq 'EntraOps-Reporting' })
        $ReportUploads.Count | Should -Be 1
        $ReportUploads[0].condition | Should -Be "and(succeeded(), eq(variables['visibility.ProjectIsPrivate'], 'true'), ne(variables['generate.RunGeneratedReportTests'], 'true'))"
        $Handover = @($Generate.steps | Where-Object { $_.task -eq 'PublishPipelineArtifact@1' -and $_.inputs.artifact -eq 'EntraOps-Reporting-Untested' })
        $Handover.Count | Should -Be 1
        $Handover[0].condition | Should -Be "and(succeeded(), eq(variables['visibility.ProjectIsPrivate'], 'true'), eq(variables['generate.RunGeneratedReportTests'], 'true'))"
        @($Test.steps | Where-Object { $_.task -eq 'DownloadPipelineArtifact@2' -and $_.inputs.artifactName -eq 'EntraOps-Reporting-Untested' }).Count | Should -Be 1
        # Third-party packages run without install scripts, cannot use logging commands, and only within a time limit.
        $Test.timeoutInMinutes | Should -Be 30
        $NpmSteps = @($Test.steps | Where-Object { $_.script -match 'npm|npx' })
        $NpmSteps.Count | Should -Be 3
        $NpmSteps[0].script | Should -Be 'npm ci --ignore-scripts'
        foreach ($Step in $NpmSteps) { $Step.target.commands | Should -Be 'restricted' }
        $Test.variables.UploadReportTestDiagnostics | Should -Be "`$[ dependencies.Generate.outputs['generate.UploadReportTestDiagnostics'] ]"
        $TestUploads = @($Test.steps | Where-Object { $_.task -eq 'PublishPipelineArtifact@1' })
        $TestUploads.Count | Should -Be 1
        $TestUploads[0].inputs.artifact | Should -Be 'EntraOps-Reporting-TestDiagnostics'
        $TestUploads[0].condition | Should -Be "and(failed(), eq(variables['UploadReportTestDiagnostics'], 'true'))"

        # The tested artifact comes from a job that never ran the npm packages.
        @($Publish.dependsOn) | Should -Be @('Generate', 'Test')
        $Publish.condition | Should -Be "and(eq(dependencies.Generate.result, 'Succeeded'), eq(dependencies.Test.result, 'Succeeded'))"
        $Publish.steps[0].checkout | Should -Be 'none'
        ($Publish | ConvertTo-Yaml) | Should -Not -Match 'AzurePowerShell|azureSubscription|SYSTEM_ACCESSTOKEN|System.AccessToken|npm|npx'
        @($Publish.steps | Where-Object { $_.task -eq 'DownloadPipelineArtifact@2' }).inputs.artifactName | Should -Be 'EntraOps-Reporting-Untested'
        @($Publish.steps | Where-Object { $_.task -eq 'PublishPipelineArtifact@1' }).inputs.artifact | Should -Be 'EntraOps-Reporting'
        $Publish.variables.ExpectedReportsDigest | Should -Be "`$[ dependencies.Generate.outputs['handover.ReportsDigest'] ]"
        $StepNames = @($Publish.steps | ForEach-Object { "$($_.displayName)" })
        [array]::IndexOf($StepNames, 'Verify report bundle digest') | Should -BeLessThan ([array]::IndexOf($StepNames, 'Publish EntraOps Reporting artifact'))
    }

    It 'hands over only report assets and a minimal test harness' -Skip:$IsConfiguredDeployment {
        $Pipeline = Get-Content -LiteralPath (Join-Path $PipelineRoot 'entraops-push-reporting.yml') -Raw | ConvertFrom-Yaml
        $Prepare = $Pipeline.jobs[0].steps | Where-Object { $_.displayName -eq 'Prepare report handover' }
        $Fixture = Join-Path $TestDrive 'ReportingHandover'
        $Staging = Join-Path $TestDrive 'ReportingStaging'
        New-Item -Path "$Fixture/Reports/Nested", $Staging -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath "$Fixture/Reports/index.html" -Value '<html>Tenant report</html>'
        Set-Content -LiteralPath "$Fixture/Reports/Nested/report.spec.mjs" -Value 'test harness'
        Set-Content -LiteralPath "$Fixture/EntraOpsConfig.json" -Value 'private config'
        foreach ($Name in 'package.json', 'package-lock.json', 'playwright.config.mjs') {
            Copy-Item -LiteralPath (Join-Path $script:TestRepositoryRoot $Name) -Destination $Fixture
        }

        Push-Location $Fixture
        try {
            $ScriptText = $Prepare.inputs.script.Replace('$(Build.ArtifactStagingDirectory)', $Staging).Replace('$(generate.RunGeneratedReportTests)', 'true')
            & ([scriptblock]::Create($ScriptText))
        } finally {
            Pop-Location
        }

        Test-Path "$Staging/Reports/index.html" | Should -BeTrue
        @(Get-ChildItem "$Staging/Reports" -Recurse -Filter '*.spec.mjs').Count | Should -Be 0
        Test-Path "$Staging/ReportTests/Reports/Nested/report.spec.mjs" | Should -BeTrue
        @(Get-ChildItem "$Staging/ReportTests" -Recurse -File).Count | Should -Be 4
        Test-Path "$Staging/ReportTests/EntraOpsConfig.json" | Should -BeFalse
    }

    It 'verifies the tested hand-over against the digest of the staged bundle' -Skip:$IsConfiguredDeployment {
        # Match the update candidate validator and pipeline's terminating error policy.
        $ErrorActionPreference = 'Stop'
        $Pipeline = Get-Content -LiteralPath (Join-Path $PipelineRoot 'entraops-push-reporting.yml') -Raw | ConvertFrom-Yaml
        $Prepare = $Pipeline.jobs[0].steps | Where-Object { $_.name -eq 'handover' }
        $Verify = $Pipeline.jobs[2].steps | Where-Object { $_.displayName -eq 'Verify report bundle digest' }
        $Fixture = Join-Path $TestDrive 'DigestHandover'
        $Staging = Join-Path $TestDrive 'DigestStaging'
        New-Item -Path "$Fixture/Reports/App", $Staging -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath "$Fixture/Reports/App/index.html" -Value '<html>Tenant report</html>'
        foreach ($Name in 'package.json', 'package-lock.json', 'playwright.config.mjs') {
            Copy-Item -LiteralPath (Join-Path $script:TestRepositoryRoot $Name) -Destination $Fixture
        }

        Push-Location $Fixture
        try {
            $ScriptText = $Prepare.inputs.script.Replace('$(Build.ArtifactStagingDirectory)', $Staging).Replace('$(generate.RunGeneratedReportTests)', 'true')
            $Output = @(& ([scriptblock]::Create($ScriptText)) 6>&1 | ForEach-Object { "$_" })
        } finally {
            Pop-Location
        }
        $Digest = ($Output -match '^##vso\[task\.setvariable variable=ReportsDigest;isOutput=true\]') -replace '^.*\]', ''
        # Same algorithm as the GitHub workflow, so both platforms report comparable bundle digests.
        $Digest | Should -Be (& (Join-Path $script:TestRepositoryRoot '.github/scripts/Get-EntraOpsReportDigest.ps1') -Path "$Staging/Reports")

        $Workspace = Join-Path $TestDrive 'DigestPublish'
        Copy-Item -LiteralPath $Staging -Destination $Workspace -Recurse
        $VerifyText = $Verify.inputs.script.Replace('$(Pipeline.Workspace)', $Workspace)
        $PreviousDigest = $env:EXPECTED_DIGEST
        try {
            $env:EXPECTED_DIGEST = $Digest
            { & ([scriptblock]::Create($VerifyText)) } | Should -Not -Throw
            Add-Content -LiteralPath "$Workspace/Reports/App/index.html" -Value '<script>tampered</script>'
            { & ([scriptblock]::Create($VerifyText)) } | Should -Throw '*does not match*'
        } finally {
            $env:EXPECTED_DIGEST = $PreviousDigest
        }
    }

    It 'reads report testing from the config at runtime (<Setting>, override <Override>)' -Skip:$IsConfiguredDeployment -ForEach @(
        @{ Setting = 'missing'; Override = 'Configured'; ExpectedTests = 'false'; ExpectedDiagnostics = 'false' }
        @{ Setting = 'false'; Override = 'Configured'; ExpectedTests = 'false'; ExpectedDiagnostics = 'false' }
        @{ Setting = 'true'; Override = 'Configured'; ExpectedTests = 'true'; ExpectedDiagnostics = 'true' }
        @{ Setting = 'false'; Override = 'true'; ExpectedTests = 'true'; ExpectedDiagnostics = 'false' }
        @{ Setting = 'true'; Override = 'false'; ExpectedTests = 'false'; ExpectedDiagnostics = 'true' }
    ) {
        $Pipeline = Get-Content -LiteralPath (Join-Path $PipelineRoot 'entraops-push-reporting.yml') -Raw | ConvertFrom-Yaml
        ($Pipeline.parameters | Where-Object name -EQ 'runGeneratedReportTests').values | Should -Be @('Configured', 'true', 'false')
        $Generate = $Pipeline.jobs[0].steps | Where-Object name -EQ 'generate'
        $Lines = @($Generate.inputs.Inline -split '\r?\n' | Where-Object { $_ -match 'RunGeneratedReportTests|ReportTestsOverride|UploadReportTestDiagnostics' })
        $Lines.Count | Should -Be 6
        $Config = [pscustomobject]@{ AutomatedReportingGeneration = [pscustomobject]@{} }
        if ($Setting -ne 'missing') {
            $Config.AutomatedReportingGeneration | Add-Member -NotePropertyName RunGeneratedReportTests -NotePropertyValue ($Setting -eq 'true')
            $Config.AutomatedReportingGeneration | Add-Member -NotePropertyName UploadReportTestDiagnostics -NotePropertyValue ($Setting -eq 'true')
        }
        $ScriptText = ($Lines -join [Environment]::NewLine).Replace('${{ parameters.runGeneratedReportTests }}', $Override)

        $Output = @(& ([scriptblock]::Create($ScriptText)) 6>&1 | ForEach-Object { "$_" })

        $Output | Should -Contain "##vso[task.setvariable variable=RunGeneratedReportTests;isOutput=true]$ExpectedTests"
        $Output | Should -Contain "##vso[task.setvariable variable=UploadReportTestDiagnostics;isOutput=true]$ExpectedDiagnostics"
    }

    It 'uses configured partial snapshot policy unless explicitly overridden' -Skip:$IsConfiguredDeployment -ForEach @(
        @{ Configured = $false; Override = 'Configured'; Expected = $false }
        @{ Configured = $true; Override = 'Configured'; Expected = $true }
        @{ Configured = $null; Override = 'Configured'; Expected = $true }
        @{ Configured = $false; Override = 'true'; Expected = $true }
        @{ Configured = $true; Override = 'false'; Expected = $false }
    ) {
        $Pipeline = Get-Content -LiteralPath (Join-Path $PipelineRoot 'entraops-push-reporting.yml') -Raw | ConvertFrom-Yaml
        $Parameter = $Pipeline.parameters | Where-Object name -EQ 'allowPartialTenantGovernance'
        $Parameter.default | Should -Be 'Configured'
        $Generate = $Pipeline.jobs[0].steps | Where-Object name -EQ 'generate'
        $Policy = [regex]::Match($Generate.inputs.Inline, '(?s)\$ReportingParameters = @\{.*?(?=\s*if \(\[bool\]::Parse)').Value
        $Policy | Should -Not -BeNullOrEmpty
        $Policy = $Policy.Replace('${{ parameters.allowPartialTenantGovernance }}', $Override)
        $Config = @{ ConfigurationAnalyzer = @{ AllowPartialTenantGovernanceSnapshot = $Configured } }
        . ([scriptblock]::Create($Policy))
        $ReportingParameters.AllowPartialTenantGovernanceSnapshot | Should -Be $Expected
    }

    It 'runs repository, cross-platform Pester, and browser validation in ADO' -Skip:$IsConfiguredDeployment {
        $TestContent = Get-Content -LiteralPath (Join-Path $PipelineRoot 'entraops-test.yml') -Raw
        $TestContent | Should -Match 'Test-ModuleManifest'
        $TestContent | Should -Match 'Pester -RequiredVersion 5\.7\.1'
        $TestContent | Should -Match 'ubuntu-latest'
        $TestContent | Should -Match 'windows-latest'
        $TestContent | Should -Match 'macos-latest'
        $TestContent | Should -Match 'npm run test:browser'
    }
}
