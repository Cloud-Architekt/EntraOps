#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:EntraOpsBaseFolder = $script:TestRepositoryRoot
    . "$script:TestRepositoryRoot/EntraOps/Public/Automation/Resolve-EntraOpsUpdateSource.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/Automation/Test-EntraOpsUpdateContract.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/Automation/Get-EntraOpsUpdateCandidate.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/Automation/Get-EntraOpsUpdatePlan.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/Core/Update-EntraOps.ps1"
}

# Evaluated at discovery: Update-EntraOpsRequiredWorkflowParameters rewrites this workflow with the
# operator's own values, so the shipped default is only assertable while it is still the template.
$UpdateWorkflowFile = Join-Path $script:TestRepositoryRoot '.github/workflows/Update-EntraOps.yaml'
$IsShippedUpdateWorkflow = (Test-Path -LiteralPath $UpdateWorkflowFile) -and
((Get-Content -LiteralPath $UpdateWorkflowFile -Raw) -match 'ClientId:\s*YourClientId')

$ScheduledWorkflowFiles = @(
    'Pull-EntraOpsPrivilegedEAM.yaml'
    'Pull-EntraOpsTenantGovernance.yaml'
    'Push-EntraOpsPrivilegedReporting.yaml'
    'Update-EntraOps.yaml'
)

# Evaluated at discovery: identifies the Cloud-Architekt distribution repositories (Insiders/public)
# by CI context or the origin remote; deployment repositories skip the distribution-only checks.
$CurrentRepositoryFullName = $env:GITHUB_REPOSITORY
if ([string]::IsNullOrWhiteSpace($CurrentRepositoryFullName)) {
    $OriginUrl = & git -C ($script:TestRepositoryRoot) remote get-url origin 2>$null
    if ($OriginUrl -match '[:/](?<Owner>[^/]+)/(?<Name>[^/]+?)(?:\.git)?/?$') {
        $CurrentRepositoryFullName = "$($Matches.Owner)/$($Matches.Name)"
    }
}
$IsDistributionRepository = $CurrentRepositoryFullName -in @(
    'Cloud-Architekt/EntraOps'
    'Cloud-Architekt/EntraOps-Insiders'
)

Describe 'Update-EntraOps update scope' {
    It 'includes documentation and regression tests in its default update folders' {
        $Command = Get-Command Update-EntraOps
        $FunctionAst = $Command.ScriptBlock.Ast.Find({
                param($Ast)
                $Ast -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Ast.Name -eq 'Update-EntraOps'
            }, $true)
        $TargetFoldersParameter = $FunctionAst.Body.ParamBlock.Parameters | Where-Object {
            $_.Name.VariablePath.UserPath -eq 'TargetUpdateFolders'
        }
        $DefaultFolders = @($TargetFoldersParameter.DefaultValue.SafeGetValue())

        $DefaultFolders | Should -Contain './Docs'
        $DefaultFolders | Should -Contain './Tests'
        $DefaultFolders | Should -Contain './.github/actions'
        $DefaultFolders | Should -Not -Contain './.github/workflows'
        $DefaultFolders | Should -Contain './package.json'
        $DefaultFolders | Should -Contain './package-lock.json'
        $DefaultFolders | Should -Contain './playwright.config.mjs'
        $DefaultFolders | Should -Contain './CHANGELOG.md'
        $DefaultFolders | Should -Contain './EntraOpsUpdateContract.json'
    }

    It 'allows documentation and regression tests as explicit update folders' {
        $Parameter = (Get-Command Update-EntraOps).Parameters['TargetUpdateFolders']
        $ValidateSet = @($Parameter.Attributes | Where-Object {
                $_ -is [System.Management.Automation.ValidateSetAttribute]
            })[0]

        $ValidateSet.ValidValues | Should -Contain './Docs'
        $ValidateSet.ValidValues | Should -Contain './Tests'
        $ValidateSet.ValidValues | Should -Contain './.github/actions'
        $ValidateSet.ValidValues | Should -Contain './.github/workflows'
        $ValidateSet.ValidValues | Should -Not -Contain './.github'
        $ValidateSet.ValidValues | Should -Contain './package.json'
        $ValidateSet.ValidValues | Should -Contain './CHANGELOG.md'
        $ValidateSet.ValidValues | Should -Contain './EntraOpsUpdateContract.json'
    }

    It 'validates the downloaded candidate before replacing any local target' {
        $Source = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot 'EntraOps/Public/Core/Update-EntraOps.ps1') -Raw
        $ValidationIndex = $Source.IndexOf('Validating update candidate')
        $ReplacementIndex = $Source.IndexOf('foreach ($TargetUpdateFolder in $TargetUpdateFolders)')

        $ValidationIndex | Should -BeGreaterThan -1
        $ReplacementIndex | Should -BeGreaterThan $ValidationIndex
        $Source | Should -Match 'Test-EntraOpsUpdateCandidate\.ps1'
        $Source | Should -Match 'SourceCommit'
        $Source.IndexOf('Test-EntraOpsUpdateContract') | Should -BeLessThan $ReplacementIndex
        $Source | Should -Match "TargetUpdateFolders -contains './\.github/workflows'"
        $Source | Should -Match 'Update-EntraOpsRequiredWorkflowParameters -ConfigFile \$ConfigFile'
    }

    It 'requires workflow dependencies and prevents validation bypass' {
        $MissingConfig = Join-Path $TestDrive 'missing.json'

        { Update-EntraOps -ConfigFile $MissingConfig -TargetUpdateFolders @('./.github/workflows') } |
        Should -Throw "*also requires target(s): ./.github/actions, ./.github/scripts*"
        { Update-EntraOps -ConfigFile $MissingConfig -TargetUpdateFolders @('./.github/actions', './.github/scripts', './.github/workflows') -SkipCandidateValidation } |
        Should -Throw "*validation cannot be skipped*"
    }

    It 'never imports candidate module code in the updater process' {
        $Source = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot 'EntraOps/Public/Core/Update-EntraOps.ps1') -Raw
        $ReplacementIndex = $Source.IndexOf('foreach ($TargetUpdateFolder in $TargetUpdateFolders)')
        $AfterReplacement = $Source.Substring($ReplacementIndex)

        $AfterReplacement | Should -Match 'Updated module import deferred until a subsequent clean process or session'
        $AfterReplacement | Should -Not -Match 'Import-Module \./EntraOps'
    }

    It 'uses the trusted action-reference validator rather than a candidate replacement' {
        $RepositoryRoot = $script:TestRepositoryRoot
        $CandidateRoot = Join-Path $TestDrive 'candidate'
        $ModuleRoot = Join-Path $CandidateRoot 'EntraOps'
        $CandidateScripts = Join-Path $CandidateRoot '.github/scripts'
        $CandidateWorkflows = Join-Path $CandidateRoot '.github/workflows'
        New-Item -ItemType Directory -Path $ModuleRoot, $CandidateScripts, $CandidateWorkflows -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $ModuleRoot 'EntraOps.psm1') -Value ''
        New-ModuleManifest -Path (Join-Path $ModuleRoot 'EntraOps.psd1') -RootModule 'EntraOps.psm1'
        Set-Content -LiteralPath (Join-Path $CandidateScripts 'Test-GitHubActionReferences.ps1') -Value "Write-Output 'candidate validator bypassed'"
        Set-Content -LiteralPath (Join-Path $CandidateWorkflows 'unsafe.yaml') -Value "steps:`n  - uses: actions/checkout@v7"

        { & (Join-Path $RepositoryRoot '.github/scripts/Test-EntraOpsUpdateCandidate.ps1') -CandidateRoot $CandidateRoot } |
        Should -Throw '*mutable or invalid external action reference*'
    }

    It 'checks action references before any candidate code can run and tamper with the validator' {
        # Run the validators from a scratch copy: a candidate that escaped the check would otherwise
        # be able to modify this repository's own scripts.
        $RepositoryRoot = $script:TestRepositoryRoot
        $TrustedScripts = Join-Path $TestDrive 'trusted-scripts'
        New-Item -ItemType Directory -Path $TrustedScripts -Force | Out-Null
        foreach ($Script in @('Test-EntraOpsUpdateCandidate.ps1', 'Test-GitHubActionReferences.ps1')) {
            Copy-Item -LiteralPath (Join-Path $RepositoryRoot ".github/scripts/$Script") -Destination $TrustedScripts
        }
        $TrustedValidator = Join-Path $TrustedScripts 'Test-GitHubActionReferences.ps1'
        $TrustedValidatorHash = (Get-FileHash -LiteralPath $TrustedValidator -Algorithm SHA256).Hash

        $CandidateRoot = Join-Path $TestDrive 'tampering-candidate'
        $ModuleRoot = Join-Path $CandidateRoot 'EntraOps'
        $CandidateWorkflows = Join-Path $CandidateRoot '.github/workflows'
        New-Item -ItemType Directory -Path $ModuleRoot, $CandidateWorkflows -Force | Out-Null
        $MarkerPath = Join-Path $TestDrive 'candidate-code-executed.marker'
        # Importing this module neuters the trusted validator and leaves proof that it ran.
        $TamperingModule = @(
            "Set-Content -LiteralPath '$TrustedValidator' -Value 'param(`$RepositoryRoot) Write-Output ''validator neutered'''"
            "Set-Content -LiteralPath '$MarkerPath' -Value 'executed'"
        ) -join [Environment]::NewLine
        Set-Content -LiteralPath (Join-Path $ModuleRoot 'EntraOps.psm1') -Value $TamperingModule
        New-ModuleManifest -Path (Join-Path $ModuleRoot 'EntraOps.psd1') -RootModule 'EntraOps.psm1'
        Set-Content -LiteralPath (Join-Path $CandidateWorkflows 'unsafe.yaml') -Value "steps:`n  - uses: actions/checkout@v7"

        { & (Join-Path $TrustedScripts 'Test-EntraOpsUpdateCandidate.ps1') -CandidateRoot $CandidateRoot } |
        Should -Throw '*mutable or invalid external action reference*'
        Test-Path -LiteralPath $MarkerPath | Should -BeFalse
        (Get-FileHash -LiteralPath $TrustedValidator -Algorithm SHA256).Hash | Should -Be $TrustedValidatorHash
    }

    It 'publishes a compatible update contract for the full deployment source' {
        $RepositoryRoot = $script:TestRepositoryRoot
        $ContractValidator = Get-Command Test-EntraOpsUpdateContract
        $Contract = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'EntraOpsUpdateContract.json') -Raw | ConvertFrom-Json
        # A deployment need not retain distribution-only root files such as CHANGELOG.md. Validate
        # the contract itself and every supported target that is present in this deployment copy.
        $Targets = @($Contract.SupportedUpdateTargets | Where-Object {
                Test-Path -LiteralPath (Join-Path $RepositoryRoot $_)
            })

        $Repositories = @($Contract.DistributionRepositories.PSObject.Properties.Name)
        $Repositories | Should -Contain 'Cloud-Architekt/EntraOps'
        foreach ($Repository in $Repositories) {
            $Result = & $ContractValidator -CandidateRoot $RepositoryRoot -Repository $Repository -TargetUpdateFolders $Targets
            $Result.SchemaVersion | Should -Be 1
            $Result.Repository | Should -Be $Repository
            $Result.SupportedTargets | Should -Contain './.github/workflows'
        }
        { & $ContractValidator -CandidateRoot $RepositoryRoot -Repository 'Cloud-Architekt/SomeOtherRepository' -TargetUpdateFolders @('./EntraOps') } | Should -Throw '*do not match requested source*'
        { & $ContractValidator -CandidateRoot $RepositoryRoot -Repository 'Cloud-Architekt/EntraOps' -TargetUpdateFolders @('./.github/workflows') } | Should -Throw '*also requires target(s)*'
    }

    It 'resolves a relative candidate path against the PowerShell location' {
        # Set-Location does not move the process working directory, so a GetFullPath-based resolver
        # would look for the candidate where pwsh was started instead of in the current location.
        $RepositoryRoot = $script:TestRepositoryRoot
        $ContractValidator = Get-Command Test-EntraOpsUpdateContract
        $CandidateRoot = Join-Path $TestDrive 'relative-candidate'
        New-Item -ItemType Directory -Path (Join-Path $CandidateRoot 'EntraOps') -Force | Out-Null
        @{ SchemaVersion = 1; Product = 'EntraOps'; DistributionRepositories = @{ 'Cloud-Architekt/EntraOps' = @{ RequiresPersonalAccessToken = $false } }; SupportedUpdateTargets = @('./EntraOps'); RequiredValidationPaths = @() } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $CandidateRoot 'EntraOpsUpdateContract.json')

        Push-Location $TestDrive
        try {
            $Result = & $ContractValidator -CandidateRoot 'relative-candidate' -Repository 'Cloud-Architekt/EntraOps' -TargetUpdateFolders @('./EntraOps')
            $Result.ContractPath | Should -Be (Join-Path $CandidateRoot 'EntraOpsUpdateContract.json')
        } finally {
            Pop-Location
        }
    }

    # The contract must list the repository that serves it, or that repository can never be a valid
    # update source. Only meaningful in the distribution repositories, so skipped elsewhere.
    It 'declares the serving distribution repository in its contract' -Skip:(-not $IsDistributionRepository) -TestCases @(@{ ExpectedRepository = $CurrentRepositoryFullName }) {
        $RepositoryRoot = $script:TestRepositoryRoot
        $Contract = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'EntraOpsUpdateContract.json') -Raw | ConvertFrom-Json

        @($Contract.DistributionRepositories.PSObject.Properties.Name) | Should -Contain $ExpectedRepository
    }

    It 'declares the public release channel without a token and the Insiders channel with one' {
        $RepositoryRoot = $script:TestRepositoryRoot
        $Contract = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'EntraOpsUpdateContract.json') -Raw | ConvertFrom-Json
        $SourceResolver = Get-Command Resolve-EntraOpsUpdateSource

        $Contract.DistributionRepositories.'Cloud-Architekt/EntraOps'.RequiresPersonalAccessToken | Should -BeFalse
        $Contract.DistributionRepositories.'Cloud-Architekt/EntraOps-Insiders'.RequiresPersonalAccessToken | Should -BeTrue

        $Public = & $SourceResolver -Repository 'EntraOps'
        $Public.Repository | Should -Be 'Cloud-Architekt/EntraOps'
        $Public.RequiresPersonalAccessToken | Should -BeFalse
        $Public.IsKnownDistributionRepository | Should -BeTrue
        $Public.RepositoryUrl | Should -Be 'https://github.com/Cloud-Architekt/EntraOps.git'

        $Insiders = & $SourceResolver -Repository 'Cloud-Architekt/EntraOps-Insiders'
        $Insiders.RepositoryName | Should -Be 'EntraOps-Insiders'
        $Insiders.RequiresPersonalAccessToken | Should -BeTrue

        $Custom = & $SourceResolver -Repository 'SomeFork' -WarningVariable ResolverWarnings -WarningAction SilentlyContinue
        $Custom.IsKnownDistributionRepository | Should -BeFalse
        $Custom.RequiresPersonalAccessToken | Should -BeFalse
        @($ResolverWarnings).Count | Should -Be 1

        { & $SourceResolver -Repository 'other-org/EntraOps' } | Should -Throw '*Only repositories in the Cloud-Architekt organization*'
        { & $SourceResolver -Repository '../evil' } | Should -Throw '*Unsupported automated-update repository*'
    }

    It 'keeps the Configuration Wizard repository options aligned with the contract catalog' {
        $RepositoryRoot = $script:TestRepositoryRoot
        $Contract = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'EntraOpsUpdateContract.json') -Raw | ConvertFrom-Json
        $Wizard = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'Docs/configuration/config-wizard.js') -Raw
        $ExpectedNames = @($Contract.DistributionRepositories.PSObject.Properties.Name | ForEach-Object { ($_ -split '/')[1] })

        $ListMatch = [regex]::Match($Wizard, 'var UPDATE_REPOSITORIES = \[(?<List>[^\]]+)\];')
        $ListMatch.Success | Should -BeTrue
        $WizardNames = @(($ListMatch.Groups['List'].Value -split ',') | ForEach-Object { $_.Trim().Trim('"') })
        ($WizardNames | Sort-Object) -join ',' | Should -Be (($ExpectedNames | Sort-Object) -join ',')
    }
}

Describe 'Update-EntraOps prepared candidate apply path' {
    It 'applies a prepared candidate from a relative path and records the manifest without cloning' {
        $RepositoryRoot = $script:TestRepositoryRoot
        $Deployment = Join-Path $TestDrive 'deployment'
        $Candidate = Join-Path $Deployment 'TmpUpdate'
        New-Item -ItemType Directory -Path (Join-Path $Deployment 'Samples'), (Join-Path $Candidate 'Samples') -Force | Out-Null
        # Minimal contract for both sides: the local copy provides the distribution catalog, the
        # candidate copy declares what this fake source contains.
        $Contract = @{ SchemaVersion = 1; Product = 'EntraOps'; DistributionRepositories = @{ 'Cloud-Architekt/EntraOps' = @{ Channel = 'Release'; RequiresPersonalAccessToken = $false } }; SupportedUpdateTargets = @('./Samples'); RequiredValidationPaths = @() } | ConvertTo-Json -Depth 5
        Set-Content -LiteralPath (Join-Path $Deployment 'EntraOpsUpdateContract.json') -Value $Contract
        Set-Content -LiteralPath (Join-Path $Candidate 'EntraOpsUpdateContract.json') -Value $Contract
        Set-Content -LiteralPath (Join-Path $Deployment 'Samples/old.txt') -Value 'old'
        Set-Content -LiteralPath (Join-Path $Candidate 'Samples/new.txt') -Value 'new'
        New-Item -ItemType Directory -Path (Join-Path $Candidate '.git') -Force | Out-Null

        $PreviousBaseFolder = $script:EntraOpsBaseFolder
        $PreviousPat = $env:ENTRAOPS_PAT
        $script:EntraOpsBaseFolder = $Deployment
        Push-Location $Deployment
        try {
            Remove-Item Env:ENTRAOPS_PAT -ErrorAction SilentlyContinue
            # Only the commit of the prepared candidate may be resolved; cloning or fetching must not happen.
            Mock git {
                if ($args -contains 'rev-parse') { $global:LASTEXITCODE = 0; return ('a' * 40) }
                throw "git must not clone or fetch for a prepared candidate (called with: $($args -join ' '))"
            }
            $Output = Update-EntraOps -ConfigFile (Join-Path $Deployment 'missing.json') -Repository 'EntraOps' -PreparedCandidatePath 'TmpUpdate' `
                -TargetUpdateFolders @('./Samples') -ValidatedSourceCommit ('a' * 40) -WarningAction SilentlyContinue
        } finally {
            Pop-Location
            $script:EntraOpsBaseFolder = $PreviousBaseFolder
            if ($null -eq $PreviousPat) { Remove-Item Env:ENTRAOPS_PAT -ErrorAction SilentlyContinue } else { $env:ENTRAOPS_PAT = $PreviousPat }
        }

        Test-Path -LiteralPath (Join-Path $Deployment 'Samples/new.txt') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $Deployment 'Samples/old.txt') | Should -BeFalse
        # The caller-supplied candidate is left for inspection; the workflow deletes it before publishing.
        Test-Path -LiteralPath $Candidate | Should -BeTrue
        $Manifest = Get-Content -LiteralPath (Join-Path $Deployment '.EntraOpsUpdateManifest.json') -Raw | ConvertFrom-Json
        $Manifest.Repository | Should -Be 'Cloud-Architekt/EntraOps'
        $Manifest.Channel | Should -Be 'Release'
        $Manifest.SourceCommit | Should -Be ('a' * 40)
        $Manifest.ValidationIsolation | Should -Be 'SeparateJob'
        @($Manifest.TargetUpdateFolders) | Should -Be @('./Samples')
        ($Output -join "`n") | Should -Match 'Using prepared update candidate'
    }
}

Describe 'Update candidate resolution' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $RepositoryRoot = $script:TestRepositoryRoot
        $Resolver = Get-Command Get-EntraOpsUpdateCandidate

        function New-UpdateConfig {
            param([hashtable]$AutomatedEntraOpsUpdate, [string]$Name)
            $Path = Join-Path $TestDrive "$Name.json"
            @{ AutomatedEntraOpsUpdate = $AutomatedEntraOpsUpdate } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Path
            return $Path
        }
    }

    It 'falls back to the built-in defaults for a configuration created before the update keys existed' {
        $ConfigPath = New-UpdateConfig -Name 'legacy' -AutomatedEntraOpsUpdate @{ ApplyAutomatedEntraOpsUpdate = $true; UpdateScheduledCron = '0 9 * * 3' }

        $Resolved = & $Resolver -ConfigFile $ConfigPath -DestinationPath (Join-Path $TestDrive 'unused') -ResolveOnly -WarningVariable Warnings -WarningAction SilentlyContinue

        $Resolved.Repository | Should -Be 'Cloud-Architekt/EntraOps'
        $Resolved.RequiresPersonalAccessToken | Should -BeFalse
        $Resolved.UsesPersonalAccessToken | Should -BeFalse
        $Resolved.RequestedRef | Should -Be 'main'
        $Resolved.TargetUpdateFolders | Should -Contain './EntraOps'
        $Resolved.TargetUpdateFolders | Should -Contain './EntraOpsUpdateContract.json'
        $Resolved.TargetUpdateFolders | Should -Not -Contain './.github'
        $Resolved.MissingConfigKeys.Count | Should -Be 3
        @($Warnings).Count | Should -Be 1
    }

    It 'prefers explicit configuration values over the defaults' {
        $ConfigPath = New-UpdateConfig -Name 'explicit' -AutomatedEntraOpsUpdate @{ Repository = 'EntraOps'; Branch = 'v1.0.0'; TargetUpdateFolders = @('./EntraOps', './Tests') }

        $Resolved = & $Resolver -ConfigFile $ConfigPath -DestinationPath (Join-Path $TestDrive 'unused') -ResolveOnly -WarningVariable Warnings -WarningAction SilentlyContinue

        $Resolved.Repository | Should -Be 'Cloud-Architekt/EntraOps'
        $Resolved.RequestedRef | Should -Be 'v1.0.0'
        $Resolved.TargetUpdateFolders | Should -Be @('./EntraOps', './Tests')
        $Resolved.MissingConfigKeys.Count | Should -Be 0
        @($Warnings).Count | Should -Be 0
    }

    It 'requires action and script targets when workflow updates are configured' {
        $IncompleteConfig = New-UpdateConfig -Name 'workflow-incomplete' -AutomatedEntraOpsUpdate @{ Repository = 'EntraOps-Insiders'; Branch = 'main'; TargetUpdateFolders = @('./.github/workflows') }
        { & $Resolver -ConfigFile $IncompleteConfig -DestinationPath (Join-Path $TestDrive 'unused') -ResolveOnly } |
        Should -Throw '*also requires target(s)*'

        $CompleteConfig = New-UpdateConfig -Name 'workflow-complete' -AutomatedEntraOpsUpdate @{ Repository = 'EntraOps-Insiders'; Branch = 'main'; TargetUpdateFolders = @('./.github/actions', './.github/scripts', './.github/workflows') }
        $Resolved = & $Resolver -ConfigFile $CompleteConfig -DestinationPath (Join-Path $TestDrive 'unused') -ResolveOnly
        $Resolved.TargetUpdateFolders | Should -Contain './.github/workflows'
    }

    It 'still rejects a present but malformed repository name or ref' {
        $BadRepository = New-UpdateConfig -Name 'bad-repo' -AutomatedEntraOpsUpdate @{ Repository = '../other-org/repo'; Branch = 'main' }
        $BadBranch = New-UpdateConfig -Name 'bad-branch' -AutomatedEntraOpsUpdate @{ Repository = 'EntraOps-Insiders'; Branch = '--upload-pack=evil' }

        { & $Resolver -ConfigFile $BadRepository -DestinationPath (Join-Path $TestDrive 'unused') -ResolveOnly -WarningAction SilentlyContinue } | Should -Throw '*Unsupported automated-update repository name*'
        { & $Resolver -ConfigFile $BadBranch -DestinationPath (Join-Path $TestDrive 'unused') -ResolveOnly -WarningAction SilentlyContinue } | Should -Throw '*Unsupported automated-update ref*'
    }

    It 'uses the same default targets as Update-EntraOps and New-EntraOpsConfigFile' {
        $ConfigPath = New-UpdateConfig -Name 'parity' -AutomatedEntraOpsUpdate @{ Branch = 'main' }
        $ResolvedDefaults = @((& $Resolver -ConfigFile $ConfigPath -DestinationPath (Join-Path $TestDrive 'unused') -ResolveOnly -WarningAction SilentlyContinue).TargetUpdateFolders)

        $FunctionAst = (Get-Command Update-EntraOps).ScriptBlock.Ast.Find({
                param($Ast)
                $Ast -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Ast.Name -eq 'Update-EntraOps'
            }, $true)
        $CmdletDefaults = @(($FunctionAst.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'TargetUpdateFolders' }).DefaultValue.SafeGetValue())

        $ConfigGenerator = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'EntraOps/Public/Configuration/New-EntraOpsConfigFile.ps1') -Raw
        $GeneratorMatch = [regex]::Match($ConfigGenerator, '(?s)\$DefaultUpdateTargets\s*=\s*if.*?\}\s*else\s*\{\s*@\((?<List>[^)]*)\)')
        $GeneratorMatch.Success | Should -BeTrue
        $GeneratorDefaults = @([regex]::Matches($GeneratorMatch.Groups['List'].Value, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })

        $ResolvedDefaults | Should -Be $CmdletDefaults
        $ResolvedDefaults | Should -Be $GeneratorDefaults
        $ResolvedDefaults | Should -Not -Contain './.github/workflows'
    }

    It 'requires a Personal Access Token for the private Insiders channel before cloning' {
        $ConfigPath = New-UpdateConfig -Name 'insiders' -AutomatedEntraOpsUpdate @{ Repository = 'EntraOps-Insiders'; Branch = 'main'; TargetUpdateFolders = @('./EntraOps') }
        $PreviousPat = $env:ENTRAOPS_PAT
        try {
            Remove-Item Env:ENTRAOPS_PAT -ErrorAction SilentlyContinue
            { & $Resolver -ConfigFile $ConfigPath -DestinationPath (Join-Path $TestDrive 'never-cloned') } | Should -Throw '*requires a Personal Access Token*'
            Test-Path -LiteralPath (Join-Path $TestDrive 'never-cloned') | Should -BeFalse

            $env:ENTRAOPS_PAT = 'test-token'
            $Resolved = & $Resolver -ConfigFile $ConfigPath -DestinationPath (Join-Path $TestDrive 'unused') -ResolveOnly
            $Resolved.Repository | Should -Be 'Cloud-Architekt/EntraOps-Insiders'
            $Resolved.RequiresPersonalAccessToken | Should -BeTrue
            $Resolved.UsesPersonalAccessToken | Should -BeTrue
        } finally {
            if ($null -eq $PreviousPat) { Remove-Item Env:ENTRAOPS_PAT -ErrorAction SilentlyContinue } else { $env:ENTRAOPS_PAT = $PreviousPat }
        }
    }

    It 'does not send a Personal Access Token to the public release channel' {
        $ConfigPath = New-UpdateConfig -Name 'public-with-pat' -AutomatedEntraOpsUpdate @{ Repository = 'EntraOps'; Branch = 'main'; TargetUpdateFolders = @('./EntraOps') }
        $PreviousPat = $env:ENTRAOPS_PAT
        try {
            $env:ENTRAOPS_PAT = 'test-token'
            $Resolved = & $Resolver -ConfigFile $ConfigPath -DestinationPath (Join-Path $TestDrive 'unused') -ResolveOnly
            $Resolved.RequiresPersonalAccessToken | Should -BeFalse
            $Resolved.UsesPersonalAccessToken | Should -BeFalse
        } finally {
            if ($null -eq $PreviousPat) { Remove-Item Env:ENTRAOPS_PAT -ErrorAction SilentlyContinue } else { $env:ENTRAOPS_PAT = $PreviousPat }
        }
    }
}

Describe 'Automated update change detection' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $RepositoryRoot = $script:TestRepositoryRoot
        $ChangeDetector = Get-Command Get-EntraOpsUpdatePlan
        $SourceCommit = '1234567890abcdef1234567890abcdef12345678'

        function New-UpdateManifest {
            param (
                [Parameter(Mandatory = $true)]
                [string]$Path,

                [string]$Repository = 'Cloud-Architekt/EntraOps-Insiders',

                [Parameter(Mandatory = $true)]
                [string]$Commit,

                [string[]]$Targets = @('./EntraOps', './Tests')
            )

            @{
                Repository           = $Repository
                SourceCommit         = $Commit
                ValidatedBeforeApply = $true
                BrowserTestsRun      = $true
                TargetUpdateFolders  = $Targets
            } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $Path -Encoding UTF8
        }
    }

    BeforeEach {
        $ManifestPath = Join-Path $TestDrive "$([guid]::NewGuid()).json"
    }

    It 'skips an already applied source commit with the same managed targets' {
        New-UpdateManifest -Path $ManifestPath -Commit $SourceCommit

        $Decision = & $ChangeDetector -Repository 'Cloud-Architekt/EntraOps-Insiders' `
            -SourceCommit $SourceCommit -TargetUpdateFolders @('./Tests', './EntraOps') -ManifestPath $ManifestPath

        $Decision.UpdateRequired | Should -BeFalse
        $Decision.ValidationRequired | Should -BeFalse
        $Decision.Reason | Should -Match 'already applied'
    }

    It 'requires validation when the source commit changes' {
        New-UpdateManifest -Path $ManifestPath -Commit 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

        $Decision = & $ChangeDetector -Repository 'Cloud-Architekt/EntraOps-Insiders' `
            -SourceCommit $SourceCommit -TargetUpdateFolders @('./EntraOps', './Tests') -ManifestPath $ManifestPath

        $Decision.UpdateRequired | Should -BeTrue
        $Decision.ValidationRequired | Should -BeTrue
        $Decision.Reason | Should -Match 'different source commit'
    }

    It 'requires validation when the repository or target set changes' {
        New-UpdateManifest -Path $ManifestPath -Commit $SourceCommit -Repository 'Cloud-Architekt/EntraOps' -Targets @('./EntraOps')

        (& $ChangeDetector -Repository 'Cloud-Architekt/EntraOps-Insiders' -SourceCommit $SourceCommit `
            -TargetUpdateFolders @('./EntraOps') -ManifestPath $ManifestPath).UpdateRequired | Should -BeTrue

        New-UpdateManifest -Path $ManifestPath -Commit $SourceCommit -Targets @('./EntraOps')
        (& $ChangeDetector -Repository 'Cloud-Architekt/EntraOps-Insiders' -SourceCommit $SourceCommit `
            -TargetUpdateFolders @('./EntraOps', './Tests') -ManifestPath $ManifestPath).UpdateRequired | Should -BeTrue
    }

    It 'fails safe for a missing or malformed manifest and supports forced revalidation' {
        (& $ChangeDetector -Repository 'Cloud-Architekt/EntraOps-Insiders' -SourceCommit $SourceCommit `
            -TargetUpdateFolders @('./EntraOps') -ManifestPath $ManifestPath).UpdateRequired | Should -BeTrue

        Set-Content -LiteralPath $ManifestPath -Value '{not-json'
        (& $ChangeDetector -Repository 'Cloud-Architekt/EntraOps-Insiders' -SourceCommit $SourceCommit `
            -TargetUpdateFolders @('./EntraOps') -ManifestPath $ManifestPath).UpdateRequired | Should -BeTrue

        New-UpdateManifest -Path $ManifestPath -Commit $SourceCommit -Targets @('./EntraOps')
        $Forced = & $ChangeDetector -Repository 'Cloud-Architekt/EntraOps-Insiders' -SourceCommit $SourceCommit `
            -TargetUpdateFolders @('./EntraOps') -ManifestPath $ManifestPath -ValidationFrequency Never -Force
        $Forced.UpdateRequired | Should -BeTrue
        $Forced.ValidationRequired | Should -BeTrue
    }

    It 'requires validation when the matching candidate was not fully validated before' {
        New-UpdateManifest -Path $ManifestPath -Commit $SourceCommit -Targets @('./EntraOps')
        $Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
        $Manifest.ValidatedBeforeApply = $false
        $Manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $ManifestPath -Encoding UTF8

        (& $ChangeDetector -Repository 'Cloud-Architekt/EntraOps-Insiders' -SourceCommit $SourceCommit `
            -TargetUpdateFolders @('./EntraOps') -ManifestPath $ManifestPath).UpdateRequired | Should -BeTrue

        $Manifest.ValidatedBeforeApply = $true
        $Manifest.BrowserTestsRun = $false
        $Manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $ManifestPath -Encoding UTF8
        (& $ChangeDetector -Repository 'Cloud-Architekt/EntraOps-Insiders' -SourceCommit $SourceCommit `
            -TargetUpdateFolders @('./EntraOps') -ManifestPath $ManifestPath).UpdateRequired | Should -BeTrue
    }

    It 'supports Always and Never validation independently of whether an update is required' {
        New-UpdateManifest -Path $ManifestPath -Commit $SourceCommit -Targets @('./EntraOps')

        $Always = & $ChangeDetector -Repository 'Cloud-Architekt/EntraOps-Insiders' -SourceCommit $SourceCommit `
            -TargetUpdateFolders @('./EntraOps') -ManifestPath $ManifestPath -ValidationFrequency Always
        $Always.UpdateRequired | Should -BeFalse
        $Always.ValidationRequired | Should -BeTrue

        New-UpdateManifest -Path $ManifestPath -Commit 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' -Targets @('./EntraOps')
        $Never = & $ChangeDetector -Repository 'Cloud-Architekt/EntraOps-Insiders' -SourceCommit $SourceCommit `
            -TargetUpdateFolders @('./EntraOps') -ManifestPath $ManifestPath -ValidationFrequency Never
        $Never.UpdateRequired | Should -BeTrue
        $Never.ValidationRequired | Should -BeFalse
    }

    It 'does not require historical browser validation when browser tests are disabled' {
        New-UpdateManifest -Path $ManifestPath -Commit $SourceCommit -Targets @('./EntraOps')
        $Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
        $Manifest.BrowserTestsRun = $false
        $Manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $ManifestPath -Encoding UTF8

        $Decision = & $ChangeDetector -Repository 'Cloud-Architekt/EntraOps-Insiders' -SourceCommit $SourceCommit `
            -TargetUpdateFolders @('./EntraOps') -ManifestPath $ManifestPath -RunBrowserTests:$false

        $Decision.UpdateRequired | Should -BeFalse
        $Decision.ValidationRequired | Should -BeFalse
        $Decision.RunBrowserTests | Should -BeFalse
    }

    It 'requires validation when a changed candidate updates workflow templates' {
        New-UpdateManifest -Path $ManifestPath -Commit 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

        $Decision = & $ChangeDetector -Repository 'Cloud-Architekt/EntraOps-Insiders' -SourceCommit $SourceCommit `
            -TargetUpdateFolders @('./.github/actions', './.github/scripts', './.github/workflows') `
            -ManifestPath $ManifestPath -ValidationFrequency Never

        $Decision.UpdateRequired | Should -BeTrue
        $Decision.ValidationRequired | Should -BeTrue
        $Decision.Reason | Should -Match 'mandatory when workflow templates are updated'
    }
}

Describe 'Automated update defaults' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $RepositoryRoot = $script:TestRepositoryRoot
    }

    It 'generates a configuration with PR-based automated updates disabled by default' {
        $ConfigGenerator = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'EntraOps/Public/Configuration/New-EntraOpsConfigFile.ps1') -Raw

        $ConfigGenerator | Should -Match '\[boolean\]\$ApplyAutomatedEntraOpsUpdate\s*=\s*\$false'
        $ConfigGenerator | Should -Match 'UpdateScheduledTrigger\s*=\s*\$ApplyAutomatedEntraOpsUpdate'
        $ConfigGenerator | Should -Match "\[ValidateSet\('PullRequest', 'DirectPush'\)\]"
        $ConfigGenerator | Should -Match '\[string\]\$UpdatePublicationMode\s*=\s*''PullRequest'''
        $ConfigGenerator | Should -Match 'PublicationMode\s*=\s*\$DefaultUpdatePublicationMode'
        $ConfigGenerator | Should -Match '(?s)\$DevOpsPlatform -eq ''AzureDevOps''.*DirectPush'
        $ConfigGenerator | Should -Match "\[ValidateSet\('OnChange', 'Always', 'Never'\)\]"
        $ConfigGenerator | Should -Match '\[string\]\$ValidationFrequency\s*=\s*''OnChange'''
        $ConfigGenerator | Should -Match '\[boolean\]\$RunBrowserTests\s*=\s*\$true'
    }

    It 'ships the Update-EntraOps workflow with automated updates disabled and PR publication' -Skip:(-not $IsShippedUpdateWorkflow) {
        $UpdateWorkflow = Get-Content -LiteralPath (Join-Path $RepositoryRoot '.github/workflows/Update-EntraOps.yaml') -Raw

        $UpdateWorkflow | Should -Match 'ApplyAutomatedEntraOpsUpdate:\s*false'
        $UpdateWorkflow | Should -Match 'PublicationMode:\s*PullRequest'
    }

    It 'defaults the Configuration Wizard to automated updates disabled with PR publication' {
        $Wizard = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'Docs/configuration/config-wizard.js') -Raw

        $Wizard | Should -Match 'ApplyAutomatedEntraOpsUpdate:\s*false'
        $Wizard | Should -Match 'UpdateScheduledTrigger:\s*false'
        $Wizard | Should -Match 'UpdatePublicationMode:\s*"PullRequest"'
        $Wizard | Should -Match 'UpdateValidationFrequency:\s*"OnChange"'
        $Wizard | Should -Match 'UpdateRunBrowserTests:\s*true'
    }

    It 'excludes workflow definitions from every automated update default' {
        $ConfigGenerator = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'EntraOps/Public/Configuration/New-EntraOpsConfigFile.ps1') -Raw
        $Wizard = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'Docs/configuration/config-wizard.js') -Raw
        $SetupWizard = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'Docs/get-started/setup-wizard.js') -Raw
        $GeneratorDefaultsRegion = ($ConfigGenerator -split '\$DefaultUpdateTargets\s*=')[1] -split '\$DefaultUpdatePublicationMode\s*='
        $SetupDefaultsRegion = ($SetupWizard -split 'var updateTargets\s*=')[1] -split 'return \{'

        $GeneratorDefaultsRegion | Should -Not -BeNullOrEmpty
        $GeneratorDefaultsRegion | Should -Not -Match '"\./\.github/workflows"'
        $Wizard | Should -Match 'UpdateTargetFolders:\s*\[(?![^\]]*"\./\.github/workflows")'
        $SetupDefaultsRegion | Should -Not -BeNullOrEmpty
        $SetupDefaultsRegion | Should -Not -Match '"\./\.github/workflows"'
    }

    It 'documents manual and GitHub App workflow-update opt-in paths' {
        $CoreDocs = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'Docs/content/core.md') -Raw
        $Wizard = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'Docs/configuration/config-wizard.js') -Raw

        $CoreDocs | Should -Match 'Update workflow definitions manually'
        $CoreDocs | Should -Match 'Enable workflow definitions in automated updates'
        $CoreDocs | Should -Match 'EntraOpsUpdateAppClientId'
        $CoreDocs | Should -Match 'EntraOpsUpdateAppPrivateKey'
        $Wizard | Should -Match 'GITHUB_TOKEN cannot publish workflow-file changes'
    }

    It 'tracks main by default for maintenance-free updates' {
        $ConfigGenerator = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'EntraOps/Public/Configuration/New-EntraOpsConfigFile.ps1') -Raw
        $Wizard = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'Docs/configuration/config-wizard.js') -Raw

        $ConfigGenerator | Should -Match 'Branch\s*=\s*"main"'
        $Wizard | Should -Match 'UpdateBranch:\s*"main"'
        $Wizard | Should -Match 'key:\s*"UpdateBranch"[^\r\n]+default:\s*"main"'
    }

    It 'defaults full deployment updates to the public release channel' {
        $ConfigGenerator = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'EntraOps/Public/Configuration/New-EntraOpsConfigFile.ps1') -Raw
        $Wizard = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'Docs/configuration/config-wizard.js') -Raw
        $SetupWizard = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'Docs/get-started/setup-wizard.js') -Raw

        $ConfigGenerator | Should -Match '\[string\]\$UpdateRepository\s*=\s*.EntraOps.'
        $ConfigGenerator | Should -Match 'Repository\s*=\s*\$UpdateRepository'
        (Get-Command Update-EntraOps).Parameters['Repository'] | Should -Not -BeNullOrEmpty
        $Wizard | Should -Match 'UpdateRepository:\s*"EntraOps"'
        $Wizard | Should -Match 'EntraOpsUpdateContract\.json'
        $SetupWizard | Should -Match 'Repository:\s*"EntraOps"'
    }

    It 'warns that PullRequest publication needs GitHub Actions permission to create pull requests' {
        $Wizard = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'Docs/configuration/config-wizard.js') -Raw
        $Publisher = Get-Content -LiteralPath (Join-Path $RepositoryRoot '.github/scripts/Publish-EntraOpsGitHubUpdate.ps1') -Raw
        $WorkflowParameters = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'EntraOps/Public/Configuration/Update-EntraOpsRequiredWorkflowParameters.ps1') -Raw
        $CoreDocs = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'Docs/content/core.md') -Raw
        $DocsLink = 'managing-github-actions-settings-for-a-repository#preventing-github-actions-from-creating-or-approving-pull-requests'

        $Wizard | Should -Match 'key:\s*"UpdatePublicationMode"[^\r\n]+Allow GitHub Actions to create and approve pull requests'
        $Wizard | Should -Match ([regex]::Escape($DocsLink))
        $Publisher | Should -Match '& gh pr create'
        $Publisher | Should -Match ([regex]::Escape($DocsLink))
        $WorkflowParameters | Should -Match ([regex]::Escape($DocsLink))
        $CoreDocs | Should -Match ([regex]::Escape($DocsLink))
    }

    It 'isolates automated candidate validation from update and write credentials' {
        $Workflow = Get-Content -LiteralPath (Join-Path $RepositoryRoot '.github/workflows/Update-EntraOps.yaml') -Raw
        $ResolveJob = ($Workflow -split '(?m)^  Resolve:\s*$')[1] -split '(?m)^  Validate:\s*$' | Select-Object -First 1
        $ValidateJob = ($Workflow -split '(?m)^  Validate:\s*$')[1] -split '(?m)^  Apply:\s*$' | Select-Object -First 1
        $ApplyJob = ($Workflow -split '(?m)^  Apply:\s*$')[1]
        $Resolver = Get-Content -LiteralPath (Join-Path $RepositoryRoot '.github/scripts/Resolve-EntraOpsGitHubUpdate.ps1') -Raw
        $CandidateValidator = Get-Content -LiteralPath (Join-Path $RepositoryRoot '.github/scripts/Test-EntraOpsUpdateCandidate.ps1') -Raw
        $CandidateInstaller = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'EntraOps/Public/Automation/Install-EntraOpsUpdateCandidate.ps1') -Raw
        $Publisher = Get-Content -LiteralPath (Join-Path $RepositoryRoot '.github/scripts/Publish-EntraOpsGitHubUpdate.ps1') -Raw

        $Workflow | Should -Match '(?m)^  Resolve:\s*$'
        $Workflow | Should -Match 'candidate_digest:.*steps\.resolve\.outputs\.candidate_digest'
        $Workflow | Should -Match 'update_required:.*steps\.resolve\.outputs\.update_required'
        $Workflow | Should -Match 'validation_required:.*steps\.resolve\.outputs\.validation_required'
        $Workflow | Should -Match 'run_browser_tests:.*steps\.resolve\.outputs\.run_browser_tests'
        $Workflow | Should -Match 'publication_mode:.*steps\.resolve\.outputs\.publication_mode'
        $Workflow | Should -Match 'Resolve-EntraOpsGitHubUpdate\.ps1'
        $Workflow | Should -Match "steps\.resolve\.outputs\.validation_required == 'true'"
        $Workflow | Should -Match 'inputs\.force'
        $Workflow | Should -Match '(?m)^      validation_required:\r?$'
        $Workflow | Should -Match '(?m)^      run_browser_tests:\r?$'
        $Workflow | Should -Match '(?m)^      publication_mode:\r?$'
        $Workflow | Should -Match 'VALIDATION_REQUIRED_OVERRIDE:\s*\$\{\{ inputs\.validation_required \}\}'
        $Workflow | Should -Match 'RUN_BROWSER_TESTS_OVERRIDE:\s*\$\{\{ inputs\.run_browser_tests \}\}'
        $Workflow | Should -Match 'PUBLICATION_MODE_OVERRIDE:\s*\$\{\{ inputs\.publication_mode \}\}'
        $Resolver | Should -Match '\$EffectiveRunBrowserTests = \[System\.Convert\]::ToBoolean\(\$RunBrowserTestsOverride\)'
        $Resolver | Should -Match "PublicationModeOverride -eq 'pull-request'"
        $Resolver | Should -Match "PublicationModeOverride -eq 'direct-push'"
        $Resolver | Should -Match 'publication_mode\s*=\s*\$EffectivePublicationMode'
        $Resolver | Should -Match '-RunBrowserTests:\$EffectiveRunBrowserTests'
        $Resolver | Should -Match '\$Decision\.ValidationRequired = \[System\.Convert\]::ToBoolean\(\$ValidationRequiredOverride\)'
        $Resolver | Should -Match "Candidate validation cannot be disabled when './\.github/workflows' is updated"
        $ValidateJob | Should -Match 'Test-EntraOpsUpdateCandidate\.ps1'
        $ValidateJob | Should -Match '-ArchivePath .*/EntraOps-update-candidate\.tar'
        $ValidateJob | Should -Match '-ExpectedArchiveSha256.*candidate_digest'
        $CandidateValidator | Should -Match 'Get-FileHash.*\$ArchivePath'
        $ValidateJob | Should -Not -Match 'ENTRAOPS_PAT|GITHUB_TOKEN|contents:\s*write'
        # Candidate tests run in Validate; they must not be able to read the deployment's tenant data.
        $ValidateJob | Should -Match 'sparse-checkout:\s*\|\s*\r?\n\s*\.github/scripts\s*\r?\n'
        $ValidateJob | Should -Match 'sparse-checkout-cone-mode:\s*true'
        $ApplyJob | Should -Match 'ExpectedSourceCommit.*needs\.Resolve\.outputs\.source_sha'
        $ApplyJob | Should -Match 'Install-EntraOpsUpdateCandidate'
        $ApplyJob | Should -Not -Match 'Get-EntraOpsUpdateCandidate\.ps1|Apply-EntraOpsUpdateCandidate\.ps1'
        $ApplyJob | Should -Match 'Apply candidate without update credentials'
        # The prepared candidate is a clone with its own .git directory; publishing it would commit an
        # embedded repository and break the next Resolve run.
        $CandidateInstaller | Should -Match 'ValidatedSourceCommit\s*=\s*\$SourceCommit'
        $CandidateInstaller | Should -Match 'Remove-Item -LiteralPath \$CandidatePath -Recurse -Force'
        $CandidateInstaller | Should -Match 'SkipCandidateValidation'
        $ApplyJob | Should -Not -Match 'uses:\s*\./\.github/actions/Git-Push'
        $ApplyJob | Should -Match 'Stage trusted GitHub publisher'
        $ApplyJob | Should -Match 'Publish the applied candidate with trusted workflow code'
        $ApplyJob.IndexOf('Stage trusted GitHub publisher') | Should -BeLessThan $ApplyJob.IndexOf('Apply candidate without update credentials')
        $ApplyJob | Should -Match 'Join-Path \$env:RUNNER_TEMP ''Publish-EntraOpsGitHubUpdate\.ps1'''
        $ApplyJob | Should -Match 'Detect updated workflow definitions'
        $ApplyJob | Should -Match 'actions/create-github-app-token@[0-9a-f]{40}\s+# v3\.2\.0'
        $ApplyJob | Should -Match 'permission-workflows:\s*write'
        $ApplyJob | Should -Match 'EntraOpsUpdateAppClientId'
        $ApplyJob | Should -Match 'EntraOpsUpdateAppPrivateKey'
        $Publisher | Should -Match '\[skip actions\]'
        $ApplyJob | Should -Match 'WORKFLOW_PUBLISH_TOKEN'
        $ApplyJob | Should -Match 'statuses:\s*write'
        $ApplyJob | Should -Not -Match 'actions:\s*write'
        $ApplyJob | Should -Match 'pull-requests:\s*write'
        $ApplyJob | Should -Match 'needs\.Resolve\.outputs\.publication_mode'
        $Publisher | Should -Match '& git push origin "HEAD:\$BaseBranch"'
        $Publisher | Should -Match 'entraops/update-\$\(\$SourceCommit\.Substring\(0, 12\)\)'
        $Publisher | Should -Match '& gh pr create'
        # The update branch carries candidate-controlled workflow files. Dispatching any workflow on
        # that ref would run them with the repository token and secrets before review, so the review
        # signal is a commit status from the trusted Apply job instead.
        $Publisher | Should -Not -Match 'gh workflow run'
        $Publisher | Should -Not -Match '--ref\s+"?\$UpdateBranch'
        $Publisher | Should -Match 'repos/\$Repository/statuses/\$Sha'
        $Publisher | Should -Match 'context=EntraOps / Update candidate validation'
        $Publisher | Should -Match '& \$PostValidationStatus \$CommitSha'
        foreach ($Job in @($ResolveJob, $ValidateJob, $ApplyJob)) {
            $Job | Should -Match 'persist-credentials:\s*false'
        }
        # Candidate code runs in Validate; a cache it populates must not reach trusted jobs.
        $ValidateJob | Should -Not -Match 'cache:\s*npm'
        # Only Apply writes, so only Apply may hold the shared writer lock.
        $Workflow | Should -Not -Match '(?m)^concurrency:'
        $ApplyJob | Should -Match 'group:\s*entraops-main-writer'

        $GitPushAction = Get-Content -LiteralPath (Join-Path $RepositoryRoot '.github/actions/Git-Push/action.yml') -Raw
        $GitPushAction | Should -Match 'Publish-EntraOpsGitHubChanges\.ps1'
    }

    It 'fails in Resolve when workflow templates are targeted without a configured GitHub App publisher' {
        $Workflow = Get-Content -LiteralPath (Join-Path $RepositoryRoot '.github/workflows/Update-EntraOps.yaml') -Raw
        $ResolveJob = ($Workflow -split '(?m)^  Resolve:\s*$')[1] -split '(?m)^  Validate:\s*$' | Select-Object -First 1
        $Resolver = Get-Content -LiteralPath (Join-Path $RepositoryRoot '.github/scripts/Resolve-EntraOpsGitHubUpdate.ps1') -Raw
        $CoreDocs = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'Docs/content/core.md') -Raw

        # The variable is passed through env so the App client ID is never interpolated into the script.
        $ResolveJob | Should -Match 'WORKFLOW_PUBLISHER_CLIENT_ID:\s*\$\{\{ vars\.EntraOpsUpdateAppClientId \}\}'
        $ResolveJob | Should -Match '-WorkflowPublisherConfigured \(-not \[string\]::IsNullOrWhiteSpace\(\$env:WORKFLOW_PUBLISHER_CLIENT_ID\)\)'
        $Resolver | Should -Match '\[bool\]\$WorkflowPublisherConfigured = \$true'
        $Resolver | Should -Match "-contains './\.github/workflows' -and \`$Decision\.UpdateRequired -and -not \`$WorkflowPublisherConfigured"
        $Resolver | Should -Match '::error title=EntraOps update publisher not configured::'
        $Resolver | Should -Match 'EntraOpsUpdateAppClientId'
        $CoreDocs | Should -Match 'the Resolve job fails immediately'
    }

    It 'tells reviewers which checks run on the update pull request and recommends a protecting ruleset' {
        $Publisher = Get-Content -LiteralPath (Join-Path $RepositoryRoot '.github/scripts/Publish-EntraOpsGitHubUpdate.ps1') -Raw
        $CoreDocs = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'Docs/content/core.md') -Raw

        # A GITHUB_TOKEN-created pull request does run pull_request workflows; only the [skip actions]
        # workflow-update commit suppresses them. The body must not claim otherwise.
        $Publisher | Should -Not -Match 'intentionally not run'
        $Publisher | Should -Match '\$ReviewGuidance = if \(\$WorkflowChanges\)'
        $Publisher | Should -Match 'runs on this pull request through its `pull_request` trigger'
        $Publisher | Should -Match 'no repository workflow runs on the branch before review'
        # A required check that [skip actions] skipped stays pending forever, so the only check the
        # ruleset may require is the status the Apply job posts itself.
        $Publisher | Should -Match 'ruleset that requires the ``EntraOps / Update candidate validation`` status'
        $Publisher | Should -Match 'Do not make Test-EntraOps a required check'
        $CoreDocs | Should -Not -Match 'No workflow is dispatched on the update branch on purpose'
        $CoreDocs | Should -Match 'ruleset that requires the\s+> `EntraOps / Update candidate validation` status'
        $CoreDocs | Should -Match 'Do\s+> not make the `Test-EntraOps` checks required'
    }
}

Describe 'Generated artifact validation' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $PullWorkflow = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot '.github/workflows/Pull-EntraOpsPrivilegedEAM.yaml') -Raw
    }

    It 'drives the artifact validator from the FailOnContradictoryTierPair environment flag' {
        $PullWorkflow | Should -Match 'Test-EntraOpsGeneratedArtifacts[^\r\n]*-FailOnContradictoryTierPair:\$Strict'
        $PullWorkflow | Should -Not -Match 'Test-EntraOpsGeneratedArtifacts\.ps1'
        $PullWorkflow | Should -Match '\$Strict = .*env\.FailOnContradictoryTierPair'
    }

    It 'reports contradictory tier pairs as warnings by default' {
        # Tier pair drift is tenant tagging data, so a default deployment must not block the whole run.
        $PullWorkflow | Should -Match 'FailOnContradictoryTierPair:\s*false'

        $ConfigGenerator = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot 'EntraOps/Public/Configuration/New-EntraOpsConfigFile.ps1') -Raw
        $ConfigGenerator | Should -Match '\[boolean\]\$FailOnContradictoryTierPair\s*=\s*\$false'
        $ConfigGenerator | Should -Match 'GeneratedArtifactValidation'
    }
}

Describe 'Deployment browser validation' {
    It 'runs browser tests without restricting them to the upstream repositories' {
        $Workflow = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot '.github/workflows/Test-EntraOps.yaml') -Raw
        $BrowserJob = ($Workflow -split '(?m)^  Browser:\s*$')[1]

        $BrowserJob | Should -Not -Match "github\.repository == 'Cloud-Architekt/EntraOps"
        $BrowserJob | Should -Match 'npm run test:browser'
    }

    It 'tests generated reports before artifacts are uploaded' {
        $Workflow = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot '.github/workflows/Push-EntraOpsPrivilegedReporting.yaml') -Raw

        $Workflow.IndexOf('Test generated reports before publication') | Should -BeLessThan $Workflow.IndexOf('Upload EntraOps Reporting artifact')
        $Workflow | Should -Match 'npm run test:reports'
        if ($Workflow -match 'Preserve report test diagnostics') {
            $Workflow | Should -Match "failure\(\).*steps\.repo-visibility\.outputs\.private == 'true'"
            $Workflow.IndexOf('Check repository visibility') | Should -BeLessThan $Workflow.IndexOf('Preserve report test diagnostics')
        }
    }

    It 'uses Classification Explorer history configuration only to select checkout depth' {
        $Workflow = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot '.github/workflows/Push-EntraOpsPrivilegedReporting.yaml') -Raw

        $Workflow | Should -Match 'ClassificationExplorerGenerateChangeHistory:\s*false'
        $Workflow | Should -Match "fetch-depth:\s*\$\{\{\s*env\.ClassificationExplorerGenerateChangeHistory\s*==\s*'true'\s*&&\s*'0'\s*\|\|\s*'1'\s*\}\}"
        $Workflow | Should -Match 'Invoke-EntraOpsReportingGeneration'
        $Workflow | Should -Not -Match 'New-EntraOpsClassificationExplorerData'
    }
}

Describe 'Git-Push credential header' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $script:GitPushAction = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot '.github/actions/Git-Push/action.yml') -Raw
        $script:GitPushScript = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot '.github/scripts/Publish-EntraOpsGitHubChanges.ps1') -Raw
    }

    It 'clears the header inherited from actions/checkout before adding its own' {
        $script:GitPushAction | Should -Match 'Publish-EntraOpsGitHubChanges\.ps1'
        $script:GitPushScript | Should -Match "GIT_CONFIG_COUNT\s*=\s*'2'"
        $script:GitPushScript | Should -Match "GIT_CONFIG_VALUE_0\s*=\s*''"
    }

    # http.extraHeader is multi-valued and an empty value only clears a byte-identical key, so any
    # divergence between the two keys silently restores the duplicate Authorization header.
    It 'resets exactly the key it then sets' {
        $Key0 = [regex]::Match($script:GitPushScript, 'GIT_CONFIG_KEY_0\s*=\s*(?<Key>\$\w+)').Groups['Key'].Value
        $Key1 = [regex]::Match($script:GitPushScript, 'GIT_CONFIG_KEY_1\s*=\s*(?<Key>\$\w+)').Groups['Key'].Value

        $Key0 | Should -Not -BeNullOrEmpty
        $Key1 | Should -Be $Key0
    }

    # GitHub runs bash steps with -e, so the former bash implementation aborted on any git error. The
    # pwsh port must check every native exit code itself or a failed git add degrades into a green
    # no-op push that silently drops generated tenant data.
    It 'checks native exit codes and distinguishes git diff --quiet results in both publishers' {
        $UpdatePublisher = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot '.github/scripts/Publish-EntraOpsGitHubUpdate.ps1') -Raw
        foreach ($Publisher in @($script:GitPushScript, $UpdatePublisher)) {
            $Publisher | Should -Match '(?s)& git add --all[^\r\n]*\r?\n\s*if \(\$LASTEXITCODE -ne 0\) \{ throw'
            $Publisher | Should -Match '(?s)& git config user\.email[^\r\n]*\r?\n\s*if \(\$LASTEXITCODE -ne 0\) \{ throw'
            $Publisher | Should -Match '\$DiffExitCode -eq 1'
            $Publisher | Should -Match "elseif \(\`$DiffExitCode -ne 0\) \{\s*\r?\n\s*throw"
            # Every token-bearing variable must be restored, not just GH_TOKEN.
            foreach ($Name in @('GH_TOKEN', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'GIT_CONFIG_KEY_1', 'GIT_CONFIG_VALUE_1')) {
                $Publisher | Should -Match "'$Name'"
            }
            $Publisher | Should -Match '(?s)finally \{\s*foreach \(\$Name in \$ManagedEnvironment\)'
        }
        $UpdatePublisher | Should -Match '\$LsRemoteExitCode -eq 0'
        $UpdatePublisher | Should -Match 'elseif \(\$LsRemoteExitCode -eq 2\)'
        $UpdatePublisher | Should -Match 'git ls-remote exit code \$LsRemoteExitCode'
        $script:GitPushAction | Should -Not -Match "-split ' '"
        $script:GitPushAction | Should -Match '-split ''\\s\+'''
    }
}

Describe 'Git-Push publisher behavior' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $script:Publisher = Join-Path $script:TestRepositoryRoot '.github/scripts/Publish-EntraOpsGitHubChanges.ps1'
        $script:Remote = Join-Path $TestDrive 'remote.git'
        $script:Seed = Join-Path $TestDrive 'seed'
        & git init --quiet --bare --initial-branch=main $script:Remote
        & git init --quiet --initial-branch=main $script:Seed
        & git -C $script:Seed config user.email 'seed@example.com'
        & git -C $script:Seed config user.name 'seed'
        Set-Content -LiteralPath (Join-Path $script:Seed 'README.md') -Value 'seed'
        & git -C $script:Seed add README.md
        & git -C $script:Seed commit --quiet -m 'seed'
        & git -C $script:Seed remote add origin $script:Remote
        & git -C $script:Seed push --quiet origin main
        $global:LASTEXITCODE = 0

        # The publisher only verifies visibility through gh; the stub must reset $LASTEXITCODE because
        # PowerShell functions leave the last native exit code untouched.
        function global:gh { $global:LASTEXITCODE = 0; 'true' }

        function script:New-PublisherClone {
            param([string]$Name)
            $Clone = Join-Path $TestDrive $Name
            & git clone --quiet $script:Remote $Clone
            & git -C $Clone config user.email 'clone@example.com'
            & git -C $Clone config user.name 'clone'
            return $Clone
        }
    }

    AfterAll {
        Remove-Item -Path Function:\gh -ErrorAction SilentlyContinue
    }

    It 'restores the token-bearing environment on success and on failure' {
        $Clone = New-PublisherClone 'clone-env'
        $env:GIT_CONFIG_COUNT = '1'
        $env:GIT_CONFIG_KEY_0 = 'core.editor'
        $env:GIT_CONFIG_VALUE_0 = 'kept'
        Remove-Item Env:GIT_CONFIG_KEY_1, Env:GIT_CONFIG_VALUE_1, Env:GH_TOKEN -ErrorAction SilentlyContinue
        Push-Location $Clone
        try {
            & $script:Publisher -Paths 'README.md' -AccessToken 'token' -Repository 'org/repo' -Actor 'tester' -CommitMessage 'noop' -ServerUrl 'https://github.com'
            $env:GIT_CONFIG_COUNT | Should -Be '1'
            $env:GIT_CONFIG_KEY_0 | Should -Be 'core.editor'
            $env:GIT_CONFIG_VALUE_0 | Should -Be 'kept'
            $env:GIT_CONFIG_KEY_1 | Should -BeNullOrEmpty
            $env:GIT_CONFIG_VALUE_1 | Should -BeNullOrEmpty
            $env:GH_TOKEN | Should -BeNullOrEmpty

            { & $script:Publisher -Paths 'does-not-exist' -AccessToken 'token' -Repository 'org/repo' -Actor 'tester' -CommitMessage 'noop' -ServerUrl 'https://github.com' } | Should -Throw
            $env:GIT_CONFIG_COUNT | Should -Be '1'
            $env:GIT_CONFIG_VALUE_1 | Should -BeNullOrEmpty
            $env:GH_TOKEN | Should -BeNullOrEmpty
        } finally {
            Pop-Location
            Remove-Item Env:GIT_CONFIG_COUNT, Env:GIT_CONFIG_KEY_0, Env:GIT_CONFIG_VALUE_0 -ErrorAction SilentlyContinue
        }
    }

    It 'fails instead of publishing a no-op when a pathspec does not match' {
        $Clone = New-PublisherClone 'clone-missing-path'
        Push-Location $Clone
        try {
            { & $script:Publisher -Paths 'does-not-exist' -AccessToken 'token' -Repository 'org/repo' -Actor 'tester' -CommitMessage 'test' -ServerUrl 'https://github.com' } |
            Should -Throw '*git add failed*does-not-exist*'
        } finally {
            Pop-Location
        }
    }

    It 'rejects an empty pathspec list before invoking git' {
        $Clone = New-PublisherClone 'clone-empty-paths'
        Push-Location $Clone
        try {
            { & $script:Publisher -Paths @('', '  ') -AccessToken 'token' -Repository 'org/repo' -Actor 'tester' -CommitMessage 'test' -ServerUrl 'https://github.com' } |
            Should -Throw '*At least one pathspec*'
        } finally {
            Pop-Location
        }
    }

    It 'commits and pushes staged output for matching pathspecs and stays a no-op without changes' {
        $Clone = New-PublisherClone 'clone-publish'
        $Before = (& git -C $script:Remote rev-parse main).Trim()
        New-Item -ItemType Directory -Path (Join-Path $Clone 'PrivilegedEAM') | Out-Null
        Set-Content -LiteralPath (Join-Path $Clone 'PrivilegedEAM/EntraID.json') -Value '[]'
        Set-Content -LiteralPath (Join-Path $Clone 'unrelated.txt') -Value 'must not be staged'
        Push-Location $Clone
        try {
            & $script:Publisher -Paths 'PrivilegedEAM' -AccessToken 'token' -Repository 'org/repo' -Actor 'tester' -CommitMessage 'publish test' -ServerUrl 'https://github.com'
            $After = (& git -C $script:Remote rev-parse main).Trim()
            $After | Should -Not -Be $Before
            (& git -C $script:Remote log -1 --format=%s main).Trim() | Should -Be 'publish test'
            @(& git -C $script:Remote ls-tree --name-only -r main) | Should -Contain 'PrivilegedEAM/EntraID.json'
            @(& git -C $script:Remote ls-tree --name-only -r main) | Should -Not -Contain 'unrelated.txt'

            & $script:Publisher -Paths 'PrivilegedEAM' -AccessToken 'token' -Repository 'org/repo' -Actor 'tester' -CommitMessage 'second run' -ServerUrl 'https://github.com'
            (& git -C $script:Remote rev-parse main).Trim() | Should -Be $After
        } finally {
            Pop-Location
        }
    }
}

Describe 'Workflow job conditions' -Skip:(-not [bool](Get-Module -ListAvailable -Name powershell-yaml)) {
    BeforeAll { Import-Module powershell-yaml -ErrorAction Stop }

    # The env context is unavailable in jobs.<job_id>.if, so GitHub cannot evaluate that condition
    # as an ordinary job gate. Keep deployment switches at step level or expose them through outputs.
    It 'never gates a job on the env context' {
        $WorkflowFiles = @(Get-ChildItem -LiteralPath (Join-Path $script:TestRepositoryRoot '.github/workflows') -File |
            Where-Object { $_.Extension -in @('.yaml', '.yml') })
        $WorkflowFiles.Count | Should -BeGreaterThan 0

        $Offenders = @(foreach ($WorkflowFile in $WorkflowFiles) {
                $Jobs = (ConvertFrom-Yaml (Get-Content -LiteralPath $WorkflowFile.FullName -Raw)).jobs
                foreach ($JobName in @($Jobs.Keys)) {
                    if ("$($Jobs[$JobName].if)" -match '(^|[^\w.])env\.') { "$($WorkflowFile.Name):$JobName" }
                }
            })

        ($Offenders -join ', ') | Should -BeNullOrEmpty
    }
}

Describe 'Shipped workflow schedule triggers' {
    # A placeholder cron makes GitHub reject the whole workflow file, and a live cron would run the
    # workflow in a repository created from the template before it has been configured.
    # Update-EntraOpsRequiredWorkflowParameters adds the schedule from EntraOpsConfig.json instead.
    It 'ships <_> without a schedule trigger' -ForEach $ScheduledWorkflowFiles -Skip:(-not $IsShippedUpdateWorkflow) {
        $Workflow = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot '.github/workflows' $_) -Raw

        $Workflow | Should -Not -Match 'YourCronSchedule'
        $Workflow | Should -Not -Match '(?m)^\s*schedule:\s*$'
    }
}

