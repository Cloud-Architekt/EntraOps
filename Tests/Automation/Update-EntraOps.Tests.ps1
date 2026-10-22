#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:EntraOpsBaseFolder = $script:TestRepositoryRoot
    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsRepositoryCheckout.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsRepositoryRoot.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsGitTrackedFile.ps1"

    # NUL-delimited "git ls-files --stage -z" output for a fake checkout: every file on disk counts as tracked
    function Get-TestTrackedFileList {
        param([object[]]$Arguments)
        $Root = $Arguments[[array]::IndexOf($Arguments, '-C') + 1]
        $Separator = [array]::IndexOf($Arguments, '--')
        $Pathspecs = @(if ($Separator -ge 0) { $Arguments[($Separator + 1)..($Arguments.Count - 1)] | ForEach-Object { "$_" -replace '^\./', '' } })
        $Files = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force | ForEach-Object { [System.IO.Path]::GetRelativePath($Root, $_.FullName).Replace('\', '/') } |
            Where-Object { $_ -notmatch '^\.git(/|$)' } |
            Where-Object { $File = $_; $Pathspecs.Count -eq 0 -or @($Pathspecs | Where-Object { $File -eq $_ -or $File.StartsWith("$_/") }).Count -gt 0 })
        (@($Files | ForEach-Object { "100644 0000000000000000000000000000000000000000 0`t$_" }) -join [char]0) + [char]0
    }

    function New-TestGitCandidate {
        param([string]$Path, [hashtable]$TrackedFiles)
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        & git -C $Path init --quiet
        foreach ($File in $TrackedFiles.Keys) {
            $FilePath = Join-Path $Path $File
            [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($FilePath))
            Set-Content -LiteralPath $FilePath -Value $TrackedFiles[$File]
        }
        & git -C $Path add --all
        & git -C $Path -c user.name=EntraOps -c user.email=entraops@example.com -c commit.gpgsign=false commit --quiet -m candidate
        (& git -C $Path rev-parse HEAD).Trim()
    }
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
        $ValidateSet.ValidValues | Should -Contain './.azure-pipelines'
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
        # The files to install are listed before the validation; local targets are only removed after it
        $ReplacementIndex = $Source.IndexOf('Remove-Item -LiteralPath $TargetPath')

        $ValidationIndex | Should -BeGreaterThan -1
        $ReplacementIndex | Should -BeGreaterThan $ValidationIndex
        $Source | Should -Match 'Test-EntraOpsUpdateCandidate\.ps1'
        $Source | Should -Match 'SourceCommit'
        $Source.IndexOf('Test-EntraOpsUpdateContract') | Should -BeLessThan $ReplacementIndex
        $Source | Should -Match "TargetUpdateFolders -contains './\.github/workflows'"
        $Source | Should -Match "TargetUpdateFolders -contains './\.azure-pipelines'"
        $Source.IndexOf('Update-EntraOpsAzureDevOpsSchedules -ConfigFile $ConfigFile') | Should -BeGreaterThan $ReplacementIndex
        $Source.IndexOf('Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigFile') | Should -BeGreaterThan $ReplacementIndex
    }

    It 'requires workflow dependencies and prevents validation bypass' {
        $MissingConfig = Join-Path $TestDrive 'missing.json'

        { Update-EntraOps -ConfigFile $MissingConfig -TargetUpdateFolders @('./.github/workflows') } |
        Should -Throw "*also requires target(s): ./.github/actions, ./.github/scripts*"
        { Update-EntraOps -ConfigFile $MissingConfig -TargetUpdateFolders @('./.github/actions', './.github/scripts', './.github/workflows') -SkipCandidateValidation } |
        Should -Throw "*validation cannot be skipped*"
    }

    It 'refuses to run when the module is not part of a repository checkout' {
        Mock Get-EntraOpsRepositoryRoot { $null }

        { Update-EntraOps -ConfigFile (Join-Path $TestDrive 'missing.json') -TargetUpdateFolders @('./Samples') } |
        Should -Throw '*Update-PSResource EntraOps*Update-Module EntraOps*'
    }

    It 'never imports candidate module code in the updater process' {
        $Source = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot 'EntraOps/Public/Core/Update-EntraOps.ps1') -Raw
        $ReplacementIndex = $Source.IndexOf('Remove-Item -LiteralPath $TargetPath')
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

    It 'rejects a candidate whose archive differs from its checkout (<Case>)' -ForEach @(
        @{ Case = 'export-ignore in a folder'; AsGitCheckout = $false }
        @{ Case = 'export-ignore in a git checkout'; AsGitCheckout = $true }
    ) {
        # The validation job tests a git archive, the apply job copies the checkout: export-ignore files would
        # be installed without validation.
        $CandidateRoot = Join-Path $TestDrive "gitattributes-$AsGitCheckout"
        New-Item -ItemType Directory -Path (Join-Path $CandidateRoot 'EntraOps/Private') -Force | Out-Null
        @{ SchemaVersion = 1; Product = 'EntraOps'; DistributionRepositories = @{ 'Cloud-Architekt/EntraOps' = @{ RequiresPersonalAccessToken = $false } }; SupportedUpdateTargets = @('./EntraOps'); RequiredValidationPaths = @() } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $CandidateRoot 'EntraOpsUpdateContract.json')
        Set-Content -LiteralPath (Join-Path $CandidateRoot 'EntraOps/Private/Unvalidated.ps1') -Value '# not in the validated archive'
        Set-Content -LiteralPath (Join-Path $CandidateRoot 'EntraOps/.gitattributes') -Value 'Private/Unvalidated.ps1 export-ignore'
        if ($AsGitCheckout) {
            & git -C $CandidateRoot init --quiet
            & git -C $CandidateRoot add --all
        }

        { Test-EntraOpsUpdateContract -CandidateRoot $CandidateRoot -Repository 'Cloud-Architekt/EntraOps' -TargetUpdateFolders @('./EntraOps') } |
        Should -Throw '*export-ignore or export-subst*EntraOps/.gitattributes*'
    }

    It 'rejects archive attributes in a path that git quotes' {
        # git quotes non-ASCII paths ("EntraOps/\303\244/.gitattributes") unless they are listed literally
        $CandidateRoot = Join-Path $TestDrive 'quoted-gitattributes'
        $Contract = @{ SchemaVersion = 1; Product = 'EntraOps'; DistributionRepositories = @{ 'Cloud-Architekt/EntraOps' = @{ RequiresPersonalAccessToken = $false } }; SupportedUpdateTargets = @('./EntraOps'); RequiredValidationPaths = @() } | ConvertTo-Json -Depth 5
        $null = New-TestGitCandidate -Path $CandidateRoot -TrackedFiles @{
            'EntraOpsUpdateContract.json'              = $Contract
            "EntraOps/$([char]0x00E4)/.gitattributes"  = 'Unvalidated.ps1 export-ignore'
            "EntraOps/$([char]0x00E4)/Unvalidated.ps1" = '# not in the validated archive'
        }

        { Test-EntraOpsUpdateContract -CandidateRoot $CandidateRoot -Repository 'Cloud-Architekt/EntraOps' -TargetUpdateFolders @('./EntraOps') } |
        Should -Throw "*export-ignore or export-subst*EntraOps/$([char]0x00E4)/.gitattributes*"
    }

    It 'rejects a candidate with a symbolic link' -Skip:$IsWindows {
        # Copy-Item copies the content of the link target, e.g. a local token cache, into the deployment
        $CandidateRoot = Join-Path $TestDrive 'symlink-candidate'
        New-Item -ItemType Directory -Path (Join-Path $CandidateRoot 'EntraOps') -Force | Out-Null
        @{ SchemaVersion = 1; Product = 'EntraOps'; DistributionRepositories = @{ 'Cloud-Architekt/EntraOps' = @{ RequiresPersonalAccessToken = $false } }; SupportedUpdateTargets = @('./EntraOps'); RequiredValidationPaths = @() } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $CandidateRoot 'EntraOpsUpdateContract.json')
        $LinkTarget = Join-Path $TestDrive 'outside-secret.json'
        Set-Content -LiteralPath $LinkTarget -Value '{}'
        New-Item -ItemType SymbolicLink -Path (Join-Path $CandidateRoot 'EntraOps/secret.json') -Target $LinkTarget | Out-Null

        { Test-EntraOpsUpdateContract -CandidateRoot $CandidateRoot -Repository 'Cloud-Architekt/EntraOps' -TargetUpdateFolders @('./EntraOps') } |
        Should -Throw '*symbolic link(s)*secret.json*'
    }

    It 'never clones into and removes an existing temporary update folder' {
        $ExistingFolder = Join-Path $TestDrive 'existing-temp'
        New-Item -ItemType Directory -Path $ExistingFolder -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $ExistingFolder 'keep.txt') -Value 'keep'
        Mock git { $global:LASTEXITCODE = 0 }

        { Update-EntraOps -UpstreamUrl 'https://git.example.invalid/EntraOps.git' -Branch 'v1.1.0' -ConfigFile (Join-Path $TestDrive 'no-config.json') -TemporaryUpdateFolder $ExistingFolder -WarningAction SilentlyContinue } |
        Should -Throw '*already exists*'
        Test-Path -LiteralPath (Join-Path $ExistingFolder 'keep.txt') | Should -BeTrue
        Should -Invoke git -Times 0 -Exactly
    }

    It 'sends ENTRAOPS_PAT only to GitHub and never logs credentials of a custom upstream URL' -ForEach @(
        @{ Case = 'custom host'; Url = 'https://user:url-secret@example.com/EntraOps.git'; ExplicitToken = $null; ExpectedHeaderKey = $null }
        @{ Case = 'explicit token'; Url = 'https://example.com/EntraOps.git'; ExplicitToken = 'explicit-token'; ExpectedHeaderKey = 'http.https://example.com/.extraheader' }
    ) {
        $PreviousPat = $env:ENTRAOPS_PAT
        $script:SeenHeaderKey = 'not-called'
        $script:SeenHeaderValue = 'not-called'
        Mock git {
            if ($args[0] -eq 'clone') { $script:SeenHeaderKey = $env:GIT_CONFIG_KEY_0; $script:SeenHeaderValue = $env:GIT_CONFIG_VALUE_0 }
            $global:LASTEXITCODE = 128
        }
        try {
            $env:ENTRAOPS_PAT = 'environment-token'
            $Output = [System.Collections.Generic.List[string]]::new()
            $UpdateParameters = @{
                UpstreamUrl           = $Url
                Branch                = 'v1.1.0'
                ConfigFile            = (Join-Path $TestDrive 'no-config.json')
                TemporaryUpdateFolder = (Join-Path $TestDrive "clone-$($Case -replace '\W', '-')")
            }
            if ($ExplicitToken) { $UpdateParameters.PersonalAccessToken = $ExplicitToken }
            $script:UpdateWarnings = $null
            {
                try {
                    Update-EntraOps @UpdateParameters -WarningVariable UpdateWarnings -WarningAction SilentlyContinue | ForEach-Object { $Output.Add("$_") }
                } finally {
                    $script:UpdateWarnings = $UpdateWarnings
                }
            } | Should -Throw '*git clone failed*'

            if ($ExpectedHeaderKey) {
                $script:SeenHeaderKey | Should -Be $ExpectedHeaderKey
                $script:SeenHeaderValue | Should -Match ([regex]::Escape([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("x-access-token:$ExplicitToken"))))
            } else {
                $script:SeenHeaderKey | Should -BeNullOrEmpty
                "$script:SeenHeaderValue" | Should -Not -Match ([regex]::Escape([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('x-access-token:environment-token'))))
            }
            ($Output -join "`n") | Should -Not -Match 'url-secret'
            ($Output -join "`n") | Should -Match ([regex]::Escape(($Url -replace '//[^/@]+@', '//')))
            if (-not $ExplicitToken) {
                "$script:UpdateWarnings" | Should -Match 'ENTRAOPS_PAT is not sent'
            }
        } finally {
            if ($null -eq $PreviousPat) { Remove-Item Env:ENTRAOPS_PAT -ErrorAction SilentlyContinue } else { $env:ENTRAOPS_PAT = $PreviousPat }
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
                # The contract check and the install list the tracked files of the candidate (read-only)
                if ($args -contains 'ls-files') { $global:LASTEXITCODE = 0; return (Get-TestTrackedFileList -Arguments $args) }
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

    Context 'installed content' {
        BeforeEach {
            $script:Deployment = Join-Path $TestDrive "installed-$([guid]::NewGuid().ToString('N'))"
            $script:Candidate = Join-Path $script:Deployment 'TmpUpdate'
            $Contract = @{ SchemaVersion = 1; Product = 'EntraOps'; DistributionRepositories = @{ 'Cloud-Architekt/EntraOps' = @{ Channel = 'Release'; RequiresPersonalAccessToken = $false } }; SupportedUpdateTargets = @('./Samples'); RequiredValidationPaths = @() } | ConvertTo-Json -Depth 5
            New-Item -ItemType Directory -Path (Join-Path $script:Deployment 'Samples') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $script:Deployment 'EntraOpsUpdateContract.json') -Value $Contract
            Set-Content -LiteralPath (Join-Path $script:Deployment 'Samples/old.txt') -Value 'old'
            $script:CandidateCommit = New-TestGitCandidate -Path $script:Candidate -TrackedFiles @{
                'EntraOpsUpdateContract.json' = $Contract
                'Samples/new.txt'             = 'new'
                'Samples/nested/tracked.txt'  = 'tracked'
            }

            $script:InvokePreparedUpdate = {
                param([string]$ValidatorScript)
                $UpdateParameters = @{ ValidatedSourceCommit = $script:CandidateCommit }
                if ($ValidatorScript) {
                    # Local flow: the trusted validator of the deployment runs candidate code in the candidate folder
                    New-Item -ItemType Directory -Path (Join-Path $script:Deployment '.github/scripts') -Force | Out-Null
                    Set-Content -LiteralPath (Join-Path $script:Deployment '.github/scripts/Test-EntraOpsUpdateCandidate.ps1') -Value $ValidatorScript
                    $UpdateParameters = @{}
                }
                $PreviousBaseFolder = $script:EntraOpsBaseFolder
                $PreviousPat = $env:ENTRAOPS_PAT
                $script:EntraOpsBaseFolder = $script:Deployment
                Push-Location $script:Deployment
                try {
                    Remove-Item Env:ENTRAOPS_PAT -ErrorAction SilentlyContinue
                    Update-EntraOps -ConfigFile (Join-Path $script:Deployment 'missing.json') -Repository 'EntraOps' -PreparedCandidatePath 'TmpUpdate' `
                        -TargetUpdateFolders @('./Samples') @UpdateParameters -WarningAction SilentlyContinue | Out-Null
                } finally {
                    Pop-Location
                    $script:EntraOpsBaseFolder = $PreviousBaseFolder
                    if ($null -eq $PreviousPat) { Remove-Item Env:ENTRAOPS_PAT -ErrorAction SilentlyContinue } else { $env:ENTRAOPS_PAT = $PreviousPat }
                }
            }
        }

        It 'installs only the tracked files of the candidate' {
            # e.g. written by candidate code during the validation in the same folder
            Set-Content -LiteralPath (Join-Path $script:Candidate 'Samples/untracked.txt') -Value 'never validated'

            & $script:InvokePreparedUpdate

            Test-Path -LiteralPath (Join-Path $script:Deployment 'Samples/new.txt') | Should -BeTrue
            Get-Content -LiteralPath (Join-Path $script:Deployment 'Samples/nested/tracked.txt') | Should -Be 'tracked'
            Test-Path -LiteralPath (Join-Path $script:Deployment 'Samples/untracked.txt') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $script:Deployment 'Samples/old.txt') | Should -BeFalse
        }

        It 'installs the files listed before the validation and runs no git command in the candidate afterwards' {
            # Candidate code in the validation can change the index or the git configuration of the candidate,
            # e.g. a core.fsmonitor command that git would run with the credentials of the updater process
            $script:HookMarker = Join-Path $TestDrive "fsmonitor-$([guid]::NewGuid().ToString('N'))"
            $Validator = @"
param([string]`$CandidateRoot, [switch]`$RunBrowserTests)
Set-Content -LiteralPath (Join-Path `$CandidateRoot 'Samples/added.txt') -Value 'added during validation'
& git -C `$CandidateRoot add --all
& git -C `$CandidateRoot config core.fsmonitor "echo hooked > '$($script:HookMarker)'"
exit 0
"@

            & $script:InvokePreparedUpdate -ValidatorScript $Validator

            Test-Path -LiteralPath (Join-Path $script:Deployment 'Samples/new.txt') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $script:Deployment 'Samples/added.txt') | Should -BeFalse
            Test-Path -LiteralPath $script:HookMarker | Should -BeFalse
        }

        It 'stops before changing any local folder when a tracked file is missing' {
            $Validator = @"
param([string]`$CandidateRoot, [switch]`$RunBrowserTests)
Remove-Item -LiteralPath (Join-Path `$CandidateRoot 'Samples/nested/tracked.txt')
exit 0
"@

            { & $script:InvokePreparedUpdate -ValidatorScript $Validator } | Should -Throw '*missing tracked file(s)*Samples/nested/tracked.txt*No local folder was changed*'

            Get-Content -LiteralPath (Join-Path $script:Deployment 'Samples/old.txt') | Should -Be 'old'
        }

        It 'stops before changing any local folder when the candidate contains a <Case>' -Skip:$IsWindows -ForEach @(
            @{ Case = 'untracked symbolic link'; LinkPath = 'Samples/link.txt'; ReplaceFolder = $false }
            @{ Case = 'tracked folder replaced by a link'; LinkPath = 'Samples/nested'; ReplaceFolder = $true }
        ) {
            # A link is copied as the content of its target, e.g. a local token cache
            $Secret = Join-Path $TestDrive 'secret-outside'
            New-Item -ItemType Directory -Path $Secret -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $Secret 'tracked.txt') -Value 'secret'
            $LinkFullPath = Join-Path $script:Candidate $LinkPath
            if ($ReplaceFolder) {
                Remove-Item -LiteralPath $LinkFullPath -Recurse -Force
                New-Item -ItemType SymbolicLink -Path $LinkFullPath -Target $Secret | Out-Null
            } else {
                New-Item -ItemType SymbolicLink -Path $LinkFullPath -Target (Join-Path $Secret 'tracked.txt') | Out-Null
            }

            { & $script:InvokePreparedUpdate } | Should -Throw '*symbolic link(s) or junction(s)*No local folder was changed*'

            Get-Content -LiteralPath (Join-Path $script:Deployment 'Samples/old.txt') | Should -Be 'old'
            Test-Path -LiteralPath (Join-Path $script:Deployment 'Samples/new.txt') | Should -BeFalse
        }
    }

    It 'replaces targets in the repository root when run from another location' {
        $Deployment = Join-Path $TestDrive 'root-deployment'
        $Candidate = Join-Path $TestDrive 'root-candidate'
        $Elsewhere = Join-Path $TestDrive 'elsewhere'
        New-Item -ItemType Directory -Path (Join-Path $Deployment 'Samples'), (Join-Path $Candidate 'Samples'), (Join-Path $Candidate '.azure-pipelines'), (Join-Path $Elsewhere 'Samples'), (Join-Path $Candidate '.git') -Force | Out-Null
        $Contract = @{ SchemaVersion = 1; Product = 'EntraOps'; DistributionRepositories = @{ 'Cloud-Architekt/EntraOps' = @{ Channel = 'Release'; RequiresPersonalAccessToken = $false } }; SupportedUpdateTargets = @('./Samples', './.azure-pipelines'); RequiredValidationPaths = @() } | ConvertTo-Json -Depth 5
        Set-Content -LiteralPath (Join-Path $Deployment 'EntraOpsUpdateContract.json') -Value $Contract
        Set-Content -LiteralPath (Join-Path $Candidate 'EntraOpsUpdateContract.json') -Value $Contract
        Set-Content -LiteralPath (Join-Path $Deployment 'Samples/old.txt') -Value 'old'
        Set-Content -LiteralPath (Join-Path $Candidate 'Samples/new.txt') -Value 'new'
        Set-Content -LiteralPath (Join-Path $Candidate '.azure-pipelines/entraops-pull.yml') -Value 'pipeline'
        Set-Content -LiteralPath (Join-Path $Deployment 'EntraOpsConfig.json') -Value '{}'
        Set-Content -LiteralPath (Join-Path $Elsewhere 'Samples/unrelated.txt') -Value 'keep'
        # The refresh must use the loaded (trusted) helper. The candidate's helper would leave a marker:
        # the publish step that follows on the same agent holds the token, so no candidate code may run.
        $ScheduleRecord = Join-Path $TestDrive 'schedule-call.json'
        $CandidateMarker = Join-Path $TestDrive 'candidate-helper-executed.marker'
        $CandidateHelperFolder = Join-Path $Candidate 'EntraOps/Public/Configuration'
        New-Item -ItemType Directory -Path $CandidateHelperFolder -Force | Out-Null
        foreach ($HelperName in 'Update-EntraOpsAzureDevOpsSchedules', 'Update-EntraOpsRequiredWorkflowParameters') {
            Set-Content -LiteralPath (Join-Path $CandidateHelperFolder "$HelperName.ps1") -Value "Set-Content -LiteralPath '$CandidateMarker' -Value 'executed'; function $HelperName { Set-Content -LiteralPath '$CandidateMarker' -Value 'executed' }"
        }
        function Update-EntraOpsAzureDevOpsSchedules {
            param($ConfigFile, $PipelineFolder)
            @{ Location = (Get-Location).ProviderPath; ConfigFile = $ConfigFile; PipelineFolder = $PipelineFolder } |
            ConvertTo-Json | Set-Content -LiteralPath $ScheduleRecord
        }

        $PreviousBaseFolder = $script:EntraOpsBaseFolder
        $PreviousPat = $env:ENTRAOPS_PAT
        $PreviousAccessToken = $env:SYSTEM_ACCESSTOKEN
        $script:EntraOpsBaseFolder = $Deployment
        Push-Location $Elsewhere
        try {
            Remove-Item Env:ENTRAOPS_PAT -ErrorAction SilentlyContinue
            $env:SYSTEM_ACCESSTOKEN = 'must-not-reach-candidate-code'
            Mock git {
                if ($args -contains 'rev-parse') { $global:LASTEXITCODE = 0; return ('a' * 40) }
                # The contract check and the install list the tracked files of the candidate (read-only)
                if ($args -contains 'ls-files') { $global:LASTEXITCODE = 0; return (Get-TestTrackedFileList -Arguments $args) }
                throw "git must not clone or fetch for a prepared candidate (called with: $($args -join ' '))"
            }
            Update-EntraOps -ConfigFile 'EntraOpsConfig.json' -Repository 'EntraOps' -PreparedCandidatePath $Candidate `
                -TargetUpdateFolders @('./Samples', './.azure-pipelines') -ValidatedSourceCommit ('a' * 40) -WarningAction SilentlyContinue | Out-Null
            (Get-Location).ProviderPath | Should -Be (Get-Item -LiteralPath $Elsewhere).FullName
            $env:SYSTEM_ACCESSTOKEN | Should -Be 'must-not-reach-candidate-code'
        } finally {
            Pop-Location
            $script:EntraOpsBaseFolder = $PreviousBaseFolder
            if ($null -eq $PreviousPat) { Remove-Item Env:ENTRAOPS_PAT -ErrorAction SilentlyContinue } else { $env:ENTRAOPS_PAT = $PreviousPat }
            if ($null -eq $PreviousAccessToken) { Remove-Item Env:SYSTEM_ACCESSTOKEN -ErrorAction SilentlyContinue } else { $env:SYSTEM_ACCESSTOKEN = $PreviousAccessToken }
        }

        Test-Path -LiteralPath (Join-Path $Deployment 'Samples/new.txt') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $Deployment 'Samples/old.txt') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $Deployment '.azure-pipelines/entraops-pull.yml') | Should -BeTrue
        $ScheduleCall = Get-Content -LiteralPath $ScheduleRecord -Raw | ConvertFrom-Json
        $ScheduleCall.Location | Should -Be (Get-Item -LiteralPath $Deployment).FullName
        $ScheduleCall.ConfigFile | Should -Be 'EntraOpsConfig.json'
        $ScheduleCall.PipelineFolder | Should -Be './.azure-pipelines'
        Test-Path -LiteralPath $CandidateMarker | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $Elsewhere '.azure-pipelines') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $Elsewhere 'Samples/unrelated.txt') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $Elsewhere 'Samples/new.txt') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $Elsewhere '.EntraOpsUpdateManifest.json') | Should -BeFalse
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
        $ConfigGenerator | Should -Match '\$DefaultUpdatePublicationMode = \$UpdatePublicationMode'
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
        # Any Dependabot-updated release: only the full commit SHA pin is required
        $ApplyJob | Should -Match 'actions/create-github-app-token@[0-9a-f]{40}\s+# v\d+\.\d+\.\d+'
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
        $Publisher | Should -Match 'Approve and run workflows'
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

    It 'runs generated report browser validation' {
        $Workflow = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot '.github/workflows/Push-EntraOpsPrivilegedReporting.yaml') -Raw

        $Workflow | Should -Match 'npm run test:reports'
        if ($Workflow -match 'Preserve report test diagnostics') {
            $Workflow | Should -Match "failure\(\).*steps\.repo-visibility\.outputs\.private == 'true'"
            $Workflow.IndexOf('Check repository visibility') | Should -BeLessThan $Workflow.IndexOf('Preserve report test diagnostics')
        }
    }

    It 'publishes the report artifact and releases only after opted-in tests pass' -Skip:(-not $IsDistributionRepository -or -not (Get-Module -ListAvailable -Name powershell-yaml)) {
        Import-Module powershell-yaml -ErrorAction Stop
        $Workflow = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot '.github/workflows/Push-EntraOpsPrivilegedReporting.yaml') -Raw
        $Jobs = ($Workflow | ConvertFrom-Yaml).jobs
        $Generation = $Jobs['Push-EntraOpsPrivilegedReporting']
        $TestJob = $Jobs['Test-EntraOpsPrivilegedReporting']
        $PublishJob = $Jobs['Publish-EntraOpsPrivilegedReporting']
        $ReleaseJob = $Jobs['Release-EntraOpsPrivilegedReporting']
        $CleanupJob = $Jobs['Remove-EntraOpsReportingHandover']
        $Needs = 'needs.Push-EntraOpsPrivilegedReporting'
        function Get-Uploads ($Job) { @($Job.steps | Where-Object { "$($_.uses)" -like 'actions/upload-artifact@*' }) }
        function Get-Downloads ($Job) { @($Job.steps | Where-Object { "$($_.uses)" -like 'actions/download-artifact@*' }) }

        $Workflow | Should -Not -Match '(?m)^  (RunGeneratedReportTests|PublishReportsAsRelease|UploadReportTestDiagnostics):'
        $Workflow | Should -Not -Match 'env\.PublishReportsAsRelease'
        $Generation.outputs.reportsDigest | Should -Be '${{ steps.stage-reports.outputs.digest }}'

        # Generation stages the exact bundle, records its digest and uploads either the final artifact or the 1-day hand-over.
        $Stage = $Generation.steps | Where-Object { $_.id -eq 'stage-reports' }
        $Stage.if | Should -Be "env.ApplyAutomatedReportingGeneration == 'true' && steps.repo-visibility.outputs.private == 'true'"
        $Stage.run | Should -Match 'Get-EntraOpsReportDigest\.ps1'
        $Uploads = Get-Uploads $Generation
        $Uploads.Count | Should -Be 2
        foreach ($Upload in $Uploads) {
            $Upload.with.path | Should -Be '${{ runner.temp }}/EntraOps-Reporting'
            $Upload.with['include-hidden-files'] | Should -BeTrue
        }
        $Final = $Uploads | Where-Object { $_.with.name -eq 'EntraOps-Reporting' }
        $Final.if | Should -Be "steps.stage-reports.outcome == 'success' && steps.automation-settings.outputs.runGeneratedReportTests != 'true'"
        $Final.with['retention-days'] | Should -Be 30
        $Handover = $Uploads | Where-Object { $_.with.name -eq 'EntraOps-Reporting-Untested' }
        $Handover.if | Should -Be "steps.stage-reports.outcome == 'success' && steps.automation-settings.outputs.runGeneratedReportTests == 'true'"
        $Handover.with['retention-days'] | Should -Be 1

        # The test job runs third-party packages: read-only, no install scripts, no dependency cache, bounded runtime.
        $TestJob.if | Should -Be "$Needs.outputs.private == 'true' && $Needs.outputs.runGeneratedReportTests == 'true'"
        $TestJob.permissions.Keys | Should -Be @('contents')
        $TestJob.permissions.contents | Should -Be 'read'
        $TestJob['timeout-minutes'] | Should -Be 30
        (Get-Downloads $TestJob).with.name | Should -Be 'EntraOps-Reporting-Untested'
        (Get-Downloads $TestJob).with['digest-mismatch'] | Should -Be 'error'
        @($TestJob.steps.run) | Should -Contain 'npm ci --ignore-scripts'
        ($TestJob.steps | Where-Object { "$($_.uses)" -like 'actions/setup-node@*' }).with.Contains('cache') | Should -BeFalse
        $Diagnostics = @(Get-Uploads $TestJob)
        $Diagnostics.Count | Should -Be 1
        $Diagnostics[0].with.name | Should -Be 'EntraOps-Reporting-TestDiagnostics'
        $Diagnostics[0].if | Should -Be "failure() && $Needs.outputs.uploadReportTestDiagnostics == 'true'"
        $Diagnostics[0].with['retention-days'] | Should -Be 1
        $TestJob.env.ENTRAOPS_REPORT_TEST_TRACE | Should -Be "`${{ $Needs.outputs.uploadReportTestDiagnostics }}"

        # The tested artifact is published read-only from the verified hand-over.
        $PublishJob.permissions.Keys | Should -Be @('contents')
        $PublishJob.permissions.contents | Should -Be 'read'
        ($PublishJob.if -replace '\s+', ' ') | Should -Be "!cancelled() && $Needs.result == 'success' && $Needs.outputs.private == 'true' && $Needs.outputs.runGeneratedReportTests == 'true' && needs.Test-EntraOpsPrivilegedReporting.result == 'success'"
        (Get-Downloads $PublishJob).with.name | Should -Be 'EntraOps-Reporting-Untested'
        ($PublishJob.steps | Where-Object { "$($_.run)" -match 'Get-EntraOpsReportDigest' }).env.ExpectedDigest | Should -Be "`${{ $Needs.outputs.reportsDigest }}"
        (Get-Uploads $PublishJob).with.name | Should -Be 'EntraOps-Reporting'
        [array]::IndexOf(@($PublishJob.steps.name), 'Verify report bundle digest') | Should -BeLessThan ([array]::IndexOf(@($PublishJob.steps.name), 'Upload tested EntraOps Reporting artifact'))

        # Only the release job can write repository contents, and it releases the verified final artifact.
        $ReleaseJob.permissions.contents | Should -Be 'write'
        $ReleaseCondition = $ReleaseJob.if -replace '\s+', ' '
        $ReleaseCondition | Should -Match ([regex]::Escape("$Needs.outputs.publishReportsAsRelease == 'true'"))
        $ReleaseCondition | Should -Match ([regex]::Escape("($Needs.outputs.runGeneratedReportTests == 'true' && needs.Publish-EntraOpsPrivilegedReporting.result == 'success')"))
        $ReleaseCondition | Should -Match ([regex]::Escape("($Needs.outputs.runGeneratedReportTests != 'true' && needs.Test-EntraOpsPrivilegedReporting.result == 'skipped')"))
        (Get-Downloads $ReleaseJob).with.name | Should -Be 'EntraOps-Reporting'
        ($ReleaseJob.steps | Where-Object { "$($_.run)" -match 'Get-EntraOpsReportDigest' }) | Should -Not -BeNullOrEmpty
        @(Get-Uploads $ReleaseJob).Count | Should -Be 0
        foreach ($Job in $Generation, $TestJob, $PublishJob, $CleanupJob) {
            "$($Job.permissions.contents)" | Should -Not -Be 'write'
        }

        # The hand-over is deleted after every run that created it, including failed and cancelled ones.
        $CleanupJob.if | Should -Be "always() && $Needs.outputs.runGeneratedReportTests == 'true' && $Needs.outputs.private == 'true'"
        $CleanupJob.permissions.Keys | Should -Be @('actions')
        $CleanupJob.permissions.actions | Should -Be 'write'
        @($CleanupJob.needs) | Should -Contain 'Publish-EntraOpsPrivilegedReporting'
        $CleanupJob.steps[0].run | Should -Match 'select\(\.name == "EntraOps-Reporting-Untested"\)'
        $CleanupJob.steps[0].run | Should -Match '--method DELETE'
    }

    It 'reads report job switches from the config at runtime (<Setting>, manual <Manual>)' -Skip:(-not $IsDistributionRepository -or -not (Get-Module -ListAvailable -Name powershell-yaml)) -ForEach @(
        @{ Setting = 'missing'; Manual = ''; Expected = 'false'; ExpectedTests = 'false' }
        @{ Setting = 'false'; Manual = 'Configured'; Expected = 'false'; ExpectedTests = 'false' }
        @{ Setting = 'true'; Manual = ''; Expected = 'true'; ExpectedTests = 'true' }
        @{ Setting = 'false'; Manual = 'true'; Expected = 'false'; ExpectedTests = 'true' }
        @{ Setting = 'true'; Manual = 'false'; Expected = 'true'; ExpectedTests = 'false' }
    ) {
        Import-Module powershell-yaml -ErrorAction Stop
        $Workflow = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot '.github/workflows/Push-EntraOpsPrivilegedReporting.yaml') -Raw | ConvertFrom-Yaml
        $Workflow.on.workflow_dispatch.inputs.runGeneratedReportTests.options | Should -Be @('Configured', 'true', 'false')
        $Step = $Workflow.jobs['Push-EntraOpsPrivilegedReporting'].steps | Where-Object { $_.id -eq 'automation-settings' }
        $Step.if | Should -Be "env.ApplyAutomatedReportingGeneration == 'true'"
        $Step.env.ManualRunGeneratedReportTests | Should -Be '${{ inputs.runGeneratedReportTests }}'
        $Settings = @{}
        if ($Setting -ne 'missing') {
            $Settings = @{ RunGeneratedReportTests = $Setting -eq 'true'; PublishReportsAsRelease = $Setting -eq 'true'; UploadReportTestDiagnostics = $Setting -eq 'true' }
        }
        $ConfigPath = Join-Path $TestDrive "config-$Setting-$Manual.json"
        $OutputPath = Join-Path $TestDrive "output-$Setting-$Manual.txt"
        @{ AutomatedReportingGeneration = $Settings } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath

        $Previous = @{ ConfigFile = $env:ConfigFile; GITHUB_OUTPUT = $env:GITHUB_OUTPUT; Manual = $env:ManualRunGeneratedReportTests }
        try {
            $env:ConfigFile = $ConfigPath
            $env:GITHUB_OUTPUT = $OutputPath
            $env:ManualRunGeneratedReportTests = $Manual
            & ([scriptblock]::Create($Step.run))
        } finally {
            $env:ConfigFile = $Previous.ConfigFile
            $env:GITHUB_OUTPUT = $Previous.GITHUB_OUTPUT
            $env:ManualRunGeneratedReportTests = $Previous.Manual
        }

        $Outputs = @(Get-Content -LiteralPath $OutputPath)
        $Outputs | Should -Contain "runGeneratedReportTests=$ExpectedTests"
        $Outputs | Should -Contain "publishReportsAsRelease=$Expected"
        $Outputs | Should -Contain "uploadReportTestDiagnostics=$Expected"
    }

    It 'computes an order-independent report bundle digest that detects any change' {
        $Script = Join-Path $script:TestRepositoryRoot '.github/scripts/Get-EntraOpsReportDigest.ps1'
        $Bundle = Join-Path $TestDrive 'DigestBundle'
        New-Item -Path "$Bundle/App/data" -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath "$Bundle/index.html" -Value '<html>Tenant report</html>'
        Set-Content -LiteralPath "$Bundle/App/data/data.js" -Value 'window.DATA = {};'
        $Digest = & $Script -Path $Bundle

        $Digest | Should -Match '^[0-9a-f]{64}$'
        & $Script -Path $Bundle | Should -Be $Digest
        Add-Content -LiteralPath "$Bundle/App/data/data.js" -Value '// tampered'
        & $Script -Path $Bundle | Should -Not -Be $Digest
        { & $Script -Path (New-Item -Path (Join-Path $TestDrive 'EmptyBundle') -ItemType Directory -Force).FullName } | Should -Throw '*No report files*'
    }

    It 'stages the report bundle and verifies the hand-over against its digest' -Skip:(-not $IsDistributionRepository -or -not (Get-Module -ListAvailable -Name powershell-yaml)) {
        Import-Module powershell-yaml -ErrorAction Stop
        $Jobs = (Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot '.github/workflows/Push-EntraOpsPrivilegedReporting.yaml') -Raw | ConvertFrom-Yaml).jobs
        $Stage = $Jobs['Push-EntraOpsPrivilegedReporting'].steps | Where-Object { $_.id -eq 'stage-reports' }
        $Verify = $Jobs['Publish-EntraOpsPrivilegedReporting'].steps | Where-Object { $_.name -eq 'Verify report bundle digest' }
        $Workspace = Join-Path $TestDrive 'StageWorkspace'
        $RunnerTemp = Join-Path $TestDrive 'RunnerTemp'
        New-Item -Path "$Workspace/Reports/App", "$Workspace/.github/scripts", $RunnerTemp -ItemType Directory -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:TestRepositoryRoot '.github/scripts/Get-EntraOpsReportDigest.ps1') -Destination "$Workspace/.github/scripts"
        Set-Content -LiteralPath "$Workspace/Reports/App/index.html" -Value '<html>Tenant report</html>'
        Set-Content -LiteralPath "$Workspace/Reports/reports.smoke.spec.mjs" -Value 'test harness'
        $Previous = @{ RUNNER_TEMP = $env:RUNNER_TEMP; GITHUB_OUTPUT = $env:GITHUB_OUTPUT; GITHUB_STEP_SUMMARY = $env:GITHUB_STEP_SUMMARY; RunGeneratedReportTests = $env:RunGeneratedReportTests; ExpectedDigest = $env:ExpectedDigest }

        Push-Location $Workspace
        try {
            $env:RUNNER_TEMP = $RunnerTemp
            $env:GITHUB_OUTPUT = Join-Path $TestDrive 'stage-output.txt'
            $env:GITHUB_STEP_SUMMARY = Join-Path $TestDrive 'stage-summary.md'
            $env:RunGeneratedReportTests = 'true'
            & ([scriptblock]::Create($Stage.run))
            $Digest = (@(Get-Content -LiteralPath $env:GITHUB_OUTPUT) -match '^digest=') -replace '^digest=', ''

            $env:ExpectedDigest = $Digest
            { & ([scriptblock]::Create($Verify.run)) } | Should -Not -Throw
            Add-Content -LiteralPath "$RunnerTemp/EntraOps-Reporting/App/index.html" -Value '<script>tampered</script>'
            { & ([scriptblock]::Create($Verify.run)) } | Should -Throw '*does not match*'
        } finally {
            Pop-Location
            foreach ($Name in $Previous.Keys) { [Environment]::SetEnvironmentVariable($Name, $Previous[$Name]) }
        }

        $Digest | Should -Match '^[0-9a-f]{64}$'
        Test-Path "$RunnerTemp/EntraOps-Reporting/reports.smoke.spec.mjs" | Should -BeFalse
        Get-Content -LiteralPath (Join-Path $TestDrive 'stage-summary.md') -Raw | Should -Match 'published only after the report tests pass'
    }

    It 'uses Classification Explorer history configuration only to select checkout depth' {
        $Workflow = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot '.github/workflows/Push-EntraOpsPrivilegedReporting.yaml') -Raw

        $Workflow | Should -Match 'ClassificationExplorerGenerateChangeHistory:\s*false'
        $Workflow | Should -Match "fetch-depth:\s*\$\{\{\s*env\.ClassificationExplorerGenerateChangeHistory\s*==\s*'true'\s*&&\s*'0'\s*\|\|\s*'1'\s*\}\}"
        $Workflow | Should -Not -Match 'New-EntraOpsClassificationExplorerData'
        # .github/workflows is never an automated update target, so deployments may still run the earlier inline call.
        if ($Workflow -match 'Invoke-EntraOpsGitHubReportingGeneration\.ps1') {
            $GenerationScript = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot '.github/scripts/Invoke-EntraOpsGitHubReportingGeneration.ps1') -Raw
            $GenerationScript | Should -Match 'Invoke-EntraOpsReportingGeneration'
            $GenerationScript | Should -Not -Match 'New-EntraOpsClassificationExplorerData'
        } else {
            $Workflow | Should -Match 'Invoke-EntraOpsReportingGeneration\s+-'
        }
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
        # An open update pull request is checked before the branch is pushed, so reviewer commits are kept.
        $UpdatePublisher.IndexOf('& gh pr list') | Should -BeGreaterThan 0
        $UpdatePublisher.IndexOf('& gh pr list') | Should -BeLessThan $UpdatePublisher.IndexOf('& git ls-remote')
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

    It 'skips a missing pathspec when another pathspec matches' {
        # E.g. Classification/<TenantName> does not exist while the automated classification update is disabled.
        $Clone = New-PublisherClone 'clone-partial-paths'
        # The tests of this block share one remote: a folder of its own keeps PrivilegedEAM absent from the
        # clones of the later tests, which create it themselves.
        New-Item -ItemType Directory -Path (Join-Path $Clone 'TenantGovernance') | Out-Null
        Set-Content -LiteralPath (Join-Path $Clone 'TenantGovernance/PartialPaths.json') -Value '[]'
        Push-Location $Clone
        try {
            & $script:Publisher -Paths 'Classification/contoso.onmicrosoft.com', 'TenantGovernance' -AccessToken 'token' -Repository 'org/repo' -Actor 'tester' -CommitMessage 'partial' -ServerUrl 'https://github.com' 6>$null
            (& git -C $script:Remote log -1 --format=%s main) | Should -Be 'partial'
            @(& git -C $script:Remote ls-tree -r --name-only main) | Should -Contain 'TenantGovernance/PartialPaths.json'
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